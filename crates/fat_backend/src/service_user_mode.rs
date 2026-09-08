use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use fat_core::debug::{ObservedProcessEntry, ObservedServiceEntry};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::rehosting_recipe::{RecipeDeviceNodePlan, RecipeFilesystemTransform, RecipePathKind};
use fat_core::runs::RuntimeEndpoint;
use serde::{Deserialize, Serialize};

const BACKEND_ID: &str = "service-user-mode";
const SERVICE_USER_MODE_TIMEOUT_SECS_ENV: &str = "FAT_SERVICE_USER_MODE_TIMEOUT_SECS";
const DEFAULT_SERVICE_USER_MODE_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUserModeRequest {
    pub project_id: String,
    pub target_id: String,
    pub architecture: String,
    pub qemu_binary: PathBuf,
    pub input_root: PathBuf,
    pub source_root: PathBuf,
    pub staging_root: PathBuf,
    pub executable_path: String,
    pub env_injections: Vec<String>,
    pub device_nodes: Vec<RecipeDeviceNodePlan>,
    pub filesystem_transforms: Vec<RecipeFilesystemTransform>,
}

impl ServiceUserModeRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        architecture: impl Into<String>,
        qemu_binary: PathBuf,
        input_root: PathBuf,
        source_root: PathBuf,
        staging_root: PathBuf,
        executable_path: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            target_id: target_id.into(),
            architecture: architecture.into(),
            qemu_binary,
            input_root,
            source_root,
            staging_root,
            executable_path: executable_path.into(),
            env_injections: Vec::new(),
            device_nodes: Vec::new(),
            filesystem_transforms: Vec::new(),
        }
    }

    pub fn with_env_injections(mut self, env_injections: Vec<String>) -> Self {
        self.env_injections = env_injections;
        self
    }

    pub fn with_device_nodes(mut self, device_nodes: Vec<RecipeDeviceNodePlan>) -> Self {
        self.device_nodes = device_nodes;
        self
    }

    pub fn with_filesystem_transforms(
        mut self,
        filesystem_transforms: Vec<RecipeFilesystemTransform>,
    ) -> Self {
        self.filesystem_transforms = filesystem_transforms;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUserModePrepared {
    pub request: ServiceUserModeRequest,
    pub prepared_id: String,
    pub staged_executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUserModeLaunchManifest {
    pub endpoints: Vec<RuntimeEndpoint>,
    #[serde(default)]
    pub processes: Vec<ObservedProcessEntry>,
    #[serde(default)]
    pub services: Vec<ObservedServiceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUserModeLaunchResult {
    pub prepared_id: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub endpoints: Vec<RuntimeEndpoint>,
    pub launch_manifest: Option<ServiceUserModeLaunchManifest>,
}

#[derive(Debug, Default)]
pub struct ServiceUserModeManager;

impl ServiceUserModeManager {
    pub fn new() -> Self {
        Self
    }

    pub fn prepare(
        &self,
        request: ServiceUserModeRequest,
    ) -> Result<ServiceUserModePrepared, DiagnosticRecord> {
        validate_request(&request)?;

        let prepared_id = stable_prepared_id(&request);
        recreate_dir(&request.source_root).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to reset source root: {err}"),
            )
        })?;
        copy_tree(&request.input_root, &request.source_root).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to materialize immutable source root: {err}"),
            )
        })?;

        recreate_dir(&request.staging_root).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to reset service staging root: {err}"),
            )
        })?;
        copy_tree(&request.source_root, &request.staging_root).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to materialize mutable service staging root: {err}"),
            )
        })?;
        materialize_repair_mutations(&request).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to materialize service repair mutations: {err}"),
            )
        })?;

        let staged_executable = request
            .staging_root
            .join(request.executable_path.trim_start_matches('/'));
        if !staged_executable.exists() {
            return Err(preparation_error(
                &prepared_id,
                &request,
                format!(
                    "staged executable is missing after materialization: {}",
                    staged_executable.display()
                ),
            ));
        }

        Ok(ServiceUserModePrepared {
            request,
            prepared_id,
            staged_executable,
        })
    }

    pub fn launch(
        &self,
        prepared: &ServiceUserModePrepared,
    ) -> Result<ServiceUserModeLaunchResult, DiagnosticRecord> {
        let mut command = Command::new(&prepared.request.qemu_binary);
        command
            .arg("-L")
            .arg(&prepared.request.staging_root)
            .arg(&prepared.staged_executable)
            .current_dir(&prepared.request.staging_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for env_injection in &prepared.request.env_injections {
            if let Some((key, value)) = env_injection.split_once('=') {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().map_err(|err| {
            launch_error(
                &prepared.prepared_id,
                format!("failed to spawn qemu-user launcher: {err}"),
                None,
                "",
                "",
            )
        })?;
        let timeout = Duration::from_secs(service_user_mode_timeout_secs());
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => sleep(Duration::from_millis(50)),
                Ok(None) => {
                    let _ = child.kill();
                    let output = child.wait_with_output().map_err(|err| {
                        launch_error(
                            &prepared.prepared_id,
                            format!("failed to collect qemu-user timeout output: {err}"),
                            None,
                            "",
                            "",
                        )
                    })?;
                    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                    return Err(launch_timeout_error(
                        &prepared.prepared_id,
                        timeout,
                        &stdout,
                        &stderr,
                    ));
                }
                Err(err) => {
                    return Err(launch_error(
                        &prepared.prepared_id,
                        format!("failed to poll qemu-user launcher: {err}"),
                        None,
                        "",
                        "",
                    ));
                }
            }
        }
        let output = child.wait_with_output().map_err(|err| {
            launch_error(
                &prepared.prepared_id,
                format!("failed to collect qemu-user output: {err}"),
                None,
                "",
                "",
            )
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(launch_error(
                &prepared.prepared_id,
                "qemu-user service launch exited unsuccessfully",
                output.status.code(),
                &stdout,
                &stderr,
            ));
        }

        let launch_manifest = parse_launch_manifest(prepared, &stdout)?;
        let endpoints = launch_manifest
            .as_ref()
            .map(|manifest| manifest.endpoints.clone())
            .unwrap_or_default();
        Ok(ServiceUserModeLaunchResult {
            prepared_id: prepared.prepared_id.clone(),
            exit_code: output.status.code(),
            stdout,
            stderr,
            endpoints,
            launch_manifest,
        })
    }
}

fn parse_launch_manifest(
    prepared: &ServiceUserModePrepared,
    stdout: &str,
) -> Result<Option<ServiceUserModeLaunchManifest>, DiagnosticRecord> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') {
        return Ok(None);
    }

    let manifest: ServiceUserModeLaunchManifest = serde_json::from_str(trimmed).map_err(|err| {
        launch_error(
            &prepared.prepared_id,
            format!("failed to parse service launch manifest: {err}"),
            None,
            stdout,
            "",
        )
    })?;
    Ok(Some(manifest))
}

fn validate_request(request: &ServiceUserModeRequest) -> Result<(), DiagnosticRecord> {
    let prepared_id = stable_prepared_id(request);
    if !request.qemu_binary.is_file() {
        return Err(preparation_error(
            &prepared_id,
            request,
            format!(
                "qemu-user binary is missing: {}",
                request.qemu_binary.display()
            ),
        ));
    }
    if !request.input_root.is_dir() {
        return Err(preparation_error(
            &prepared_id,
            request,
            format!(
                "extracted rootfs is missing: {}",
                request.input_root.display()
            ),
        ));
    }
    if !request.executable_path.starts_with('/') {
        return Err(preparation_error(
            &prepared_id,
            request,
            format!(
                "service executable must be an absolute guest path, got {}",
                request.executable_path
            ),
        ));
    }
    let input_executable = request
        .input_root
        .join(request.executable_path.trim_start_matches('/'));
    if !input_executable.exists() {
        return Err(preparation_error(
            &prepared_id,
            request,
            format!(
                "service executable is missing from the extracted rootfs: {}",
                input_executable.display()
            ),
        ));
    }
    Ok(())
}

fn stable_prepared_id(request: &ServiceUserModeRequest) -> String {
    fat_core::ids::stable_prefixed_id(
        "svc-prep",
        [
            request.project_id.as_str(),
            request.target_id.as_str(),
            request.architecture.as_str(),
            request.executable_path.as_str(),
        ],
    )
}

fn preparation_error(
    prepared_id: &str,
    request: &ServiceUserModeRequest,
    summary: String,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        prepared_id.to_string(),
        DiagnosticPhase::Preparation,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::PreparationFailed,
        Some(request.architecture.clone()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresTargetChange,
        format!("{BACKEND_ID}: {summary}"),
        Vec::new(),
        Vec::new(),
        vec![
            "provide an extracted rootfs and an executable service candidate".to_string(),
            "retry with the system substrate if the target requires full init orchestration"
                .to_string(),
        ],
    )
}

fn launch_error(
    prepared_id: &str,
    summary: impl Into<String>,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let summary = summary.into();
    let combined = format!("{summary}\n{stdout}\n{stderr}");
    let repair_hint = extract_repair_hint(&combined);
    let device_path = extract_guest_paths(&combined)
        .into_iter()
        .find(|path| path.starts_with("/dev/"));
    let (class, subclass, detail_summary) = if let Some(path) = device_path {
        if combined.contains("missing") || combined.contains("No such file") {
            (
                DiagnosticClass::DeviceOrPathMissing,
                Some(path.clone()),
                format!("{BACKEND_ID}: missing device path {path} during qemu-user launch"),
            )
        } else {
            (
                DiagnosticClass::LaunchFailed,
                Some("service".to_string()),
                summarize_launch_failure(&summary, repair_hint.as_deref()),
            )
        }
    } else {
        (
            DiagnosticClass::LaunchFailed,
            Some("service".to_string()),
            summarize_launch_failure(&summary, repair_hint.as_deref()),
        )
    };
    let mut suggested_next_actions = vec![
        "inspect the qemu-user launch manifest and service staging root".to_string(),
        "retry under the system substrate if the service needs peer daemons or kernel support"
            .to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect service launch stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect service launch stderr".to_string());
    }
    if let Some(hint) = repair_hint {
        suggested_next_actions.push(hint);
    }

    DiagnosticRecord::new(
        prepared_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        class,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        detail_summary,
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn summarize_launch_failure(summary: &str, repair_hint: Option<&str>) -> String {
    match repair_hint {
        Some(hint) => format!("{BACKEND_ID}: {summary}; {hint}"),
        None => format!("{BACKEND_ID}: {summary}"),
    }
}

fn extract_repair_hint(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        let normalized = line.to_ascii_lowercase();
        if normalized.contains("wrong init path")
            || normalized.contains("retry with /etc/init.d")
            || normalized.contains("materialize")
            || normalized.contains("overlay")
            || normalized.contains("config")
        {
            Some(line.to_string())
        } else {
            None
        }
    })
}

fn launch_timeout_error(
    prepared_id: &str,
    timeout: Duration,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        format!(
            "inspect why the service did not reach a steady state within {} seconds",
            timeout.as_secs()
        ),
        "retry under the system substrate if the service depends on init sequencing or peripherals"
            .to_string(),
    ];
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect service launch stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect service launch stderr".to_string());
    }

    DiagnosticRecord::new(
        prepared_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some("service-timeout".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        format!(
            "{BACKEND_ID}: qemu-user service launch timed out after {} seconds",
            timeout.as_secs()
        ),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn recreate_dir(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn materialize_repair_mutations(request: &ServiceUserModeRequest) -> std::io::Result<()> {
    for node in &request.device_nodes {
        let node_path = request.staging_root.join(node.path.trim_start_matches('/'));
        if let Some(parent) = node_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !node_path.exists() {
            fs::write(&node_path, b"")?;
        }
    }

    for transform in &request.filesystem_transforms {
        if transform.destination.trim().is_empty() {
            continue;
        }
        let destination = request
            .staging_root
            .join(transform.destination.trim_start_matches('/'));
        if transform.destination_kind == RecipePathKind::Directory {
            fs::create_dir_all(destination)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = format!(
            "# synthesized by FAT repair loop\nkind={}\nsource={}\n",
            transform.transform_kind,
            transform.source.as_str()
        );
        fs::write(destination, contents)?;
    }

    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> std::io::Result<()> {
    copy_tree_with_roots(source, destination, source, destination)
}

fn copy_tree_with_roots(
    source_root: &Path,
    destination_root: &Path,
    source: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree_with_roots(source_root, destination_root, &src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&src_path)?;
            let source_target = resolved_symlink_target(source_root, &src_path, &target)?;
            let relative_target = source_target
                .strip_prefix(source_root)
                .map_err(std::io::Error::other)?;
            let destination_target = destination_root.join(relative_target);
            let rewritten_target = relative_path(
                dst_path
                    .parent()
                    .ok_or_else(|| std::io::Error::other("symlink missing parent"))?,
                &destination_target,
            )?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(rewritten_target, &dst_path)?;
            #[cfg(not(unix))]
            fs::copy(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn resolved_symlink_target(
    source_root: &Path,
    link_path: &Path,
    target: &Path,
) -> std::io::Result<PathBuf> {
    let joined = if target.is_absolute() {
        source_root.join(
            target
                .strip_prefix(std::path::MAIN_SEPARATOR_STR)
                .map_err(std::io::Error::other)?,
        )
    } else {
        link_path
            .parent()
            .ok_or_else(|| std::io::Error::other("symlink missing parent"))?
            .join(target)
    };
    let normalized = normalize_lexical(&joined)?;
    if !normalized.starts_with(source_root) {
        return Err(std::io::Error::other(format!(
            "symlink target would escape rootfs: {} -> {}",
            link_path.display(),
            target.display()
        )));
    }
    Ok(normalized)
}

fn normalize_lexical(path: &Path) -> std::io::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => {
                normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR))
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(std::io::Error::other(format!(
                        "path would escape root while normalizing: {}",
                        path.display()
                    )));
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn relative_path(from_dir: &Path, to: &Path) -> std::io::Result<PathBuf> {
    let from_components: Vec<_> = from_dir.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let mut common = 0usize;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }

    let mut relative = PathBuf::new();
    for _ in common..from_components.len() {
        relative.push("..");
    }
    for component in &to_components[common..] {
        relative.push(component.as_os_str());
    }
    if relative.as_os_str().is_empty() {
        return Err(std::io::Error::other(
            "refusing to create empty symlink target",
        ));
    }
    Ok(relative)
}

fn service_user_mode_timeout_secs() -> u64 {
    std::env::var(SERVICE_USER_MODE_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_SERVICE_USER_MODE_TIMEOUT_SECS)
}

fn extract_guest_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for token in text.split_whitespace() {
        let cleaned = token
            .trim_matches(|character: char| {
                character == ','
                    || character == ';'
                    || character == ':'
                    || character == ')'
                    || character == '('
                    || character == '.'
            })
            .trim();
        if cleaned.starts_with('/') && !paths.iter().any(|existing| existing == cleaned) {
            paths.push(cleaned.to_string());
        }
    }
    paths
}
