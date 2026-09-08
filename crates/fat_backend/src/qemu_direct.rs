use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::runs::{RuntimeEndpoint, RuntimeEndpointKind, SubstrateKind};

use crate::native_host;
use crate::substrate::{BackendSubstrateContract, BackendSubstrateKind};

const BACKEND_ID: &str = "qemu-direct";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuDirectRequest {
    pub project_id: String,
    pub target_id: String,
    pub family_id: String,
    pub goal: String,
    pub architecture: String,
    pub qemu_binary: PathBuf,
    pub docker_binary: PathBuf,
    pub workspace_dir: PathBuf,
    pub preferred_substrate: Option<BackendSubstrateKind>,
}

impl QemuDirectRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        family_id: impl Into<String>,
        goal: impl Into<String>,
        architecture: impl Into<String>,
        qemu_binary: PathBuf,
        docker_binary: PathBuf,
        workspace_dir: PathBuf,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            target_id: target_id.into(),
            family_id: family_id.into(),
            goal: goal.into(),
            architecture: architecture.into(),
            qemu_binary,
            docker_binary,
            workspace_dir,
            preferred_substrate: None,
        }
    }

    pub fn with_preferred_substrate(mut self, preferred_substrate: BackendSubstrateKind) -> Self {
        self.preferred_substrate = Some(preferred_substrate);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QemuDirectPlacementSpec {
    pub substrate: BackendSubstrateKind,
    pub substrate_contract: BackendSubstrateContract,
    pub launch_command: Vec<PathBuf>,
    pub endpoints: Vec<RuntimeEndpoint>,
    pub working_dir: PathBuf,
}

impl QemuDirectPlacementSpec {
    pub fn substrate_kind(&self) -> SubstrateKind {
        match self.substrate {
            BackendSubstrateKind::NativeHost => SubstrateKind::NativeHost,
            BackendSubstrateKind::DockerEngine => SubstrateKind::DockerEngine,
            BackendSubstrateKind::ManagedLinuxVm => SubstrateKind::ManagedLinuxVm,
        }
    }

    pub fn substrate_contract(&self) -> &BackendSubstrateContract {
        &self.substrate_contract
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QemuDirectPreparedWorkingSet {
    pub request: QemuDirectRequest,
    pub prepared_id: String,
    pub placements: Vec<QemuDirectPlacementSpec>,
}

impl QemuDirectPreparedWorkingSet {
    pub fn placement(&self, substrate: BackendSubstrateKind) -> Option<&QemuDirectPlacementSpec> {
        self.placements
            .iter()
            .find(|placement| placement.substrate == substrate)
    }

    pub fn working_dir(&self) -> &Path {
        self.placements
            .first()
            .map(|placement| placement.working_dir.as_path())
            .unwrap_or(self.request.workspace_dir.as_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuDirectLaunchResult {
    pub prepared_id: String,
    pub substrate: BackendSubstrateKind,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub endpoints: Vec<RuntimeEndpoint>,
}

#[derive(Debug, Default)]
pub struct QemuDirectDriver;

impl QemuDirectDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn prepare(
        &self,
        request: QemuDirectRequest,
    ) -> Result<QemuDirectPreparedWorkingSet, DiagnosticRecord> {
        validate_request(&request)?;

        let prepared_id = stable_prepared_id(&request);
        let working_dir = request.workspace_dir.join(&prepared_id);
        fs::create_dir_all(&working_dir).map_err(|err| {
            preparation_error(
                &prepared_id,
                &request,
                format!("failed to create working directory: {err}"),
            )
        })?;

        let mut placements = Vec::new();
        if request.qemu_binary.is_file() {
            placements.push(native_host::build_placement(&request, &working_dir));
        }
        if placements.is_empty() {
            return Err(preparation_error(
                &prepared_id,
                &request,
                "no runnable substrate placements were available".to_string(),
            ));
        }

        if let Some(preferred_substrate) = request.preferred_substrate {
            placements.sort_by_key(|placement| placement.substrate != preferred_substrate);
        }

        Ok(QemuDirectPreparedWorkingSet {
            request,
            prepared_id,
            placements,
        })
    }

    pub fn launch(
        &self,
        prepared: &QemuDirectPreparedWorkingSet,
        substrate: BackendSubstrateKind,
    ) -> Result<QemuDirectLaunchResult, DiagnosticRecord> {
        let placement = prepared.placement(substrate).ok_or_else(|| {
            launch_error(
                &prepared.prepared_id,
                substrate,
                "requested substrate was not prepared",
                None,
                "",
                "",
            )
        })?;

        let output = Command::new(&placement.launch_command[0])
            .args(&placement.launch_command[1..])
            .current_dir(&placement.working_dir)
            .output()
            .map_err(|err| {
                launch_error(
                    &prepared.prepared_id,
                    substrate,
                    format!("failed to spawn launch command: {err}"),
                    None,
                    "",
                    "",
                )
            })?;

        if !output.status.success() {
            let exit_code = output.status.code();
            return Err(launch_error(
                &prepared.prepared_id,
                substrate,
                "launch command exited unsuccessfully",
                exit_code,
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
            ));
        }

        Ok(QemuDirectLaunchResult {
            prepared_id: prepared.prepared_id.clone(),
            substrate,
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            endpoints: placement.endpoints.clone(),
        })
    }
}

fn validate_request(request: &QemuDirectRequest) -> Result<(), DiagnosticRecord> {
    if request.family_id != "linux-router-arm" || request.architecture != "armel" {
        return Err(preparation_error(
            &stable_prepared_id(request),
            request,
            format!(
                "qemu-direct generic path only supports linux-router-arm on armel, got {} / {}",
                request.family_id, request.architecture
            ),
        ));
    }

    if !request.qemu_binary.is_file() {
        return Err(preparation_error(
            &stable_prepared_id(request),
            request,
            format!(
                "qemu-direct requires a native QEMU system binary: {}",
                request.qemu_binary.display()
            ),
        ));
    }

    Ok(())
}

fn stable_prepared_id(request: &QemuDirectRequest) -> String {
    fat_core::ids::stable_prefixed_id(
        "qemu-prep",
        [
            request.project_id.as_str(),
            request.target_id.as_str(),
            request.family_id.as_str(),
            request.goal.as_str(),
            request.architecture.as_str(),
        ],
    )
}

fn preparation_error(
    prepared_id: &str,
    request: &QemuDirectRequest,
    summary: String,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        prepared_id.to_string(),
        DiagnosticPhase::Preparation,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::PreparationFailed,
        Some(request.family_id.clone()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresTargetChange,
        format!("{BACKEND_ID}: {summary}"),
        Vec::new(),
        Vec::new(),
        vec!["adjust the target family or supplied runtime binaries".to_string()],
    )
}

fn launch_error(
    prepared_id: &str,
    substrate: BackendSubstrateKind,
    summary: impl Into<String>,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the launch command and substrate-specific workspace".to_string(),
        "retry with a fallback backend if available".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect launch stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect launch stderr".to_string());
    }

    DiagnosticRecord::new(
        prepared_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some(substrate_label(substrate).to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        format!("{BACKEND_ID}: {}", summary.into()),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

pub(crate) fn build_endpoints(
    shell_port: u16,
    debugger_port: u16,
    monitor_port: u16,
) -> Vec<RuntimeEndpoint> {
    vec![
        RuntimeEndpoint::new(RuntimeEndpointKind::Shell, "shell", "127.0.0.1", shell_port)
            .with_target_port(22)
            .with_uri(format!("ssh://127.0.0.1:{shell_port}")),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Debugger,
            "debugger",
            "127.0.0.1",
            debugger_port,
        )
        .with_target_port(1234)
        .with_uri(format!("tcp://127.0.0.1:{debugger_port}")),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Monitor,
            "monitor",
            "127.0.0.1",
            monitor_port,
        )
        .with_target_port(4444)
        .with_uri(format!("tcp://127.0.0.1:{monitor_port}")),
    ]
}

fn substrate_label(substrate: BackendSubstrateKind) -> &'static str {
    match substrate {
        BackendSubstrateKind::NativeHost => "native-host",
        BackendSubstrateKind::DockerEngine => "docker-engine",
        BackendSubstrateKind::ManagedLinuxVm => "managed-linux-vm",
    }
}

pub(crate) fn common_launch_args(
    request: &QemuDirectRequest,
    working_dir: &std::path::Path,
) -> Vec<PathBuf> {
    vec![
        PathBuf::from("--family"),
        PathBuf::from(request.family_id.clone()),
        PathBuf::from("--architecture"),
        PathBuf::from(request.architecture.clone()),
        PathBuf::from("--goal"),
        PathBuf::from(request.goal.clone()),
        PathBuf::from("--workspace"),
        working_dir.to_path_buf(),
    ]
}
