use crate::bootplan::{BootExecutionResult, BootPlan};
use crate::project::BootloaderWorkspaceManifest;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootloaderQemuLaunch {
    pub profile_name: String,
    pub project_dir: String,
    pub machine: String,
    pub qemu_binary: String,
    pub qemu_args: Vec<String>,
    pub qemu_command: String,
    pub u_boot_asset_reference: String,
    pub u_boot_asset_path: Option<String>,
    pub serial_log: String,
    pub console: String,
    pub tmux_session: String,
    pub attach_command: String,
    pub bootargs: String,
    pub prompt: String,
    pub launchable: bool,
    pub launched: bool,
    pub reason: Option<String>,
}

/// Result of stopping a bootloader session. `stopped` is true only when this
/// call terminated a live session; `reason` explains every other outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootloaderStopOutcome {
    pub project_dir: String,
    pub tmux_session: String,
    pub stopped: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootAssistResult {
    pub commands_sent: Vec<String>,
    pub command_log: String,
    pub execution: BootExecutionResult,
}

#[derive(Debug)]
pub enum BootloaderQemuError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    MissingProject(PathBuf),
    MissingWorkspace(PathBuf),
    CommandFailed(String),
}

impl fmt::Display for BootloaderQemuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::MissingProject(path) => {
                write!(
                    f,
                    "bootloader project path does not exist: {}",
                    path.display()
                )
            }
            Self::MissingWorkspace(path) => {
                write!(f, "bootloader workspace is missing: {}", path.display())
            }
            Self::CommandFailed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for BootloaderQemuError {}

impl From<std::io::Error> for BootloaderQemuError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BootloaderQemuError {
    fn from(error: serde_json::Error) -> Self {
        Self::Parse(error)
    }
}

pub fn prepare_launch(project_dir: &Path) -> Result<BootloaderQemuLaunch, BootloaderQemuError> {
    if !project_dir.is_dir() {
        return Err(BootloaderQemuError::MissingProject(
            project_dir.to_path_buf(),
        ));
    }

    let manifest = load_workspace_manifest(project_dir)?;
    let boot_plan = load_boot_plan(project_dir)?;
    let env_text = fs::read_to_string(project_dir.join("bootloader").join("env.txt"))?;
    let env_map = parse_env_text(&env_text);
    let bootargs = env_map
        .get("bootargs")
        .cloned()
        .unwrap_or_else(|| manifest.profile.bootargs.clone());
    let prompt = env_map
        .get("prompt")
        .cloned()
        .unwrap_or_else(|| manifest.profile.prompt.clone());
    let console = console_from_bootargs(&bootargs).unwrap_or_else(|| "ttyAMA0".to_string());
    let tmux_session = tmux_session_name(project_dir);
    let attach_command = format!("tmux attach-session -t {tmux_session}");
    let u_boot_asset = discover_u_boot_asset(&manifest)?;
    let qemu_binary = u_boot_asset
        .qemu_binary
        .clone()
        .or_else(discover_qemu_binary)
        .unwrap_or_else(|| "qemu-system-arm".to_string());
    let qemu_binary = resolve_host_binary(&qemu_binary).unwrap_or(qemu_binary);
    let machine = u_boot_asset
        .machine
        .clone()
        .unwrap_or_else(|| "virt".to_string());
    let serial_dir = project_dir.join("bootloader").join("qemu");
    fs::create_dir_all(&serial_dir)?;
    let serial_log = serial_dir.join("serial.log");
    fs::write(&serial_log, b"")?;

    let qemu_available = resolve_host_binary(&qemu_binary).is_some();
    let asset_available = u_boot_asset.path.is_some();
    let mapping_reason = validate_root_mapping(&manifest, &bootargs, &boot_plan);
    let launchable = qemu_available && asset_available && mapping_reason.is_none();
    let reason = if let Some(reason) = mapping_reason {
        Some(reason)
    } else if launchable {
        None
    } else {
        Some(match (qemu_available, asset_available) {
            (false, false) => {
                "qemu binary is unavailable on this host and no suitable U-Boot asset was found"
                    .to_string()
            }
            (false, true) => "qemu binary is unavailable on this host".to_string(),
            (true, false) => {
                "no suitable U-Boot asset was explicitly configured or found on this host"
                    .to_string()
            }
            (true, true) => unreachable!("launchable combinations should be handled above"),
        })
    };

    let qemu_args = build_args(&machine, u_boot_asset.path.as_deref(), &boot_plan);
    let qemu_command = shell_command(&qemu_binary, &qemu_args);
    let launch = BootloaderQemuLaunch {
        profile_name: manifest.profile_name,
        project_dir: project_dir.display().to_string(),
        machine,
        qemu_binary,
        qemu_args,
        qemu_command,
        u_boot_asset_reference: u_boot_asset.reference,
        u_boot_asset_path: u_boot_asset.path.map(|path| path.display().to_string()),
        serial_log: serial_log.display().to_string(),
        console,
        tmux_session,
        attach_command,
        bootargs,
        prompt,
        launchable,
        launched: false,
        reason,
    };

    let launch_path = serial_dir.join("launch.json");
    fs::write(&launch_path, serde_json::to_vec_pretty(&launch)?)?;

    Ok(launch)
}

pub fn launch_in_tmux(project_dir: &Path) -> Result<BootloaderQemuLaunch, BootloaderQemuError> {
    let mut launch = prepare_launch(project_dir)?;

    if !launch.launchable {
        return Ok(launch);
    }

    if !tmux_available() {
        launch.reason = Some("tmux is unavailable on this host".to_string());
        write_launch(project_dir, &launch)?;
        return Ok(launch);
    }

    if tmux_has_session(&launch.tmux_session)? && session_needs_restart(&launch)? {
        kill_tmux_session(&launch.tmux_session)?;
    }

    if !tmux_has_session(&launch.tmux_session)? {
        run_tmux(&[
            "new-session",
            "-d",
            "-s",
            &launch.tmux_session,
            &launch.qemu_command,
        ])?;
        run_tmux(&[
            "set-option",
            "-t",
            &launch.tmux_session,
            "@fat_launch_command_hex",
            &launch_command_identity(&launch.qemu_command),
        ])?;
        run_tmux(&[
            "pipe-pane",
            "-o",
            "-t",
            &launch.tmux_session,
            &format!("cat >> {}", launch.serial_log),
        ])?;
        sync_serial_log_from_pane(&launch)?;
    }

    launch.launched = true;
    write_launch(project_dir, &launch)?;
    Ok(launch)
}

/// Stop the tmux-hosted bootloader QEMU session for `project_dir`.
///
/// Deliberately independent of `prepare_launch`: a session must remain
/// stoppable even when the workspace it was launched from has been edited,
/// half-materialized, or deleted underneath it. The session name is derived
/// from the canonical project path alone, which is the same identity
/// `launch_in_tmux` used to create it.
///
/// Stopping is idempotent — an absent session is a reported non-event, not an
/// error — so the command is safe to run when the session state is unknown.
pub fn stop_tmux_session(project_dir: &Path) -> Result<BootloaderStopOutcome, BootloaderQemuError> {
    if !project_dir.is_dir() {
        return Err(BootloaderQemuError::MissingProject(
            project_dir.to_path_buf(),
        ));
    }

    let tmux_session = tmux_session_name(project_dir);
    let mut outcome = BootloaderStopOutcome {
        project_dir: project_dir.display().to_string(),
        tmux_session,
        stopped: false,
        reason: None,
    };

    if !tmux_available() {
        outcome.reason = Some("tmux is unavailable on this host".to_string());
        return Ok(outcome);
    }

    if !tmux_has_session(&outcome.tmux_session)? {
        outcome.reason = Some("no live bootloader session was running".to_string());
        mark_launch_stopped(project_dir)?;
        return Ok(outcome);
    }

    kill_tmux_session(&outcome.tmux_session)?;
    outcome.stopped = true;
    mark_launch_stopped(project_dir)?;
    Ok(outcome)
}

/// Every FAT-managed bootloader tmux session currently running on this host,
/// sorted by name.
///
/// An absent tmux binary or a tmux server that is not running are both normal
/// "nothing is running" answers, not failures.
pub fn list_managed_tmux_sessions() -> Result<Vec<String>, BootloaderQemuError> {
    if !tmux_available() {
        return Ok(Vec::new());
    }

    let output = Command::new(tmux_binary_path()?)
        .args(["list-sessions", "-F", "#{session_name}"])
        .stderr(Stdio::null())
        .output()?;
    // `list-sessions` exits non-zero when no server is running.
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let prefix = tmux_session_prefix();
    let mut sessions: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with(prefix.as_str()))
        .map(str::to_string)
        .collect();
    sessions.sort();
    sessions.dedup();
    Ok(sessions)
}

/// Stop every FAT-managed bootloader session on this host and return the names
/// that were stopped.
///
/// This is the counterpart to [`stop_tmux_session`] for orphans whose project
/// directory is gone or unknown — a session survives any teardown that never
/// got to run, such as a test process killed outright, and the session name
/// alone is enough to reap it. Only sessions carrying the FAT prefix are
/// considered.
pub fn stop_all_tmux_sessions() -> Result<Vec<String>, BootloaderQemuError> {
    let sessions = list_managed_tmux_sessions()?;
    let mut stopped = Vec::new();
    for session in sessions {
        // A session that ended between listing and killing is already in the
        // state the caller wanted, so it is not reported as stopped.
        if !tmux_has_session(&session)? {
            continue;
        }
        kill_tmux_session(&session)?;
        stopped.push(session);
    }
    Ok(stopped)
}

/// Live state of the bootloader session belonging to `project_dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootloaderSessionStatus {
    pub tmux_session: String,
    /// A tmux session with this name is running right now.
    pub live: bool,
    /// Pid of the process tmux started in the session's pane — the QEMU
    /// process itself, which is what resource accounting has to measure.
    pub pane_pid: Option<u32>,
    /// The project's `launch.json` records a launched session. Combined with
    /// `live == false` this identifies a stale record.
    pub recorded_launched: bool,
}

/// Inspect the bootloader session for `project_dir` without touching it.
///
/// Reports from tmux and the launch record together so a caller can tell a
/// running session from a record left behind by one that died.
pub fn inspect_tmux_session(
    project_dir: &Path,
) -> Result<BootloaderSessionStatus, BootloaderQemuError> {
    let tmux_session = tmux_session_name(project_dir);
    let recorded_launched = read_launch_record(project_dir)
        .map(|launch| launch.launched)
        .unwrap_or(false);

    if !tmux_available() || !tmux_has_session(&tmux_session)? {
        return Ok(BootloaderSessionStatus {
            tmux_session,
            live: false,
            pane_pid: None,
            recorded_launched,
        });
    }

    Ok(BootloaderSessionStatus {
        pane_pid: tmux_pane_pid(&tmux_session)?,
        tmux_session,
        live: true,
        recorded_launched,
    })
}

fn tmux_pane_pid(session: &str) -> Result<Option<u32>, BootloaderQemuError> {
    let output = Command::new(tmux_binary_path()?)
        .args(["display-message", "-p", "-t", session, "#{pane_pid}"])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().parse().ok())
}

fn read_launch_record(project_dir: &Path) -> Option<BootloaderQemuLaunch> {
    let bytes = fs::read(
        project_dir
            .join("bootloader")
            .join("qemu")
            .join("launch.json"),
    )
    .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Clear the `launched` flag in a previously written `launch.json` so status
/// readers do not report a session that no longer exists. A missing or
/// unreadable record is not an error: the session is already stopped, which is
/// the outcome the caller asked for.
fn mark_launch_stopped(project_dir: &Path) -> Result<(), BootloaderQemuError> {
    let Some(mut launch) = read_launch_record(project_dir) else {
        return Ok(());
    };
    if !launch.launched {
        return Ok(());
    }
    launch.launched = false;
    write_launch(project_dir, &launch)
}

pub fn assist_boot(project_dir: &Path) -> Result<BootAssistResult, BootloaderQemuError> {
    let serial_dir = project_dir.join("bootloader").join("qemu");
    fs::create_dir_all(&serial_dir)?;
    let serial_log_path = serial_dir.join("serial.log");
    fs::write(&serial_log_path, b"")?;
    let session = tmux_session_name(project_dir);
    if tmux_available() && tmux_has_session(&session)? {
        kill_tmux_session(&session)?;
    }
    let launch = launch_in_tmux(project_dir)?;
    if !launch.launchable {
        return Err(BootloaderQemuError::CommandFailed(
            launch
                .reason
                .unwrap_or_else(|| "bootloader session is not launchable".to_string()),
        ));
    }

    let plan = load_boot_plan(project_dir)?;
    if let Some(reason) = &plan.rejection_reason {
        return Err(BootloaderQemuError::CommandFailed(reason.clone()));
    }

    let commands_sent = plan.u_boot_commands();
    if commands_sent.is_empty() {
        return Err(BootloaderQemuError::CommandFailed(
            "boot plan did not generate any U-Boot commands".to_string(),
        ));
    }

    interrupt_autoboot(&launch)?;
    wait_for_prompt(&launch)?;

    for command in &commands_sent {
        run_tmux(&["send-keys", "-t", &launch.tmux_session, command, "Enter"])?;
        thread::sleep(Duration::from_millis(150));
    }

    let command_log = project_dir
        .join("bootloader")
        .join("qemu")
        .join("assist.log");
    fs::write(&command_log, commands_sent.join("\n"))?;

    let execution = observe_execution(&launch);
    let execution_path = project_dir
        .join("bootloader")
        .join("qemu")
        .join("execution-result.json");
    fs::write(&execution_path, serde_json::to_vec_pretty(&execution)?)?;

    Ok(BootAssistResult {
        commands_sent,
        command_log: command_log.display().to_string(),
        execution,
    })
}

fn observe_execution(launch: &BootloaderQemuLaunch) -> BootExecutionResult {
    let mut last = BootExecutionResult {
        stage: "timed_out".into(),
        result: "unknown".into(),
        observed_output: Vec::new(),
        error: None,
    };

    for _ in 0..60 {
        let _ = sync_serial_log_from_pane(launch);
        let serial_output = fs::read_to_string(&launch.serial_log).unwrap_or_default();
        last = classify_serial_output(&serial_output);
        if last.stage != "timed_out" {
            return last;
        }
        thread::sleep(Duration::from_millis(250));
    }

    last
}

pub fn classify_serial_output(output: &str) -> BootExecutionResult {
    let stage = if contains_any(
        output,
        &[
            "wrong image type for bootm command",
            "can't get kernel image",
            "bad linux arm zimage magic",
            "bad image format",
            "bad magic number",
            "fdt and atags support not compiled in",
            "could not find a valid device tree",
            "resetting ...",
        ],
    ) {
        "kernel_handoff_failed"
    } else if contains_any(
        output,
        &[
            "starting kernel ...",
            "loading kernel image",
            "booting using the fdt blob",
            "working fdt set to",
        ],
    ) {
        "kernel_handoff_attempted"
    } else if contains_any(output, &["linux version", "booting linux"]) {
        "kernel_banner_seen"
    } else if contains_any(output, &["kernel panic", "panic - not syncing"]) {
        "kernel_panic"
    } else if contains_any(output, &["starting init", "run-init", "init:"]) {
        "init_started"
    } else if contains_shell_prompt(output) || contains_any(output, &["/bin/sh", "sh-"]) {
        "interactive_shell"
    } else if contains_any(output, &["login:", "starting dropbear", "starting telnetd"]) {
        "userspace_started"
    } else {
        "timed_out"
    };

    let result = match stage {
        "kernel_banner_seen" | "init_started" | "interactive_shell" | "userspace_started" => {
            "observed"
        }
        "kernel_panic" | "kernel_handoff_failed" => "failed",
        _ => "unknown",
    };

    let error = if result == "failed" {
        output
            .lines()
            .find(|line| {
                let lowered = line.to_ascii_lowercase();
                lowered.contains("wrong image type")
                    || lowered.contains("can't get kernel image")
                    || lowered.contains("bad linux")
                    || lowered.contains("bad image")
                    || lowered.contains("panic")
            })
            .map(str::to_string)
    } else {
        None
    };

    BootExecutionResult {
        stage: stage.into(),
        result: result.into(),
        observed_output: output.lines().take(10).map(str::to_string).collect(),
        error,
    }
}

fn contains_shell_prompt(output: &str) -> bool {
    output.lines().any(|line| {
        let trimmed = line.trim();
        (trimmed == "#" || trimmed.starts_with("# ") || trimmed.ends_with(" #"))
            && !trimmed.starts_with("##")
    })
}

fn load_workspace_manifest(
    project_dir: &Path,
) -> Result<BootloaderWorkspaceManifest, BootloaderQemuError> {
    let path = project_dir.join("bootloader").join("profile.json");
    if !path.is_file() {
        return Err(BootloaderQemuError::MissingWorkspace(path));
    }

    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_boot_plan(project_dir: &Path) -> Result<BootPlan, BootloaderQemuError> {
    let path = project_dir.join("bootloader").join("boot-plan.json");
    if !path.is_file() {
        return Err(BootloaderQemuError::MissingWorkspace(path));
    }

    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_env_text(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn contains_any(output: &str, needles: &[&str]) -> bool {
    let output = output.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| output.contains(&needle.to_ascii_lowercase()))
}

fn console_from_bootargs(bootargs: &str) -> Option<String> {
    for token in bootargs.split_whitespace() {
        if let Some(value) = token.strip_prefix("console=") {
            return Some(value.split(',').next().unwrap_or(value).to_string());
        }
    }
    None
}

fn discover_qemu_binary() -> Option<String> {
    let candidates = [
        "qemu-system-arm",
        "qemu-system-aarch64",
        "qemu-system-ppc",
        "qemu-system-ppc64",
    ];
    for candidate in candidates {
        if let Some(path) = find_in_path(candidate) {
            return Some(path.display().to_string());
        }
    }

    for candidate in [
        "/opt/homebrew/bin/qemu-system-arm",
        "/opt/homebrew/bin/qemu-system-aarch64",
        "/opt/homebrew/bin/qemu-system-ppc",
        "/opt/homebrew/bin/qemu-system-ppc64",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.display().to_string());
        }
    }

    None
}

fn resolve_host_binary(candidate: &str) -> Option<String> {
    let path = Path::new(candidate);
    if path.is_file() {
        return Some(path.display().to_string());
    }

    find_in_path(candidate).map(|path| path.display().to_string())
}

fn discover_u_boot_asset(
    manifest: &BootloaderWorkspaceManifest,
) -> Result<BootloaderAsset, BootloaderQemuError> {
    if manifest.mode == "true-boot-chain" {
        if let Some(image) = manifest.bootloader_image.as_ref() {
            let compatibility = manifest.compatibility.as_ref();
            return Ok(BootloaderAsset {
                reference: format!("vendor bootloader image: {}", image.path),
                path: Some(PathBuf::from(&image.path)),
                qemu_binary: compatibility.and_then(|data| data.qemu_binary.clone()),
                machine: compatibility.and_then(|data| data.machine.clone()),
            });
        }
    }

    if let Some(asset) = env_override_asset() {
        return Ok(asset);
    }

    let candidates = [
        "/opt/homebrew/Cellar/qemu",
        "/opt/homebrew/share/qemu",
        "/usr/local/share/qemu",
        "/usr/share/qemu",
    ];

    for base in candidates {
        let base = Path::new(base);
        if let Some(path) = find_u_boot_asset(base, 0) {
            let (qemu_binary, machine) = infer_qemu_pair(&path);
            return Ok(BootloaderAsset {
                reference: format!("u-boot asset: {}", path.display()),
                path: Some(path),
                qemu_binary,
                machine,
            });
        }
    }

    Ok(BootloaderAsset {
        reference: "u-boot asset: unavailable".to_string(),
        path: None,
        qemu_binary: None,
        machine: None,
    })
}

fn find_u_boot_asset(dir: &Path, depth: usize) -> Option<PathBuf> {
    if depth > 4 || !dir.is_dir() {
        return None;
    }

    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_ascii_lowercase().starts_with("u-boot"))
                .unwrap_or(false)
            {
                return Some(path);
            }
        } else if let Some(found) = find_u_boot_asset(&path, depth + 1) {
            return Some(found);
        }
    }

    None
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for entry in env::split_paths(&path) {
        let candidate = entry.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn infer_qemu_pair(path: &Path) -> (Option<String>, Option<String>) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if name.contains("sam460") {
        return (
            find_in_path("qemu-system-ppc").map(|value| value.display().to_string()),
            Some("sam460ex".to_string()),
        );
    }

    if name.contains("e500") {
        return (
            find_in_path("qemu-system-ppc").map(|value| value.display().to_string()),
            Some("ppce500".to_string()),
        );
    }

    if name.contains("arm") || name.contains("aarch64") {
        return (discover_qemu_binary(), Some("virt".to_string()));
    }

    (None, None)
}

fn build_args(
    machine: &str,
    u_boot_asset_path: Option<&Path>,
    boot_plan: &BootPlan,
) -> Vec<String> {
    let mut args = vec![
        "-M".to_string(),
        machine.to_string(),
        "-nographic".to_string(),
        "-serial".to_string(),
        "mon:stdio".to_string(),
    ];

    if let Some(path) = u_boot_asset_path {
        args.push("-bios".to_string());
        args.push(path.display().to_string());
    }

    if let Some((artifact_path, load_addr)) = boot_loader_artifact(boot_plan) {
        args.push("-device".to_string());
        args.push(format!(
            "loader,file={},addr={},force-raw=on",
            artifact_path.display(),
            load_addr
        ));
    }
    if let Some((dtb_path, load_addr)) = dtb_loader_artifact(boot_plan) {
        args.push("-device".to_string());
        args.push(format!(
            "loader,file={},addr={},force-raw=on",
            dtb_path.display(),
            load_addr
        ));
    }

    if let Some(rootfs) = boot_plan
        .rootfs
        .as_ref()
        .filter(|artifact| artifact.format == "rootfs-image")
    {
        args.push("-drive".to_string());
        args.push(format!("file={},format=raw,if=virtio", rootfs.path));
    }

    args
}

fn validate_root_mapping(
    manifest: &BootloaderWorkspaceManifest,
    bootargs: &str,
    boot_plan: &BootPlan,
) -> Option<String> {
    if manifest.mode != "true-boot-chain" {
        return None;
    }

    let expects_mmc = bootargs.contains("root=/dev/mmc");
    let attached_as_virtio = boot_plan
        .rootfs
        .as_ref()
        .is_some_and(|artifact| artifact.format == "rootfs-image");

    if expects_mmc && attached_as_virtio {
        return Some(
            "root device mapping is incoherent for true boot-chain mode: bootargs expect MMC but the current launch model only provides a virtio rootfs image"
                .into(),
        );
    }

    None
}

fn shell_command(binary: &str, args: &[String]) -> String {
    std::iter::once("exec".to_string())
        .chain(std::iter::once(shell_escape(binary)))
        .chain(args.iter().map(|arg| shell_escape(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '='))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

struct BootloaderAsset {
    reference: String,
    path: Option<PathBuf>,
    qemu_binary: Option<String>,
    machine: Option<String>,
}

fn env_override_asset() -> Option<BootloaderAsset> {
    let path = env::var_os("FAT_BOOTLOADER_UBOOT_ASSET")?;
    let qemu_binary = env::var("FAT_BOOTLOADER_QEMU_BINARY").ok();
    let machine = env::var("FAT_BOOTLOADER_QEMU_MACHINE").ok();
    let path = PathBuf::from(path);

    Some(BootloaderAsset {
        reference: format!("u-boot asset: {}", path.display()),
        path: Some(path),
        qemu_binary,
        machine,
    })
}

/// Prefix marking a tmux session as FAT-managed. Every session FAT launches
/// carries it, and the sweep in [`stop_all_tmux_sessions`] refuses to touch
/// anything without it, so a developer's own tmux sessions are never at risk.
///
/// `FAT_BOOTLOADER_TMUX_PREFIX` overrides it. That namespaces one caller's
/// sessions away from another's, which is what lets concurrent test binaries
/// each sweep their own sessions without reaping their neighbours'.
pub const DEFAULT_TMUX_SESSION_PREFIX: &str = "fat-bootloader-";

fn tmux_session_prefix() -> String {
    env::var("FAT_BOOTLOADER_TMUX_PREFIX")
        .ok()
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or_else(|| DEFAULT_TMUX_SESSION_PREFIX.to_string())
}

fn tmux_session_name(project_dir: &Path) -> String {
    let canonical_project_dir =
        fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let slug = canonical_project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical_project_dir.hash(&mut hasher);
    let suffix = format!("{:08x}", hasher.finish() as u32);
    format!("{}{slug}-{suffix}", tmux_session_prefix())
}

fn tmux_available() -> bool {
    tmux_binary().is_some()
}

fn tmux_has_session(session: &str) -> Result<bool, BootloaderQemuError> {
    let status = Command::new(tmux_binary_path()?)
        .args(["has-session", "-t", session])
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

fn run_tmux(args: &[&str]) -> Result<(), BootloaderQemuError> {
    let status = Command::new(tmux_binary_path()?).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(BootloaderQemuError::CommandFailed(format!(
            "tmux command failed: tmux {}",
            args.join(" ")
        )))
    }
}

fn write_launch(
    project_dir: &Path,
    launch: &BootloaderQemuLaunch,
) -> Result<(), BootloaderQemuError> {
    let launch_path = project_dir
        .join("bootloader")
        .join("qemu")
        .join("launch.json");
    fs::write(launch_path, serde_json::to_vec_pretty(launch)?)?;
    Ok(())
}

fn session_needs_restart(launch: &BootloaderQemuLaunch) -> Result<bool, BootloaderQemuError> {
    let output = Command::new(tmux_binary_path()?)
        .args([
            "display-message",
            "-p",
            "-t",
            &launch.tmux_session,
            "#{pane_dead}|#{@fat_launch_command_hex}",
        ])
        .output()?;
    if !output.status.success() {
        return Ok(true);
    }

    let state = String::from_utf8_lossy(&output.stdout);
    // tmux may sanitize literal control characters in display formats. A
    // printable separator is unambiguous because the command identity is hex.
    let (pane_dead, command_identity) = state.trim_end().split_once('|').unwrap_or(("1", ""));

    Ok(pane_dead == "1" || command_identity != launch_command_identity(&launch.qemu_command))
}

fn launch_command_identity(command: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut identity = String::with_capacity(7 + command.len() * 2);
    identity.push_str("hex-v1:");
    for byte in command.bytes() {
        identity.push(char::from(HEX[usize::from(byte >> 4)]));
        identity.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    identity
}

fn boot_loader_artifact(boot_plan: &BootPlan) -> Option<(PathBuf, String)> {
    let artifact = boot_plan.fit.as_ref().or(boot_plan.kernel.as_ref())?;
    let load_addr = artifact
        .load_addr
        .clone()
        .or_else(|| boot_plan.load_addresses.first().cloned())?;
    Some((PathBuf::from(&artifact.path), load_addr))
}

fn dtb_loader_artifact(boot_plan: &BootPlan) -> Option<(PathBuf, String)> {
    let artifact = boot_plan.dtb.as_ref()?;
    let load_addr = artifact.load_addr.clone()?;
    Some((PathBuf::from(&artifact.path), load_addr))
}

fn interrupt_autoboot(launch: &BootloaderQemuLaunch) -> Result<(), BootloaderQemuError> {
    wait_for_autoboot_window(launch)?;

    for _ in 0..6 {
        run_tmux(&["send-keys", "-t", &launch.tmux_session, "Space"])?;
        run_tmux(&["send-keys", "-t", &launch.tmux_session, "Enter"])?;
        thread::sleep(Duration::from_millis(125));
    }
    Ok(())
}

fn wait_for_autoboot_window(launch: &BootloaderQemuLaunch) -> Result<(), BootloaderQemuError> {
    for _ in 0..40 {
        sync_serial_log_from_pane(launch)?;
        let serial_output = fs::read_to_string(&launch.serial_log).unwrap_or_default();
        if serial_output.contains("Hit any key to stop autoboot")
            || serial_output.contains(&launch.prompt)
            || serial_output.contains("=>")
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    Ok(())
}

fn wait_for_prompt(launch: &BootloaderQemuLaunch) -> Result<(), BootloaderQemuError> {
    for _ in 0..120 {
        sync_serial_log_from_pane(launch)?;
        let serial_output = fs::read_to_string(&launch.serial_log).unwrap_or_default();
        if serial_output.contains(&launch.prompt) || serial_output.contains("=>") {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    Err(BootloaderQemuError::CommandFailed(format!(
        "timed out waiting for U-Boot prompt in {}",
        launch.serial_log
    )))
}

fn sync_serial_log_from_pane(launch: &BootloaderQemuLaunch) -> Result<(), BootloaderQemuError> {
    let output = Command::new(tmux_binary_path()?)
        .args(["capture-pane", "-p", "-t", &launch.tmux_session])
        .output()?;
    if !output.status.success() {
        return Ok(());
    }

    let pane_output = String::from_utf8_lossy(&output.stdout);
    if pane_output.is_empty() {
        return Ok(());
    }

    let serial_path = Path::new(&launch.serial_log);
    let current = fs::read_to_string(serial_path).unwrap_or_default();
    if current == pane_output {
        return Ok(());
    }

    fs::write(serial_path, pane_output.as_bytes())?;
    Ok(())
}

fn kill_tmux_session(session: &str) -> Result<(), BootloaderQemuError> {
    let status = Command::new(tmux_binary_path()?)
        .args(["kill-session", "-t", session])
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        // tmux also exits non-zero when the session is simply not there any
        // more — it ended on its own, or a concurrent caller won the race.
        // That is the state the caller asked for, so only a session that is
        // still standing counts as a failure.
        if !tmux_has_session(session)? {
            return Ok(());
        }
        return Err(BootloaderQemuError::CommandFailed(format!(
            "failed to kill tmux session {session}"
        )));
    }

    for _ in 0..40 {
        if !tmux_has_session(session)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }

    Err(BootloaderQemuError::CommandFailed(format!(
        "timed out waiting for tmux session {session} to stop"
    )))
}

fn tmux_binary() -> Option<PathBuf> {
    find_in_path("tmux").or_else(|| {
        let path = PathBuf::from("/opt/homebrew/bin/tmux");
        path.is_file().then_some(path)
    })
}

fn tmux_binary_path() -> Result<PathBuf, BootloaderQemuError> {
    tmux_binary().ok_or_else(|| {
        BootloaderQemuError::CommandFailed("tmux is unavailable on this host".to_string())
    })
}
