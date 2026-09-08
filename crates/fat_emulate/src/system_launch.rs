use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::runs::RuntimeEndpoint;

use crate::system_runner::SystemLaunchSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemLaunchResult {
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub process_id: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_log_path: String,
    pub stderr_log_path: String,
    pub registered_surfaces: Vec<RuntimeEndpoint>,
}

pub fn launch_native_system(
    spec: &SystemLaunchSpec,
) -> Result<SystemLaunchResult, DiagnosticRecord> {
    launch_native_system_with(spec, |_| {})
}

/// The same launch, except `on_spawn` receives the pid as soon as the child is
/// confirmed running and before any further bookkeeping. Callers use it to arm
/// cleanup for the window where the emulator is running but its pid has not
/// reached disk yet.
pub fn launch_native_system_with(
    spec: &SystemLaunchSpec,
    on_spawn: impl FnOnce(u32),
) -> Result<SystemLaunchResult, DiagnosticRecord> {
    verify_required_qemu_version(spec)?;
    let stdout_log_path = system_launch_log_path(spec, "stdout.log");
    let stderr_log_path = system_launch_log_path(spec, "stderr.log");
    ensure_capture_file(&stdout_log_path).map_err(|err| {
        launch_error(
            &spec.qemu_binary,
            format!("failed to prepare stdout capture file: {err}"),
            None,
        )
    })?;
    ensure_capture_file(&stderr_log_path).map_err(|err| {
        launch_error(
            &spec.qemu_binary,
            format!("failed to prepare stderr capture file: {err}"),
            None,
        )
    })?;

    // Build the full argument list, including instrumentation plugin if configured
    let mut full_args: Vec<String> = spec.args.clone();

    if let Some(instrumentation) = &spec.instrumentation {
        // Fail fast if the plugin shared object doesn't exist
        if !instrumentation.plugin_path.exists() {
            return Err(launch_error(
                &spec.qemu_binary,
                format!(
                    "instrumentation plugin not found: {} — build it with: \
                     cc -shared -fPIC -o fat-hook.so scripts/fat-hook-plugin.c \
                     $(pkg-config --cflags glib-2.0) -I$(brew --prefix)/include \
                     -undefined dynamic_lookup",
                    instrumentation.plugin_path.display()
                ),
                None,
            ));
        }

        let trace_log = system_launch_log_path(spec, "instrument-trace.jsonl");
        let _ = ensure_capture_file(&trace_log);
        let plugin_arg = instrumentation.plugin_arg(&trace_log);
        full_args.push("-plugin".to_string());
        full_args.push(plugin_arg);
    }

    let mut command = Command::new(&spec.qemu_binary);
    command.args(&full_args);
    #[cfg(unix)]
    command.process_group(0);

    let stdout_file = open_capture_file_for_child(&stdout_log_path).map_err(|err| {
        launch_error(
            &spec.qemu_binary,
            format!("failed to open stdout capture file for child: {err}"),
            None,
        )
    })?;
    let stderr_file = open_capture_file_for_child(&stderr_log_path).map_err(|err| {
        launch_error(
            &spec.qemu_binary,
            format!("failed to open stderr capture file for child: {err}"),
            None,
        )
    })?;
    command.stdout(Stdio::from(stdout_file));
    command.stderr(Stdio::from(stderr_file));
    let child_cwd = launch_root(spec);
    if let Some(current_dir) = &child_cwd {
        command.current_dir(current_dir);
    }

    let mut child = command.spawn().map_err(|err| {
        launch_error(
            &spec.qemu_binary,
            format!(
                "failed to spawn native-host system launch: {err}{}",
                child_cwd_detail(child_cwd.as_deref())
            ),
            None,
        )
    })?;

    let process_id = Some(child.id());

    match child.try_wait() {
        Ok(Some(status)) => {
            let stdout = fs::read_to_string(&stdout_log_path).unwrap_or_default();
            let stderr = fs::read_to_string(&stderr_log_path).unwrap_or_default();
            let exit_code = status.code();
            return Err(launch_error(
                &spec.qemu_binary,
                format!(
                    "native-host system launch exited immediately{}",
                    child_cwd_detail(child_cwd.as_deref())
                ),
                exit_code,
            )
            .with_suggested_actions(launch_suggested_actions(&stdout, &stderr, exit_code)));
        }
        Ok(None) => {}
        Err(err) => {
            // The child spawned but its state is unknown. Dropping the handle
            // here would leave it running with its pid reported to nobody, so
            // reap it before returning the failure.
            let _ = child.kill();
            let _ = child.wait();
            return Err(launch_error(
                &spec.qemu_binary,
                format!("failed while probing native-host system launch state: {err}"),
                None,
            ));
        }
    }

    // Confirmed running: hand the pid over before anything else, so the
    // caller's cleanup window opens as early as it can.
    on_spawn(child.id());

    let mut recorded_command = vec![spec.qemu_binary.clone()];
    recorded_command.extend(full_args);

    Ok(SystemLaunchResult {
        command: recorded_command,
        exit_code: None,
        process_id,
        stdout: fs::read_to_string(&stdout_log_path).unwrap_or_default(),
        stderr: fs::read_to_string(&stderr_log_path).unwrap_or_default(),
        stdout_log_path,
        stderr_log_path,
        registered_surfaces: spec.registered_surfaces.clone(),
    })
}

fn verify_required_qemu_version(spec: &SystemLaunchSpec) -> Result<(), DiagnosticRecord> {
    let Some(expected) = spec.required_qemu_version.as_deref() else {
        return Ok(());
    };
    let output = Command::new(&spec.qemu_binary)
        .arg("--version")
        .output()
        .map_err(|error| {
            launch_error(
                &spec.qemu_binary,
                format!("failed to verify required QEMU {expected}: {error}"),
                None,
            )
        })?;
    let observed = String::from_utf8_lossy(if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    })
    .lines()
    .next()
    .unwrap_or("<no version output>")
    .trim()
    .to_string();
    let observed_version = observed
        .split_once("version ")
        .and_then(|(_, suffix)| suffix.split_whitespace().next());
    if !output.status.success() || observed_version != Some(expected) {
        return Err(launch_error(
            &spec.qemu_binary,
            format!("managed machine requires QEMU {expected}; observed {observed}"),
            output.status.code(),
        ));
    }
    Ok(())
}

fn system_launch_log_path(spec: &SystemLaunchSpec, suffix: &str) -> String {
    let root = launch_root(spec).unwrap_or_else(std::env::temp_dir);
    root.join(suffix).display().to_string()
}

fn launch_root(spec: &SystemLaunchSpec) -> Option<PathBuf> {
    Path::new(&spec.serial_log).parent().map(Path::to_path_buf)
}

/// Launch failures are almost always path-resolution failures, and the child
/// runs with its own working directory. Report both so a relative path that the
/// child cannot resolve is visible in the diagnostic itself.
fn child_cwd_detail(child_cwd: Option<&Path>) -> String {
    match child_cwd {
        Some(cwd) => format!("; child cwd: {}", cwd.display()),
        None => "; child cwd: inherited from fat".to_string(),
    }
}

fn ensure_capture_file(path: &str) -> io::Result<()> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    File::create(path)?;
    Ok(())
}

fn open_capture_file_for_child(path: &str) -> io::Result<File> {
    File::options().append(true).open(path)
}

trait DiagnosticRecordExt {
    fn with_suggested_actions(self, suggested_actions: Vec<String>) -> Self;
}

impl DiagnosticRecordExt for DiagnosticRecord {
    fn with_suggested_actions(mut self, suggested_actions: Vec<String>) -> Self {
        self.suggested_next_actions = suggested_actions;
        self
    }
}

fn launch_error(
    summary: &str,
    detail: impl Into<String>,
    exit_code: Option<i32>,
) -> DiagnosticRecord {
    let mut diagnostic = DiagnosticRecord::new(
        summary.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some("native-host-system-launch".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        format!("fat-emulate: {}", detail.into()),
        Vec::new(),
        Vec::new(),
        launch_suggested_actions("", "", exit_code),
    );
    if diagnostic.suggested_next_actions.is_empty() {
        diagnostic.suggested_next_actions = vec![
            "inspect the native-host launch command".to_string(),
            "retry with a fallback substrate if available".to_string(),
        ];
    }
    diagnostic
}

fn launch_suggested_actions(stdout: &str, stderr: &str, exit_code: Option<i32>) -> Vec<String> {
    let mut suggested_next_actions = vec![
        "inspect the native-host launch command and staged boot assets".to_string(),
        "retry with a fallback substrate if available".to_string(),
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
    suggested_next_actions
}
