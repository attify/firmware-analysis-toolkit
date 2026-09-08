use std::collections::HashMap;
use std::env;
use std::fs;
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use serde::{Deserialize, Serialize};

use crate::model::EMUX_ROOTFUL_PODMAN_ENV;

pub const EMUX_DIR_ENV: &str = "FAT_EMUX_DIR";
pub const EMUX_REFERENCE_DEVICE_ENV: &str = "FAT_EMUX_REFERENCE_DEVICE";
const EMUX_RUNTIME_ADAPTER_DIR_ENV: &str = "FAT_EMUX_RUNTIME_ADAPTER_DIR";
const EMUX_DIALOG_HELPER_NAME: &str = "emux-dialog-helper";
const EMUX_LAUNCH_HELPER_NAME: &str = "emux-launch-helper.sh";
const EMUX_USERSPACE_HELPER_NAME: &str = "emux-userspace-helper.sh";
const EMUX_REFERENCE_DEVICE_DEFAULT_USERSPACE_CHOICE: &str = "1";
const EMUX_REPO_RUNTIME_ROOT: &str = "files/emux";
const EMUX_WORKSPACE_DIR: &str = "workspace";
const EMUX_LAUNCH_READY_TIMEOUT: Duration = Duration::from_secs(15);
const EMUX_LAUNCH_OUTPUT_TIMEOUT: Duration = Duration::from_secs(15);
const EMUX_OUTPUT_READY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxRequest {
    pub emux_dir: PathBuf,
    pub reference_device_id: String,
    pub workspace_root: PathBuf,
    pub run_id: Option<String>,
}

impl EmuxRequest {
    pub fn new(
        emux_dir: PathBuf,
        reference_device_id: impl Into<String>,
        workspace_root: PathBuf,
    ) -> Self {
        Self {
            emux_dir,
            reference_device_id: reference_device_id.into(),
            workspace_root,
            run_id: None,
        }
    }

    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxPrepared {
    pub request: EmuxRequest,
    pub selected_reference_device_id: String,
    pub launch_device_id: String,
    pub reference_device_index: usize,
    pub reference_device_description: String,
    pub emux_runtime_root: PathBuf,
    pub reference_device_dir: PathBuf,
    pub launch_device_dir: PathBuf,
    pub runtime_workspace_dir: PathBuf,
    pub container_workspace_dir: PathBuf,
    pub dialog_helper_path: PathBuf,
    pub launch_helper_path: PathBuf,
    pub userspace_helper_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmuxReconstructionState {
    pub requested_reference_device_id: String,
    pub selected_reference_device_id: String,
    pub reference_device_description: String,
    pub reference_device_dir: String,
    pub runtime_workspace_dir: String,
    pub container_workspace_dir: String,
    pub startup_service_name: Option<String>,
    pub startup_service_endpoint: Option<String>,
    pub startup_network_name: Option<String>,
    pub startup_network_host: Option<String>,
    pub startup_network_port: Option<u16>,
    pub startup_network_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxLaunchResult {
    pub supervisor_pid: u32,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxUserspaceResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxLaunchError {
    pub diagnostic: DiagnosticRecord,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxUserspaceError {
    pub diagnostic: DiagnosticRecord,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmuxRuntimePhase {
    LaunchComplete,
    UserspaceStarted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmuxLaunchState {
    pub backend_id: String,
    pub reference_device_id: String,
    pub reference_device_index: usize,
    pub reference_device_description: String,
    pub reference_device_dir: String,
    pub runtime_workspace_dir: String,
    pub container_workspace_dir: String,
    pub dialog_helper_path: String,
    pub launch_command: String,
    pub launch_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmuxUserspaceState {
    pub backend_id: String,
    pub reference_device_id: String,
    pub reference_device_index: usize,
    pub reference_device_description: String,
    pub reference_device_dir: String,
    pub runtime_workspace_dir: String,
    pub container_workspace_dir: String,
    pub dialog_helper_path: String,
    pub userspace_command: String,
    pub userspace_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmuxRuntimeStatus {
    pub backend_id: String,
    pub reference_device_id: String,
    pub reference_device_index: usize,
    pub reference_device_description: String,
    pub runtime_phase: EmuxRuntimePhase,
    pub runtime_outcome: Option<String>,
    pub launch_state_present: bool,
    pub userspace_state_present: bool,
    pub launch_command: String,
    pub userspace_command: Option<String>,
    pub launch_exit_code: Option<i32>,
    pub userspace_exit_code: Option<i32>,
    pub reference_device_dir: String,
    pub runtime_workspace_dir: String,
    pub container_workspace_dir: String,
    pub dialog_helper_path: String,
}

#[derive(Debug, Default)]
struct EmuxLaunchStateTracker {
    inflight_launches: Mutex<HashMap<String, TrackedEmuxLaunch>>,
}

#[derive(Debug)]
struct TrackedEmuxLaunch {
    child: Child,
    process_group_id: u32,
}

#[derive(Debug, Default)]
pub struct EmuxManager {
    tracker: EmuxLaunchStateTracker,
}

impl EmuxManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare(&self, request: EmuxRequest) -> Result<EmuxPrepared, EmuxPreparationError> {
        let emux_runtime_root = request.emux_dir.join(EMUX_REPO_RUNTIME_ROOT);
        let devices_file = emux_runtime_root.join("firmware").join("devices");
        if !devices_file.is_file() {
            return Err(preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                request.reference_device_id.clone(),
                format!("missing {}", devices_file.display()),
            ));
        }

        let selected_reference_device_id = request.reference_device_id.clone();

        let (_selected_reference_device_index, reference_device_description) =
            lookup_reference_device(&devices_file, &selected_reference_device_id).ok_or_else(
                || {
                    preparation_error(
                        request.run_id.as_deref().unwrap_or("emux-preparation"),
                        selected_reference_device_id.clone(),
                        format!(
                            "reference device {} not found in {}",
                            selected_reference_device_id,
                            devices_file.display()
                        ),
                    )
                },
            )?;

        let reference_device_dir = emux_runtime_root.join(&selected_reference_device_id);
        if !reference_device_dir.is_dir() {
            return Err(preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "reference device directory missing: {}",
                    reference_device_dir.display()
                ),
            ));
        }
        let config_path = reference_device_dir.join("config");
        if !config_path.is_file() {
            return Err(preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!("missing {}", config_path.display()),
            ));
        }

        let runtime_workspace_dir = request.workspace_root.join(stable_emux_workspace_id(
            request.run_id.as_deref().unwrap_or("emux-session"),
            &selected_reference_device_id,
        ));
        fs::create_dir_all(&runtime_workspace_dir).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create runtime workspace {}: {err}",
                    runtime_workspace_dir.display()
                ),
            )
        })?;

        let container_workspace_root = request.emux_dir.join(EMUX_WORKSPACE_DIR);
        fs::create_dir_all(&container_workspace_root).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create EMUX workspace root {}: {err}",
                    container_workspace_root.display()
                ),
            )
        })?;
        let container_workspace_dir =
            container_workspace_root.join(runtime_workspace_dir.file_name().unwrap_or_default());
        fs::create_dir_all(&container_workspace_dir).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create EMUX workspace {}: {err}",
                    container_workspace_dir.display()
                ),
            )
        })?;

        let dialog_helper_path = container_workspace_dir.join(EMUX_DIALOG_HELPER_NAME);
        fs::write(
            &dialog_helper_path,
            format!(
                "#!/bin/sh\ntarget=${{EMUX_DIALOG_DEVICE_ID:-}}\nif [ -n \"$target\" ]; then\n  choice=0\n  for devices in /emux/firmware*/devices; do\n    while IFS= read -r line || [ -n \"$line\" ]; do\n      id=${{line%%,*}}\n      case \"$id\" in ''|'#'*) continue ;; esac\n      if [ \"$id\" = \"$target\" ]; then\n        printf '%s\\n' \"$choice\"\n        exit 0\n      fi\n      choice=$((choice + 1))\n    done < \"$devices\"\n  done\n  printf 'EMUX device ID not found: %s\\n' \"$target\" >&2\n  exit 64\nfi\nprintf '%s\\n' \"${{EMUX_DIALOG_CHOICE:-{EMUX_REFERENCE_DEVICE_DEFAULT_USERSPACE_CHOICE}}}\"\n"
            ),
        )
        .map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create EMUX dialog helper {}: {err}",
                    dialog_helper_path.display()
                ),
            )
        })?;
        make_executable(&dialog_helper_path).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to mark EMUX dialog helper executable {}: {err}",
                    dialog_helper_path.display()
                ),
            )
        })?;

        let launch_device_id = selected_reference_device_id.clone();
        let launch_device_dir = reference_device_dir.clone();

        let (reference_device_index, _) =
            lookup_reference_device_in_runtime_root(&emux_runtime_root, &launch_device_id)
                .ok_or_else(|| {
                    preparation_error(
                        request.run_id.as_deref().unwrap_or("emux-preparation"),
                        selected_reference_device_id.clone(),
                        format!("launch device {launch_device_id} not found after generation"),
                    )
                })?;
        let launch_helper_path = container_workspace_dir.join(EMUX_LAUNCH_HELPER_NAME);
        fs::write(&launch_helper_path, {
            let marker = format!(
                "{}/emux-runtime.marker",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let launch_stdout = format!(
                "{}/emux-launch.stdout",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let launch_stderr = format!(
                "{}/emux-launch.stderr",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let dialog_helper = container_dialog_helper_path_for(&container_workspace_dir);
            let launch_device_selector = format!(
                "EMUX_DIALOG_DEVICE_ID={} ",
                shell_quote(&launch_device_id)
            );
            format!(
                "#!/bin/sh\nmarker={marker:?}\nlaunch_stdout={launch_stdout:?}\nlaunch_stderr={launch_stderr:?}\n: > \"$launch_stdout\"\n: > \"$launch_stderr\"\ntouch \"$marker\"\ntrap 'rm -f \"$marker\"' EXIT\n{launch_device_selector}fundialog={dialog_helper:?} /emux/run/launcher >\"$launch_stdout\" 2>\"$launch_stderr\"\nlauncher_exit=$?\nwhile [ -e \"$marker\" ]; do sleep 1; done\nexit \"$launcher_exit\"\n",
            )
        })
        .map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create EMUX launch helper {}: {err}",
                    launch_helper_path.display()
                ),
            )
        })?;
        make_executable(&launch_helper_path).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to mark EMUX launch helper executable {}: {err}",
                    launch_helper_path.display()
                ),
            )
        })?;
        let userspace_helper_path = container_workspace_dir.join(EMUX_USERSPACE_HELPER_NAME);
        fs::write(&userspace_helper_path, {
            let marker = format!(
                "{}/emux-runtime.marker",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let userspace_stdout = format!(
                "{}/emux-userspace.stdout",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let userspace_stderr = format!(
                "{}/emux-userspace.stderr",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let userspace_ready = format!(
                "{}/emux-userspace.ready",
                container_workspace_mount_path_for(&container_workspace_dir)
            );
            let userspace_invocation = "if [ \"$(id -u)\" = \"1000\" ] && command -v sudo >/dev/null 2>&1; then\n  sudo ./run-init >\"$userspace_stdout\" 2>\"$userspace_stderr\"\nelse\n  ./run-init >\"$userspace_stdout\" 2>\"$userspace_stderr\"\nfi".to_string();
            format!(
                "#!/bin/sh\nmarker={marker:?}\nuserspace_stdout={userspace_stdout:?}\nuserspace_stderr={userspace_stderr:?}\nuserspace_ready={userspace_ready:?}\n[ -e \"$marker\" ] || exit 11\n: > \"$userspace_stdout\"\n: > \"$userspace_stderr\"\nrm -f \"$userspace_ready\"\ncd \"/emux/{launch_device_id}\" || exit 12\n{userspace_invocation}\nuserspace_exit=$?\nif [ \"$userspace_exit\" -eq 0 ]; then printf 'ready\\n' > \"$userspace_ready\"; fi\nrm -f \"$marker\"\nexit \"$userspace_exit\"\n",
            )
        })
        .map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to create EMUX userspace helper {}: {err}",
                    userspace_helper_path.display()
                ),
            )
        })?;
        make_executable(&userspace_helper_path).map_err(|err| {
            preparation_error(
                request.run_id.as_deref().unwrap_or("emux-preparation"),
                selected_reference_device_id.clone(),
                format!(
                    "failed to mark EMUX userspace helper executable {}: {err}",
                    userspace_helper_path.display()
                ),
            )
        })?;

        Ok(EmuxPrepared {
            request,
            selected_reference_device_id,
            launch_device_id,
            reference_device_index,
            reference_device_description,
            emux_runtime_root,
            reference_device_dir,
            launch_device_dir,
            runtime_workspace_dir,
            container_workspace_dir,
            dialog_helper_path,
            launch_helper_path,
            userspace_helper_path,
        })
    }

    pub fn launch_reference_device(
        &self,
        prepared: &EmuxPrepared,
    ) -> Result<EmuxLaunchResult, EmuxLaunchError> {
        if !cfg!(unix) {
            return Err(launch_error(
                prepared,
                "EmuX launch is supported only on Unix hosts because its shell, PTY, and process-group lifecycle cannot be enforced on native Windows".to_string(),
                "",
                "",
                None,
            ));
        }
        let launch_command = prepared.launch_command_string();
        let process_group_path = prepared.launch_process_group_path();
        match fs::remove_file(&process_group_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(launch_error(
                    prepared,
                    format!(
                        "refusing to launch with an unremovable stale EmuX process-group identity {}: {err}",
                        process_group_path.display()
                    ),
                    "",
                    "",
                    None,
                ));
            }
        }
        let mut launch_process = spawn_emux_wrapper(
            &prepared.request.emux_dir,
            "run-emux-docker",
            &["/bin/sh", &prepared.container_launch_helper_path()],
            Some(&process_group_path),
        );
        configure_emux_container_runtime(&mut launch_process)
            .map_err(|summary| launch_error(prepared, summary, "", "", None))?;
        let wrapper_stdout = fs::File::create(prepared.wrapper_stdout_path()).map_err(|err| {
            launch_error(
                prepared,
                format!("failed to create EmuX PTY stdout log: {err}"),
                "",
                "",
                None,
            )
        })?;
        let wrapper_stderr = fs::File::create(prepared.wrapper_stderr_path()).map_err(|err| {
            launch_error(
                prepared,
                format!("failed to create EmuX PTY stderr log: {err}"),
                "",
                "",
                None,
            )
        })?;
        let mut child = launch_process
            // EMUX launch is non-interactive: dialog input is provided by the
            // generated helper. Inheriting a caller's terminal here can leave
            // macOS `script` waiting on that terminal before it executes the
            // process-group handshake.
            .stdin(Stdio::null())
            // The wrapper outlives the `fat emulate` command. Giving it the
            // CLI's inherited descriptors keeps a caller using
            // `Command::output()` blocked until the emulated guest exits.
            // Regular files remain connected for GNU `script` while making
            // the launched runtime independent of the invoking CLI's pipes.
            .stdout(Stdio::from(wrapper_stdout))
            .stderr(Stdio::from(wrapper_stderr))
            .spawn()
            .map_err(|err| {
                launch_error(
                    prepared,
                    format!("failed to spawn launch command: {err}"),
                    "",
                    "",
                    None,
                )
            })?;
        let supervisor_pid = wait_for_wrapper_process_group(&process_group_path, &mut child)
            .map_err(|summary| {
                launch_error(
                    prepared,
                    summary,
                    &fs::read_to_string(prepared.wrapper_stdout_path()).unwrap_or_default(),
                    &fs::read_to_string(prepared.wrapper_stderr_path()).unwrap_or_default(),
                    None,
                )
            })?;

        if let Err(summary) = self.wait_for_runtime_ready(prepared, &mut child) {
            let summary = append_group_cleanup_result(
                summary,
                terminate_child_group(&mut child, supervisor_pid),
            );
            return Err(launch_error(prepared, summary, "", "", None));
        }

        if let Err(summary) =
            self.wait_for_output_ready(prepared, prepared.launch_stdout_path(), "launch stdout")
        {
            let summary = append_group_cleanup_result(
                summary,
                terminate_child_group(&mut child, supervisor_pid),
            );
            return Err(launch_error(prepared, summary, "", "", None));
        }

        self.tracker
            .inflight_launches
            .lock()
            .expect("emux launch tracker lock")
            .insert(
                prepared.runtime_key(),
                TrackedEmuxLaunch {
                    child,
                    process_group_id: supervisor_pid,
                },
            );

        let stdout = fs::read_to_string(prepared.launch_stdout_path()).unwrap_or_default();
        let stderr = fs::read_to_string(prepared.launch_stderr_path()).unwrap_or_default();

        if !prepared.runtime_marker_path().is_file() {
            let summary = append_group_cleanup_result(
                "runtime marker missing after launch".to_string(),
                self.terminate_inflight_launch(prepared),
            );
            return Err(launch_error(prepared, summary, &stdout, &stderr, None));
        }

        Ok(EmuxLaunchResult {
            supervisor_pid,
            exit_code: None,
            stdout,
            stderr,
            command: launch_command,
        })
    }

    pub fn start_userspace(
        &self,
        prepared: &EmuxPrepared,
        _launch_result: &EmuxLaunchResult,
    ) -> Result<EmuxUserspaceResult, EmuxUserspaceError> {
        let userspace_command = prepared.userspace_command_string();
        let mut userspace_command_process = spawn_emux_wrapper(
            &prepared.request.emux_dir,
            "emux-docker-shell",
            &["/bin/sh", &prepared.container_userspace_helper_path()],
            None,
        );
        if let Err(summary) = configure_emux_container_runtime(&mut userspace_command_process) {
            let summary =
                append_group_cleanup_result(summary, self.terminate_inflight_launch(prepared));
            return Err(userspace_error(prepared, summary, "", "", None));
        }
        let output = match userspace_command_process.output() {
            Ok(output) => output,
            Err(err) => {
                let summary = append_group_cleanup_result(
                    format!("failed to spawn userspace command: {err}"),
                    self.terminate_inflight_launch(prepared),
                );
                return Err(userspace_error(prepared, summary, "", "", None));
            }
        };

        if !output.status.success() {
            let summary = append_group_cleanup_result(
                "userspace command exited unsuccessfully".to_string(),
                self.terminate_inflight_launch(prepared),
            );
            return Err(userspace_error(
                prepared,
                summary,
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
                output.status.code(),
            ));
        }

        self.wait_for_output_ready(
            prepared,
            prepared.userspace_ready_path(),
            "userspace readiness marker",
        )
        .map_err(|summary| {
            let summary =
                append_group_cleanup_result(summary, self.terminate_inflight_launch(prepared));
            userspace_error(
                prepared,
                format!("userspace artifact not ready: {summary}"),
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
                output.status.code(),
            )
        })?;

        let stdout = fs::read_to_string(prepared.userspace_stdout_path()).unwrap_or_default();
        let stderr = fs::read_to_string(prepared.userspace_stderr_path()).unwrap_or_default();
        let result = EmuxUserspaceResult {
            exit_code: output.status.code(),
            stdout,
            stderr,
            command: userspace_command,
        };
        self.detach_inflight_launch(prepared);
        Ok(result)
    }
}

impl EmuxPrepared {
    pub fn requested_reference_device_id(&self) -> &str {
        &self.request.reference_device_id
    }

    pub fn selected_reference_device_id(&self) -> &str {
        &self.selected_reference_device_id
    }

    pub fn launch_device_id(&self) -> &str {
        &self.launch_device_id
    }

    pub fn reconstruction_state(&self) -> EmuxReconstructionState {
        EmuxReconstructionState {
            requested_reference_device_id: self.request.reference_device_id.clone(),
            selected_reference_device_id: self.selected_reference_device_id.clone(),
            reference_device_description: self.reference_device_description.clone(),
            reference_device_dir: self.reference_device_dir.display().to_string(),
            runtime_workspace_dir: self.runtime_workspace_dir.display().to_string(),
            container_workspace_dir: self.container_workspace_dir.display().to_string(),
            startup_service_name: None,
            startup_service_endpoint: None,
            startup_network_name: None,
            startup_network_host: None,
            startup_network_port: None,
            startup_network_uri: None,
        }
    }

    pub fn launch_state(&self, launch_result: &EmuxLaunchResult) -> EmuxLaunchState {
        EmuxLaunchState {
            backend_id: "emux".to_string(),
            reference_device_id: self.launch_device_id.clone(),
            reference_device_index: self.reference_device_index,
            reference_device_description: self.reference_device_description.clone(),
            reference_device_dir: self.launch_device_dir.display().to_string(),
            runtime_workspace_dir: self.runtime_workspace_dir.display().to_string(),
            container_workspace_dir: self.container_workspace_dir.display().to_string(),
            dialog_helper_path: self.dialog_helper_path.display().to_string(),
            launch_command: launch_result.command.clone(),
            launch_exit_code: launch_result.exit_code,
        }
    }

    pub fn userspace_state(
        &self,
        _launch_result: &EmuxLaunchResult,
        userspace_result: &EmuxUserspaceResult,
    ) -> EmuxUserspaceState {
        EmuxUserspaceState {
            backend_id: "emux".to_string(),
            reference_device_id: self.launch_device_id.clone(),
            reference_device_index: self.reference_device_index,
            reference_device_description: self.reference_device_description.clone(),
            reference_device_dir: self.launch_device_dir.display().to_string(),
            runtime_workspace_dir: self.runtime_workspace_dir.display().to_string(),
            container_workspace_dir: self.container_workspace_dir.display().to_string(),
            dialog_helper_path: self.dialog_helper_path.display().to_string(),
            userspace_command: userspace_result.command.clone(),
            userspace_exit_code: userspace_result.exit_code,
        }
    }

    pub fn runtime_status(
        &self,
        launch_state: &EmuxLaunchState,
        userspace_state: Option<&EmuxUserspaceState>,
    ) -> EmuxRuntimeStatus {
        let runtime_phase = if userspace_state.is_some() {
            EmuxRuntimePhase::UserspaceStarted
        } else {
            EmuxRuntimePhase::LaunchComplete
        };
        let runtime_outcome = if userspace_state.is_some() {
            Some("reference-device-userspace-started".to_string())
        } else {
            Some("reference-device-launch-complete".to_string())
        };
        EmuxRuntimeStatus {
            backend_id: "emux".to_string(),
            reference_device_id: self.launch_device_id.clone(),
            reference_device_index: self.reference_device_index,
            reference_device_description: self.reference_device_description.clone(),
            runtime_phase,
            runtime_outcome,
            launch_state_present: true,
            userspace_state_present: userspace_state.is_some(),
            launch_command: launch_state.launch_command.clone(),
            userspace_command: userspace_state.map(|state| state.userspace_command.clone()),
            launch_exit_code: launch_state.launch_exit_code,
            userspace_exit_code: userspace_state.and_then(|state| state.userspace_exit_code),
            reference_device_dir: self.launch_device_dir.display().to_string(),
            runtime_workspace_dir: self.runtime_workspace_dir.display().to_string(),
            container_workspace_dir: self.container_workspace_dir.display().to_string(),
            dialog_helper_path: self.dialog_helper_path.display().to_string(),
        }
    }

    fn launch_command_string(&self) -> String {
        emux_wrapper_command_string(
            &self.request.emux_dir,
            "run-emux-docker",
            &["/bin/sh", &self.container_launch_helper_path()],
        )
    }

    fn userspace_command_string(&self) -> String {
        emux_wrapper_command_string(
            &self.request.emux_dir,
            "emux-docker-shell",
            &["/bin/sh", &self.container_userspace_helper_path()],
        )
    }

    fn container_launch_helper_path(&self) -> String {
        let workspace_dir_name = self
            .container_workspace_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(EMUX_LAUNCH_HELPER_NAME);
        format!("/home/r0/workspace/{workspace_dir_name}/{EMUX_LAUNCH_HELPER_NAME}")
    }

    fn container_userspace_helper_path(&self) -> String {
        let workspace_dir_name = self
            .container_workspace_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(EMUX_USERSPACE_HELPER_NAME);
        format!("/home/r0/workspace/{workspace_dir_name}/{EMUX_USERSPACE_HELPER_NAME}")
    }

    fn runtime_key(&self) -> String {
        self.runtime_workspace_dir.display().to_string()
    }

    fn runtime_marker_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-runtime.marker")
    }

    fn launch_stdout_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-launch.stdout")
    }

    fn launch_stderr_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-launch.stderr")
    }

    fn launch_process_group_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-launch.pgid")
    }

    fn wrapper_stdout_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-wrapper.stdout")
    }

    fn wrapper_stderr_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-wrapper.stderr")
    }

    fn userspace_stdout_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-userspace.stdout")
    }

    fn userspace_stderr_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-userspace.stderr")
    }

    fn userspace_ready_path(&self) -> PathBuf {
        self.container_workspace_dir.join("emux-userspace.ready")
    }

    fn clear_runtime_marker(&self) {
        let _ = fs::remove_file(self.runtime_marker_path());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuxPreparationError {
    pub diagnostic: DiagnosticRecord,
}

fn lookup_reference_device(
    devices_file: &Path,
    reference_device_id: &str,
) -> Option<(usize, String)> {
    let contents = fs::read_to_string(devices_file).ok()?;
    let mut index = 0usize;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(',').map(str::trim);
        let id = fields.next()?;
        let description = line
            .split(',')
            .map(str::trim)
            .next_back()
            .unwrap_or("")
            .to_string();
        if id == reference_device_id {
            return Some((index, description));
        }
        index += 1;
    }
    None
}

fn lookup_reference_device_in_runtime_root(
    emux_runtime_root: &Path,
    reference_device_id: &str,
) -> Option<(usize, String)> {
    let mut devices_files = Vec::new();
    for entry in fs::read_dir(emux_runtime_root).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name()?.to_str()?;
        if !name.starts_with("firmware") {
            continue;
        }
        let devices_file = path.join("devices");
        if devices_file.is_file() {
            devices_files.push(devices_file);
        }
    }
    devices_files.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));
    let mut index = 0usize;
    for devices_file in devices_files {
        let contents = fs::read_to_string(&devices_file).ok()?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(',').map(str::trim);
            let id = fields.next()?;
            let description = line
                .split(',')
                .map(str::trim)
                .next_back()
                .unwrap_or("")
                .to_string();
            if id == reference_device_id {
                return Some((index, description));
            }
            index += 1;
        }
    }
    None
}

fn stable_emux_workspace_id(run_id: &str, reference_device_id: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(run_id.as_bytes());
    hasher.write(reference_device_id.as_bytes());
    format!("emux-work-{:016x}", hasher.finish())
}

fn container_dialog_helper_path_for(container_workspace_dir: &Path) -> String {
    let workspace_dir_name = container_workspace_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(EMUX_DIALOG_HELPER_NAME);
    format!("/home/r0/workspace/{workspace_dir_name}/{EMUX_DIALOG_HELPER_NAME}")
}

fn container_workspace_mount_path_for(container_workspace_dir: &Path) -> String {
    let workspace_dir_name = container_workspace_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(EMUX_DIALOG_HELPER_NAME);
    format!("/home/r0/workspace/{workspace_dir_name}")
}

fn spawn_emux_wrapper(
    emux_dir: &Path,
    wrapper_name: &str,
    args: &[&str],
    process_group_path: Option<&Path>,
) -> Command {
    let wrapper_path = emux_dir.join(wrapper_name);
    let script_path = script_binary_path();
    if cfg!(target_os = "macos") {
        let mut command = Command::new(&script_path);
        command.current_dir(emux_dir).arg("-q").arg("/dev/null");
        if let Some(process_group_path) = process_group_path {
            command
                .arg("/bin/sh")
                .arg("-c")
                .arg(emux_wrapper_shell_command_with_group_file(
                    emux_dir,
                    wrapper_name,
                    args,
                    process_group_path,
                ));
        } else {
            command.arg(&wrapper_path).args(args);
        }
        configure_wrapper_process_group(&mut command);
        return command;
    }

    let mut command = Command::new(&script_path);
    command
        .current_dir(emux_dir)
        .arg("-qefc")
        .arg(if let Some(process_group_path) = process_group_path {
            emux_wrapper_shell_command_with_group_file(
                emux_dir,
                wrapper_name,
                args,
                process_group_path,
            )
        } else {
            emux_wrapper_shell_command(emux_dir, wrapper_name, args)
        })
        .arg("/dev/null");
    configure_wrapper_process_group(&mut command);
    command
}

fn emux_wrapper_shell_command_with_group_file(
    emux_dir: &Path,
    wrapper_name: &str,
    args: &[&str],
    process_group_path: &Path,
) -> String {
    format!(
        "printf '%s\\n' \"$$\" > {} && {}",
        shell_quote(&process_group_path.display().to_string()),
        emux_wrapper_shell_command(emux_dir, wrapper_name, args)
    )
}

fn configure_wrapper_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn emux_wrapper_command_string(emux_dir: &Path, wrapper_name: &str, args: &[&str]) -> String {
    let wrapper_path = emux_dir.join(wrapper_name);
    let script_path = script_binary_path();
    if cfg!(target_os = "macos") {
        let mut parts = vec![
            shell_quote(&script_path.display().to_string()),
            "-q".to_string(),
            "/dev/null".to_string(),
            shell_quote(&wrapper_path.display().to_string()),
        ];
        parts.extend(args.iter().map(|arg| shell_quote(arg)));
        return parts.join(" ");
    }

    format!(
        "{} -qefc {} /dev/null",
        shell_quote(&script_path.display().to_string()),
        shell_quote(&emux_wrapper_shell_command(emux_dir, wrapper_name, args))
    )
}

fn emux_wrapper_shell_command(emux_dir: &Path, wrapper_name: &str, args: &[&str]) -> String {
    let mut parts = vec![shell_quote(
        &emux_dir.join(wrapper_name).display().to_string(),
    )];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    format!(
        "if [ -n \"${{{EMUX_RUNTIME_ADAPTER_DIR_ENV}:-}}\" ]; then PATH=\"${{{EMUX_RUNTIME_ADAPTER_DIR_ENV}}}:$PATH\"; export PATH; fi; exec {}",
        parts.join(" ")
    )
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

/// Configure an EMUX wrapper command for the explicitly opted-in rootful Podman path.
///
/// EMUX's upstream scripts invoke a binary named `docker`. When that command is a
/// Podman compatibility frontend, rootless execution cannot provide EMUX's TUN,
/// iptables, and NFS substrate. The adapter is therefore created only after the
/// operator sets `FAT_EMUX_ROOTFUL_PODMAN=1`; it delegates every operation through
/// non-interactive sudo and adds `--privileged --user root` only to container creation.
pub fn configure_emux_container_runtime(command: &mut Command) -> Result<(), String> {
    let Some(docker) = executable_command_path("docker") else {
        return Ok(());
    };
    let version = Command::new(&docker)
        .arg("--version")
        .output()
        .map_err(|err| format!("failed to identify EMUX container runtime: {err}"))?;
    let version_text = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    )
    .to_ascii_lowercase();
    if !version_text.contains("podman") {
        return Ok(());
    }
    if env::var(EMUX_ROOTFUL_PODMAN_ENV).as_deref() != Ok("1") {
        return Err(format!(
            "Podman detected; EMUX requires rootful privileged networking. Set {EMUX_ROOTFUL_PODMAN_ENV}=1 only on an isolated lab host to opt in"
        ));
    }
    let sudo = executable_command_path("sudo").ok_or_else(|| {
        format!("{EMUX_ROOTFUL_PODMAN_ENV}=1 is set, but sudo is unavailable for rootful Podman")
    })?;

    let adapter_dir =
        env::temp_dir().join(format!("fat-emux-rootful-podman-{}", std::process::id()));
    fs::create_dir_all(&adapter_dir).map_err(|err| {
        format!(
            "failed to create rootful Podman adapter directory {}: {err}",
            adapter_dir.display()
        )
    })?;
    let adapter = adapter_dir.join("docker");
    fs::write(
        &adapter,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"${{1:-}}\" = run ]; then\n  shift\n  exec {} -n {} run --privileged --user root \"$@\"\nfi\nexec {} -n {} \"$@\"\n",
            shell_quote(&sudo.display().to_string()),
            shell_quote(&docker.display().to_string()),
            shell_quote(&sudo.display().to_string()),
            shell_quote(&docker.display().to_string()),
        ),
    )
    .map_err(|err| {
        format!(
            "failed to write rootful Podman adapter {}: {err}",
            adapter.display()
        )
    })?;
    make_executable(&adapter).map_err(|err| {
        format!(
            "failed to mark rootful Podman adapter executable {}: {err}",
            adapter.display()
        )
    })?;

    command.env(EMUX_RUNTIME_ADAPTER_DIR_ENV, &adapter_dir);
    let mut paths = vec![adapter_dir];
    if let Some(current_path) = env::var_os("PATH") {
        paths.extend(env::split_paths(&current_path));
    }
    let runtime_path = env::join_paths(paths)
        .map_err(|err| format!("failed to construct EMUX Podman adapter PATH: {err}"))?;
    command.env("PATH", runtime_path);
    Ok(())
}

/// Remove the fixed-name upstream EMUX container if it still exists.
///
/// Rootful Podman containers are not reliably terminated by signalling FAT's
/// unprivileged PTY process group. Stop therefore needs an explicit container
/// lifecycle operation before it can report the runtime as completed.
pub fn remove_emux_container_if_present() -> Result<(), String> {
    let mut inspect = Command::new("docker");
    inspect.args(["container", "inspect", "emux-docker"]);
    configure_emux_container_runtime(&mut inspect)?;
    let inspect_output = inspect
        .output()
        .map_err(|err| format!("failed to inspect EMUX container: {err}"))?;
    if !inspect_output.status.success() {
        let detail = format!(
            "{}{}",
            String::from_utf8_lossy(&inspect_output.stdout),
            String::from_utf8_lossy(&inspect_output.stderr)
        );
        let normalized = detail.to_ascii_lowercase();
        if normalized.contains("no such")
            || normalized.contains("not found")
            || normalized.contains("does not exist")
        {
            return Ok(());
        }
        return Err(format!(
            "failed to inspect EMUX container (exit {:?}): {}",
            inspect_output.status.code(),
            detail.trim()
        ));
    }

    let mut remove = Command::new("docker");
    remove.args(["rm", "-f", "emux-docker"]);
    configure_emux_container_runtime(&mut remove)?;
    let remove_output = remove
        .output()
        .map_err(|err| format!("failed to remove EMUX container: {err}"))?;
    if remove_output.status.success() {
        return Ok(());
    }
    Err(format!(
        "failed to remove EMUX container (exit {:?}): {}{}",
        remove_output.status.code(),
        String::from_utf8_lossy(&remove_output.stdout),
        String::from_utf8_lossy(&remove_output.stderr)
    ))
}

fn executable_command_path(command: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var)
        .map(|entry| entry.join(command))
        .find(|candidate| candidate.is_file())
}

fn script_binary_path() -> PathBuf {
    let preferred = PathBuf::from("/usr/bin/script");
    if preferred.is_file() {
        preferred
    } else {
        PathBuf::from("script")
    }
}

impl EmuxManager {
    fn wait_for_runtime_ready(
        &self,
        prepared: &EmuxPrepared,
        child: &mut Child,
    ) -> Result<(), String> {
        let deadline = Instant::now() + EMUX_LAUNCH_READY_TIMEOUT;
        while Instant::now() < deadline {
            if prepared.runtime_marker_path().is_file() {
                return Ok(());
            }
            if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                let stdout = fs::read_to_string(prepared.launch_stdout_path()).unwrap_or_default();
                let stderr = fs::read_to_string(prepared.launch_stderr_path()).unwrap_or_default();
                return Err(format!(
                    "launch runtime exited before becoming ready (code: {:?}); stdout: {stdout}; stderr: {stderr}",
                    status.code()
                ));
            }
            sleep(Duration::from_millis(20));
        }
        Err(format!(
            "timed out waiting for EMUX runtime marker {}",
            prepared.runtime_marker_path().display()
        ))
    }

    fn wait_for_output_ready(
        &self,
        prepared: &EmuxPrepared,
        path: PathBuf,
        label: &str,
    ) -> Result<(), String> {
        let timeout = if label.contains("launch") {
            EMUX_LAUNCH_OUTPUT_TIMEOUT
        } else {
            EMUX_OUTPUT_READY_TIMEOUT
        };
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.len() > 0 {
                    return Ok(());
                }
            }
            if !prepared.runtime_marker_path().is_file() && label.contains("launch") {
                return Err(format!(
                    "{} became unavailable before {} was written",
                    prepared.runtime_marker_path().display(),
                    label
                ));
            }
            sleep(Duration::from_millis(20));
        }
        Err(format!(
            "timed out waiting for {} at {}",
            label,
            path.display()
        ))
    }

    fn detach_inflight_launch(&self, prepared: &EmuxPrepared) {
        let _ = self
            .tracker
            .inflight_launches
            .lock()
            .expect("emux launch tracker lock")
            .remove(&prepared.runtime_key());
    }

    fn terminate_inflight_launch(&self, prepared: &EmuxPrepared) -> Result<(), String> {
        let mut result = Ok(());
        if let Some(mut launch) = self
            .tracker
            .inflight_launches
            .lock()
            .expect("emux launch tracker lock")
            .remove(&prepared.runtime_key())
        {
            result = terminate_child_group(&mut launch.child, launch.process_group_id);
        }
        prepared.clear_runtime_marker();
        result
    }
}

fn append_group_cleanup_result(summary: String, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => summary,
        Err(cleanup_error) => {
            format!("{summary}; additionally failed to clean EmuX process group: {cleanup_error}")
        }
    }
}

fn wait_for_wrapper_process_group(path: &Path, child: &mut Child) -> Result<u32, String> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Ok(child.id());
    }

    #[cfg(unix)]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(value) = fs::read_to_string(path) {
                if let Ok(pid) = value.trim().parse::<i32>() {
                    let process_group_id = unsafe { libc::getpgid(pid) };
                    if process_group_id > 0 {
                        return u32::try_from(process_group_id)
                            .map_err(|_| "EmuX process group id overflow".to_string());
                    }
                }
            }
            if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                return Err(format!(
                    "EmuX PTY wrapper exited before publishing its process group (code: {:?})",
                    status.code()
                ));
            }
            sleep(Duration::from_millis(20));
        }
        let summary = format!(
            "timed out waiting for EmuX PTY process-group identity at {}",
            path.display()
        );
        let cleanup = child
            .kill()
            .or_else(|err| is_missing_process(&err).then_some(()).ok_or(err))
            .and_then(|_| child.wait().map(|_| ()))
            .map_err(|err| format!("failed to reap EmuX PTY wrapper: {err}"));
        Err(append_group_cleanup_result(summary, cleanup))
    }
}

fn terminate_child_group(child: &mut Child, process_group_id: u32) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        child.kill().map_err(|err| err.to_string())?;
        child.wait().map_err(|err| err.to_string())?;
        return Ok(());
    }

    signal_child_group(process_group_id, terminate_child_signal())
        .or_else(|err| is_missing_process(&err).then_some(()).ok_or(err))
        .map_err(|err| format!("failed to terminate process group {process_group_id}: {err}"))?;
    for _ in 0..40 {
        let _ = child.try_wait();
        if !child_group_is_running(process_group_id) {
            let _ = child.wait();
            return Ok(());
        }
        sleep(Duration::from_millis(50));
    }
    signal_child_group(process_group_id, kill_child_signal())
        .or_else(|err| is_missing_process(&err).then_some(()).ok_or(err))
        .map_err(|err| format!("failed to kill process group {process_group_id}: {err}"))?;
    for _ in 0..40 {
        let _ = child.try_wait();
        if !child_group_is_running(process_group_id) {
            let _ = child.wait();
            return Ok(());
        }
        sleep(Duration::from_millis(50));
    }
    Err(format!(
        "process group {process_group_id} remained alive after kill"
    ))
}

fn child_group_is_running(process_group_id: u32) -> bool {
    match signal_child_group(process_group_id, 0) {
        Ok(()) => true,
        Err(err) if is_missing_process(&err) => false,
        Err(_) => true,
    }
}

#[cfg(unix)]
fn signal_child_group(process_group_id: u32, signal: i32) -> std::io::Result<()> {
    let process_group_id = i32::try_from(process_group_id).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process group id overflow",
        )
    })?;
    let result = unsafe { libc::kill(-process_group_id, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_child_group(_process_group_id: u32, _signal: i32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-group signaling is unavailable",
    ))
}

#[cfg(unix)]
const fn terminate_child_signal() -> i32 {
    libc::SIGTERM
}

#[cfg(not(unix))]
const fn terminate_child_signal() -> i32 {
    15
}

#[cfg(unix)]
const fn kill_child_signal() -> i32 {
    libc::SIGKILL
}

#[cfg(not(unix))]
const fn kill_child_signal() -> i32 {
    9
}

fn is_missing_process(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        error.kind() == std::io::ErrorKind::NotFound
    }
}

fn make_executable(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn preparation_error(
    run_id: &str,
    reference_device_id: String,
    summary: String,
) -> EmuxPreparationError {
    EmuxPreparationError {
        diagnostic: DiagnosticRecord::new(
            run_id.to_string(),
            DiagnosticPhase::Preparation,
            DiagnosticOwner::BackendDriver,
            DiagnosticClass::PreparationFailed,
            Some(format!("emux:{reference_device_id}")),
            DiagnosticSeverity::High,
            DiagnosticConfidence::High,
            DiagnosticActionability::RequiresBackendFix,
            format!("emux: {summary}"),
            Vec::new(),
            Vec::new(),
            vec![
                "verify the local EMUX recipe directory".to_string(),
                "configure the EMUX reference device and retry".to_string(),
            ],
        ),
    }
}

fn launch_error(
    prepared: &EmuxPrepared,
    summary: String,
    stdout: &str,
    stderr: &str,
    _exit_code: Option<i32>,
) -> EmuxLaunchError {
    EmuxLaunchError {
        diagnostic: DiagnosticRecord::new(
            prepared
                .request
                .run_id
                .clone()
                .unwrap_or_else(|| "emux-launch".to_string()),
            DiagnosticPhase::Launch,
            DiagnosticOwner::BackendDriver,
            DiagnosticClass::LaunchFailed,
            Some("emux-launch".to_string()),
            DiagnosticSeverity::High,
            DiagnosticConfidence::High,
            DiagnosticActionability::Retryable,
            format!("emux: {summary}"),
            Vec::new(),
            Vec::new(),
            vec![
                "inspect launch stdout and stderr".to_string(),
                "verify the EMUX container launcher and selected device".to_string(),
            ],
        ),
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

fn userspace_error(
    prepared: &EmuxPrepared,
    summary: String,
    stdout: &str,
    stderr: &str,
    _exit_code: Option<i32>,
) -> EmuxUserspaceError {
    EmuxUserspaceError {
        diagnostic: DiagnosticRecord::new(
            prepared
                .request
                .run_id
                .clone()
                .unwrap_or_else(|| "emux-userspace".to_string()),
            DiagnosticPhase::UserspaceStartup,
            DiagnosticOwner::BackendDriver,
            DiagnosticClass::GuestUnreachable,
            Some("emux-userspace".to_string()),
            DiagnosticSeverity::High,
            DiagnosticConfidence::High,
            DiagnosticActionability::Retryable,
            format!("emux: {summary}"),
            Vec::new(),
            Vec::new(),
            vec![
                "inspect userspace stdout and stderr".to_string(),
                "verify the EMUX hostfs shell and dialog helper".to_string(),
            ],
        ),
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}
