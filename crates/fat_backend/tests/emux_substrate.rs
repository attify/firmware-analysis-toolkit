use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fat_backend::emux::{EmuxManager, EmuxRequest, EmuxRuntimePhase};

#[test]
fn emux_source_rejects_non_unix_launch_before_spawning() {
    let source = include_str!("../src/emux.rs");
    let launch = source
        .split("pub fn launch_reference_device")
        .nth(1)
        .expect("launch implementation");
    let platform_gate = launch
        .find("if !cfg!(unix)")
        .expect("Unix-only launch gate");
    let spawn = launch
        .find("spawn_emux_wrapper")
        .expect("EmuX wrapper spawn");
    assert!(
        platform_gate < spawn,
        "native Windows must be rejected before any EmuX process is spawned"
    );
}

fn serial_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn emux_launch_establishes_runtime_without_auto_userspace() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-1"),
        )
        .expect("prepare emux");

    let launch_result = manager
        .launch_reference_device(&prepared)
        .expect("launch reference device");
    assert!(launch_result.stdout.contains("launch:"));
    assert!(launch_result.command.contains("run-emux-docker"));
    assert!(launch_result.command.contains("emux-launch-helper.sh"));
    assert!(!launch_result.command.contains(" -lc "));
    assert_eq!(launch_result.exit_code, None);

    let launch_state = prepared.launch_state(&launch_result);
    let runtime_status = prepared.runtime_status(&launch_state, None);

    assert_eq!(runtime_status.backend_id, "emux");
    assert_eq!(runtime_status.reference_device_id, "firmware/TRI227WF");
    assert_eq!(
        runtime_status.runtime_phase,
        EmuxRuntimePhase::LaunchComplete
    );
    assert!(runtime_status.launch_state_present);
    assert!(!runtime_status.userspace_state_present);
}

#[cfg(target_os = "linux")]
#[test]
fn emux_launch_keeps_gnu_script_output_connected() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());

    let wrapper_path = recipe_dir.path().join("run-emux-docker");
    let original_wrapper = fs::read_to_string(&wrapper_path).expect("fake EMUX wrapper");
    let wrapper_body = original_wrapper
        .strip_prefix("#!/bin/sh\n")
        .expect("fake wrapper shebang");
    write_executable(
        wrapper_path,
        &format!(
            "#!/bin/sh\nparent_output=$(readlink /proc/$PPID/fd/1)\n[ \"$parent_output\" != /dev/null ] || exit 73\n{wrapper_body}"
        ),
    );

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-connected-output"),
        )
        .expect("prepare emux");

    manager
        .launch_reference_device(&prepared)
        .expect("GNU script must retain a connected output stream");
}

#[test]
fn emux_launch_tolerates_slow_wrapper_startup_before_runtime_marker() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-slow-launch"),
        )
        .expect("prepare emux");
    let launch_helper_path = prepared
        .container_workspace_dir
        .join("emux-launch-helper.sh");
    let original_launch_helper =
        fs::read_to_string(&launch_helper_path).expect("launch helper contents");
    fs::write(
        &launch_helper_path,
        format!("#!/bin/sh\nsleep 6\n{original_launch_helper}"),
    )
    .expect("rewrite delayed launch helper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&launch_helper_path)
            .expect("launch helper metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&launch_helper_path, permissions).expect("launch helper perms");
    }

    let launch_result = manager
        .launch_reference_device(&prepared)
        .expect("launch reference device");
    assert!(launch_result.stdout.contains("launch:"));
}

#[cfg(unix)]
#[test]
fn emux_launch_timeout_terminates_the_wrapper_process_group() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());
    let descendant_pid_path = recipe_dir.path().join("timeout-descendant.pid");
    write_executable(
        recipe_dir.path().join("run-emux-docker"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > {}\nexec sleep 30\n",
            descendant_pid_path.display()
        ),
    );

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-timeout-cleanup"),
        )
        .expect("prepare emux");
    let error = manager
        .launch_reference_device(&prepared)
        .expect_err("missing runtime marker must fail");
    assert!(error.diagnostic.summary.contains("timed out"));
    let descendant_pid = fs::read_to_string(descendant_pid_path)
        .expect("timeout descendant pid")
        .trim()
        .parse::<u32>()
        .expect("numeric timeout descendant pid");
    assert_process_exits(descendant_pid);
}

#[cfg(unix)]
#[test]
fn emux_launch_refuses_to_exec_when_group_handshake_cannot_be_published() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());
    let launch_marker = recipe_dir.path().join("unexpected-launch.marker");
    write_executable(
        recipe_dir.path().join("run-emux-docker"),
        &format!(
            "#!/bin/sh\ntouch {}\nexec sleep 30\n",
            launch_marker.display()
        ),
    );

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-handshake-failure"),
        )
        .expect("prepare emux");
    let stale_identity = prepared.container_workspace_dir.join("emux-launch.pgid");
    fs::create_dir_all(&stale_identity).expect("block process-group handshake path");
    fs::write(
        stale_identity.join("stale"),
        format!("{}\n", std::process::id()),
    )
    .expect("readable stale process identity");

    let error = manager
        .launch_reference_device(&prepared)
        .expect_err("unwritable process-group handshake must fail closed");
    assert!(error
        .diagnostic
        .summary
        .contains("unremovable stale EmuX process-group identity"));
    assert!(
        !launch_marker.exists(),
        "EmuX wrapper must not execute without a published cleanup identity"
    );
}

#[cfg(unix)]
#[test]
fn emux_userspace_failure_terminates_the_launch_process_group() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());
    write_executable(
        recipe_dir.path().join("files/emux/run/launcher"),
        "#!/bin/sh\nprintf 'launch ready\\n'\nexec sleep 30\n",
    );
    write_executable(
        recipe_dir.path().join("files/emux/run/hostfs-emux.sh"),
        "#!/bin/sh\nprintf 'userspace failed\\n' >&2\nexit 42\n",
    );

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-userspace-cleanup"),
        )
        .expect("prepare emux");
    let launch = manager
        .launch_reference_device(&prepared)
        .expect("launch reference device");
    assert_process_is_running(launch.supervisor_pid);
    manager
        .start_userspace(&prepared, &launch)
        .expect_err("userspace failure must be surfaced");
    assert_process_exits(launch.supervisor_pid);
}

#[cfg(unix)]
#[test]
fn emux_userspace_success_writes_explicit_readiness_marker() {
    let _serial = serial_guard();
    let recipe_dir = make_temp_dir("emux-recipe");
    let workspace_dir = make_temp_dir("emux-workspace");
    write_fake_emux_recipe(recipe_dir.path());
    write_executable(
        recipe_dir
            .path()
            .join("files/emux/firmware/TRI227WF/run-init"),
        "#!/bin/sh\nprintf 'userspace ready\n'\n",
    );

    let manager = EmuxManager::new();
    let prepared = manager
        .prepare(
            EmuxRequest::new(
                recipe_dir.path().to_path_buf(),
                "firmware/TRI227WF",
                workspace_dir.path().to_path_buf(),
            )
            .with_run_id("run-emux-userspace-ready"),
        )
        .expect("prepare emux");
    let launch = manager
        .launch_reference_device(&prepared)
        .expect("launch reference device");
    manager
        .start_userspace(&prepared, &launch)
        .expect("start userspace");

    assert!(
        prepared
            .container_workspace_dir
            .join("emux-userspace.ready")
            .is_file(),
        "a zero-exit userspace bootstrap must publish an explicit readiness witness"
    );
}

fn write_fake_emux_recipe(root: &std::path::Path) {
    fs::create_dir_all(root.join("files/emux/run")).expect("recipe dirs");
    fs::create_dir_all(root.join("files/emux/firmware/TRI227WF/kernel")).expect("device dirs");
    fs::create_dir_all(root.join("files/emux/firmware/DV-MIPSEL/kernel")).expect("device dirs");
    fs::write(
        root.join("files/emux/firmware/devices"),
        "firmware/TRI227WF,qemu-system-arm,versatilepb,,,128M,zImage,TRI227WF,Trivision Camera\nfirmware/DV-MIPSEL,qemu-system-mipsel,malta,,,128M,vmlinux,DV-MIPSEL,Damn Vulnerable MIPS Router (Little Endian)\n",
    )
    .expect("devices file");
    fs::write(
        root.join("files/emux/firmware/TRI227WF/config"),
        "# fake emux config\nid=firmware/TRI227WF\nrootfs=rootfs\ninitcommands=\"/bin/sh\"\n",
    )
    .expect("config");
    fs::write(
        root.join("files/emux/firmware/DV-MIPSEL/config"),
        "# fake emux config\nid=firmware/DV-MIPSEL\nrootfs=rootfs\ninitcommands=\"/bin/sh\"\n",
    )
    .expect("config");
    write_executable(
        root.join("run-emux-docker"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexec /bin/sh -lc \"$cmd\"\n",
    );
    write_executable(
        root.join("emux-docker-shell"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexec /bin/sh -lc \"$cmd\"\n",
    );
    for script in [
        "launcher",
        "hostfs-emux.sh",
        "emuxps",
        "emuxmaps",
        "emuxnetstat",
        "emuxgdb",
        "monitor",
    ] {
        let contents = match script {
            "launcher" => {
                "#!/bin/sh\nprintf 'launch:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nexit 0\n"
            }
            "hostfs-emux.sh" => {
                "#!/bin/sh\nworkspace_dir=$(dirname \"$fundialog\")\nmarker=\"$workspace_dir/emux-runtime.marker\"\n[ -e \"$marker\" ] || { printf 'missing-marker\\n' >&2; exit 42; }\nprintf 'userspace:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nexit 0\n"
            }
            _ => "#!/bin/sh\nexit 0\n",
        };
        write_executable(root.join("files/emux/run").join(script), contents);
    }
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn assert_process_is_running(pid: u32) {
    assert!(process_is_running(pid), "process {pid} should be running");
}

#[cfg(unix)]
fn assert_process_exits(pid: u32) {
    for _ in 0..80 {
        if !process_is_running(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("process {pid} remained alive");
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn make_temp_dir(prefix: &str) -> TempPath {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&path).expect("temp dir");
    TempPath { path }
}

fn write_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}
