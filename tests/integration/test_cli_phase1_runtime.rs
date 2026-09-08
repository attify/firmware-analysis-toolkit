use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

use fat_core::rehosting::{AttemptRecord, ReadinessReport, TargetExecutionProfile};
use fat_core::runtime_store::RuntimeStore;

#[test]
fn fat_cli_runs_and_inspects_the_first_real_phase1_runtime_path() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    make_executable(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'phase1-launch-ok\\n'\nexit 0\n",
    );
    let ssh_args_log = path_dir.path().join("ssh-args.log");
    make_executable(
        path_dir.path().join("ssh"),
        "#!/bin/sh\nprintf '%s\n' \"$@\" > \"$FAT_TEST_SSH_ARGS\"\nport=''\nif [ \"$1\" = \"-p\" ]; then port=\"$2\"; shift 2; fi\ntarget=\"$1\"; shift\nprintf 'ssh-port:%s\\n' \"$port\"\nprintf 'ssh-target:%s\\n' \"$target\"\nexit 0\n",
    );
    let nc_args_log = path_dir.path().join("nc-args.log");
    make_executable(
        path_dir.path().join("nc"),
        "#!/bin/sh\nprintf '%s\n' \"$@\" > \"$FAT_TEST_NC_ARGS\"\nhost=\"$1\"; port=\"$2\"\ninput=\"$(cat)\"\nprintf 'nc-host:%s\\n' \"$host\"\nprintf 'nc-port:%s\\n' \"$port\"\nprintf 'monitor-command:%s\\n' \"$input\"\nexit 0\n",
    );
    let gdb_args_log = path_dir.path().join("gdb-args.log");
    make_executable(
        path_dir.path().join("gdb"),
        "#!/bin/sh\nprintf '%s\n' \"$@\" > \"$FAT_TEST_GDB_ARGS\"\nprintf 'gdb-args:%s\\n' \"$*\"\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--port",
            "8080",
            "--session-id",
            "phase1-live-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let emulate_stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&emulate_stdout);
    let session_id = parsed.get("session").expect("session id");
    assert_eq!(
        parsed.get("backend").map(String::as_str),
        Some("qemu-direct")
    );
    assert_eq!(
        parsed.get("run-status").map(String::as_str),
        Some("running")
    );
    assert_eq!(
        parsed.get("session status").map(String::as_str),
        Some("active")
    );
    assert_eq!(
        parsed.get("substrate").map(String::as_str),
        Some("native-host")
    );
    assert_eq!(
        parsed.get("active endpoints").map(String::as_str),
        Some("4")
    );

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = fat_core::targets::derive_target_id("demo", "demo.bin");
    let target_profile = read_single_json_record::<TargetExecutionProfile>(
        &store
            .target_path(&target_id)
            .parent()
            .expect("target parent")
            .join("rehosting")
            .join("profiles"),
    );
    assert_eq!(target_profile.project_id, "demo");
    assert_eq!(target_profile.target_id, target_id);

    let attempt = read_single_json_record::<AttemptRecord>(
        &store
            .run_path(session_id, parsed.get("run").expect("run id"))
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("attempts"),
    );
    assert_eq!(attempt.session_id, session_id.as_str());
    assert_eq!(attempt.target_id, target_id);

    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, parsed.get("run").expect("run id"))
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert_eq!(readiness.session_id, session_id.as_str());
    assert_eq!(readiness.target_id, target_id);
    assert!(!readiness.surfaces.is_empty());

    let status_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
            "--status",
        ])
        .output()
        .expect("fat emulate --status runs");

    assert!(status_output.status.success(), "{status_output:?}");
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_stdout.contains("endpoint shell: ssh://127.0.0.1:10022"));
    assert!(status_stdout.contains("endpoint debugger: tcp://127.0.0.1:10023"));
    assert!(status_stdout.contains("endpoint monitor: tcp://127.0.0.1:10024"));
    assert!(status_stdout.contains("endpoint port-8080: 127.0.0.1:8080"));

    let info_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["info", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat info runs");

    assert!(info_output.status.success(), "{info_output:?}");
    let info_stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(info_stdout.contains("active session:"));
    assert!(info_stdout.contains("active run:"));
    assert!(info_stdout.contains("active backend: qemu-direct"));
    assert!(info_stdout.contains("active substrate: native-host"));
    assert!(info_stdout.contains("active logical substrate: service"));
    assert!(info_stdout.contains("active substrate preference: auto"));
    assert!(info_stdout.contains("active session status: active"));
    assert!(info_stdout.contains("active run status: running"));
    assert!(info_stdout.contains("active endpoints: 4"));
    assert!(info_stdout.contains("active readiness summary: launch completed with ready surfaces"));

    let debug_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "debug",
            "surfaces",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat debug surfaces runs");

    assert!(debug_output.status.success(), "{debug_output:?}");
    let debug_stdout = String::from_utf8_lossy(&debug_output.stdout);
    assert!(debug_stdout.contains("surface count: 4"));
    assert!(debug_stdout.contains("surface shell [shell] state=ready: ssh://127.0.0.1:10022"));
    assert!(debug_stdout.contains("surface debugger [debugger] state=ready: tcp://127.0.0.1:10023"));
    assert!(debug_stdout.contains("surface monitor [monitor] state=ready: tcp://127.0.0.1:10024"));
    assert!(
        debug_stdout.contains("surface port-8080 [forwarded-port] state=validated: 127.0.0.1:8080")
    );
    assert!(debug_stdout.contains("capability: observe-supported"));
    assert!(debug_stdout.contains("capability: diagnostics-supported"));

    let suggest_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "debug",
            "suggest",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat debug suggest runs");

    assert!(suggest_output.status.success(), "{suggest_output:?}");
    let suggest_stdout = String::from_utf8_lossy(&suggest_output.stdout);
    assert!(suggest_stdout.contains("suggestion: Prefer shell attach first"));
    assert!(suggest_stdout.contains("fat observe net --project"));

    let observe_net_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "observe",
            "net",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat observe net runs");

    assert!(
        observe_net_output.status.success(),
        "{observe_net_output:?}"
    );
    let observe_net_stdout = String::from_utf8_lossy(&observe_net_output.stdout);
    assert!(observe_net_stdout.contains("network endpoint count: 4"));
    assert!(observe_net_stdout.contains("network shell [shell] state=ready: ssh://127.0.0.1:10022"));
    assert!(observe_net_stdout
        .contains("network debugger [debugger] state=ready: tcp://127.0.0.1:10023"));
    assert!(observe_net_stdout
        .contains("network port-8080 [forwarded-port] state=validated: 127.0.0.1:8080"));

    let debug_shell_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_SSH_ARGS", &ssh_args_log)
        .args([
            "debug",
            "shell",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat debug shell runs");

    assert!(
        debug_shell_output.status.success(),
        "{debug_shell_output:?}"
    );
    let debug_shell_stdout = String::from_utf8_lossy(&debug_shell_output.stdout);
    assert!(debug_shell_stdout.contains("ssh-port:10022"));
    assert!(debug_shell_stdout.contains("ssh-target:root@127.0.0.1"));
    let ssh_args = std::fs::read_to_string(&ssh_args_log).expect("ssh args log");
    assert!(ssh_args.contains("-p"));
    assert!(ssh_args.contains("10022"));
    assert!(ssh_args.contains("root@127.0.0.1"));

    let debug_monitor_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_NC_ARGS", &nc_args_log)
        .args([
            "debug",
            "monitor",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat debug monitor runs");

    assert!(
        debug_monitor_output.status.success(),
        "{debug_monitor_output:?}"
    );
    let debug_monitor_stdout = String::from_utf8_lossy(&debug_monitor_output.stdout);
    assert!(debug_monitor_stdout.contains("nc-host:127.0.0.1"));
    assert!(debug_monitor_stdout.contains("nc-port:10024"));
    let nc_args = std::fs::read_to_string(&nc_args_log).expect("nc args log");
    assert!(nc_args.contains("127.0.0.1"));
    assert!(nc_args.contains("10024"));

    let debug_gdb_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_GDB_ARGS", &gdb_args_log)
        .args([
            "debug",
            "gdb",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat debug gdb runs");

    assert!(debug_gdb_output.status.success(), "{debug_gdb_output:?}");
    let debug_gdb_stdout = String::from_utf8_lossy(&debug_gdb_output.stdout);
    assert!(debug_gdb_stdout.contains("gdb-args:"));
    let gdb_args = std::fs::read_to_string(&gdb_args_log).expect("gdb args log");
    assert!(gdb_args.contains("--quiet"));
    assert!(gdb_args.contains("target remote 127.0.0.1:10023"));
}

fn parse_keyed_output(stdout: &str) -> HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn make_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}

fn read_single_json_record<T>(dir: &std::path::Path) -> T
where
    T: serde::de::DeserializeOwned,
{
    let mut entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"));
    let path = entries
        .next()
        .unwrap_or_else(|| panic!("no json records found in {}", dir.display()));
    assert!(
        entries.next().is_none(),
        "expected exactly one json record in {}",
        dir.display()
    );
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}
