use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn fat_cli_preserves_failed_launch_semantics() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );
    make_executable(path_dir.path().join("firmae"), "#!/bin/sh\nexit 0\n");

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
            "--session-id",
            "phase2-failed-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let emulate_stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&emulate_stdout);
    let session_id = parsed.get("session").expect("session id");
    assert_eq!(
        parsed.get("session status").map(String::as_str),
        Some("degraded")
    );
    assert_eq!(parsed.get("run status").map(String::as_str), Some("failed"));

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
    assert!(status_stdout.contains("run status: failed"));
    assert!(!status_stdout.contains("run status: degraded-completed"));

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
    assert!(suggest_stdout.contains("suggestion: Lead failure diagnostic:"));
    assert!(suggest_stdout.contains("suggestion: Inspect launch diagnostics in fat info"));
    assert!(suggest_stdout.contains("fat info"));
    assert!(suggest_stdout.contains("suggestion: Re-run preflight before retry"));
    assert!(suggest_stdout.contains("fat preflight"));
    assert!(!suggest_stdout.contains("Retry with available backend: firmae"));

    let suggest_json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "debug",
            "suggest",
            "--project",
            project_dir.to_str().expect("project path"),
            "--json",
        ])
        .output()
        .expect("fat debug suggest --json runs");
    assert!(
        suggest_json_output.status.success(),
        "{suggest_json_output:?}"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&suggest_json_output.stdout).expect("suggestion report JSON");
    assert!(report
        .get("suggestions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|suggestions| suggestions
            .iter()
            .any(|suggestion| suggestion.get("command").is_some())));
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
