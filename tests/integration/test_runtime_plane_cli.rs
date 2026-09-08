use std::process::Command;

#[test]
fn fat_cli_shows_runtime_plane_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["runtime-plane", "--help"])
        .output()
        .expect("fat runtime-plane help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("runtime-plane"), "got:\n{stdout}");
    assert!(stdout.contains("--file"), "got:\n{stdout}");
    assert!(stdout.contains("runtime-backed"), "got:\n{stdout}");
}

#[test]
fn fat_runtime_plane_runs_on_a_small_binary() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["runtime-plane", "--file", small_binary])
        .output()
        .expect("fat runtime-plane runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Runtime Plane"), "got:\n{stdout}");
    assert!(stdout.contains("binary"), "got:\n{stdout}");
    assert!(!stdout.contains("Next steps"), "got:\n{stdout}");
}

#[test]
fn fat_runtime_plane_json_is_evidence_only() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["runtime-plane", "--file", small_binary, "--json"])
        .output()
        .expect("fat runtime-plane JSON runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(report.get("objects").is_some());
    assert!(report.get("evidence_notes").is_some());
    assert!(report.get("next_steps").is_none(), "report: {report}");
}
