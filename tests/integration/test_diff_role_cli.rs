use std::process::Command;

#[test]
fn fat_cli_shows_diff_role_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["diff", "role", "--help"])
        .output()
        .expect("fat diff role help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff role"), "got:\n{stdout}");
    assert!(stdout.contains("--left"), "got:\n{stdout}");
    assert!(stdout.contains("--right"), "got:\n{stdout}");
}

#[test]
fn fat_diff_role_runs_on_identical_small_binaries() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "diff",
            "role",
            "--left",
            small_binary,
            "--right",
            small_binary,
            "--json",
        ])
        .output()
        .expect("fat diff role runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(report.get("same_role").is_some());
    assert!(report.get("left_assessment").is_some());
    assert!(report.get("shared_runtime_plane_ids").is_some());
    assert!(report.get("next_steps").is_none(), "report: {report}");
}
