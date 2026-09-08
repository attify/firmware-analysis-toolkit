use std::process::Command;

#[test]
fn fat_cli_shows_inspect_handoff_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect-handoff", "--help"])
        .output()
        .expect("fat inspect-handoff help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("inspect-handoff"),
        "expected help output to mention inspect-handoff, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--file"),
        "expected help output to mention --file, got:\n{stdout}"
    );
}

#[test]
fn fat_inspect_handoff_runs_on_a_small_binary() {
    let fat_binary = env!("CARGO_BIN_EXE_fat");
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(fat_binary)
        .args(["inspect-handoff", "--file", small_binary])
        .output()
        .expect("fat inspect-handoff runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Handoff Inspection",
        "Downstream targets",
        "Artifact reality",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Next steps"), "got:\n{stdout}");
}

#[test]
fn fat_inspect_handoff_json_is_evidence_only() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect-handoff", "--file", small_binary, "--json"])
        .output()
        .expect("fat inspect-handoff JSON runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(report.get("downstream_targets").is_some());
    assert!(report.get("artifact_reality").is_some());
    assert!(report.get("next_steps").is_none(), "report: {report}");
}
