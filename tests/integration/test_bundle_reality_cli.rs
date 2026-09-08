use std::process::Command;

#[test]
fn fat_cli_shows_bundle_reality_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bundle-reality", "--help"])
        .output()
        .expect("fat bundle-reality help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bundle-reality"), "got:\n{stdout}");
    assert!(stdout.contains("--file"), "got:\n{stdout}");
    assert!(stdout.contains("runtime-backed"), "got:\n{stdout}");
}

#[test]
fn fat_bundle_reality_runs_on_a_small_binary() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bundle-reality", "--file", small_binary])
        .output()
        .expect("fat bundle-reality runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Bundle Reality"), "got:\n{stdout}");
    assert!(stdout.contains("binary"), "got:\n{stdout}");
    assert!(!stdout.contains("Next steps"), "got:\n{stdout}");
}

#[test]
fn fat_bundle_reality_json_is_evidence_only() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bundle-reality", "--file", small_binary, "--json"])
        .output()
        .expect("fat bundle-reality JSON runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(report.get("items").is_some());
    assert!(report.get("evidence_notes").is_some());
    assert!(report.get("next_steps").is_none(), "report: {report}");
}
