use std::process::Command;

#[test]
fn fat_cli_shows_identify_launcher_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify-launcher", "--help"])
        .output()
        .expect("fat identify-launcher help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("identify-launcher"),
        "expected help output to mention identify-launcher, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--file"),
        "expected help output to mention --file, got:\n{stdout}"
    );
}

#[test]
fn fat_identify_launcher_runs_on_the_fat_binary() {
    let fat_binary = env!("CARGO_BIN_EXE_fat");
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(fat_binary)
        .args(["identify-launcher", "--file", small_binary])
        .output()
        .expect("fat identify-launcher runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in ["Launcher Identification", "Assessment", "Evidence"] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Next steps"), "got:\n{stdout}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.trim().is_empty(),
        "expected identify-launcher to keep stderr quiet, got:\n{stderr}"
    );
    assert!(
        !stdout.contains("WARN:") && !stdout.contains("INFO:"),
        "expected identify-launcher output to avoid leaking r2 chatter, got:\n{stdout}"
    );
}

#[test]
fn fat_identify_launcher_json_is_evidence_only() {
    let small_binary = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify-launcher", "--file", small_binary, "--json"])
        .output()
        .expect("fat identify-launcher JSON runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(report.get("assessment").is_some());
    assert!(report.get("confidence").is_some());
    assert!(report.get("evidence").is_some());
    assert!(report.get("next_steps").is_none(), "report: {report}");
}
