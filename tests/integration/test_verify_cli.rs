use std::process::Command;

#[test]
fn verify_cli_returns_runtime_verdict() {
    let fixture = format!(
        "{}/../../tests/fixtures/query/runtime/verification",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["verify", "--fixture", &fixture, "--json"])
        .output()
        .expect("fat verify runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"verdict\""));
}
