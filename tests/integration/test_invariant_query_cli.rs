use std::process::Command;

#[test]
fn invariant_query_reports_violations_from_source_fixture() {
    let fixture = format!(
        "{}/../../tests/fixtures/query/source/invariant-permission",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "invariant",
            "query",
            "--fixture",
            &fixture,
            "--rule",
            "Every override binder method must call enforcePermission()",
            "--mode",
            "triage",
            "--json",
        ])
        .output()
        .expect("fat invariant query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"violating\""));
    assert!(stdout.contains("\"mode\": \"triage\""), "{stdout}");
}
