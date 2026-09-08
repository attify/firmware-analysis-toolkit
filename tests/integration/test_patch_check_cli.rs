use std::process::Command;

#[test]
fn patch_check_reports_variant_candidates() {
    let fixture = format!(
        "{}/../../tests/fixtures/query/source/invariant-permission",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "patch",
            "check",
            "--fixture",
            &fixture,
            "--find-variants",
            "--mode",
            "deep",
            "--json",
        ])
        .output()
        .expect("fat patch check runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"variant_candidates\""));
    assert!(stdout.contains("\"mode\": \"deep\""));
    assert!(stdout.contains("\"required_call\": \"enforcePermission\""));
    assert!(stdout.contains("\"derived\""));
    assert!(stdout.contains("\"replay\""));
    assert!(stdout.contains("\"variant_leads\""));
    assert!(stdout.contains("\"locality\""));
}
