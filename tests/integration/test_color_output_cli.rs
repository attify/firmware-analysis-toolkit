use std::process::Command;

#[test]
fn doctor_supports_forced_color_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_COLOR", "always")
        .args(["doctor"])
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{1b}["));
    assert!(stdout.contains("fat doctor"));
}

#[test]
fn taint_query_supports_forced_color_output() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/query/binary/genie-constant-arg"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_COLOR", "always")
        .args([
            "taint-query",
            "--fixture",
            fixture,
            "--from",
            "call[name=\"getenv\" and arg0=\"QUERY_STRING\"].ret",
            "--to",
            "call[name=\"popen\"].arg0",
        ])
        .output()
        .expect("fat taint-query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{1b}["));
    assert!(stdout.contains("ConstantSinkArg"));
}
