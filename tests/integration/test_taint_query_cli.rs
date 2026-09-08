use std::process::Command;
use tempfile::tempdir;

#[test]
fn taint_query_cli_reports_constant_sink_arg_for_genie_fixture() {
    let fixture = format!(
        "{}/../../tests/fixtures/query/binary/genie-constant-arg",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "taint-query",
            "--fixture",
            &fixture,
            "--from",
            r#"call[name="getenv" and arg0="QUERY_STRING"].ret"#,
            "--to",
            r#"call[name="popen"].arg0"#,
            "--json",
        ])
        .output()
        .expect("fat taint-query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"path_kind\": \"ConstantSinkArg\""));
}

#[test]
fn taint_query_rejects_macho_targets_honestly() {
    let dir = tempdir().expect("tempdir");
    let macho = dir.path().join("service-launcher");
    std::fs::write(&macho, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).expect("macho");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "taint-query",
            "--file",
            macho.to_str().expect("utf8"),
            "--from",
            r#"call[name="getenv"].ret"#,
            "--to",
            r#"call[name="popen"].arg0"#,
        ])
        .output()
        .expect("fat taint-query runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Mach-O"));
    assert!(stderr.contains("identify-launcher") || stderr.contains("inspect-handoff"));
}
