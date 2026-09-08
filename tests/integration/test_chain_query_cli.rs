use std::process::Command;

#[test]
fn chain_query_reports_multi_step_channel_path() {
    let fixture = format!(
        "{}/../../tests/fixtures/query/binary/httpd-cross-channel",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "chain",
            "query",
            "--fixture",
            &fixture,
            "--goal",
            "preauth-rce",
            "--json",
        ])
        .output()
        .expect("fat chain query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"steps\""));
}
