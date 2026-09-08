use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn write_manifest_apk(path: &std::path::Path, package_name: &str) {
    let file = std::fs::File::create(path).expect("create apk");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = format!(r#"<manifest package="{package_name}"><application /></manifest>"#);
    zip.start_file("AndroidManifest.xml", opts)
        .expect("manifest entry");
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes()).expect("manifest bytes");
    zip.start_file("classes.dex", opts).expect("classes.dex");
    zip.write_all(b"dex").expect("dex bytes");
    zip.finish().expect("finish zip");
}

fn semantic_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/android/semantic")
        .join(name)
}

#[test]
fn webview_bridge_uri_emits_lead_for_remote_uri_plus_bridge() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    write_manifest_apk(&base_apk, "com.example.webview");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            semantic_fixture("webview-positive.json")
                .to_str()
                .expect("bundle path"),
            "--family",
            "webview-bridge-uri",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 1);
    assert_eq!(report["leads"][0]["family"], "webview-bridge-uri");
    assert!(report["leads"][0]["provenance_summary"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(report["leads"][0]["why_matched"]
        .as_array()
        .expect("why matched")
        .iter()
        .any(|value| value == "remote URI reaches WebView bridge boundary with weak validation"));
}

#[test]
fn webview_bridge_uri_suppresses_strongly_validated_webview() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    write_manifest_apk(&base_apk, "com.example.webview.safe");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            semantic_fixture("webview-negative.json")
                .to_str()
                .expect("bundle path"),
            "--family",
            "webview-bridge-uri",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 0);
}
