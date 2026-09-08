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
fn android_discover_ranks_cross_family_leads_and_attaches_siblings() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    write_manifest_apk(&base_apk, "com.example.rank");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            semantic_fixture("ranking-multi.json")
                .to_str()
                .expect("bundle path"),
            "--top-k",
            "2",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 2);
    assert_eq!(report["leads"][0]["family"], "remote-router-gadget");
    assert_eq!(report["leads"][1]["family"], "webview-bridge-uri");
    assert!(report["leads"][0]["sibling_candidates"]
        .as_array()
        .expect("siblings")
        .iter()
        .any(|value| {
            value["family"] == "remote-router-gadget"
                && value["symbol"]
                    .as_str()
                    .map(|symbol| symbol.starts_with("/api/devices/{id}/"))
                    .unwrap_or(false)
        }));
}
