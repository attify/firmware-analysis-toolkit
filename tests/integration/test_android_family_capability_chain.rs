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
fn capability_chain_confused_deputy_emits_delegated_identity_lead() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    write_manifest_apk(&base_apk, "com.example.chain");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            semantic_fixture("capability-chain-positive.json")
                .to_str()
                .expect("bundle path"),
            "--family",
            "capability-chain-confused-deputy",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 1);
    assert_eq!(
        report["leads"][0]["family"],
        "capability-chain-confused-deputy"
    );
    assert!(report["leads"][0]["provenance_summary"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(report["leads"][0]["score_trace"]["family_pack_hits"]
        .as_array()
        .expect("pack hits")
        .iter()
        .any(|value| value == "path-composition-owned-by-capability-chain"));
}

#[test]
fn capability_chain_confused_deputy_suppresses_immutable_chain() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    write_manifest_apk(&base_apk, "com.example.chain.safe");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            semantic_fixture("capability-chain-negative.json")
                .to_str()
                .expect("bundle path"),
            "--family",
            "capability-chain-confused-deputy",
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["lead_count"], 0);
}
