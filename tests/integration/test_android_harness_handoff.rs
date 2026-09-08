use std::path::Path;
use std::process::Command;

use fat_query::target_lanes::{load_target_lane_manifest, LaneAdapterKind, PreflightCheckKind};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn write_manifest_apk(path: &Path, package_name: &str) {
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

fn semantic_fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/android/semantic")
        .join(name)
        .display()
        .to_string()
}

#[test]
fn android_discover_writes_router_runtime_manifest() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let runtime_manifest = dir.path().join("router-runtime.json");
    write_manifest_apk(&base_apk, "com.example.app");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            &semantic_fixture("router-mini.json"),
            "--family",
            "remote-router-gadget",
            "--runtime-manifest-out",
            runtime_manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let manifest = load_target_lane_manifest(&runtime_manifest).expect("runtime manifest");
    assert_eq!(manifest.lanes.len(), 1);
    let lane = &manifest.lanes[0];
    assert_eq!(lane.family_allowlist, vec!["remote-router-gadget"]);
    assert_eq!(
        lane.parsed_adapter_kind(),
        Some(LaneAdapterKind::AndroidAdbIcc)
    );
    assert_eq!(lane.binary_or_driver, "python3");
    assert!(lane
        .launcher_command
        .iter()
        .any(|arg| arg.ends_with("adb_icc_runner.py")));
    assert!(lane
        .proof_class_allowlist
        .iter()
        .any(|proof| proof == "internal-navigation"));
    assert!(lane
        .preflight_checks
        .iter()
        .any(|check| check.parsed_kind() == Some(PreflightCheckKind::CommandAvailable)));
    assert!(lane
        .preflight_checks
        .iter()
        .any(|check| check.parsed_kind() == Some(PreflightCheckKind::AdbDevice)));
    assert!(lane
        .preflight_checks
        .iter()
        .any(|check| check.parsed_kind() == Some(PreflightCheckKind::AdbPackageInstalled)));
}

#[test]
fn android_discover_writes_webview_runtime_manifest() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let runtime_manifest = dir.path().join("webview-runtime.json");
    write_manifest_apk(&base_apk, "com.example.webview");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            &semantic_fixture("webview-positive.json"),
            "--family",
            "webview-bridge-uri",
            "--runtime-manifest-out",
            runtime_manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let manifest = load_target_lane_manifest(&runtime_manifest).expect("runtime manifest");
    assert_eq!(manifest.lanes.len(), 1);
    let lane = &manifest.lanes[0];
    assert_eq!(
        lane.parsed_adapter_kind(),
        Some(LaneAdapterKind::AndroidInstrumentationWebview)
    );
    assert!(lane
        .launcher_command
        .iter()
        .any(|arg| arg.ends_with("webview_runner.py")));
    assert!(lane
        .proof_class_allowlist
        .iter()
        .any(|proof| proof == "bridge-reachable-from-uri"));
}

#[test]
fn android_discover_writes_binder_native_runtime_manifest() {
    let dir = tempdir().expect("tempdir");
    let base_apk = dir.path().join("base.apk");
    let runtime_manifest = dir.path().join("native-runtime.json");
    write_manifest_apk(&base_apk, "com.example.native");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "android",
            "discover",
            "--apk",
            base_apk.to_str().expect("apk path"),
            "--semantic-bundle",
            &semantic_fixture("binder-native-positive.json"),
            "--family",
            "binder-native-boundary",
            "--runtime-manifest-out",
            runtime_manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("android discover runs");

    assert!(output.status.success(), "{output:?}");
    let manifest = load_target_lane_manifest(&runtime_manifest).expect("runtime manifest");
    assert_eq!(manifest.lanes.len(), 1);
    let lane = &manifest.lanes[0];
    assert_eq!(
        lane.parsed_adapter_kind(),
        Some(LaneAdapterKind::AndroidInstrumentationNative)
    );
    assert!(lane
        .launcher_command
        .iter()
        .any(|arg| arg.ends_with("native_runner.py")));
    assert!(lane
        .proof_class_allowlist
        .iter()
        .any(|proof| proof == "native-parser-reached"));
}
