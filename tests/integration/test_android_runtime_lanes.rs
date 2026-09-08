use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn runner_script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/discovery/android")
        .join(name)
}

fn write_fake_adb(bin_dir: &Path) -> PathBuf {
    let adb_path = bin_dir.join("adb");
    let script = r#"#!/bin/sh
set -eu
args="$*"
if echo "$args" | grep -q "get-state"; then
  echo "device"
  exit 0
fi
if echo "$args" | grep -q "shell pm path"; then
  echo "package:/data/app/base.apk"
  exit 0
fi
if echo "$args" | grep -q "logcat -d"; then
  echo "04-06 12:00:00.000 I FAT: synthetic logcat"
  exit 0
fi
if echo "$args" | grep -q "logcat -c"; then
  exit 0
fi
if echo "$args" | grep -q "install-multiple"; then
  echo "Success"
  exit 0
fi
if echo "$args" | grep -q " install "; then
  echo "Success"
  exit 0
fi
if echo "$args" | grep -q "shell am start"; then
  echo "Starting: Intent"
  exit 0
fi
if echo "$args" | grep -q "shell am instrument"; then
  echo "INSTRUMENTATION_STATUS: class=com.example.Runner"
  echo "INSTRUMENTATION_CODE: -1"
  exit 0
fi
if echo "$args" | grep -q "shell am force-stop"; then
  exit 0
fi
echo "unsupported adb invocation: $args" 1>&2
exit 1
"#;
    fs::write(&adb_path, script).expect("write fake adb");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&adb_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&adb_path, perms).expect("chmod");
    }
    adb_path
}

fn write_fake_apk(path: &Path) {
    fs::write(path, b"fake-apk").expect("write fake apk");
}

#[test]
fn android_icc_runner_persists_runner_and_logcat_artifacts() {
    let dir = tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let artifact_dir = dir.path().join("icc-artifacts");
    let apk_path = dir.path().join("base.apk");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_fake_adb(&bin_dir);
    write_fake_apk(&apk_path);

    let output = Command::new("python3")
        .arg(runner_script("adb_icc_runner.py"))
        .args([
            "--package",
            "com.example.app",
            "--apk",
            apk_path.to_str().expect("apk"),
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir"),
            "--action",
            "android.intent.action.VIEW",
            "--data-uri",
            "route://deeplink",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("ANDROID_SERIAL", "emulator-5554")
        .output()
        .expect("icc runner");

    assert!(output.status.success(), "{output:?}");
    assert!(artifact_dir.join("runner.json").exists());
    assert!(artifact_dir.join("logcat.txt").exists());
    let runner: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("runner.json")).expect("read runner"))
            .expect("runner json");
    assert_eq!(runner["status"], "ok");
    assert_eq!(runner["adapter_kind"], "android-adb-icc");
}

#[test]
fn android_webview_runner_persists_runner_and_logcat_artifacts() {
    let dir = tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let artifact_dir = dir.path().join("webview-artifacts");
    let apk_path = dir.path().join("base.apk");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_fake_adb(&bin_dir);
    write_fake_apk(&apk_path);

    let output = Command::new("python3")
        .arg(runner_script("webview_runner.py"))
        .args([
            "--package",
            "com.example.webview",
            "--apk",
            apk_path.to_str().expect("apk"),
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir"),
            "--entry-url",
            "https://attacker.example/bridge.html",
            "--runner",
            "com.example.webview.test/androidx.test.runner.AndroidJUnitRunner",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("ANDROID_SERIAL", "emulator-5554")
        .output()
        .expect("webview runner");

    assert!(output.status.success(), "{output:?}");
    assert!(artifact_dir.join("runner.json").exists());
    assert!(artifact_dir.join("logcat.txt").exists());
    let runner: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("runner.json")).expect("read runner"))
            .expect("runner json");
    assert_eq!(runner["status"], "ok");
    assert_eq!(runner["adapter_kind"], "android-instrumentation-webview");
}

#[test]
fn android_native_runner_persists_runner_and_logcat_artifacts() {
    let dir = tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let artifact_dir = dir.path().join("native-artifacts");
    let apk_path = dir.path().join("base.apk");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    write_fake_adb(&bin_dir);
    write_fake_apk(&apk_path);

    let output = Command::new("python3")
        .arg(runner_script("native_runner.py"))
        .args([
            "--package",
            "com.example.native",
            "--apk",
            apk_path.to_str().expect("apk"),
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir"),
            "--runner",
            "com.example.native.test/androidx.test.runner.AndroidJUnitRunner",
            "--binder-transaction",
            "TRANSACTION_parseBlob",
            "--symbol",
            "com.example.NativeBridge.parseBlob",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("ANDROID_SERIAL", "emulator-5554")
        .output()
        .expect("native runner");

    assert!(output.status.success(), "{output:?}");
    assert!(artifact_dir.join("runner.json").exists());
    assert!(artifact_dir.join("logcat.txt").exists());
    let runner: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("runner.json")).expect("read runner"))
            .expect("runner json");
    assert_eq!(runner["status"], "ok");
    assert_eq!(runner["adapter_kind"], "android-instrumentation-native");
}
