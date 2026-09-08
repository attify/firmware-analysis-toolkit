use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use fat_core::database::ProjectDb;
use fat_core::project::{Project, ProjectStatus};
use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::derive_target_id;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn fat_extract_analyze_and_info_write_target_scoped_records() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _demo.bin.extracted
touch _demo.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract"
  mkdir -p "$extract_dir"
  touch "$extract_dir/image.squashfs_v4_le"
fi
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  dest="$2"
  mkdir -p "$dest/bin"
  touch "$dest/bin/busybox"
fi
exit 0
"#,
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");
    assert!(extract_output.status.success(), "{extract_output:?}");

    let analyze_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze_output.status.success(), "{analyze_output:?}");

    let info_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["info", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat info runs");
    assert!(info_output.status.success(), "{info_output:?}");

    let stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(stdout.contains("target: demo"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "target id: {}",
            derive_target_id("demo", "demo.bin")
        )),
        "{stdout}"
    );
    assert!(stdout.contains("target artifacts:"), "{stdout}");
    assert!(stdout.contains("analysis artifacts:"), "{stdout}");

    let target_id = derive_target_id("demo", "demo.bin");
    let target_artifacts_dir = project_dir
        .join("targets")
        .join(&target_id)
        .join("artifacts");
    assert!(target_artifacts_dir.is_dir(), "{target_artifacts_dir:?}");
    assert!(
        fs::read_dir(&target_artifacts_dir)
            .expect("target artifacts dir")
            .count()
            > 0
    );

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let indexed_artifacts = store.read_artifact_index().expect("artifact index");
    assert!(indexed_artifacts.iter().any(|artifact| {
        artifact.target_id == target_id
            && artifact.session_id.is_empty()
            && artifact.run_id.is_empty()
            && matches!(artifact.kind, fat_core::artifacts::ArtifactKind::Analysis)
    }));

    assert!(project_dir.join("analysis").join("summary.txt").exists());
    assert!(project_dir
        .join("analysis")
        .join("bootloader.json")
        .exists());
}

#[test]
fn fat_info_fails_honestly_when_target_record_is_missing() {
    let project_root = tempdir().expect("project root");
    let project_dir = project_root.path().join("demo");
    fs::create_dir_all(&project_dir).expect("project dir");

    let db = ProjectDb::open(&project_dir).expect("project db");
    db.save(&Project {
        name: "demo".to_string(),
        firmware_name: "demo.bin".to_string(),
        status: ProjectStatus::Created,
        fingerprint: None,
    })
    .expect("save project");

    let info_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["info", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat info runs");

    assert!(!info_output.status.success(), "{info_output:?}");
    let stderr = String::from_utf8_lossy(&info_output.stderr);
    assert!(
        stderr.contains("target record missing for demo"),
        "{stderr}"
    );
}

#[test]
fn fat_info_json_emits_project_target_and_count_summary() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _demo.bin.extracted
touch _demo.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract"
  mkdir -p "$extract_dir"
  touch "$extract_dir/image.squashfs_v4_le"
fi
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  dest="$2"
  mkdir -p "$dest/bin"
  touch "$dest/bin/busybox"
fi
exit 0
"#,
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");
    assert!(extract_output.status.success(), "{extract_output:?}");

    let analyze_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze_output.status.success(), "{analyze_output:?}");

    let info_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["info", project_dir.to_str().expect("project dir"), "--json"])
        .output()
        .expect("fat info --json runs");
    assert!(info_output.status.success(), "{info_output:?}");

    let summary: Value = serde_json::from_slice(&info_output.stdout).expect("info json");
    assert_eq!(summary["project"]["name"], "demo");
    assert_eq!(summary["target"]["display_name"], "demo");
    assert_eq!(
        summary["target"]["target_id"],
        derive_target_id("demo", "demo.bin")
    );
    assert!(summary["counts"]["target_artifacts"].as_u64().unwrap_or(0) > 0);
    assert!(
        summary["counts"]["analysis_artifacts"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(summary["latest_session"].is_null() || summary["latest_session"].is_object());
    assert!(summary["active_runtime"].is_null() || summary["active_runtime"].is_object());
}

#[test]
fn fat_analyze_emits_service_signal_for_rootfs_web_server_binary() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("camera.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _camera.bin.extracted/jffs2-root/bin
mkdir -p _camera.bin.extracted/jffs2-root/etc_ro/web/cgi
touch _camera.bin.extracted/jffs2-root/bin/alphapd
touch _camera.bin.extracted/jffs2-root/bin/busybox
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
echo "unblob should not run when binwalk already recovered a rootfs" >&2
exit 9
"#,
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("camera");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");
    assert!(extract_output.status.success(), "{extract_output:?}");

    let analyze_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze_output.status.success(), "{analyze_output:?}");

    let signals =
        fs::read_to_string(project_dir.join("analysis").join("signals.txt")).expect("signals");
    assert!(signals.contains("service:/bin/alphapd"), "{signals}");
}

fn write_script(path: &std::path::Path, script: &str) {
    fs::write(path, script).expect("script written");

    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("permissions");
}
