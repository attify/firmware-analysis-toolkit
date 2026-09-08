use std::fs;
use std::process::Command;

use sha2::{Digest, Sha256};

const VALID_PACK_YAML: &str = r#"
id: example/camera
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: app_init.sh
caveats:
  - no camera ISP fidelity
"#;

#[test]
fn rehost_profiles_validate_accepts_valid_pack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pack = dir.path().join("example-camera.yaml");
    fs::write(
        &pack,
        r#"
id: example/camera
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: app_init.sh
caveats:
  - no camera ISP fidelity
"#,
    )
    .expect("write pack");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["rehost", "profiles", "validate"])
        .arg(&pack)
        .output()
        .expect("fat runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("valid rehosting pack: example/camera"),
        "{stdout}"
    );
}

#[test]
fn rehost_profiles_validate_rejects_overbroad_pack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pack = dir.path().join("generic.yaml");
    fs::write(
        &pack,
        r#"
id: generic/mipsel
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
validators:
  - goal: shell-access
    kind: surface-ready
"#,
    )
    .expect("write pack");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["rehost", "profiles", "validate"])
        .arg(&pack)
        .output()
        .expect("fat runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("matcher-overbroad"), "{stderr}");
}

#[test]
fn rehost_profiles_show_emits_json_pack_and_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pack = dir.path().join("example-camera.yaml");
    fs::write(
        &pack,
        r#"
id: example/camera
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: app_init.sh
caveats:
  - no camera ISP fidelity
"#,
    )
    .expect("write pack");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["rehost", "profiles", "show", "--json"])
        .arg(&pack)
        .output()
        .expect("fat runs");

    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json output from show");
    assert_eq!(value["pack"]["id"], "example/camera");
    assert_eq!(value["validation"]["valid"], true);
}

fn write_project(project: &std::path::Path, firmware: &[u8]) -> std::path::PathBuf {
    let rootfs = project.join("work/rootfs");
    fs::create_dir_all(project.join("analysis")).unwrap();
    fs::create_dir_all(project.join("input")).unwrap();
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(project.join("analysis/signals.txt"), "arch:armel\n").unwrap();
    fs::write(project.join("input/firmware.bin"), firmware).unwrap();
    fs::create_dir_all(project.join("work")).unwrap();
    fs::write(
        project.join("work/extraction-manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "rootfs_path": rootfs,
            "kernel_paths": [],
            "file_count": 0
        }))
        .unwrap(),
    )
    .unwrap();
    project.join("work/rootfs")
}

#[test]
fn rehost_match_reports_invalid_packs_instead_of_silently_skipping_them() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    write_project(&project, b"firmware");
    let packs = temp.path().join("packs");
    fs::create_dir_all(&packs).unwrap();
    fs::write(
        packs.join("invalid.yaml"),
        "id: invalid/pack\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: armel\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["rehost", "match"])
        .arg(&project)
        .args(["--packs-dir"])
        .arg(&packs)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid rehosting pack"), "{stderr}");
    assert!(stderr.contains("missing-validators"), "{stderr}");
}

#[test]
fn rehost_match_consumes_firmware_hash_and_declared_target_paths() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let firmware = b"exact firmware bytes";
    let rootfs = write_project(&project, firmware);
    fs::create_dir_all(rootfs.join("etc/init.d")).unwrap();
    fs::write(rootfs.join("etc/init.d/rcS"), "#!/bin/sh\n").unwrap();
    let digest = format!("{:x}", Sha256::digest(firmware));
    let packs = temp.path().join("packs");
    fs::create_dir_all(&packs).unwrap();
    fs::write(
        packs.join("exact.yaml"),
        format!(
            r#"id: exact/device
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  firmware_sha256: ["{digest}"]
  paths: ["/etc/init.d/rcS"]
validators:
  - goal: init-handoff
    kind: file-exists
    path: /etc/init.d/rcS
caveats: ["test pack"]
"#
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["rehost", "match"])
        .arg(&project)
        .args(["--packs-dir"])
        .arg(&packs)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "exact/device")
        .unwrap();
    assert_eq!(row["is_match"], true);
    assert_eq!(row["sha_exact"], true);
    assert_eq!(row["matched_paths"][0], "/etc/init.d/rcS");
}

/// FAT used to always search a bundled `profiles/rehosting` tree, so a pack it
/// shipped could match and be applied without the operator choosing anything.
/// Discovery is now explicit-source-only: with no `--packs-dir` and no
/// `FAT_REHOSTING_PACKS`, nothing is found — including a pack left behind in a
/// data directory by an older install.
#[test]
fn no_selected_source_discovers_no_packs_even_with_a_populated_data_directory() {
    let data_root = tempfile::tempdir().expect("data root");
    let stale = data_root.path().join("profiles").join("rehosting");
    fs::create_dir_all(&stale).expect("stale pack dir");
    fs::write(stale.join("leftover.yaml"), VALID_PACK_YAML).expect("stale pack");

    let project = tempfile::tempdir().expect("project dir");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_DATA_DIR", data_root.path())
        .env_remove("FAT_REHOSTING_PACKS")
        .args([
            "rehost",
            "match",
            "--project",
            project.path().to_str().expect("project path"),
        ])
        .output()
        .expect("fat rehost match runs");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("leftover"),
        "a pack in the data directory must not be discovered without an explicit source: {combined}"
    );
}

/// The same project does find a pack once a source is named, which keeps the
/// test above from passing merely because discovery is broken.
#[test]
fn an_explicitly_named_source_discovers_its_packs() {
    let packs = tempfile::tempdir().expect("packs dir");
    fs::write(packs.path().join("example-camera.yaml"), VALID_PACK_YAML).expect("pack");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "rehost",
            "profiles",
            "validate",
            packs
                .path()
                .join("example-camera.yaml")
                .to_str()
                .expect("pack path"),
        ])
        .output()
        .expect("fat rehost profiles validate runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("example/camera"), "{stdout}");
}
