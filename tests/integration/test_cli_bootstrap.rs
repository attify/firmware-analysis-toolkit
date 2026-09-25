use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::derive_target_id;
use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn fat_cli_shows_top_level_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg("--help")
        .output()
        .expect("fat help runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "new",
        "extract",
        "analyze",
        "preflight",
        "emulate",
        "diff",
        "bootloader",
    ] {
        assert!(
            stdout.contains(flag),
            "expected help output to mention {flag}, got:\n{stdout}"
        );
    }
    for removed in ["modify", "repack", "export"] {
        assert!(
            !stdout.contains(&format!("\n  {removed} ")),
            "removed top-level command {removed} leaked into help:\n{stdout}"
        );
    }
}

#[test]
fn fat_cli_shows_bootloader_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bootloader", "--help"])
        .output()
        .expect("fat bootloader help runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("inspect"),
        "expected bootloader help output to mention inspect, got:\n{stdout}"
    );
    assert!(
        stdout.contains("export-env"),
        "expected bootloader help output to mention export-env, got:\n{stdout}"
    );
}

#[test]
fn fat_cli_shows_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg("--version")
        .output()
        .expect("fat version runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), concat!("fat ", env!("CARGO_PKG_VERSION")));
}

#[test]
fn emulate_help_labels_rehosting_experimental_and_exposes_explicit_consent_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--help"])
        .output()
        .expect("fat emulate help runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--experimental-rehosting"), "{stdout}");
    assert!(stdout.contains("--accept-degraded-rehosting"), "{stdout}");
    assert!(
        stdout.to_ascii_lowercase().contains("experimental"),
        "{stdout}"
    );
}

#[test]
fn fat_new_creates_project_workspace() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("demo");
    assert!(project_dir.join(".fat.db").exists());
    assert!(project_dir.join("input").join("demo.bin").exists());

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let target = store.read_target(&target_id).expect("target record");
    assert_eq!(target.project_id, "demo");
    assert_eq!(target.display_name, "demo");
}

#[test]
fn fat_edge_ai_scan_json_scans_arbitrary_rootfs_with_format_filter() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    let models = rootfs.join("opt/ai");
    std::fs::create_dir_all(&models).expect("model dir");

    let mut magik = Vec::new();
    for word in [0x08ACu32, 0, 1, 320, 240, 3, 0, 6, 36] {
        magik.extend_from_slice(&word.to_le_bytes());
    }
    magik.extend_from_slice(&[0u8; 64]);
    std::fs::write(models.join("persondet.bin"), magik).expect("magik fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "edge-ai",
            "scan",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--format",
            "magik",
            "--json",
        ])
        .output()
        .expect("fat edge-ai scan runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "edge-ai-scan/v1");
    assert_eq!(report["formats"], serde_json::json!(["magik"]));
    assert_eq!(report["finding_count"], 1);
    assert_eq!(report["findings"][0]["plugin_id"], "magik-model");
    assert_eq!(
        report["findings"][0]["subject"]["File"]["rel_path"],
        "opt/ai/persondet.bin"
    );
}
