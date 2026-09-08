use fat_bootloader::materialize_workspace;
use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::process::Command;
use tempfile::{tempdir, TempDir};

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write test file");
}

/// Returns the tempdir guard alongside the project path: the caller must keep
/// the guard alive for the duration of the test, and dropping it removes the
/// fixture instead of leaving it behind in the system temp directory.
fn prepared_bootloader_project() -> (TempDir, std::path::PathBuf) {
    let tempdir = tempdir().expect("tempdir");
    let project_dir = tempdir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2024.01".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "sig_check".into(),
                value: "yes".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );

    materialize_workspace(&project_dir, "consumer-iot-camera").expect("materialize workspace");
    (tempdir, project_dir)
}

#[test]
fn bootloader_export_env_outputs_generated_env_text() {
    let (_tempdir, project) = prepared_bootloader_project();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "export-env",
            project.to_str().expect("project path"),
        ])
        .output()
        .expect("bootloader export-env runs");

    assert!(
        output.status.success(),
        "bootloader export-env failed: {output:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bootcmd="));
    assert!(stdout.contains("sig_check="));
}
