use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::process::Command;
use tempfile::tempdir;

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write test file");
}

#[test]
fn bootloader_inspect_renders_boot_artifact_sets_and_method() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2024.01".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr}".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "sig_check".into(),
                value: "no".into(),
                source: BootValueSource::Imported,
            },
        ],
        findings: vec!["BOOT-SIG-BYPASS".into()],
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
        &project_dir.join("extracted").join("board.dtb"),
        &[0xd0, 0x0d, 0xfe, 0xed, b'd', b't', b'b'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );
    write_file(
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2019.07\0MIPS\0bootdelay=3\0",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "inspect",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("bootloader inspect runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("u-boot"));
    assert!(stdout.contains("BOOT-SIG-BYPASS"));
    assert!(stdout.contains("boot method"));
    assert!(stdout.contains("primary boot set"));
    assert!(stdout.contains("uImage"));
    assert!(stdout.contains("mode: hybrid-boot-chain"));
    assert!(stdout.contains("why not true-boot-chain"));
}

#[test]
fn bootloader_inspect_explains_when_image_looks_like_partial_upgrade_without_bootloader() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("upgrade-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2013.01".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr}".into(),
                source: BootValueSource::Observed,
            },
            BootEnvVariable {
                key: "auimg0".into(),
                value: "u-boot_spi.bin".into(),
                source: BootValueSource::Observed,
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

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "inspect",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("bootloader inspect runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mode: hybrid-boot-chain"));
    assert!(stdout.contains("upgrade package or partial firmware image"));
}
