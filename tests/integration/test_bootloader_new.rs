use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::process::Command;
use tempfile::tempdir;

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write test file");
}

fn minimal_dtb_blob() -> Vec<u8> {
    let total_size = 40u32;
    let off_dt_struct = 40u32;
    let off_dt_strings = 40u32;
    let off_mem_rsvmap = 40u32;
    let version = 17u32;
    let last_comp_version = 16u32;
    let boot_cpuid_phys = 0u32;
    let size_dt_strings = 0u32;
    let size_dt_struct = 0u32;

    let mut bytes = Vec::new();
    for value in [
        0xd00d_feedu32,
        total_size,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        version,
        last_comp_version,
        boot_cpuid_phys,
        size_dt_strings,
        size_dt_struct,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

#[test]
fn bootloader_new_imports_real_values_and_fills_profile_defaults() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
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

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "new",
            project_dir.to_str().expect("project path"),
            "--profile",
            "consumer-iot-camera",
        ])
        .output()
        .expect("bootloader new runs");

    assert!(output.status.success(), "bootloader new failed: {output:?}");

    let env = std::fs::read_to_string(project_dir.join("bootloader").join("env.txt"))
        .expect("generated env");
    assert!(env.contains("sig_check=yes"));
    assert!(env.contains("bootdelay=3"));
    assert!(env.contains("loadaddr=0x80008000"));
    assert!(env.contains("bootargs=console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw"));
    assert!(env.contains("verify=yes"));
    assert!(project_dir.join("bootloader").join("storage").is_dir());
    assert!(project_dir
        .join("bootloader")
        .join("boot-plan.json")
        .is_file());

    let manifest = std::fs::read_to_string(project_dir.join("bootloader").join("profile.json"))
        .expect("generated manifest");
    assert!(manifest.contains("\"profile_name\": \"consumer-iot-camera\""));
    assert!(manifest.contains("\"imported_snapshot\""));
    assert!(manifest.contains("\"sig_check\""));
}

#[test]
fn bootloader_new_preserves_rootfs_symlinks_in_strict_real_workspace() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::create_dir_all(
        project_dir
            .join("extracted")
            .join("rootfs-tree")
            .join("bin"),
    )
    .expect("rootfs tree");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        env_variables: vec![BootEnvVariable {
            key: "bootcmd".into(),
            value: "bootm ${loadaddr}".into(),
            source: BootValueSource::Imported,
        }],
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
        &project_dir
            .join("extracted")
            .join("rootfs-tree")
            .join("sbin")
            .join("init"),
        b"#!/bin/sh\n",
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/var/run/udhcpc.sock",
        project_dir
            .join("extracted")
            .join("rootfs-tree")
            .join("bin")
            .join("udhcpc.sock"),
    )
    .expect("create rootfs symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "new",
            project_dir.to_str().expect("project path"),
            "--profile",
            "consumer-iot-camera",
        ])
        .output()
        .expect("bootloader new runs");

    assert!(output.status.success(), "bootloader new failed: {output:?}");

    #[cfg(unix)]
    {
        let copied = project_dir
            .join("bootloader")
            .join("storage")
            .join("rootfs")
            .join("rootfs-tree")
            .join("bin")
            .join("udhcpc.sock");
        let target = std::fs::read_link(copied).expect("copied symlink");
        assert_eq!(target, std::path::PathBuf::from("/var/run/udhcpc.sock"));
    }
}

#[test]
fn bootloader_new_materializes_vendor_bootloader_when_true_mode_is_selected() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2019.07 ARM".into()),
        env_variables: vec![BootEnvVariable {
            key: "bootcmd".into(),
            value: "bootm ${loadaddr}".into(),
            source: BootValueSource::Imported,
        }],
        ..Default::default()
    };
    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2019.07\0ARM\0bootdelay=3\0",
    );
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
            "new",
            project_dir.to_str().expect("project path"),
            "--profile",
            "consumer-iot-camera",
        ])
        .output()
        .expect("bootloader new runs");

    assert!(output.status.success(), "bootloader new failed: {output:?}");

    assert!(project_dir
        .join("bootloader")
        .join("storage")
        .join("bootloader")
        .join("u-boot.bin")
        .is_file());

    let manifest = std::fs::read_to_string(project_dir.join("bootloader").join("profile.json"))
        .expect("generated manifest");
    assert!(manifest.contains("\"mode\": \"true-boot-chain\""));
    assert!(manifest.contains("\"bootloader_image\""));
}

#[test]
fn bootloader_new_preserves_dtb_load_address_when_remapping_storage_paths() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2019.07 ARM".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr} - ${fdt_addr_r}".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "fdt_addr_r".into(),
                value: "0x43000000".into(),
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
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2019.07\0ARM\0bootdelay=3\0",
    );
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("board.dtb"),
        &minimal_dtb_blob(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "new",
            project_dir.to_str().expect("project path"),
            "--profile",
            "consumer-iot-camera",
        ])
        .output()
        .expect("bootloader new runs");

    assert!(output.status.success(), "bootloader new failed: {output:?}");

    let boot_plan = std::fs::read_to_string(project_dir.join("bootloader").join("boot-plan.json"))
        .expect("boot plan");
    assert!(boot_plan.contains("\"load_addr\": \"0x43000000\""));
    assert!(boot_plan.contains("setenv fdt_addr_r 0x43000000"));
    assert!(boot_plan.contains("bootm ${loadaddr} - ${fdt_addr_r}"));
}

#[test]
fn bootloader_new_downgrades_true_mode_when_bootloader_and_dtb_board_profiles_conflict() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2023.01 ARM".into()),
        env_variables: vec![BootEnvVariable {
            key: "bootcmd".into(),
            value: "bootm ${loadaddr} - ${fdt_addr_r}".into(),
            source: BootValueSource::Imported,
        }],
        ..Default::default()
    };
    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2023.01\0board=qemu-arm\0board_name=qemu-arm\0virtio-mmio\0",
    );
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("board.dtb"),
        b"\xd0\r\xfe\xedhisilicon,hi3516ev200\0Hisilicon HI3516EV200 DEMO Board\0",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "new",
            project_dir.to_str().expect("project path"),
            "--profile",
            "consumer-iot-camera",
        ])
        .output()
        .expect("bootloader new runs");

    assert!(output.status.success(), "bootloader new failed: {output:?}");

    let manifest = std::fs::read_to_string(project_dir.join("bootloader").join("profile.json"))
        .expect("generated manifest");
    assert!(manifest.contains("\"mode\": \"hybrid-boot-chain\""));
    assert!(manifest.contains("board-coherence"));
}
