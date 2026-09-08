use fat_bootloader::bootplan::{BootArtifact, BootArtifactSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn compatibility_rejects_true_mode_without_supported_machine_mapping() {
    let image = fat_bootloader::BootloaderImage {
        family: "u-boot".into(),
        format: "raw".into(),
        architecture: "mips".into(),
        confidence: 0.9,
        ..Default::default()
    };

    let compatibility = fat_bootloader::compatibility::evaluate_true_boot_chain(&image, None, None);

    assert!(!compatibility.compatible);
    assert!(compatibility
        .reasons
        .iter()
        .any(|line| line.contains("machine")));
}

#[test]
fn compatibility_accepts_supported_arm_u_boot_mapping() {
    let image = fat_bootloader::BootloaderImage {
        family: "u-boot".into(),
        format: "raw".into(),
        architecture: "arm".into(),
        confidence: 0.9,
        ..Default::default()
    };

    let compatibility = fat_bootloader::compatibility::evaluate_true_boot_chain(&image, None, None);

    assert!(compatibility.compatible);
    assert_eq!(compatibility.mode, "true-boot-chain");
    assert_eq!(compatibility.machine.as_deref(), Some("virt"));
    assert_eq!(
        compatibility.qemu_binary.as_deref(),
        Some("qemu-system-arm")
    );
}

#[test]
fn compatibility_rejects_mismatched_bootloader_and_dtb_board_profiles() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let tempdir = std::env::temp_dir().join(format!("fat-bootloader-compatibility-{unique}"));
    fs::create_dir_all(&tempdir).expect("create tempdir");
    let u_boot = tempdir.join("u-boot.bin");
    let dtb = tempdir.join("board.dtb");
    fs::write(
        &u_boot,
        b"U-Boot 2023.01\0board=qemu-arm\0board_name=qemu-arm\0virtio-mmio\0",
    )
    .expect("write bootloader");
    fs::write(
        &dtb,
        b"\xd0\r\xfe\xedhisilicon,hi3516ev200\0Hisilicon HI3516EV200 DEMO Board\0",
    )
    .expect("write dtb");

    let image = fat_bootloader::BootloaderImage {
        family: "u-boot".into(),
        path: u_boot.display().to_string(),
        format: "raw".into(),
        architecture: "arm".into(),
        confidence: 0.9,
        ..Default::default()
    };
    let artifacts = BootArtifactSet {
        primary: Some(BootArtifact {
            kind: "kernel".into(),
            path: tempdir.join("uImage").display().to_string(),
            format: "uImage".into(),
            ..Default::default()
        }),
        alternates: vec![BootArtifact {
            kind: "dtb".into(),
            path: dtb.display().to_string(),
            format: "dtb".into(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let compatibility =
        fat_bootloader::compatibility::evaluate_true_boot_chain(&image, Some(&artifacts), None);

    assert!(!compatibility.compatible);
    assert!(compatibility
        .reasons
        .iter()
        .any(|line| line.contains("does not match extracted artifact board profile")));
    assert!(compatibility
        .blocking_requirements
        .iter()
        .any(|line| line == "board-coherence"));

    let _ = fs::remove_dir_all(tempdir);
}
