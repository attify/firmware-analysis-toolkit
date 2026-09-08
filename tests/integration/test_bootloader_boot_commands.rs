#[test]
fn boot_plan_generates_real_bootm_commands() {
    let plan = fat_bootloader::bootplan::BootPlan {
        boot_method: "bootm".into(),
        kernel: Some(fat_bootloader::bootplan::BootArtifact {
            kind: "kernel".into(),
            path: "bootloader/storage/kernel/uImage".into(),
            source_path: "/tmp/project/extracted/uImage".into(),
            format: "uImage".into(),
            load_addr: Some("0x80008000".into()),
            provenance: "extracted".into(),
            confidence: 0.95,
            ..Default::default()
        }),
        bootargs_template: Some("console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into()),
        ..Default::default()
    };

    let commands = plan.u_boot_commands();

    assert!(commands.iter().any(|line| line.contains("bootm")));
    assert!(commands.iter().any(|line| line.contains("bootargs")));
    assert!(commands.iter().any(|line| line.contains("loadaddr")));
}

#[test]
fn boot_plan_generates_bootm_commands_with_fdt_when_dtb_is_present() {
    let plan = fat_bootloader::bootplan::BootPlan {
        boot_method: "bootm".into(),
        kernel: Some(fat_bootloader::bootplan::BootArtifact {
            kind: "kernel".into(),
            path: "bootloader/storage/kernel/uImage".into(),
            source_path: "/tmp/project/extracted/uImage".into(),
            format: "uImage".into(),
            load_addr: Some("0x40200000".into()),
            provenance: "extracted".into(),
            confidence: 0.95,
            ..Default::default()
        }),
        dtb: Some(fat_bootloader::bootplan::BootArtifact {
            kind: "dtb".into(),
            path: "bootloader/storage/dtb/board.dtb".into(),
            source_path: "/tmp/project/extracted/board.dtb".into(),
            format: "dtb".into(),
            load_addr: Some("0x43000000".into()),
            provenance: "extracted".into(),
            confidence: 0.95,
            ..Default::default()
        }),
        bootargs_template: Some("console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into()),
        ..Default::default()
    };

    let commands = plan.u_boot_commands();

    assert!(commands
        .iter()
        .any(|line| line == "setenv fdt_addr_r 0x43000000"));
    assert!(commands
        .iter()
        .any(|line| line == "bootm ${loadaddr} - ${fdt_addr_r}"));
}

#[test]
fn boot_plan_uses_bootcmd_method_when_kernel_format_is_unknown() {
    let artifact_set = fat_bootloader::bootplan::BootArtifactSet {
        primary: Some(fat_bootloader::bootplan::BootArtifact {
            kind: "kernel".into(),
            path: "bootloader/storage/kernel/lzma.uncompressed".into(),
            source_path: "/tmp/project/extracted/lzma.uncompressed".into(),
            format: "kernel-raw".into(),
            load_addr: Some("0x80008000".into()),
            provenance: "manifest".into(),
            confidence: 0.9,
            ..Default::default()
        }),
        ..Default::default()
    };
    let snapshot = fat_core::bootloader::BootloaderSnapshot {
        env_variables: vec![
            fat_core::bootloader::BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr}".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };
    let profile = fat_bootloader::profile::load_profile("consumer-iot-plug").expect("profile");

    let plan = fat_bootloader::bootplan::build_boot_plan(&artifact_set, Some(&snapshot), &profile);

    assert_eq!(plan.boot_method, "bootm");
    assert!(plan
        .u_boot_commands
        .iter()
        .any(|line| line == "bootm ${loadaddr}"));
}

#[test]
fn boot_plan_uses_fdtcontroladdr_when_bootloader_implies_internal_fdt() {
    let artifact_set = fat_bootloader::bootplan::BootArtifactSet {
        primary: Some(fat_bootloader::bootplan::BootArtifact {
            kind: "kernel".into(),
            path: "bootloader/storage/kernel/zImage".into(),
            source_path: "/tmp/project/extracted/zImage".into(),
            format: "zImage".into(),
            load_addr: Some("0x40200000".into()),
            provenance: "manifest".into(),
            confidence: 0.95,
            ..Default::default()
        }),
        ..Default::default()
    };
    let snapshot = fat_core::bootloader::BootloaderSnapshot {
        env_variables: vec![
            fat_core::bootloader::BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x40200000".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "bootcmd_qfw".into(),
                value: "bootz $kernel_addr_r $ramdisk_addr_r:$filesize $fdtcontroladdr".into(),
                source: fat_core::bootloader::BootValueSource::Observed,
            },
        ],
        ..Default::default()
    };
    let profile = fat_bootloader::profile::load_profile("consumer-iot-camera").expect("profile");

    let plan = fat_bootloader::bootplan::build_boot_plan(&artifact_set, Some(&snapshot), &profile);

    assert_eq!(plan.boot_method, "bootz");
    assert!(plan
        .u_boot_commands
        .iter()
        .any(|line| line == "bootz ${loadaddr} - ${fdtcontroladdr}"));
}
