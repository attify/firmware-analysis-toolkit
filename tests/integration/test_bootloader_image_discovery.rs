use fat_core::bootloader::BootloaderSnapshot;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dirs");
    }
    fs::write(path, bytes).expect("write file");
}

fn prepared_project_with_u_boot_binary() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let project_dir = std::env::temp_dir().join(format!("fat-bootloader-image-{unique}"));
    fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    fs::create_dir_all(project_dir.join("extracted")).expect("extracted dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2019.07".into()),
        ..Default::default()
    };
    write_file(
        &project_dir.join("analysis").join("bootloader.json"),
        &serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    );
    write_file(
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2019.07\0ARM\0bootdelay=3\0",
    );

    project_dir
}

#[test]
fn discovery_finds_vendor_bootloader_candidates() {
    let project = prepared_project_with_u_boot_binary();
    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(discovery
        .bootloader_images
        .iter()
        .any(|image| image.family == "u-boot"));
}

#[test]
fn discovery_does_not_treat_generic_boot_named_files_as_bootloaders() {
    let project = prepared_project_with_u_boot_binary();
    write_file(
        &project.join("extracted").join("boot.sh"),
        b"#!/bin/sh\necho boot\n",
    );

    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovery
        .bootloader_images
        .iter()
        .any(|image| image.path.ends_with("boot.sh")));
}

#[test]
fn discovery_does_not_treat_uboot_envtools_metadata_as_bootloader_images() {
    let project = prepared_project_with_u_boot_binary();
    write_file(
        &project
            .join("extracted")
            .join("usr/lib/opkg/info/uboot-envtools.control"),
        b"Package: uboot-envtools\nDescription: U-Boot environment utilities\n",
    );
    write_file(
        &project.join("extracted").join("lib/uboot-envtools.sh"),
        b"#!/bin/sh\nuboot_env_read() { echo U-Boot environment; }\n",
    );

    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovery.bootloader_images.iter().any(|image| {
        image.path.ends_with("uboot-envtools.control") || image.path.ends_with("uboot-envtools.sh")
    }));
}

#[test]
fn discovery_does_not_treat_generic_carved_blobs_with_u_boot_strings_as_bootloaders() {
    let project = prepared_project_with_u_boot_binary();
    write_file(
        &project
            .join("extracted")
            .join("512-1022438.lzma_extract/lzma.uncompressed"),
        b"\x00\x01U-Boot 1.1.4\0bootdelay=5\0bootcmd=bootm\0",
    );

    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovery
        .bootloader_images
        .iter()
        .any(|image| { image.path.ends_with("lzma.uncompressed") }));
}

#[test]
fn discovery_does_not_treat_fw_printenv_binary_as_bootloader_image() {
    let project = prepared_project_with_u_boot_binary();
    write_file(
        &project.join("extracted").join("usr/sbin/fw_printenv"),
        b"\x7fELFU-Boot 1.1.4\0fw_printenv\0",
    );

    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovery
        .bootloader_images
        .iter()
        .any(|image| image.path.ends_with("fw_printenv")));
}

#[test]
fn discovery_does_not_treat_generic_decompressed_bin_as_bootloader_image() {
    let project = prepared_project_with_u_boot_binary();
    write_file(
        &project.join("extracted").join("decompressed.bin"),
        b"\x00\x01U-Boot 1.1.4\0bootdelay=5\0bootcmd=bootm\0",
    );

    let discovery = fat_bootloader::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovery
        .bootloader_images
        .iter()
        .any(|image| image.path.ends_with("decompressed.bin")));
}
