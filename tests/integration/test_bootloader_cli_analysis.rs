use fat_core::{
    database::ProjectDb,
    project::{Project, ProjectStatus},
};
use std::process::Command;
use tempfile::tempdir;

#[test]
fn fat_analyze_writes_bootloader_artifact() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("input")).expect("input dir");
    std::fs::create_dir_all(project_dir.join("work")).expect("work dir");

    let firmware_path = project_dir.join("input").join("demo.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");
    std::fs::write(
        project_dir.join("work").join("binwalk.log"),
        "$ binwalk -e demo.bin\nexit=0\n",
    )
    .expect("binwalk log");
    std::fs::write(
        project_dir.join("work").join("unblob.log"),
        "$ unblob -e demo.bin\nexit=0\n",
    )
    .expect("unblob log");

    let manifest = fat_extract::manifest::ExtractionManifest::default();
    std::fs::write(
        project_dir.join("work").join("extraction-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest file");

    let db = ProjectDb::open(&project_dir).expect("open db");
    db.save(&Project::new("demo".into(), "demo.bin".into()))
        .expect("save project");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat analyze runs");

    assert!(output.status.success(), "{output:?}");

    let artifact = project_dir.join("analysis").join("bootloader.json");
    let snapshot: fat_core::bootloader::BootloaderSnapshot =
        serde_json::from_slice(&std::fs::read(&artifact).expect("bootloader artifact"))
            .expect("bootloader json");
    assert_eq!(snapshot.family.as_deref(), Some("u-boot"));
    assert!(snapshot
        .flow_hints
        .iter()
        .any(|hint| hint.value == "bootdelay=3"));
    assert!(!snapshot
        .findings
        .iter()
        .any(|finding| finding == "BOOT-SIG-BYPASS"));
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding == "BOOT-ENV-CONTROLLED-FLOW"));
    assert!(
        !snapshot
            .env_variables
            .iter()
            .any(|variable| variable.key == "exit"),
        "generic log metadata must not be parsed as bootloader env"
    );
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding == "BOOT-UIMAGE-CRC32-ONLY"));
    assert_eq!(snapshot.image_headers.len(), 2);
    assert_eq!(snapshot.image_headers[0].name.as_deref(), Some("jz_fw"));
    assert_eq!(
        snapshot.image_headers[1].name.as_deref(),
        Some("Linux-3.10.14__isvp_swan_1.0__")
    );

    let image_headers_artifact = project_dir.join("analysis").join("image-headers.json");
    let image_headers: Vec<fat_core::bootloader::BootImageHeader> = serde_json::from_slice(
        &std::fs::read(&image_headers_artifact).expect("image headers artifact"),
    )
    .expect("image headers json");
    assert_eq!(image_headers.len(), 2);

    let signals = std::fs::read_to_string(project_dir.join("analysis").join("signals.txt"))
        .expect("signals file");
    assert!(signals.contains("container:uimage"));
    assert!(signals.contains("bootloader:u-boot"));
    assert!(signals.contains("auth:crc32-only"));
    assert!(signals.contains("uimage:name:jz_fw"));
    assert_eq!(
        ProjectDb::open(&project_dir)
            .unwrap()
            .get("demo")
            .unwrap()
            .unwrap()
            .status,
        ProjectStatus::Analyzed
    );
}

#[test]
fn fat_inspect_headers_renders_student_friendly_uimage_field_table() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("input")).expect("input dir");
    std::fs::create_dir_all(project_dir.join("work")).expect("work dir");

    let firmware_path = project_dir.join("input").join("demo.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = fat_analyze::bootloader::merge_snapshots(
        fat_analyze::bootloader::analyze_text(
            "U-Boot 2024.01\nbootdelay=3\nbootcmd=run verify_sig; bootm ${loadaddr}\n",
        ),
        fat_analyze::bootloader::analyze_firmware_bytes(&wyze_style_uimage_with_boot_text())
            .expect("uimage parse"),
    );
    std::fs::write(
        project_dir.join("analysis").join("image-headers.json"),
        serde_json::to_vec_pretty(&snapshot.image_headers).expect("image headers json"),
    )
    .expect("image headers artifact");

    let db = ProjectDb::open(&project_dir).expect("open db");
    db.save(&Project::new("demo".into(), "demo.bin".into()))
        .expect("save project");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Header 1: uimage @ 0x00000000"));
    assert!(stdout.contains("| Offset | Size | Value"));
    assert!(stdout.contains("| 0x00 | 4 | 0x27051956 | uImage magic number |"));
    assert!(stdout.contains("| 0x04 | 4 | 0xF4591363 | Header CRC-32 |"));
    assert!(stdout.contains("| 0x08 | 4 | 0x633BBA09 | Timestamp (Unix) |"));
    assert!(stdout.contains("| 0x0C | 4 | 0x008EF000 | Data size (9367552 bytes) |"));
    assert!(stdout.contains("| 0x18 | 4 | 0x31189874 | Data CRC-32 |"));
    assert!(stdout.contains("| 0x1C | 1 | 0x05 | OS type (linux) |"));
    assert!(stdout.contains("| 0x1D | 1 | 0x05 | Architecture (mips) |"));
    assert!(stdout.contains("| 0x1E | 1 | 0x05 | Image type (firmware) |"));
    assert!(stdout.contains("| 0x1F | 1 | 0x00 | Compression (none) |"));
    assert!(stdout.contains("| 0x20 | 32 | \"jz_fw\" | Image name |"));
    assert!(stdout.contains("Header 2: uimage @ 0x00000040"));
}

#[test]
fn fat_analyze_prefers_explicit_artifact_signals_over_loose_strings() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("input")).expect("input dir");
    std::fs::create_dir_all(project_dir.join("work")).expect("work dir");

    let firmware_path = project_dir.join("input").join("demo.bin");
    std::fs::write(
        &firmware_path,
        b"goahead.gif\nmips helper text that should not override concrete ARM evidence\n",
    )
    .expect("firmware file");

    let rootfs = project_dir
        .join("work")
        .join("extractions")
        .join("binwalk")
        .join("extractions")
        .join("demo.bin.extracted")
        .join("400020")
        .join("jffs2-root");
    std::fs::create_dir_all(rootfs.join("bin")).expect("rootfs bin");
    std::fs::create_dir_all(rootfs.join("www").join("cgi-bin")).expect("cgi dir");
    std::fs::write(rootfs.join("bin").join("busybox"), b"#!/bin/sh\n").expect("busybox");
    std::fs::write(
        rootfs.join("www").join("cgi-bin").join("status.cgi"),
        b"#!/bin/sh\n",
    )
    .expect("cgi");

    let kernel_path = project_dir
        .join("work")
        .join("extractions")
        .join("binwalk")
        .join("extractions")
        .join("demo.bin.extracted")
        .join("34A4")
        .join("decompressed.bin");
    std::fs::create_dir_all(kernel_path.parent().expect("kernel parent")).expect("kernel dir");
    std::fs::write(
        &kernel_path,
        b"arch/arm/kernel/process.c\nRAMDISK: squashfs filesystem found at block %d\n",
    )
    .expect("kernel file");

    std::fs::write(
        project_dir.join("work").join("binwalk.log"),
        "$ binwalk -e demo.bin\nexit=0\n",
    )
    .expect("binwalk log");
    std::fs::write(
        project_dir.join("work").join("unblob.log"),
        "skipped unblob because binwalk already recovered a rootfs\n",
    )
    .expect("unblob log");

    let manifest = fat_extract::manifest::ExtractionManifest {
        rootfs_path: Some(rootfs.clone()),
        kernel_paths: vec![kernel_path.clone()],
        file_count: 3,
        filesystem_trees: Vec::new(),
        ..Default::default()
    };
    std::fs::write(
        project_dir.join("work").join("extraction-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest file");

    let db = ProjectDb::open(&project_dir).expect("open db");
    db.save(&Project::new("demo".into(), "demo.bin".into()))
        .expect("save project");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat analyze runs");
    assert!(output.status.success(), "{output:?}");

    let signals = std::fs::read_to_string(project_dir.join("analysis").join("signals.txt"))
        .expect("signals file");
    assert!(signals.contains("arch:armel"), "{signals}");
    assert!(signals.contains("init:busybox"), "{signals}");
    assert!(signals.contains("web:cgi"), "{signals}");
    assert!(signals.contains("fs:jffs2"), "{signals}");
    assert!(!signals.contains("arch:mips"), "{signals}");
    assert!(!signals.contains("fs:squashfs"), "{signals}");
}

#[test]
fn fat_inspect_headers_supports_raw_firmware_files() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("demo.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .env("FAT_COLOR", "never")
        .output()
        .expect("fat inspect headers runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Header 1: uimage @ 0x00000000"));
    assert!(stdout.contains("| 0x00 | 4 | 0x27051956 | uImage magic number |"));
    assert!(stdout.contains("| 0x20 | 32 | \"jz_fw\" | Image name |"));
    assert!(stdout.contains("Header 2: uimage @ 0x00000040"));
}

#[test]
fn fat_inspect_headers_supports_raw_firmware_json_output() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("demo.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"image_headers\": ["));
    assert!(stdout.contains("\"compression_members\": []"));
    assert!(stdout.contains("\"filesystem_headers\": []"));
    assert!(stdout.contains("\"format\": \"uimage\""));
    assert!(stdout.contains("\"magic_hex\": \"0x27051956\""));
    assert!(stdout.contains("\"offset\": 0"));
    assert!(stdout.contains("\"name\": \"jz_fw\""));
}

#[test]
fn fat_inspect_headers_reports_embedded_signatures_when_no_uimage_exists() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("tapo-like.bin");
    std::fs::write(&firmware_path, structured_signature_firmware_bytes()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compressed and embedded objects"));
    assert!(stdout.contains("| 0x00000020 | lzma | 0x5D | 8388608 | 111464 |"));
    assert!(stdout.contains("| 0x000000C0 | gzip | unix | 1700000255 | 12 |"));
    assert!(stdout.contains("Filesystem objects"));
    assert!(
        stdout.contains("| 0x00000080 | squashfs | little | 4.0 | xz | 1064 | 262144 | 5955826 |")
    );
}

#[test]
fn fat_inspect_headers_reports_embedded_signatures_as_json() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("tapo-like.bin");
    std::fs::write(&firmware_path, structured_signature_firmware_bytes()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"image_headers\": []"));
    assert!(stdout.contains("\"compression_members\": ["));
    assert!(stdout.contains("\"filesystem_headers\": ["));
    assert!(stdout.contains("\"format\": \"lzma\""));
    assert!(stdout.contains("\"format\": \"gzip\""));
    assert!(stdout.contains("\"properties_hex\": \"0x5D\""));
    assert!(stdout.contains("\"dictionary_size\": 8388608"));
    assert!(stdout.contains("\"operating_system\": \"unix\""));
    assert!(stdout.contains("\"version\": \"4.0\""));
    assert!(stdout.contains("\"compression\": \"xz\""));
}

#[test]
fn fat_inspect_layout_reports_regions_for_tapo_like_firmware() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("tapo-like.bin");
    std::fs::write(&firmware_path, structured_signature_firmware_bytes()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Firmware layout summary"));
    assert!(stdout.contains("- Top-level regions: 2"));
    assert!(stdout.contains("- Nested regions: 1"));
    assert!(stdout.contains("- Dominant boot image: none"));
    assert!(stdout.contains("- Dominant rootfs: squashfs @ 0x00000080"));
    assert!(stdout.contains("Firmware layout"));
    assert!(
        stdout.contains("| Offset | Kind | Format | Size/Span | Role | Scope | Parent | Notes |")
    );
    assert!(stdout.contains("| 0x00000020 | compression | lzma | span unknown | likely compressed payload | top-level | - |"));
    assert!(stdout.contains(
        "| Offset | Kind | Format | Size/Span | Role | Scope | Parent | Notes | Name | Architecture | Exact span |"
    ));
    assert!(stdout.contains(
        "| 0x00000080 | filesystem | squashfs | 5955826 bytes | likely rootfs | top-level | - |"
    ));
    assert!(stdout.contains("| 0x000000C0 | compression | gzip | 32 bytes | likely archive tail | nested | 0x00000080 |"));
    for forbidden in ["Recommended next steps", "Next step"] {
        assert!(
            !stdout.contains(forbidden),
            "unexpected {forbidden}:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_layout_renders_partial_overlap_diagnostics() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("overlap.bin");
    let mut bytes = vec![0u8; 0x110];
    write_squashfs_header(&mut bytes, 0, 0x100, 1);
    bytes[0xF0..0x110].copy_from_slice(&[
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ]);
    std::fs::write(&firmware_path, bytes).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Partial overlaps"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("0x00000000 and 0x000000F0 overlap from 0x000000F0 to 0x000000FF"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("neither contains the other"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn fat_inspect_layout_opaque_wrapper_error_reports_measurements_without_guidance() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("opaque.bin");

    let mut state: u32 = 0xA5A5_5A5A;
    let mut blob = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        blob.push((state & 0xff) as u8);
    }
    std::fs::write(&firmware, blob).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(
        !output.status.success(),
        "expected opaque wrapper to be unsupported, got success:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for evidence in [
        "opaque wrapper likely",
        "Entropy:",
        "Unique bytes:",
        "Duplicate 16-byte blocks:",
    ] {
        assert!(stderr.contains(evidence), "missing {evidence}:\n{stderr}");
    }
    for guidance in ["Suggestion:", "decrypt or unwrap", "inspect envelope"] {
        assert!(
            !stderr.contains(guidance),
            "unexpected {guidance}:\n{stderr}"
        );
    }
}

#[test]
fn fat_inspect_layout_refuses_macho_binaries_honestly() {
    let temp = tempdir().expect("temp dir");
    let macho_path = temp.path().join("service-launcher");
    std::fs::write(&macho_path, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).expect("macho file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            macho_path.to_str().expect("macho path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Mach-O"));
    assert!(stderr.contains("identify-launcher"));
    assert!(stderr.contains("inspect-handoff"));
}

#[test]
fn fat_inspect_layout_reports_regions_as_json() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("tapo-like.bin");
    std::fs::write(&firmware_path, structured_signature_firmware_bytes()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware_path.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("layout json");
    assert_eq!(report["summary"]["top_level_region_count"], 2);
    assert_eq!(report["summary"]["nested_region_count"], 1);
    assert_eq!(report["summary"]["dominant_rootfs_offset"], 128);
    assert!(
        report.get("guidance").is_none(),
        "unexpected guidance: {report}"
    );
    let regions = report["regions"].as_array().expect("regions");
    assert!(regions.iter().any(|region| region["kind"] == "compression"));
    assert!(regions
        .iter()
        .any(|region| region["role"] == "likely rootfs"));
    assert!(regions
        .iter()
        .all(|region| region.get("next_action").is_none()));
}

#[test]
fn fat_inspect_layout_reports_boot_roles_for_uimage_firmware() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("wyze-like.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Firmware layout summary"));
    assert!(stdout.contains("- Top-level regions: 1"));
    assert!(stdout.contains("- Nested regions: 1"));
    assert!(stdout.contains("- Dominant boot image: uimage @ 0x00000000"));
    assert!(stdout.contains("- Dominant rootfs: none"));
    assert!(stdout.contains(
        "| 0x00000000 | boot-image | uimage | 9367616 bytes | likely boot image | top-level | - |"
    ));
    assert!(stdout.contains("| 0x00000040 | boot-image | uimage | 1882715 bytes | likely kernel payload | nested | 0x00000000 |"));
    for forbidden in ["Recommended next steps", "Next step"] {
        assert!(
            !stdout.contains(forbidden),
            "unexpected {forbidden}:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_layout_reports_kernel_mtd_partition_map_for_file_input() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("wyze-partitioned.bin");
    std::fs::write(&firmware_path, wyze_partitioned_firmware_bytes()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Partition map"));
    assert!(stdout.contains("- Source: kernel cmdline (lzma @ 0x00000080)"));
    assert!(stdout.contains("- Root: /dev/mtdblock2 (squashfs)"));
    assert!(stdout.contains("| mtdblock2 | rootfs | 3904K | 0x00230000 |"));
    assert!(stdout.contains("| mtdblock3 | app | 3904K | 0x00600000 |"));
    assert!(stdout.contains("Resolved filesystems"));
    assert!(stdout.contains("squashfs @ 0x001F0040 -> mtdblock2/rootfs -> /"));
    assert!(stdout.contains("squashfs @ 0x005C0040 -> mtdblock3/app"));
}

#[test]
fn fat_inspect_layout_resolves_project_runtime_mount_points() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::create_dir_all(project_dir.join("input")).expect("input dir");
    std::fs::create_dir_all(
        project_dir
            .join("extracted")
            .join("wyze_rootfs")
            .join("etc")
            .join("init.d"),
    )
    .expect("init dir");

    let firmware = wyze_partitioned_firmware_bytes();
    std::fs::write(
        project_dir.join("input").join("wyze-partitioned.bin"),
        &firmware,
    )
    .expect("firmware file");
    std::fs::write(
        project_dir
            .join("extracted")
            .join("wyze_rootfs")
            .join("etc")
            .join("init.d")
            .join("rcS"),
        "mount -t squashfs /dev/mtdblock3 /system\n",
    )
    .expect("rcS");
    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(
            &fat_analyze::bootloader::analyze_firmware_bytes(&firmware)
                .expect("bootloader snapshot"),
        )
        .expect("bootloader json"),
    )
    .expect("bootloader artifact");

    let db = ProjectDb::open(&project_dir).expect("open db");
    db.save(&Project::new("demo".into(), "wyze-partitioned.bin".into()))
        .expect("save project");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("squashfs @ 0x005C0040 -> mtdblock3/app -> /system"));
}

#[test]
fn fat_inspect_layout_help_omits_action_guidance_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "layout", "--help"])
        .output()
        .expect("fat inspect layout help runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("--emit-actions"), "{stdout}");
    assert!(!stdout.contains("--include-advisory"), "{stdout}");
}

#[test]
fn fat_inspect_headers_rejects_missing_input_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "headers"])
        .output()
        .expect("fat inspect headers runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exactly one input source is required"));
}

#[test]
fn fat_inspect_headers_rejects_project_and_file_together() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(&project_dir).expect("project dir");

    let firmware_path = projects_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, wyze_style_uimage_with_boot_text()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            project_dir.to_str().expect("project path"),
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exactly one input source is required"));
}

#[test]
fn fat_inspect_headers_parses_unitree_upk_signature() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("package_test.upk");
    std::fs::write(&firmware_path, unitree_upk_fixture()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .env("FAT_COLOR", "never")
        .output()
        .expect("fat inspect headers runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Unitree UPK / UTPK @ 0x00000000"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("package_test"), "stdout:\n{stdout}");
    assert!(stdout.contains("TEA"), "stdout:\n{stdout}");
    assert!(stdout.contains("MD5 ok"), "stdout:\n{stdout}");
    assert!(
        !stdout.contains("Evidence"),
        "inspect output should not include lab-style evidence prose:\n{stdout}"
    );
    assert!(
        !stdout.contains("Boundary"),
        "inspect output should not include lab-style boundary prose:\n{stdout}"
    );
    assert!(
        !stdout.contains("does not prove device acceptance"),
        "inspect output should keep proof-boundary teaching prose out of CLI output:\n{stdout}"
    );
    assert!(
        !stdout.contains("uimage @"),
        "encrypted payload bytes must not be promoted as nested uImage headers:\n{stdout}"
    );
    assert!(
        !stdout.contains("Compressed and embedded objects"),
        "encrypted payload bytes must not be promoted as compression members:\n{stdout}"
    );
    assert!(
        stdout.contains("| Offset | Size | Value | Field |"),
        "plain output must preserve Markdown tables:\n{stdout}"
    );
}

#[test]
fn fat_inspect_headers_styles_unitree_upk_for_terminal() {
    let temp = tempdir().expect("temp dir");
    let firmware_path = temp.path().join("package_test.upk");
    std::fs::write(&firmware_path, unitree_upk_fixture()).expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            firmware_path.to_str().expect("firmware path"),
        ])
        .env("FAT_COLOR", "always")
        .output()
        .expect("fat inspect headers runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\u{1b}["),
        "expected ANSI styling:\n{stdout}"
    );
    assert!(
        !stdout.contains("| --- |"),
        "interactive output should not retain Markdown separators:\n{stdout}"
    );
    for expected in [
        "Unitree UPK / UTPK",
        "Container magic",
        "package_test",
        "TEA",
        "MD5 ok",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}:\n{stdout}");
    }
}

fn wyze_style_uimage_with_boot_text() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x200];
    write_uimage_header(
        &mut bytes[0x00..0x40],
        0xF459_1363,
        0x633B_BA09,
        0x008E_F000,
        0x0000_0000,
        0x0000_0000,
        0x3118_9874,
        0x05,
        0x05,
        0x05,
        0x00,
        "jz_fw",
    );
    write_uimage_header(
        &mut bytes[0x40..0x80],
        0x35B6_FD4C,
        0x6291_E82C,
        0x001C_BA1B,
        0x8001_0000,
        0x8040_F090,
        0x5FD5_5C70,
        0x05,
        0x05,
        0x02,
        0x03,
        "Linux-3.10.14__isvp_swan_1.0__",
    );
    let boot_text =
        b"U-Boot 2024.01\nbootdelay=3\nbootcmd=run verify_sig; bootm ${loadaddr}\nsig_check=yes\nverify=yes\nrecovery_mode=0\n";
    bytes[0x80..0x80 + boot_text.len()].copy_from_slice(boot_text);
    bytes
}

fn unitree_upk_fixture() -> Vec<u8> {
    let payload = [b"TEA\0".as_slice(), &(0u8..16).collect::<Vec<_>>()].concat();
    let mut bytes = vec![0u8; 112 + payload.len()];
    bytes[0..4].copy_from_slice(b"UTPK");
    bytes[5] = 1;
    bytes[8..16].copy_from_slice(&1_700_000_000u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes[24] = 3;
    bytes[28..32].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    bytes[32..48].copy_from_slice(&[
        0x82, 0xc0, 0xa1, 0xb6, 0x7a, 0xd4, 0x81, 0xe8, 0xbd, 0x5e, 0xf1, 0xce, 0xbe, 0x0a, 0x22,
        0x34,
    ]);
    bytes[48..60].copy_from_slice(b"package_test");
    bytes[112..].copy_from_slice(&payload);
    bytes
}

fn wyze_partitioned_firmware_bytes() -> Vec<u8> {
    let cmdline = b"Linux version 3.10.14 console=ttyS1,115200n8 mem=64M@0x0 root=/dev/mtdblock2 rootfstype=squashfs init=/linuxrc mtdparts=jz_sfc:256K(boot),1984K(kernel),3904K(rootfs),3904K(app),1984K(kback),3904K(aback),384K(cfg),64K(para)\0";
    let mut reader = std::io::Cursor::new(cmdline.as_slice());
    let mut compressed = Vec::new();
    lzma_rs::lzma_compress(&mut reader, &mut compressed).expect("compress cmdline");

    let app_image_size = 3_338_240u64;
    let mut bytes = vec![0u8; 0x005C_0040 + app_image_size as usize + 0x100];
    let outer_size = (bytes.len() - 0x40) as u32;
    write_uimage_header(
        &mut bytes[0x00..0x40],
        0xF459_1363,
        0x633B_BA09,
        outer_size,
        0x0000_0000,
        0x0000_0000,
        0x3118_9874,
        0x05,
        0x05,
        0x05,
        0x00,
        "jz_fw",
    );
    write_uimage_header(
        &mut bytes[0x40..0x80],
        0x35B6_FD4C,
        0x6291_E82C,
        compressed.len() as u32,
        0x8001_0000,
        0x8040_F090,
        0x5FD5_5C70,
        0x05,
        0x05,
        0x02,
        0x03,
        "Linux-3.10.14__isvp_swan_1.0__",
    );
    bytes[0x80..0x80 + compressed.len()].copy_from_slice(&compressed);
    write_squashfs_header(&mut bytes, 0x001F_0040, 2_818_048, 358);
    write_squashfs_header(&mut bytes, 0x005C_0040, app_image_size, 161);
    bytes
}

fn structured_signature_firmware_bytes() -> Vec<u8> {
    let squashfs_size = 5_955_826usize;
    let mut bytes = vec![0u8; 0x80 + squashfs_size];
    bytes[0x20] = 0x5D;
    bytes[0x21..0x25].copy_from_slice(&(1u32 << 23).to_le_bytes());
    bytes[0x25..0x2D].copy_from_slice(&(111_464u64).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"hsqs");
    bytes[0x84..0x88].copy_from_slice(&1_064u32.to_le_bytes());
    bytes[0x88..0x8C].copy_from_slice(&1_636_595_875u32.to_le_bytes());
    bytes[0x8C..0x90].copy_from_slice(&262_144u32.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&4u16.to_le_bytes());
    bytes[0x9C..0x9E].copy_from_slice(&4u16.to_le_bytes());
    bytes[0x9E..0xA0].copy_from_slice(&0u16.to_le_bytes());
    bytes[0xA8..0xB0].copy_from_slice(&(squashfs_size as u64).to_le_bytes());
    // Real gzip member: OS=unix, mtime 1700000255, payload "hello world!" (12 bytes),
    // compressed span 32. The previous fixture stuffed plaintext + a fake ISIZE and
    // only worked because identify used to ISIZE-fish instead of inflating.
    bytes[0xC0..0xE0].copy_from_slice(&[
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ]);
    bytes[0xC9] = 0x03;
    bytes
}

fn write_squashfs_header(bytes: &mut [u8], offset: usize, image_size: u64, inode_count: u32) {
    bytes[offset..offset + 4].copy_from_slice(b"hsqs");
    bytes[offset + 4..offset + 8].copy_from_slice(&inode_count.to_le_bytes());
    bytes[offset + 8..offset + 12].copy_from_slice(&1_636_595_875u32.to_le_bytes());
    bytes[offset + 12..offset + 16].copy_from_slice(&262_144u32.to_le_bytes());
    bytes[offset + 20..offset + 22].copy_from_slice(&2u16.to_le_bytes());
    bytes[offset + 28..offset + 30].copy_from_slice(&4u16.to_le_bytes());
    bytes[offset + 30..offset + 32].copy_from_slice(&0u16.to_le_bytes());
    bytes[offset + 40..offset + 48].copy_from_slice(&image_size.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_uimage_header(
    target: &mut [u8],
    header_crc: u32,
    timestamp: u32,
    data_size: u32,
    load_address: u32,
    entry_point: u32,
    data_crc: u32,
    os: u8,
    arch: u8,
    image_type: u8,
    compression: u8,
    name: &str,
) {
    target[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    target[4..8].copy_from_slice(&header_crc.to_be_bytes());
    target[8..12].copy_from_slice(&timestamp.to_be_bytes());
    target[12..16].copy_from_slice(&data_size.to_be_bytes());
    target[16..20].copy_from_slice(&load_address.to_be_bytes());
    target[20..24].copy_from_slice(&entry_point.to_be_bytes());
    target[24..28].copy_from_slice(&data_crc.to_be_bytes());
    target[28] = os;
    target[29] = arch;
    target[30] = image_type;
    target[31] = compression;
    let name_bytes = name.as_bytes();
    target[32..32 + name_bytes.len()].copy_from_slice(name_bytes);
}
