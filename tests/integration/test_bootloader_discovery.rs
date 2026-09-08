use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dirs");
    }
    fs::write(path, bytes).expect("write file");
}

fn minimal_dtb_blob() -> Vec<u8> {
    let total_size = 60u32;
    let off_mem_rsvmap = 40u32;
    let off_dt_struct = 56u32;
    let off_dt_strings = 60u32;
    let version = 17u32;
    let last_comp_version = 16u32;
    let boot_cpuid_phys = 0u32;
    let size_dt_strings = 0u32;
    let size_dt_struct = 4u32;

    let mut blob = Vec::new();
    blob.extend_from_slice(&0xd00dfeedu32.to_be_bytes());
    blob.extend_from_slice(&total_size.to_be_bytes());
    blob.extend_from_slice(&off_dt_struct.to_be_bytes());
    blob.extend_from_slice(&off_dt_strings.to_be_bytes());
    blob.extend_from_slice(&off_mem_rsvmap.to_be_bytes());
    blob.extend_from_slice(&version.to_be_bytes());
    blob.extend_from_slice(&last_comp_version.to_be_bytes());
    blob.extend_from_slice(&boot_cpuid_phys.to_be_bytes());
    blob.extend_from_slice(&size_dt_strings.to_be_bytes());
    blob.extend_from_slice(&size_dt_struct.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&9u32.to_be_bytes());
    blob
}

fn prepared_project_with_boot_artifacts() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let ordinal = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let project_dir =
        std::env::temp_dir().join(format!("fat-bootloader-discovery-{unique}-{ordinal}"));
    fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

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
        ],
        ..Default::default()
    };

    write_file(
        &project_dir.join("analysis").join("bootloader.json"),
        &serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    );

    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("firmware.itb"),
        &[0xd0, 0x0d, 0xfe, 0xed, b'f', b'i', b't'],
    );
    write_file(
        &project_dir.join("extracted").join("board.dtb"),
        &[0xd0, 0x0d, 0xfe, 0xed, b'd', b't', b'b'],
    );
    write_file(
        &project_dir.join("extracted").join("board_blob"),
        &[0xd0, 0x0d, 0xfe, 0xed, b'd', b't', b'b'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );
    write_file(
        &project_dir
            .join("extracted")
            .join("rootfs-tree")
            .join("sbin")
            .join("init"),
        b"",
    );
    write_file(
        &project_dir
            .join("extracted")
            .join("rootfs-tree")
            .join("etc")
            .join("inittab"),
        b"::sysinit:/etc/init.d/rcS",
    );

    project_dir
}

fn prepared_project_with_manifest_kernel() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let ordinal = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let project_dir =
        std::env::temp_dir().join(format!("fat-bootloader-manifest-{unique}-{ordinal}"));
    fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    fs::create_dir_all(project_dir.join("work")).expect("work dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr}".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };
    write_file(
        &project_dir.join("analysis").join("bootloader.json"),
        &serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    );

    let kernel_path = project_dir
        .join("work")
        .join("extractions")
        .join("unblob")
        .join("sample.bin_extract")
        .join("512-1022438.lzma_extract")
        .join("lzma.uncompressed");
    write_file(
        &kernel_path,
        b"CMDLINE:board=TL-WR703N console=ttyATH0,115200\0Linux version 3.10.26\0MIPS\0uImage\0",
    );

    let manifest = serde_json::json!({
        "rootfs_path": null,
        "kernel_paths": [kernel_path],
        "file_count": 1
    });
    write_file(
        &project_dir.join("work").join("extraction-manifest.json"),
        &serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    );

    project_dir
}

#[test]
fn discovery_finds_kernel_rootfs_and_boot_hints() {
    let project = prepared_project_with_boot_artifacts();

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(discovered.primary.is_some());
    assert!(!discovered.artifacts.is_empty());
    assert!(discovered
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "kernel"));
    assert!(discovered
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "rootfs"));
    assert!(discovered
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "dtb"));
    assert!(!discovered.alternates.is_empty());
    assert_eq!(
        discovered
            .primary
            .as_ref()
            .and_then(|set| set.primary.as_ref())
            .and_then(|artifact| artifact.load_addr.as_deref()),
        Some("0x80008000")
    );
    assert!(discovered
        .primary
        .as_ref()
        .map(|set| set
            .selection_rationale
            .iter()
            .any(|line| line.contains("bootloader evidence")))
        .unwrap_or(false));
}

#[test]
fn discovery_uses_fit_as_primary_when_no_kernel_candidate_exists() {
    let project = prepared_project_with_boot_artifacts();
    std::fs::remove_file(project.join("extracted").join("uImage")).expect("remove uimage");

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    assert_eq!(
        discovered
            .primary
            .as_ref()
            .and_then(|set| set.primary.as_ref())
            .map(|artifact| artifact.kind.as_str()),
        Some("fit")
    );
}

#[test]
fn discovery_ignores_generated_bootloader_workspace_artifacts() {
    let project = prepared_project_with_boot_artifacts();
    write_file(
        &project
            .join("bootloader")
            .join("storage")
            .join("kernel")
            .join("image"),
        &[0x27, 0x05, 0x19, 0x56, b'f', b'a', b'k', b'e'],
    );

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(!discovered
        .artifacts
        .iter()
        .any(|artifact| artifact.path.contains("/bootloader/storage/")));
}

#[test]
fn discovery_skips_unreadable_symlink_entries() {
    let project = prepared_project_with_boot_artifacts();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        project.join("does-not-exist"),
        project.join("extracted").join("broken-link"),
    )
    .expect("create broken symlink");

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(discovered.primary.is_some());
}

#[test]
fn discovery_uses_manifest_kernel_candidates_for_strict_real_sets() {
    let project = prepared_project_with_manifest_kernel();

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    let primary = discovered.primary.expect("primary boot set");
    let kernel = primary.primary.expect("kernel artifact");
    assert_eq!(kernel.kind, "kernel");
    assert!(kernel.path.ends_with("lzma.uncompressed"));
    assert_eq!(kernel.load_addr.as_deref(), Some("0x80008000"));
}

#[test]
fn discovery_carves_embedded_dtb_from_kernel_image() {
    let project = prepared_project_with_boot_artifacts();
    let mut kernel = vec![0x27, 0x05, 0x19, 0x56];
    kernel.extend_from_slice(&[0u8; 124]);
    kernel.extend_from_slice(&minimal_dtb_blob());
    write_file(&project.join("extracted").join("uImage"), &kernel);
    std::fs::remove_file(project.join("extracted").join("board.dtb"))
        .expect("remove standalone dtb");

    let discovered =
        fat_bootloader::discovery::discover_boot_artifacts(&project).expect("discover artifacts");

    assert!(discovered
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "dtb" && artifact.path.contains("embedded-dtb")));
}
