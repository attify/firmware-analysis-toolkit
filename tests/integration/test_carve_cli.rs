use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn fat_carve_copies_explicit_offset_and_size() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("firmware.bin");
    let output_path = temp.path().join("slice.bin");
    fs::write(&firmware, b"0123456789abcdef").expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--offset",
            "0x4",
            "--size",
            "6",
            "--output",
            output_path.to_str().expect("output path"),
        ])
        .output()
        .expect("fat carve runs");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&output_path).expect("carved output"), b"456789");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("offset: 0x00000004"), "{stdout}");
    assert!(stdout.contains("size: 6"), "{stdout}");
}

#[test]
fn fat_carve_squashfs_infers_size_from_superblock() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("firmware.bin");
    let output_path = temp.path().join("rootfs.sqsh");
    let mut bytes = vec![0xAA; 0x80 + 96];
    for idx in 0..96 {
        bytes[0x20 + idx] = idx as u8;
    }
    bytes[0x20..0x24].copy_from_slice(b"hsqs");
    bytes[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x2C..0x30].copy_from_slice(&4_096u32.to_le_bytes());
    bytes[0x34..0x36].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x3C..0x3E].copy_from_slice(&4u16.to_le_bytes());
    bytes[0x3E..0x40].copy_from_slice(&0u16.to_le_bytes());
    bytes[0x20 + 40..0x20 + 48].copy_from_slice(&(96_u64).to_le_bytes());
    fs::write(&firmware, &bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--offset",
            "0x20",
            "--format",
            "squashfs",
            "--output",
            output_path.to_str().expect("output path"),
        ])
        .output()
        .expect("fat carve runs");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read(&output_path).expect("carved output"),
        bytes[0x20..0x20 + 96]
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("format: squashfs"), "{stdout}");
    assert!(stdout.contains("size: 96"), "{stdout}");
}

#[test]
fn fat_carve_squashfs_rejects_magic_with_an_unbounded_declared_size() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("not-squashfs.bin");
    let mut bytes = vec![0u8; 96];
    bytes[..4].copy_from_slice(b"hsqs");
    bytes[40..48].copy_from_slice(&4_096u64.to_le_bytes());
    fs::write(&firmware, bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--offset",
            "0",
            "--format",
            "squashfs",
        ])
        .output()
        .expect("fat carve runs");

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("valid SquashFS image not found at requested offset"),
        "{output:?}"
    );
}

#[test]
fn fat_carve_gzip_infers_exact_validated_member_span() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("firmware.bin");
    let output_path = temp.path().join("kernel.gz");
    let member = named_gzip_member();
    let mut bytes = vec![0xAA; 0x20];
    bytes.extend_from_slice(&member);
    bytes.extend_from_slice(&[0xBB; 16]);
    fs::write(&firmware, &bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--offset",
            "0x20",
            "--format",
            "gzip",
            "--output",
            output_path.to_str().expect("output path"),
        ])
        .output()
        .expect("fat carve runs");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&output_path).expect("carved output"), member);
}

#[test]
fn fat_carve_cramfs_infers_declared_image_size() {
    let temp = tempdir().expect("temp dir");
    let firmware = temp.path().join("firmware.bin");
    let output_path = temp.path().join("rootfs.cramfs");
    let image = cramfs_image(96);
    let mut bytes = vec![0xAA; 0x80];
    bytes.extend_from_slice(&image);
    bytes.extend_from_slice(&[0xBB; 16]);
    fs::write(&firmware, &bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--offset",
            "0x80",
            "--format",
            "cramfs",
            "--output",
            output_path.to_str().expect("output path"),
        ])
        .output()
        .expect("fat carve runs");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&output_path).expect("carved output"), image);
}

#[test]
fn fat_carve_rejects_corrupt_gzip_and_truncated_cramfs() {
    let temp = tempdir().expect("temp dir");
    let gzip_path = temp.path().join("corrupt-gzip.bin");
    let mut gzip = named_gzip_member();
    gzip[45] ^= 0xFF;
    fs::write(&gzip_path, &gzip).expect("gzip firmware");

    let gzip_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            gzip_path.to_str().expect("gzip path"),
            "--offset",
            "0",
            "--format",
            "gzip",
        ])
        .output()
        .expect("fat carve runs");
    assert!(!gzip_output.status.success(), "{gzip_output:?}");
    assert!(
        String::from_utf8_lossy(&gzip_output.stderr)
            .contains("valid gzip member not found at requested offset"),
        "{gzip_output:?}"
    );

    let cramfs_path = temp.path().join("truncated-cramfs.bin");
    let truncated = cramfs_image(96)[..80].to_vec();
    fs::write(&cramfs_path, truncated).expect("cramfs firmware");
    let cramfs_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "carve",
            "--file",
            cramfs_path.to_str().expect("cramfs path"),
            "--offset",
            "0",
            "--format",
            "cramfs",
        ])
        .output()
        .expect("fat carve runs");
    assert!(!cramfs_output.status.success(), "{cramfs_output:?}");
    assert!(
        String::from_utf8_lossy(&cramfs_output.stderr)
            .contains("valid CramFS image not found at requested offset"),
        "{cramfs_output:?}"
    );
}

fn named_gzip_member() -> Vec<u8> {
    vec![
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ]
}

fn cramfs_image(image_size: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; image_size as usize];
    bytes[0..4].copy_from_slice(&0x28cd_3d45u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&image_size.to_le_bytes());
    bytes[16..32].copy_from_slice(b"Compressed ROMFS");
    bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
    bytes
}
