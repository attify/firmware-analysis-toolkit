use std::fs;

use fat_extract::cramfs::{extract_cramfs, CramfsLimits};
use fat_extract::native::{extract_gzip_member, GzipExtractionOptions};
use tempfile::tempdir;

#[path = "../../../tests/support/firmware_formats.rs"]
mod firmware_formats;

const PAYLOAD: &[u8] = b"kernel-payload-for-fat";

#[test]
fn gzip_extraction_writes_exact_member_and_decompressed_payload() {
    let temp = tempdir().expect("temp dir");
    let member = named_gzip_member();
    let result = extract_gzip_member(
        &member,
        temp.path(),
        GzipExtractionOptions {
            original_name: Some("vmlinux.64".into()),
            max_output: 8 * 1024 * 1024,
        },
    )
    .expect("extract gzip");

    assert_eq!(result.decompressed_path.file_name().unwrap(), "vmlinux.64");
    assert_eq!(result.member_path.file_name().unwrap(), "vmlinux.64.gz");
    assert_eq!(fs::read(result.member_path).expect("member"), member);
    assert_eq!(
        fs::read(result.decompressed_path).expect("payload"),
        PAYLOAD
    );
    assert_eq!(result.decompressed_size, PAYLOAD.len() as u64);
}

#[test]
fn gzip_extraction_rejects_crc_isize_trailing_and_output_limit_failures() {
    let temp = tempdir().expect("temp dir");
    let options = || GzipExtractionOptions {
        original_name: None,
        max_output: 8 * 1024 * 1024,
    };

    let mut corrupt_crc = named_gzip_member();
    let crc_index = corrupt_crc.len() - 8;
    corrupt_crc[crc_index] ^= 0xFF;
    assert!(extract_gzip_member(&corrupt_crc, temp.path(), options()).is_err());

    let mut corrupt_isize = named_gzip_member();
    let isize_index = corrupt_isize.len() - 4;
    corrupt_isize[isize_index] ^= 0xFF;
    assert!(extract_gzip_member(&corrupt_isize, temp.path(), options()).is_err());

    let mut trailing = named_gzip_member();
    trailing.extend_from_slice(b"trailing");
    assert!(extract_gzip_member(&trailing, temp.path(), options()).is_err());

    assert!(extract_gzip_member(
        &named_gzip_member(),
        temp.path(),
        GzipExtractionOptions {
            original_name: None,
            max_output: PAYLOAD.len() as u64 - 1,
        },
    )
    .is_err());
}

#[test]
fn gzip_extraction_replaces_unsafe_original_name_with_safe_fallback() {
    let temp = tempdir().expect("temp dir");
    let result = extract_gzip_member(
        &named_gzip_member(),
        temp.path(),
        GzipExtractionOptions {
            original_name: Some("../../vmlinux".into()),
            max_output: 8 * 1024 * 1024,
        },
    )
    .expect("extract with fallback");

    assert_eq!(
        result.decompressed_path.file_name().unwrap(),
        "gzip-member.bin"
    );
    assert!(result.decompressed_path.starts_with(temp.path()));
}

#[test]
fn cramfs_extracts_little_and_big_endian_filesystems() {
    for endian in [
        firmware_formats::FixtureEndian::Little,
        firmware_formats::FixtureEndian::Big,
    ] {
        let temp = tempdir().expect("temp dir");
        let fixture = firmware_formats::cramfs_fixture(endian);
        let destination = temp.path().join("rootfs");
        let result = extract_cramfs(
            &fixture.image,
            &destination,
            CramfsLimits {
                max_inodes: 64,
                max_depth: 16,
                max_file_size: 1024 * 1024,
                max_total_output: 8 * 1024 * 1024,
            },
        )
        .expect("extract CramFS");

        assert_eq!(result.root, destination);
        assert_eq!(
            fs::read(result.root.join("bin/busybox")).unwrap(),
            b"#!/bin/sh\necho busybox\n"
        );
        assert_eq!(
            fs::read(result.root.join("etc/inittab")).unwrap(),
            b"::sysinit:/etc/init.d/rcS\n"
        );
        assert_eq!(fs::read(result.root.join("empty")).unwrap(), b"");
        assert_eq!(
            fs::read(result.root.join("large.bin")).unwrap(),
            fixture.large_file
        );
        assert_eq!(
            fs::read_link(result.root.join("init")).unwrap(),
            std::path::Path::new("bin/busybox")
        );
        assert_eq!(result.files, 4);
        assert_eq!(result.directories, 3);
        assert_eq!(result.symlinks, 1);
        assert_eq!(result.skipped_special, 0);
    }
}

#[test]
fn cramfs_rejects_declared_inode_count_above_limit() {
    let temp = tempdir().expect("temp dir");
    let mut fixture = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    fixture.set_declared_inode_count(65);
    let result = extract_cramfs(&fixture.image, &temp.path().join("rootfs"), cramfs_limits());
    assert!(
        result.is_err(),
        "oversized declared inode count was accepted"
    );
}

#[test]
fn cramfs_rejects_bad_superblock_crc_unknown_flags_and_undeclared_holes() {
    let temp = tempdir().expect("temp dir");
    let mut bad_crc = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    bad_crc.corrupt_crc();
    assert!(extract_cramfs(
        &bad_crc.image,
        &temp.path().join("bad-crc"),
        cramfs_limits(),
    )
    .is_err());

    let mut unknown_flags =
        firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    unknown_flags.set_flags(0x8000_0001);
    assert!(extract_cramfs(
        &unknown_flags.image,
        &temp.path().join("unknown-flags"),
        cramfs_limits(),
    )
    .is_err());

    let mut hole = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    hole.make_busybox_an_undeclared_hole();
    assert!(extract_cramfs(&hole.image, &temp.path().join("hole"), cramfs_limits(),).is_err());
}

#[test]
fn cramfs_accepts_legacy_superblock_without_declared_inode_count() {
    let temp = tempdir().expect("temp dir");
    let mut fixture = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    fixture.set_flags(0);
    extract_cramfs(&fixture.image, &temp.path().join("legacy"), cramfs_limits())
        .expect("legacy CramFS extraction");
}

#[test]
fn cramfs_rejects_unsafe_names_without_path_escape() {
    for name in [*b".\0\0\0", *b"..\0\0", *b"a/b\0", *b"a\0b\0"] {
        let temp = tempdir().expect("temp dir");
        let outside = temp.path().join("outside");
        fs::write(&outside, b"sentinel").expect("sentinel");
        let mut fixture = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
        fixture.replace_init_name(name);
        let destination = temp.path().join("rootfs");
        assert!(extract_cramfs(&fixture.image, &destination, cramfs_limits()).is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
    }
}

#[test]
fn cramfs_rejects_directory_cycles_depth_and_inode_limits() {
    let temp = tempdir().expect("temp dir");
    let mut cyclic = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    cyclic.set_bin_directory_offset(cyclic.root_start);
    assert!(extract_cramfs(&cyclic.image, &temp.path().join("cyclic"), cramfs_limits(),).is_err());

    let fixture = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    let mut depth_limits = cramfs_limits();
    depth_limits.max_depth = 0;
    assert!(extract_cramfs(&fixture.image, &temp.path().join("deep"), depth_limits,).is_err());

    let mut inode_limits = cramfs_limits();
    inode_limits.max_inodes = 2;
    assert!(extract_cramfs(&fixture.image, &temp.path().join("many"), inode_limits,).is_err());
}

#[test]
fn cramfs_enforces_file_and_total_output_limits() {
    let temp = tempdir().expect("temp dir");
    let fixture = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    let mut file_limits = cramfs_limits();
    file_limits.max_file_size = 4_096;
    assert!(extract_cramfs(&fixture.image, &temp.path().join("large"), file_limits,).is_err());

    let mut total_limits = cramfs_limits();
    total_limits.max_total_output = 32;
    assert!(extract_cramfs(&fixture.image, &temp.path().join("total"), total_limits,).is_err());
}

#[test]
fn cramfs_rejects_invalid_block_pointers_and_zlib_output() {
    let temp = tempdir().expect("temp dir");
    let mut decreasing = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    let first_end = decreasing.large_block_pointer(0);
    decreasing.set_large_block_pointer(1, first_end - 1);
    assert!(extract_cramfs(
        &decreasing.image,
        &temp.path().join("decreasing"),
        cramfs_limits(),
    )
    .is_err());

    let mut outside = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    let outside_pointer = outside.image.len() as u32 + 4;
    outside.set_large_block_pointer(1, outside_pointer);
    assert!(extract_cramfs(
        &outside.image,
        &temp.path().join("outside"),
        cramfs_limits(),
    )
    .is_err());

    let mut truncated = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    let first_end = truncated.large_block_pointer(0);
    truncated.set_large_block_pointer(0, first_end - 1);
    assert!(extract_cramfs(
        &truncated.image,
        &temp.path().join("truncated"),
        cramfs_limits(),
    )
    .is_err());

    let mut wrong_size = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    wrong_size.set_large_size(5_136);
    assert!(extract_cramfs(
        &wrong_size.image,
        &temp.path().join("wrong-size"),
        cramfs_limits(),
    )
    .is_err());
}

#[test]
fn cramfs_skips_special_inodes_and_cleans_staging_on_failure() {
    let temp = tempdir().expect("temp dir");
    for (index, mode) in [0o010644, 0o020644, 0o060644, 0o140644]
        .into_iter()
        .enumerate()
    {
        let mut special = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
        special.set_empty_mode(mode);
        let destination = temp.path().join(format!("special-{index}"));
        let result = extract_cramfs(&special.image, &destination, cramfs_limits()).unwrap();
        assert_eq!(result.skipped_special, 1);
        assert!(!destination.join("empty").exists());
    }

    let mut bad = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    bad.replace_init_name(*b"..\0\0");
    let failed_destination = temp.path().join("failed");
    assert!(extract_cramfs(&bad.image, &failed_destination, cramfs_limits()).is_err());
    assert!(!failed_destination.exists());
    assert!(
        fs::read_dir(temp.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fat-cramfs-")),
        "staging directory was not cleaned"
    );
}

fn cramfs_limits() -> CramfsLimits {
    CramfsLimits {
        max_inodes: 64,
        max_depth: 16,
        max_file_size: 1024 * 1024,
        max_total_output: 8 * 1024 * 1024,
    }
}

fn named_gzip_member() -> Vec<u8> {
    vec![
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ]
}
