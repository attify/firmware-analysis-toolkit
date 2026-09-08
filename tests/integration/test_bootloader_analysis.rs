#[test]
fn bootloader_analyzer_detects_zero_bootdelay_and_truthy_sig_check() {
    let input = r#"
U-Boot 2024.01
bootdelay=0
sig_check=yes
verify=yes
recovery_mode=0
"#;

    let snapshot = fat_analyze::bootloader::analyze_text(input);
    assert_eq!(snapshot.family.as_deref(), Some("u-boot"));
    assert!(snapshot
        .flow_hints
        .iter()
        .any(|hint| hint.value == "bootdelay=0"));
    assert!(snapshot.env_variables.iter().any(|v| v.key == "sig_check"));
    assert!(
        !snapshot.findings.iter().any(|f| f == "BOOT-SIG-BYPASS"),
        "truthy sig_check must not be treated as a bypass"
    );
}

#[test]
fn bootloader_analyzer_emits_bypass_for_disabled_sig_check() {
    let snapshot = fat_analyze::bootloader::analyze_text("sig_check=no\n");

    assert!(snapshot.findings.iter().any(|f| f == "BOOT-SIG-BYPASS"));
}

#[test]
fn bootloader_analyzer_ignores_garbage_binary_assignments() {
    let input = r#"
U-Boot 2023.01
*=current mode
-=unusable mode
bootdelay=2
sig_check=yes
verify=yes
"#;

    let snapshot = fat_analyze::bootloader::analyze_text(input);

    assert!(snapshot.env_variables.iter().any(|v| v.key == "bootdelay"));
    assert!(snapshot.env_variables.iter().any(|v| v.key == "sig_check"));
    assert!(!snapshot.env_variables.iter().any(|v| v.key == "*"));
    assert!(!snapshot.env_variables.iter().any(|v| v.key == "-"));
}

#[test]
fn bootloader_analyzer_parses_legacy_uimage_headers_from_firmware_bytes() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&wyze_style_uimage_bytes())
        .expect("uimage parse succeeds");

    assert_eq!(snapshot.family.as_deref(), Some("u-boot"));
    assert!(snapshot
        .findings
        .iter()
        .any(|finding| finding == "BOOT-UIMAGE-CRC32-ONLY"));
    assert_eq!(snapshot.image_headers.len(), 2);

    let outer = &snapshot.image_headers[0];
    assert_eq!(outer.format, "uimage");
    assert_eq!(outer.offset, 0);
    assert_eq!(outer.header_size, 64);
    assert_eq!(outer.data_size, 0x008E_F000);
    assert_eq!(outer.header_crc32_hex, "0xF4591363");
    assert_eq!(outer.data_crc32_hex, "0x31189874");
    assert_eq!(outer.timestamp_unix, 0x633B_BA09);
    assert_eq!(outer.name.as_deref(), Some("jz_fw"));
    assert_eq!(outer.operating_system.as_deref(), Some("linux"));
    assert_eq!(outer.architecture.as_deref(), Some("mips"));
    assert_eq!(outer.image_type.as_deref(), Some("firmware"));
    assert_eq!(outer.compression.as_deref(), Some("none"));

    let inner = &snapshot.image_headers[1];
    assert_eq!(inner.offset, 0x40);
    assert_eq!(
        inner.name.as_deref(),
        Some("Linux-3.10.14__isvp_swan_1.0__")
    );
    assert_eq!(inner.image_type.as_deref(), Some("kernel"));
}

#[test]
fn bootloader_analyzer_detects_embedded_signatures_without_uimage_headers() {
    let snapshot =
        fat_analyze::bootloader::analyze_firmware_bytes(&structured_signature_firmware_bytes())
            .expect("signature scan succeeds");

    assert!(snapshot.image_headers.is_empty());
    assert!(snapshot
        .embedded_signatures
        .iter()
        .any(|signature| signature.format == "lzma" && signature.offset == 0x20));
    assert!(snapshot
        .embedded_signatures
        .iter()
        .any(|signature| signature.format == "squashfs" && signature.offset == 0x80));
    assert!(snapshot
        .embedded_signatures
        .iter()
        .any(|signature| signature.format == "gzip" && signature.offset == 0xC0));
    assert_eq!(snapshot.compression_members.len(), 2);
    assert_eq!(snapshot.filesystem_headers.len(), 1);

    let lzma = snapshot
        .compression_members
        .iter()
        .find(|member| member.format == "lzma")
        .expect("lzma member");
    assert_eq!(lzma.offset, 0x20);
    assert_eq!(lzma.properties_hex.as_deref(), Some("0x5D"));
    assert_eq!(lzma.dictionary_size, Some(1 << 23));
    assert_eq!(lzma.uncompressed_size, Some(111_464));

    let gzip = snapshot
        .compression_members
        .iter()
        .find(|member| member.format == "gzip")
        .expect("gzip member");
    assert_eq!(gzip.offset, 0xC0);
    assert_eq!(gzip.operating_system.as_deref(), Some("unix"));
    assert_eq!(gzip.timestamp_unix, Some(1_700_000_255));
    assert_eq!(gzip.uncompressed_size, Some(12));

    let squashfs = &snapshot.filesystem_headers[0];
    assert_eq!(squashfs.format, "squashfs");
    assert_eq!(squashfs.offset, 0x80);
    assert_eq!(squashfs.endianness.as_deref(), Some("little"));
    assert_eq!(squashfs.version.as_deref(), Some("4.0"));
    assert_eq!(squashfs.compression.as_deref(), Some("xz"));
    assert_eq!(squashfs.inode_count, Some(1_064));
    assert_eq!(squashfs.block_size, Some(262_144));
    assert_eq!(squashfs.image_size, Some(5_955_826));
    assert_eq!(squashfs.created_unix, Some(1_636_595_875));
}

#[test]
fn bootloader_analyzer_parses_big_endian_cramfs_superblock() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&cramfs_be_firmware_bytes())
        .expect("cramfs parse succeeds");

    let cramfs = snapshot
        .filesystem_headers
        .iter()
        .find(|header| header.format == "cramfs" && header.offset == 0x40)
        .expect("cramfs filesystem header");
    assert_eq!(cramfs.endianness.as_deref(), Some("big"));
    assert_eq!(cramfs.inode_count, Some(3_861));
    assert_eq!(cramfs.image_size, Some(0x0016_0100));
    assert_eq!(cramfs.block_size, Some(4_096));
}

fn cramfs_be_firmware_bytes() -> Vec<u8> {
    let image_size = 0x0016_0100u32;
    let mut bytes = vec![0u8; 0x40 + image_size as usize];
    let sb = &mut bytes[0x40..0x40 + 64];
    sb[0..4].copy_from_slice(&0x28cd_3d45u32.to_be_bytes());
    sb[4..8].copy_from_slice(&image_size.to_be_bytes());
    sb[8..12].copy_from_slice(&0x3u32.to_be_bytes());
    sb[16..32].copy_from_slice(b"Compressed ROMFS");
    sb[32..36].copy_from_slice(&0xd081_fdcdu32.to_be_bytes());
    sb[40..44].copy_from_slice(&15_409u32.to_be_bytes());
    sb[44..48].copy_from_slice(&3_861u32.to_be_bytes());
    sb[48..58].copy_from_slice(b"Compressed");
    bytes
}

#[test]
fn bootloader_analyzer_parses_gzip_original_name_and_member_span() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&named_gzip_firmware_bytes())
        .expect("gzip parse succeeds");

    let gzip = snapshot
        .compression_members
        .iter()
        .find(|member| member.format == "gzip" && member.offset == 0x20)
        .expect("named gzip member");
    assert_eq!(gzip.original_name.as_deref(), Some("vmlinux.64"));
    assert_eq!(gzip.operating_system.as_deref(), Some("unix"));
    assert_eq!(gzip.timestamp_unix, Some(1_639_479_107));
    assert_eq!(gzip.uncompressed_size, Some(22));
    assert_eq!(gzip.compressed_size, Some(53));
}

#[test]
fn bootloader_analyzer_keeps_valid_gzip_with_an_unreportable_optional_name() {
    let mut bytes = named_gzip_firmware_bytes();
    bytes[0x20 + 10] = 0xff;

    let member = fat_analyze::firmware_formats::scan(&bytes)
        .compression_members
        .into_iter()
        .find(|member| member.format == "gzip")
        .expect("valid gzip member");
    assert_eq!(member.original_name, None);
    assert_eq!(member.compressed_size, Some(53));
}

fn named_gzip_firmware_bytes() -> Vec<u8> {
    let member = [
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ];
    let mut bytes = vec![0u8; 0x20 + member.len() + 16];
    bytes[0x20..0x20 + member.len()].copy_from_slice(&member);
    bytes
}

#[test]
fn reusable_native_format_scanner() {
    let gzip_scan = fat_analyze::firmware_formats::scan(&named_gzip_firmware_bytes());
    assert_eq!(gzip_scan.compression_members.len(), 1);
    assert_eq!(gzip_scan.compression_members[0].format, "gzip");
    assert_eq!(gzip_scan.compression_members[0].offset, 0x20);

    let cramfs_scan = fat_analyze::firmware_formats::scan(&cramfs_be_firmware_bytes());
    assert_eq!(cramfs_scan.filesystem_headers.len(), 1);
    assert_eq!(cramfs_scan.filesystem_headers[0].format, "cramfs");
    assert_eq!(cramfs_scan.filesystem_headers[0].offset, 0x40);
}

#[test]
fn native_scanner_accepts_only_structurally_valid_jffs2_runs() {
    for endian in [
        firmware_formats::FixtureEndian::Little,
        firmware_formats::FixtureEndian::Big,
    ] {
        let image = firmware_formats::jffs2_fixture(endian);
        let scan = fat_analyze::firmware_formats::scan(&image);
        let header = scan
            .filesystem_headers
            .iter()
            .find(|header| header.format == "jffs2")
            .expect("JFFS2 header");
        assert_eq!(header.offset, 0);
        assert_eq!(header.image_size, Some(image.len() as u64));

        let mut embedded = vec![0xa5];
        embedded.extend_from_slice(&image);
        assert!(fat_analyze::firmware_formats::scan(&embedded)
            .filesystem_headers
            .iter()
            .any(|header| header.format == "jffs2" && header.offset == 1));

        let mut bad_crc = image.clone();
        firmware_formats::corrupt_jffs2_header_crc(&mut bad_crc);
        assert!(fat_analyze::firmware_formats::scan(&bad_crc)
            .filesystem_headers
            .iter()
            .all(|header| header.format != "jffs2"));

        let mut bad_length = image.clone();
        firmware_formats::set_jffs2_second_totlen(&mut bad_length, endian, 8);
        assert!(fat_analyze::firmware_formats::scan(&bad_length)
            .filesystem_headers
            .iter()
            .all(|header| header.format != "jffs2"));

        let mut unsupported = image.clone();
        firmware_formats::set_jffs2_second_node_type(&mut unsupported, endian, 0x9999);
        assert!(fat_analyze::firmware_formats::scan(&unsupported)
            .filesystem_headers
            .iter()
            .all(|header| header.format != "jffs2"));

        let truncated = &image[..image.len() - 1];
        assert!(fat_analyze::firmware_formats::scan(truncated)
            .filesystem_headers
            .iter()
            .all(|header| header.format != "jffs2"));
    }

    assert!(fat_analyze::firmware_formats::scan(&[0x85, 0x19, 0, 0])
        .filesystem_headers
        .iter()
        .all(|header| header.format != "jffs2"));
}

#[test]
fn native_scanner_validates_ubi_eraseblocks_and_nested_ubifs_nodes() {
    let fixture = firmware_formats::ubi_ubifs_fixture();
    let mut repeated_image = fixture.image.clone();
    let extra_peb = repeated_image[fixture.peb_size..fixture.peb_size * 2].to_vec();
    repeated_image.extend_from_slice(&extra_peb);
    repeated_image.extend_from_slice(&extra_peb);
    let scan = fat_analyze::firmware_formats::scan(&repeated_image);
    let ubi = scan
        .filesystem_headers
        .iter()
        .find(|header| header.format == "ubi")
        .expect("UBI header");
    assert_eq!(ubi.offset, 0);
    assert_eq!(ubi.block_size, Some(fixture.peb_size as u32));
    assert_eq!(ubi.image_size, Some(repeated_image.len() as u64));
    assert_eq!(
        scan.filesystem_headers
            .iter()
            .filter(|header| header.format == "ubi")
            .count(),
        1,
        "one validated UBI image must not be re-reported from each eraseblock"
    );
    let ubifs = scan
        .filesystem_headers
        .iter()
        .find(|header| header.format == "ubifs")
        .expect("UBIFS header");
    assert_eq!(ubifs.offset, fixture.ubifs_offset as u64);
    assert_eq!(ubifs.image_size, Some(24));

    let mut embedded = vec![0xa5];
    embedded.extend_from_slice(&fixture.image);
    let embedded_scan = fat_analyze::firmware_formats::scan(&embedded);
    assert!(embedded_scan
        .filesystem_headers
        .iter()
        .any(|header| header.format == "ubi" && header.offset == 1));
    assert!(embedded_scan.filesystem_headers.iter().any(|header| {
        header.format == "ubifs" && header.offset == fixture.ubifs_offset as u64 + 1
    }));

    let mut bad_crc = firmware_formats::ubi_ubifs_fixture();
    bad_crc.corrupt_first_ec_crc();
    assert!(fat_analyze::firmware_formats::scan(&bad_crc.image)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "ubi"));

    let mut bad_version = firmware_formats::ubi_ubifs_fixture();
    bad_version.set_first_version(2);
    assert!(fat_analyze::firmware_formats::scan(&bad_version.image)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "ubi"));

    let mut bad_offset = firmware_formats::ubi_ubifs_fixture();
    bad_offset.set_first_data_offset(0x42);
    assert!(fat_analyze::firmware_formats::scan(&bad_offset.image)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "ubi"));

    let mut bad_ubifs_crc = firmware_formats::ubi_ubifs_fixture();
    bad_ubifs_crc.corrupt_ubifs_crc();
    assert!(fat_analyze::firmware_formats::scan(&bad_ubifs_crc.image)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "ubifs"));

    let mut bad_ubifs_len = firmware_formats::ubi_ubifs_fixture();
    bad_ubifs_len.set_ubifs_length(20);
    assert!(fat_analyze::firmware_formats::scan(&bad_ubifs_len.image)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "ubifs"));
}

#[test]
fn native_scanner_validates_complete_cpio_newc_archives() {
    let archive = firmware_formats::cpio_newc_fixture();
    let scan = fat_analyze::firmware_formats::scan(&archive);
    let header = scan
        .filesystem_headers
        .iter()
        .find(|header| header.format == "cpio-newc")
        .expect("CPIO newc archive");
    assert_eq!(header.offset, 0);
    assert_eq!(header.inode_count, Some(1));
    assert_eq!(header.image_size, Some(archive.len() as u64));

    let mut embedded = vec![0xa5];
    embedded.extend_from_slice(&archive);
    let embedded_header = fat_analyze::firmware_formats::scan(&embedded)
        .filesystem_headers
        .into_iter()
        .find(|header| header.format == "cpio-newc")
        .expect("unaligned embedded CPIO newc archive");
    assert_eq!(embedded_header.offset, 1);
    assert_eq!(embedded_header.image_size, Some(archive.len() as u64));

    let crc_archive = firmware_formats::cpio_crc_fixture();
    assert!(fat_analyze::firmware_formats::scan(&crc_archive)
        .filesystem_headers
        .iter()
        .any(|header| header.format == "cpio-newc"));
    let mut bad_checksum = crc_archive;
    bad_checksum[118] ^= 1;
    assert!(fat_analyze::firmware_formats::scan(&bad_checksum)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "cpio-newc"));

    let mut bad_hex = archive.clone();
    bad_hex[6] = b'g';
    assert!(fat_analyze::firmware_formats::scan(&bad_hex)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "cpio-newc"));

    let truncated = &archive[..archive.len() - 1];
    assert!(fat_analyze::firmware_formats::scan(truncated)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "cpio-newc"));

    let first_name_size = 6 + 11 * 8;
    let mut missing_name_terminator = archive.clone();
    missing_name_terminator[110 + 4] = b'X';
    assert!(
        fat_analyze::firmware_formats::scan(&missing_name_terminator)
            .filesystem_headers
            .iter()
            .all(|header| header.format != "cpio-newc")
    );

    let mut impossible_name_size = archive;
    impossible_name_size[first_name_size..first_name_size + 8].copy_from_slice(b"ffffffff");
    assert!(fat_analyze::firmware_formats::scan(&impossible_name_size)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "cpio-newc"));
}

#[test]
fn native_scanner_classifies_bounded_ext_filesystem_generations() {
    for (kind, expected) in [
        (firmware_formats::ExtFixtureKind::Ext2, "ext2"),
        (firmware_formats::ExtFixtureKind::Ext3, "ext3"),
        (firmware_formats::ExtFixtureKind::Ext4, "ext4"),
    ] {
        let image = firmware_formats::ext_filesystem_fixture(kind);
        let mut firmware = vec![0xa5; 0x200];
        firmware.extend_from_slice(&image);
        let header = fat_analyze::firmware_formats::scan(&firmware)
            .filesystem_headers
            .into_iter()
            .find(|header| header.format == expected)
            .expect("ext filesystem header");
        assert_eq!(header.offset, 0x200);
        assert_eq!(header.block_size, Some(1_024));
        assert_eq!(header.inode_count, Some(32));
        assert_eq!(header.image_size, Some(image.len() as u64));
    }

    let mut bad_block_size =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2);
    firmware_formats::set_ext_log_block_size(&mut bad_block_size, 32);
    assert_no_ext_header(&bad_block_size);

    let mut bad_magic =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2);
    bad_magic[0x438] ^= 0xff;
    assert_no_ext_header(&bad_magic);

    let mut zero_inodes =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2);
    firmware_formats::set_ext_inode_count(&mut zero_inodes, 0);
    assert_no_ext_header(&zero_inodes);

    let mut zero_blocks =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2);
    firmware_formats::set_ext_block_count(&mut zero_blocks, 0);
    assert_no_ext_header(&zero_blocks);

    let mut oversized =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2);
    firmware_formats::set_ext_block_count(&mut oversized, u32::MAX);
    assert_no_ext_header(&oversized);

    let mut unsupported =
        firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext4);
    firmware_formats::set_ext_incompat_features(&mut unsupported, 0x8000_0000);
    assert_no_ext_header(&unsupported);

    let truncated =
        &firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext2)[..1_100];
    assert_no_ext_header(truncated);
}

#[test]
fn bootloader_analyzer_distinguishes_structurally_valid_fit_and_fdt() {
    for (fit, expected) in [(false, "fdt"), (true, "fit")] {
        let fixture = firmware_formats::fdt_fixture(fit);
        let mut firmware = vec![0xa5; 0x100];
        firmware.extend_from_slice(&fixture.image);
        let snapshot =
            fat_analyze::bootloader::analyze_firmware_bytes(&firmware).expect("firmware analysis");
        let header = snapshot
            .container_headers
            .iter()
            .find(|header| header.format == expected)
            .expect("FDT-family container");
        assert_eq!(header.offset, 0x100);
        assert_eq!(header.header_size, 40);
        assert_eq!(
            header.declared_payload_size,
            Some(fixture.image.len() as u64)
        );
        assert_eq!(
            header.payload_type.as_deref(),
            Some(if fit {
                "boot image tree"
            } else {
                "device tree blob"
            })
        );
    }

    let mut oversized = firmware_formats::fdt_fixture(false);
    oversized.set_total_size(u32::MAX);
    assert_no_fdt_header(&oversized.image);

    let mut bad_blocks = firmware_formats::fdt_fixture(false);
    bad_blocks.set_structure_offset(41);
    assert_no_fdt_header(&bad_blocks.image);

    let mut bad_version = firmware_formats::fdt_fixture(false);
    bad_version.set_version(15, 16);
    assert_no_fdt_header(&bad_version.image);

    let mut bad_reserve_map = firmware_formats::fdt_fixture(false);
    bad_reserve_map.remove_reserve_terminator();
    assert_no_fdt_header(&bad_reserve_map.image);

    let mut bad_token = firmware_formats::fdt_fixture(false);
    bad_token.set_first_structure_token(0xfeed);
    assert_no_fdt_header(&bad_token.image);

    let mut bad_string_offset = firmware_formats::fdt_fixture(false);
    bad_string_offset.set_property_name_offset(u32::MAX);
    assert_no_fdt_header(&bad_string_offset.image);

    let mut unterminated_name = firmware_formats::fdt_fixture(false);
    unterminated_name.remove_root_name_terminator();
    assert_no_fdt_header(&unterminated_name.image);
}

#[test]
fn bootloader_analyzer_accepts_only_crc_valid_ordered_trx_containers() {
    let fixture = firmware_formats::trx_fixture();
    let mut firmware = vec![0xa5; 0x80];
    firmware.extend_from_slice(&fixture.image);
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&firmware).expect("analysis");
    let header = snapshot
        .container_headers
        .iter()
        .find(|header| header.format == "trx")
        .expect("TRX container");
    assert_eq!(header.offset, 0x80);
    assert_eq!(header.header_size, 28);
    assert_eq!(
        header.declared_payload_size,
        Some(fixture.image.len() as u64)
    );
    assert_eq!(header.integrity_status.as_deref(), Some("CRC32 ok"));
    assert_eq!(
        header.payload_marker.as_deref(),
        Some("partitions@0x1C,0x80")
    );

    let v2 = firmware_formats::trx_v2_fixture();
    let v2_snapshot =
        fat_analyze::bootloader::analyze_firmware_bytes(&v2.image).expect("v2 analysis");
    let v2_header = v2_snapshot
        .container_headers
        .iter()
        .find(|header| header.format == "trx")
        .expect("TRX v2 container");
    assert_eq!(v2_header.header_size, 32);
    assert_eq!(
        v2_header.payload_marker.as_deref(),
        Some("partitions@0x20,0x60,0xA0,0xC0")
    );

    let mut bad_crc = firmware_formats::trx_fixture();
    bad_crc.corrupt_crc();
    assert_no_trx_header(&bad_crc.image);

    let mut short = firmware_formats::trx_fixture();
    short.set_length(20);
    assert_no_trx_header(&short.image);

    let mut oversized = firmware_formats::trx_fixture();
    oversized.set_length(u32::MAX);
    assert_no_trx_header(&oversized.image);

    let mut unordered = firmware_formats::trx_fixture();
    unordered.set_partition_offsets([0x80, 0x40, 0]);
    assert_no_trx_header(&unordered.image);

    let mut out_of_range = firmware_formats::trx_fixture();
    out_of_range.set_partition_offsets([28, 0x100, 0]);
    assert_no_trx_header(&out_of_range.image);

    assert_no_trx_header(b"HDR0 magic without a complete header");
}

fn assert_no_trx_header(bytes: &[u8]) {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(bytes).expect("analysis");
    assert!(snapshot
        .container_headers
        .iter()
        .all(|header| header.format != "trx"));
}

#[test]
fn aggregate_native_scan_is_deterministic_across_all_supported_format_families() {
    let mut firmware = Vec::new();
    append_aligned(&mut firmware, &firmware_formats::named_gzip_member());
    append_aligned(
        &mut firmware,
        &firmware_formats::jffs2_fixture(firmware_formats::FixtureEndian::Little),
    );
    let ubi = firmware_formats::ubi_ubifs_fixture();
    append_aligned(&mut firmware, &ubi.image);
    append_aligned(&mut firmware, &firmware_formats::cpio_newc_fixture());
    append_aligned(
        &mut firmware,
        &firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext4),
    );
    append_aligned(&mut firmware, &squashfs_fixture());
    let cramfs = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Little);
    append_aligned(&mut firmware, &cramfs.image);
    append_aligned(&mut firmware, &firmware_formats::fdt_fixture(true).image);
    append_aligned(&mut firmware, &firmware_formats::trx_fixture().image);

    let first = fat_analyze::firmware_formats::scan(&firmware);
    let second = fat_analyze::firmware_formats::scan(&firmware);
    assert_eq!(first, second);

    let filesystem_formats = first
        .filesystem_headers
        .iter()
        .map(|header| header.format.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for expected in [
        "jffs2",
        "ubi",
        "ubifs",
        "cpio-newc",
        "ext4",
        "squashfs",
        "cramfs",
    ] {
        assert!(filesystem_formats.contains(expected), "missing {expected}");
    }
    assert!(first
        .compression_members
        .iter()
        .any(|member| member.format == "gzip"));
    assert!(first
        .container_headers
        .iter()
        .any(|header| header.format == "fit"));
    assert!(first
        .container_headers
        .iter()
        .any(|header| header.format == "trx"));
    assert!(first
        .filesystem_headers
        .windows(2)
        .all(|pair| pair[0].offset < pair[1].offset));
}

#[test]
fn gzip_kernel_peek_is_bounded_and_reports_only_valid_elf_identity() {
    for (class_64, little_endian, expected_architecture) in [
        (false, true, "mips (little-endian)"),
        (false, false, "mips (big-endian)"),
        (true, true, "mips64 (little-endian)"),
        (true, false, "mips64 (big-endian)"),
    ] {
        let gzip = firmware_formats::gzip_elf_fixture(class_64, little_endian);
        let member = fat_analyze::firmware_formats::scan(&gzip)
            .compression_members
            .into_iter()
            .find(|member| member.format == "gzip")
            .expect("gzip member");
        assert_eq!(member.payload_format.as_deref(), Some("ELF"));
        assert_eq!(
            member.payload_architecture.as_deref(),
            Some(expected_architecture)
        );

        let layout = fat_analyze::bootloader::analyze_layout_bytes(&gzip).expect("layout");
        let region = layout
            .regions
            .iter()
            .find(|region| region.format == "gzip")
            .expect("gzip region");
        assert_eq!(region.kernel_format.as_deref(), Some("ELF"));
        assert_eq!(region.architecture.as_deref(), Some(expected_architecture));
    }

    let non_elf = firmware_formats::named_gzip_member();
    let non_elf_member = fat_analyze::firmware_formats::scan(&non_elf)
        .compression_members
        .into_iter()
        .find(|member| member.format == "gzip")
        .expect("gzip member");
    assert!(non_elf_member.payload_format.is_none());
    assert!(non_elf_member.payload_architecture.is_none());

    let truncated_elf = firmware_formats::gzip_payload(b"\x7fELF\x02\x02\x01", "vmlinux");
    let truncated_member = fat_analyze::firmware_formats::scan(&truncated_elf)
        .compression_members
        .into_iter()
        .find(|member| member.format == "gzip")
        .expect("gzip member");
    assert!(truncated_member.payload_format.is_none());

    let mut beyond_peek = vec![0u8; 128];
    beyond_peek[96..100].copy_from_slice(b"\x7fELF");
    let beyond_gzip = firmware_formats::gzip_payload(&beyond_peek, "vmlinux");
    let beyond_member = fat_analyze::firmware_formats::scan(&beyond_gzip)
        .compression_members
        .into_iter()
        .find(|member| member.format == "gzip")
        .expect("gzip member");
    assert!(beyond_member.payload_format.is_none());
}

fn append_aligned(firmware: &mut Vec<u8>, image: &[u8]) -> usize {
    while !firmware.len().is_multiple_of(0x100) {
        firmware.push(0);
    }
    let offset = firmware.len();
    firmware.extend_from_slice(image);
    offset
}

fn squashfs_fixture() -> Vec<u8> {
    let mut image = vec![0u8; 0x100];
    let image_len = image.len() as u64;
    image[0..4].copy_from_slice(b"hsqs");
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[12..16].copy_from_slice(&4_096u32.to_le_bytes());
    image[20..22].copy_from_slice(&1u16.to_le_bytes());
    image[28..30].copy_from_slice(&4u16.to_le_bytes());
    image[40..48].copy_from_slice(&image_len.to_le_bytes());
    image
}

#[test]
fn native_scanner_rejects_unbounded_or_implausible_squashfs_headers() {
    let valid = squashfs_fixture();
    assert!(fat_analyze::firmware_formats::scan(&valid)
        .filesystem_headers
        .iter()
        .any(|header| header.format == "squashfs"));

    let mut truncated = valid.clone();
    truncated[40..48].copy_from_slice(&0x200u64.to_le_bytes());
    assert!(fat_analyze::firmware_formats::scan(&truncated)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "squashfs"));

    let mut bad_block_size = valid.clone();
    bad_block_size[12..16].copy_from_slice(&123u32.to_le_bytes());
    assert!(fat_analyze::firmware_formats::scan(&bad_block_size)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "squashfs"));

    let mut unknown_compression = valid.clone();
    unknown_compression[20..22].copy_from_slice(&99u16.to_le_bytes());
    assert!(fat_analyze::firmware_formats::scan(&unknown_compression)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "squashfs"));

    let mut unsupported_version = valid;
    unsupported_version[28..30].copy_from_slice(&3u16.to_le_bytes());
    assert!(fat_analyze::firmware_formats::scan(&unsupported_version)
        .filesystem_headers
        .iter()
        .all(|header| header.format != "squashfs"));
}

fn assert_no_fdt_header(bytes: &[u8]) {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(bytes).expect("analysis");
    assert!(snapshot
        .container_headers
        .iter()
        .all(|header| !matches!(header.format.as_str(), "fit" | "fdt")));
}

fn assert_no_ext_header(bytes: &[u8]) {
    assert!(fat_analyze::firmware_formats::scan(bytes)
        .filesystem_headers
        .iter()
        .all(|header| !matches!(header.format.as_str(), "ext2" | "ext3" | "ext4")));
}

#[test]
fn bootloader_analyzer_drops_gzip_member_with_junk_deflate_stream() {
    // A gzip magic followed by a deflate stream that cannot inflate must not be
    // promoted to a compression member. This is the Moxa inner-hit case:
    // 0x0178ED7B looks like gzip until the deflate stream is actually decoded.
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&junk_gzip_firmware_bytes())
        .expect("analyze succeeds");

    assert!(
        snapshot.compression_members.is_empty(),
        "junk-deflate gzip must not be emitted as a compression member: {:?}",
        snapshot.compression_members
    );
}

#[test]
fn bootloader_analyzer_does_not_panic_on_truncated_gzip_extra_field() {
    // FLG = FEXTRA|FNAME, XLEN = 65535, but the blob is only 32 bytes. The
    // parser must return None instead of slicing past the end.
    let mut bytes = vec![0u8; 32];
    bytes[0..3].copy_from_slice(&[0x1f, 0x8b, 0x08]);
    bytes[3] = 0x04 | 0x08;
    bytes[10..12].copy_from_slice(&65535u16.to_le_bytes());
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&bytes)
        .expect("malformed gzip must not panic");
    assert!(
        snapshot
            .compression_members
            .iter()
            .all(|member| member.format != "gzip"),
        "truncated extra-field gzip must not become a member: {:?}",
        snapshot.compression_members
    );
}

#[test]
fn bootloader_analyzer_drops_gzip_member_with_corrupt_crc() {
    let mut bytes = named_gzip_firmware_bytes();
    let trailer_crc = 0x20 + 53 - 8;
    bytes[trailer_crc] ^= 0xFF;
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&bytes)
        .expect("corrupt-crc gzip must not panic");
    assert!(
        snapshot
            .compression_members
            .iter()
            .all(|member| member.format != "gzip"),
        "CRC-corrupt gzip must not be emitted as a compression member: {:?}",
        snapshot.compression_members
    );
}

fn junk_gzip_firmware_bytes() -> Vec<u8> {
    // 10-byte gzip header (FLG=0, no extra/name/comment), then a deflate stream
    // that begins with a reserved block type (0xFF) and has no valid ISIZE trailer.
    let mut bytes = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    bytes.extend(std::iter::repeat_n(0xFF, 54));
    bytes
}

#[test]
fn bootloader_analyzer_nests_gzip_members_inside_cramfs() {
    let snapshot =
        fat_analyze::bootloader::analyze_firmware_bytes(&cramfs_with_nested_gzip_bytes())
            .expect("nested gzip parse succeeds");

    let gzip_offsets: Vec<u64> = snapshot
        .compression_members
        .iter()
        .filter(|member| member.format == "gzip")
        .map(|member| member.offset)
        .collect();
    assert_eq!(gzip_offsets, vec![0x20, 0xC0]);
    assert!(
        snapshot
            .filesystem_headers
            .iter()
            .any(|header| header.format == "cramfs" && header.offset == 0x80),
        "expected cramfs header at 0x80"
    );

    let report = fat_analyze::bootloader::build_layout_report(&snapshot).expect("layout builds");
    assert_eq!(report.summary.dominant_rootfs_offset, Some(0x80));
    let inner = report
        .regions
        .iter()
        .find(|region| region.offset == 0xC0)
        .expect("inner gzip region");
    assert_eq!(inner.scope.as_str(), "nested");
    assert_eq!(inner.parent_offset, Some(0x80));
    let kernel = report
        .regions
        .iter()
        .find(|region| region.offset == 0x20)
        .expect("kernel gzip region");
    assert_eq!(kernel.role.as_str(), "likely kernel payload");
    assert_eq!(kernel.scope.as_str(), "top-level");
}

fn cramfs_with_nested_gzip_bytes() -> Vec<u8> {
    let kernel = named_gzip_member();
    let nested = real_gzip_member();
    let cramfs_offset = 0x80usize;
    let image_size = 0x200u32;
    let mut bytes = vec![0u8; cramfs_offset + image_size as usize];
    bytes[0x20..0x20 + kernel.len()].copy_from_slice(&kernel);
    write_cramfs_be_superblock(
        &mut bytes[cramfs_offset..cramfs_offset + 64],
        image_size,
        12,
    );
    bytes[0xC0..0xC0 + nested.len()].copy_from_slice(&nested);
    bytes
}

fn named_gzip_member() -> [u8; 53] {
    [
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ]
}

fn real_gzip_member() -> [u8; 32] {
    [
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ]
}

fn write_cramfs_be_superblock(sb: &mut [u8], image_size: u32, inode_count: u32) {
    sb[0..4].copy_from_slice(&0x28cd_3d45u32.to_be_bytes());
    sb[4..8].copy_from_slice(&image_size.to_be_bytes());
    sb[8..12].copy_from_slice(&0x3u32.to_be_bytes());
    sb[16..32].copy_from_slice(b"Compressed ROMFS");
    sb[32..36].copy_from_slice(&0xd081_fdcdu32.to_be_bytes());
    sb[40..44].copy_from_slice(&0u32.to_be_bytes());
    sb[44..48].copy_from_slice(&inode_count.to_be_bytes());
    sb[48..58].copy_from_slice(b"Compressed");
}

#[test]
fn bootloader_analyzer_parses_moxa_rom_partition_map_without_skipping_payloads() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&moxa_like_firmware_bytes())
        .expect("moxa map parse succeeds");

    let header = snapshot
        .container_headers
        .iter()
        .find(|header| header.format == "moxa-rom-map")
        .expect("moxa rom map");
    assert_eq!(header.offset, 0);
    assert_eq!(header.header_size, 32);
    assert_eq!(header.vendor.as_deref(), Some("Moxa"));
    assert_eq!(header.package_name.as_deref(), Some("5.7"));
    assert_eq!(header.payload_type.as_deref(), Some("kernel+cramfs"));

    assert!(
        snapshot
            .compression_members
            .iter()
            .any(|member| member.offset == 0x20
                && member.original_name.as_deref() == Some("vmlinux.64")),
        "kernel gzip must still be parsed after the vendor map"
    );
    let cramfs = snapshot
        .filesystem_headers
        .iter()
        .find(|header| header.format == "cramfs")
        .expect("cramfs after vendor map");
    assert_eq!(cramfs.offset, 0x420);
}

#[test]
fn moxa_layout_serializes_first_class_container_and_member_metadata() {
    let bytes = moxa_like_firmware_bytes();
    let report = fat_analyze::bootloader::analyze_layout_bytes(&bytes).expect("layout");
    let container = report
        .regions
        .iter()
        .find(|region| region.format == "moxa-rom-map")
        .expect("container region");
    assert_eq!(container.kind.as_str(), "container");
    assert_eq!(container.end_offset, Some(bytes.len() as u64));
    assert!(container.span_is_exact);

    let kernel = report
        .regions
        .iter()
        .find(|region| region.format == "gzip")
        .expect("gzip region");
    assert_eq!(kernel.original_name.as_deref(), Some("vmlinux.64"));
    assert_eq!(kernel.parent_offset, Some(0));
    assert_eq!(kernel.scope.as_str(), "nested");
    assert!(kernel.span_is_exact);

    let json = serde_json::to_value(&report).expect("layout JSON");
    let gzip = json["regions"]
        .as_array()
        .and_then(|regions| regions.iter().find(|region| region["format"] == "gzip"))
        .expect("serialized gzip region");
    assert_eq!(gzip["original_name"], "vmlinux.64");
    assert_eq!(gzip["parent_offset"], 0);
    assert_eq!(gzip["span_is_exact"], true);
}

#[test]
fn moxa_layout_names_exact_padding_and_rootfs_to_eof() {
    let bytes = moxa_like_firmware_bytes();
    let report = fat_analyze::bootloader::analyze_layout_bytes(&bytes).expect("layout");
    let container = report
        .regions
        .iter()
        .find(|region| region.kind.as_str() == "container")
        .expect("container");
    let kernel = report
        .regions
        .iter()
        .find(|region| region.format == "gzip")
        .expect("kernel");
    let padding = report
        .regions
        .iter()
        .find(|region| region.kind.as_str() == "padding")
        .expect("padding");
    let rootfs = report
        .regions
        .iter()
        .find(|region| region.format == "cramfs")
        .expect("rootfs");

    assert_eq!(padding.offset, kernel.end_offset.expect("kernel end"));
    assert_eq!(padding.end_offset, Some(rootfs.offset));
    assert_eq!(padding.parent_offset, Some(container.offset));
    assert!(padding.span_is_exact);
    assert!(rootfs.fills_to_eof);
    assert_eq!(rootfs.end_offset, Some(bytes.len() as u64));
    assert_eq!(report.summary.top_level_region_count, 1);
    assert_eq!(report.summary.nested_region_count, 3);
    assert!(report.overlaps.is_empty());
}

#[test]
fn layout_reports_partial_overlaps_without_claiming_containment() {
    let snapshot = fat_core::bootloader::BootloaderSnapshot {
        filesystem_headers: vec![
            fat_core::inspection::FilesystemHeader {
                format: "first".to_string(),
                offset: 0x100,
                image_size: Some(0x100),
                ..Default::default()
            },
            fat_core::inspection::FilesystemHeader {
                format: "second".to_string(),
                offset: 0x180,
                image_size: Some(0x100),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let report = fat_analyze::bootloader::build_layout_report(&snapshot).expect("layout");
    assert!(report
        .regions
        .iter()
        .all(|region| region.parent_offset.is_none()));
    assert_eq!(report.overlaps.len(), 1);
    assert_eq!(report.overlaps[0].start_offset, 0x180);
    assert_eq!(report.overlaps[0].end_offset, 0x200);

    let unknown = fat_core::bootloader::BootloaderSnapshot {
        compression_members: vec![fat_core::inspection::CompressionMember {
            format: "lzma".to_string(),
            offset: 0x20,
            ..Default::default()
        }],
        filesystem_headers: vec![fat_core::inspection::FilesystemHeader {
            format: "cramfs".to_string(),
            offset: 0x100,
            image_size: Some(0x100),
            ..Default::default()
        }],
        ..Default::default()
    };
    let unknown_report =
        fat_analyze::bootloader::build_layout_report(&unknown).expect("unknown layout");
    assert!(unknown_report
        .regions
        .iter()
        .all(|region| region.kind.as_str() != "padding"));
}

fn moxa_like_firmware_bytes() -> Vec<u8> {
    let kernel_slot = 0x400u32;
    let rootfs_size = 0x200u32;
    let kernel_off = 0x20u32;
    let rootfs_off = (kernel_off + kernel_slot) as usize;
    let mut bytes = vec![0u8; rootfs_off + rootfs_size as usize];
    bytes[0..4].copy_from_slice(&kernel_slot.to_be_bytes());
    bytes[4..8].copy_from_slice(&rootfs_size.to_be_bytes());
    bytes[8..12].copy_from_slice(&kernel_off.to_be_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
    bytes[16..20].copy_from_slice(&0x0f85_509cu32.to_be_bytes());
    bytes[20..24].copy_from_slice(&[0x05, 0x07, 0x00, 0x00]);
    bytes[24..28].copy_from_slice(&[0x15, 0x0c, 0x0e, 0x13]);
    let kernel = named_gzip_member();
    bytes[0x20..0x20 + kernel.len()].copy_from_slice(&kernel);
    write_cramfs_be_superblock(&mut bytes[rootfs_off..rootfs_off + 64], rootfs_size, 16);
    bytes
}

#[test]
fn bootloader_analyzer_builds_layout_regions_for_tapo_like_firmware() {
    let report =
        fat_analyze::bootloader::analyze_layout_bytes(&structured_signature_firmware_bytes())
            .expect("layout analysis succeeds");

    assert_eq!(report.summary.top_level_region_count, 2);
    assert_eq!(report.summary.nested_region_count, 1);
    assert_eq!(report.summary.dominant_boot_image_offset, None);
    assert_eq!(report.summary.dominant_rootfs_offset, Some(0x80));
    let json = serde_json::to_value(&report).expect("layout json");
    assert!(
        json.get("guidance").is_none(),
        "unexpected guidance: {json}"
    );

    assert_eq!(report.regions.len(), 3);

    let lzma = report
        .regions
        .iter()
        .find(|region| region.format == "lzma")
        .expect("lzma region");
    assert_eq!(lzma.offset, 0x20);
    assert_eq!(lzma.kind.as_str(), "compression");
    assert_eq!(lzma.role.as_str(), "likely compressed payload");
    assert_eq!(lzma.scope.as_str(), "top-level");
    assert_eq!(lzma.depth, 0);
    assert_eq!(lzma.parent_offset, None);

    let squashfs = report
        .regions
        .iter()
        .find(|region| region.format == "squashfs")
        .expect("squashfs region");
    assert_eq!(squashfs.offset, 0x80);
    assert_eq!(squashfs.kind.as_str(), "filesystem");
    assert_eq!(squashfs.size, Some(5_955_826));
    assert_eq!(squashfs.role.as_str(), "likely rootfs");
    assert_eq!(squashfs.scope.as_str(), "top-level");
    assert_eq!(squashfs.depth, 0);
    assert_eq!(squashfs.parent_offset, None);
    assert!(
        json["regions"]
            .as_array()
            .expect("regions")
            .iter()
            .all(|region| region.get("next_action").is_none()),
        "unexpected region action: {json}"
    );
    assert!(
        squashfs.notes.iter().any(|note| note.contains("xz")),
        "squashfs notes should preserve parsed metadata"
    );

    let gzip = report
        .regions
        .iter()
        .find(|region| region.format == "gzip")
        .expect("gzip region");
    assert_eq!(gzip.offset, 0xC0);
    assert_eq!(gzip.kind.as_str(), "compression");
    assert_eq!(gzip.role.as_str(), "likely archive tail");
    assert_eq!(gzip.scope.as_str(), "nested");
    assert_eq!(gzip.depth, 1);
    assert_eq!(gzip.parent_offset, Some(0x80));
}

#[test]
fn bootloader_analyzer_builds_layout_regions_for_wyze_uimage_firmware() {
    let report = fat_analyze::bootloader::analyze_layout_bytes(&wyze_style_uimage_bytes())
        .expect("layout analysis succeeds");

    assert_eq!(report.summary.top_level_region_count, 1);
    assert_eq!(report.summary.nested_region_count, 1);
    assert_eq!(report.summary.dominant_boot_image_offset, Some(0));
    assert_eq!(report.summary.dominant_rootfs_offset, None);
    let json = serde_json::to_value(&report).expect("layout json");
    assert!(
        json.get("guidance").is_none(),
        "unexpected guidance: {json}"
    );

    assert_eq!(report.regions.len(), 2);

    let outer = &report.regions[0];
    assert_eq!(outer.offset, 0);
    assert_eq!(outer.kind.as_str(), "boot-image");
    assert_eq!(outer.format, "uimage");
    assert_eq!(outer.role.as_str(), "likely boot image");
    assert_eq!(outer.scope.as_str(), "top-level");
    assert_eq!(outer.depth, 0);
    assert_eq!(outer.parent_offset, None);

    let inner = &report.regions[1];
    assert_eq!(inner.offset, 0x40);
    assert_eq!(inner.kind.as_str(), "boot-image");
    assert_eq!(inner.format, "uimage");
    assert_eq!(inner.role.as_str(), "likely kernel payload");
    assert_eq!(inner.scope.as_str(), "nested");
    assert_eq!(inner.depth, 1);
    assert_eq!(inner.parent_offset, Some(0));
    assert!(
        json["regions"]
            .as_array()
            .expect("regions")
            .iter()
            .all(|region| region.get("next_action").is_none()),
        "unexpected region action: {json}"
    );
}

#[test]
fn bootloader_analyzer_maps_kernel_mtdparts_to_filesystem_regions() {
    let snapshot =
        fat_analyze::bootloader::analyze_firmware_bytes(&wyze_partitioned_firmware_bytes())
            .expect("firmware analysis succeeds");

    let cmdline = snapshot
        .kernel_cmdline
        .as_ref()
        .expect("kernel cmdline recovered");
    assert!(cmdline.value.contains("root=/dev/mtdblock2"));
    assert!(cmdline.value.contains("mtdparts=jz_sfc:"));
    assert_eq!(cmdline.source.as_deref(), Some("lzma @ 0x00000080"));

    let map = snapshot.partition_map.as_ref().expect("mtd partition map");
    assert_eq!(map.device, "jz_sfc");
    assert_eq!(map.root_device.as_deref(), Some("/dev/mtdblock2"));
    assert_eq!(map.root_fstype.as_deref(), Some("squashfs"));
    assert_eq!(map.partitions.len(), 8);
    assert_eq!(map.partitions[2].index, 2);
    assert_eq!(map.partitions[2].name, "rootfs");
    assert_eq!(map.partitions[2].size_bytes, 3904 * 1024);
    assert_eq!(map.partitions[2].flash_offset, 0x0023_0000);
    assert_eq!(map.partitions[3].index, 3);
    assert_eq!(map.partitions[3].name, "app");
    assert_eq!(map.partitions[3].flash_offset, 0x0060_0000);

    let report =
        fat_analyze::bootloader::build_layout_report(&snapshot).expect("layout report builds");
    assert_eq!(report.summary.dominant_rootfs_offset, Some(0x001F_0040));

    let rootfs = report
        .regions
        .iter()
        .find(|region| region.offset == 0x001F_0040)
        .expect("rootfs squashfs region");
    let rootfs_partition = rootfs.partition.as_ref().expect("rootfs partition");
    assert_eq!(rootfs.role.as_str(), "likely rootfs");
    assert_eq!(rootfs_partition.mtdblock, 2);
    assert_eq!(rootfs_partition.name, "rootfs");
    assert_eq!(rootfs_partition.mount_point.as_deref(), Some("/"));

    let app = report
        .regions
        .iter()
        .find(|region| region.offset == 0x005C_0040)
        .expect("app squashfs region");
    let app_partition = app.partition.as_ref().expect("app partition");
    assert_eq!(app.role.as_str(), "likely app partition");
    assert_eq!(app_partition.mtdblock, 3);
    assert_eq!(app_partition.name, "app");
    assert_eq!(app_partition.mount_point, None);
}

#[test]
fn bootloader_analyzer_recovers_kernel_mtdparts_from_partial_lzma_output() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(
        &wyze_partitioned_firmware_with_trailing_lzma_garbage(),
    )
    .expect("firmware analysis succeeds");

    let cmdline = snapshot
        .kernel_cmdline
        .as_ref()
        .expect("kernel cmdline recovered from partial decompression output");
    assert!(cmdline.value.contains("root=/dev/mtdblock2"));
    assert!(cmdline.value.contains("mtdparts=jz_sfc:"));
    assert!(
        snapshot.partition_map.is_some(),
        "partial LZMA output should still feed mtdparts parsing"
    );
}

fn wyze_style_uimage_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x80];
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

fn wyze_partitioned_firmware_with_trailing_lzma_garbage() -> Vec<u8> {
    let mut bytes = wyze_partitioned_firmware_bytes();
    let data_size = u32::from_be_bytes(bytes[0x4C..0x50].try_into().unwrap()) as usize;
    let data_size_with_trailer = (data_size + 1) as u32;
    bytes[0x4C..0x50].copy_from_slice(&data_size_with_trailer.to_be_bytes());
    bytes[0x80 + data_size] = 0xFF;
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
    bytes[0xC0..0xE0].copy_from_slice(&[
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ]);
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
#[path = "../support/firmware_formats.rs"]
mod firmware_formats;
