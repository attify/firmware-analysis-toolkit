use fat_extract::squashfs;
use std::io::ErrorKind;

#[test]
fn rejects_truncated_superblock() {
    assert_eq!(
        squashfs::probe(b"hsqs").unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn identifies_v4_header_without_executing_a_decoder() {
    let image = image(4, false);
    let info = squashfs::probe(&image).unwrap();
    assert_eq!(info.version, "4.0");
    assert_eq!(info.endianness, "little");
    assert_eq!(info.inode_count, 2);
}

#[test]
fn identifies_legacy_headers_in_both_byte_orders() {
    for version in [2, 3] {
        for big in [false, true] {
            let info = squashfs::probe(&image(version, big)).unwrap();
            assert_eq!(info.version, format!("{version}.0"));
            assert_eq!(info.endianness, if big { "big" } else { "little" });
        }
    }
}

fn put(data: &mut [u8], bit: usize, width: usize, value: u64, big: bool) {
    for i in 0..width {
        let source = if big { width - i - 1 } else { i };
        let target = if big {
            7 - (bit + i) % 8
        } else {
            (bit + i) % 8
        };
        data[(bit + i) / 8] |= (((value >> source) & 1) as u8) << target;
    }
}

fn image(version: u16, big: bool) -> Vec<u8> {
    let mut data = vec![0u8; 256];
    data[..4].copy_from_slice(if big { b"sqsh" } else { b"hsqs" });
    put(&mut data, 32, 32, 2, big);
    put(&mut data, 224, 16, version as u64, big);
    if version == 4 {
        put(&mut data, 96, 32, 4096, big);
        put(&mut data, 160, 16, 1, big);
        put(&mut data, 176, 16, 12, big);
        put(&mut data, 320, 64, 256, big);
        put(&mut data, 512, 64, 128, big);
        put(&mut data, 576, 64, 200, big);
    } else {
        put(&mut data, 272, 16, 12, big);
        put(&mut data, 408, 32, 4096, big);
        if version == 3 {
            put(&mut data, 504, 64, 256, big);
            put(&mut data, 696, 64, 128, big);
            put(&mut data, 760, 64, 200, big);
        } else {
            put(&mut data, 64, 32, 256, big);
            put(&mut data, 160, 32, 128, big);
            put(&mut data, 192, 32, 200, big);
        }
    }
    data
}

#[test]
fn recovers_files_and_symlinks_across_versions_and_byte_orders() {
    for version in [2, 3, 4] {
        for big in [false, true] {
            let image = tree_image(version, big, Encoding::Plain);
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("root");
            let mut output =
                fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
            squashfs::extract(&image, &mut output).unwrap();
            let stats = output.finish().unwrap();
            assert_eq!(
                std::fs::read(destination.join("hello.txt")).unwrap(),
                b"hello firmware\n"
            );
            assert_eq!(
                std::fs::read_link(destination.join("link")).unwrap(),
                std::path::Path::new("hello.txt")
            );
            assert_eq!((stats.files, stats.symlinks), (1, 1));
        }
    }
}

#[test]
fn recovers_supported_block_encodings() {
    for (encoding, codec) in [
        (Encoding::Zlib, "zlib"),
        (Encoding::Lzma, "lzma"),
        (Encoding::CompactLzma, "lzma"),
        (Encoding::MarkedLzma, "lzma"),
    ] {
        let image = tree_image(3, true, encoding);
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("root");
        let mut output =
            fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
        assert_eq!(
            squashfs::extract(&image, &mut output).unwrap().compression,
            codec
        );
        output.finish().unwrap();
        assert_eq!(
            std::fs::read(destination.join("hello.txt")).unwrap(),
            b"hello firmware\n"
        );
    }
}

#[test]
fn failed_extraction_does_not_publish_output() {
    let mut image = tree_image(4, false, Encoding::Plain);
    image[32..40].copy_from_slice(&0u64.to_le_bytes());
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("root");
    let mut output =
        fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
    assert!(squashfs::extract(&image, &mut output).is_err());
    drop(output);
    assert!(!destination.exists());
}

#[test]
fn rejects_files_over_the_configured_limit() {
    let image = tree_image(3, true, Encoding::Plain);
    let temp = tempfile::tempdir().unwrap();
    let limits = fat_extract::output::ExtractionLimits {
        max_file_bytes: 4,
        ..Default::default()
    };
    let mut output =
        fat_extract::output::OutputTree::new(&temp.path().join("root"), limits).unwrap();
    assert!(squashfs::extract(&image, &mut output)
        .unwrap_err()
        .to_string()
        .contains("size limit"));
}

#[test]
#[ignore = "requires a local filesystem image"]
fn local_image_recovery() {
    let source = std::env::var_os("FAT_SQUASHFS_IMAGE").expect("FAT_SQUASHFS_IMAGE");
    let destination = std::env::var_os("FAT_SQUASHFS_OUTPUT").expect("FAT_SQUASHFS_OUTPUT");
    let image = std::fs::read(source).unwrap();
    let start = std::time::Instant::now();
    let mut output = fat_extract::output::OutputTree::new(
        std::path::Path::new(&destination),
        Default::default(),
    )
    .unwrap();
    let info = squashfs::extract(&image, &mut output).unwrap();
    let stats = output.finish().unwrap();
    eprintln!(
        "{}",
        serde_json::json!({ "info": info, "stats": stats, "milliseconds": start.elapsed().as_millis() })
    );
}

#[derive(Clone, Copy)]
enum Encoding {
    Plain,
    Zlib,
    Lzma,
    CompactLzma,
    MarkedLzma,
    Xz,
}

fn metadata(data: &[u8], big: bool, encoding: Encoding) -> Vec<u8> {
    use std::io::Write;
    let encoded = match encoding {
        Encoding::Plain => data.to_vec(),
        Encoding::Xz => {
            let mut writer = xz2::write::XzEncoder::new(Vec::new(), 6);
            writer.write_all(data).unwrap();
            writer.finish().unwrap()
        }
        Encoding::Zlib => {
            let mut writer =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(data).unwrap();
            writer.finish().unwrap()
        }
        _ => {
            let mut bytes = Vec::new();
            lzma_rs::lzma_compress(&mut std::io::Cursor::new(data), &mut bytes).unwrap();
            match encoding {
                Encoding::CompactLzma => {
                    bytes.drain(5..13);
                }
                Encoding::MarkedLzma => {
                    bytes.splice(..13, b"7zip".iter().copied());
                }
                _ => {}
            }
            bytes
        }
    };
    let size = encoded.len() as u16
        | if matches!(encoding, Encoding::Plain) {
            0x8000
        } else {
            0
        };
    let mut result = if big {
        size.to_be_bytes().to_vec()
    } else {
        size.to_le_bytes().to_vec()
    };
    result.extend_from_slice(&encoded);
    result
}

fn base(version: u16, big: bool, kind: u64, mode: u64) -> Vec<u8> {
    let mut bytes = vec![
        0;
        match version {
            4 => 16,
            3 => 12,
            _ => 4,
        }
    ];
    if version == 4 {
        put(&mut bytes, 0, 16, kind, big);
        put(&mut bytes, 16, 16, mode, big);
    } else {
        put(&mut bytes, 0, 4, kind, big);
        put(&mut bytes, 4, 12, mode, big);
    }
    bytes
}

fn tree_image(version: u16, big: bool, encoding: Encoding) -> Vec<u8> {
    let content = b"hello firmware\n";
    let mut image = vec![0; 128];
    image.extend_from_slice(content);
    let inode_start = image.len();
    let mut inodes = base(version, big, 2, 0o644);
    let mut tail = vec![0; if version == 4 { 16 } else { 20 }];
    match version {
        4 => {
            put(&mut tail, 0, 32, 128, big);
            put(&mut tail, 32, 32, u32::MAX as u64, big);
            put(&mut tail, 96, 32, content.len() as u64, big);
        }
        3 => {
            put(&mut tail, 0, 64, 128, big);
            put(&mut tail, 64, 32, u32::MAX as u64, big);
            put(&mut tail, 128, 32, content.len() as u64, big);
        }
        _ => {
            put(&mut tail, 32, 32, 128, big);
            put(&mut tail, 64, 32, u32::MAX as u64, big);
            put(&mut tail, 128, 32, content.len() as u64, big);
        }
    }
    inodes.extend_from_slice(&tail);
    let descriptor = 0x0100_0000 | content.len() as u32;
    inodes.extend_from_slice(&if big {
        descriptor.to_be_bytes()
    } else {
        descriptor.to_le_bytes()
    });
    let symlink_offset = inodes.len();
    inodes.extend(base(version, big, 3, 0o777));
    let mut tail = vec![
        0;
        match version {
            4 => 8,
            3 => 6,
            _ => 2,
        }
    ];
    put(
        &mut tail,
        if version == 2 { 0 } else { 32 },
        if version == 4 { 32 } else { 16 },
        9,
        big,
    );
    inodes.extend(tail);
    inodes.extend_from_slice(b"hello.txt");
    let root_offset = inodes.len();
    let mut directories = vec![
        0;
        match version {
            4 => 12,
            3 => 9,
            _ => 4,
        }
    ];
    put(
        &mut directories,
        0,
        if version == 4 { 32 } else { 8 },
        1,
        big,
    );
    for (name, offset, kind) in [
        (b"hello.txt".as_slice(), 0, 2),
        (b"link".as_slice(), symlink_offset, 3),
    ] {
        let mut entry = vec![
            0;
            match version {
                4 => 8,
                3 => 5,
                _ => 3,
            }
        ];
        if version == 4 {
            put(&mut entry, 0, 16, offset as u64, big);
            put(&mut entry, 32, 16, kind, big);
            put(&mut entry, 48, 16, name.len() as u64 - 1, big);
        } else {
            put(&mut entry, 0, 13, offset as u64, big);
            put(&mut entry, 13, 3, kind, big);
            entry[2] = name.len() as u8 - 1;
        }
        directories.extend(entry);
        directories.extend_from_slice(name);
    }
    inodes.extend(base(version, big, 1, 0o755));
    let mut tail = vec![0; if version == 2 { 11 } else { 16 }];
    match version {
        4 => put(&mut tail, 64, 16, directories.len() as u64 + 3, big),
        3 => put(&mut tail, 32, 19, directories.len() as u64 + 3, big),
        _ => put(&mut tail, 0, 19, directories.len() as u64, big),
    }
    inodes.extend(tail);
    image.extend(metadata(&inodes, big, encoding));
    let directory_start = image.len();
    image.extend(metadata(&directories, big, encoding));
    let used = image.len();
    image[..4].copy_from_slice(if big { b"sqsh" } else { b"hsqs" });
    put(&mut image, 32, 32, 3, big);
    put(&mut image, 224, 16, version as u64, big);
    if version == 4 {
        put(&mut image, 96, 32, 4096, big);
        put(&mut image, 160, 16, 1, big);
        put(&mut image, 176, 16, 12, big);
        put(&mut image, 256, 64, root_offset as u64, big);
        put(&mut image, 320, 64, used as u64, big);
        put(&mut image, 512, 64, inode_start as u64, big);
        put(&mut image, 576, 64, directory_start as u64, big);
    } else {
        put(&mut image, 272, 16, 12, big);
        put(&mut image, 344, 64, root_offset as u64, big);
        put(&mut image, 408, 32, 4096, big);
        if version == 3 {
            put(&mut image, 504, 64, used as u64, big);
            put(&mut image, 696, 64, inode_start as u64, big);
            put(&mut image, 760, 64, directory_start as u64, big);
        } else {
            put(&mut image, 64, 32, used as u64, big);
            put(&mut image, 160, 32, inode_start as u64, big);
            put(&mut image, 192, 32, directory_start as u64, big);
        }
    }
    image
}

#[test]
fn rejects_directory_cycles() {
    let mut image = tree_image(4, false, Encoding::Plain);
    let root = u64::from_le_bytes(image[32..40].try_into().unwrap()) as u16;
    let directory = u64::from_le_bytes(image[72..80].try_into().unwrap()) as usize;
    image[directory + 14..directory + 16].copy_from_slice(&root.to_le_bytes());
    let temp = tempfile::tempdir().unwrap();
    let mut output =
        fat_extract::output::OutputTree::new(&temp.path().join("root"), Default::default())
            .unwrap();
    assert!(squashfs::extract(&image, &mut output)
        .unwrap_err()
        .to_string()
        .contains("cycle"));
}

#[test]
fn rejects_directory_path_escape() {
    let mut image = tree_image(4, false, Encoding::Plain);
    let directory = u64::from_le_bytes(image[72..80].try_into().unwrap()) as usize;
    image[directory + 22] = b'/';
    let temp = tempfile::tempdir().unwrap();
    let mut output =
        fat_extract::output::OutputTree::new(&temp.path().join("root"), Default::default())
            .unwrap();
    assert!(squashfs::extract(&image, &mut output)
        .unwrap_err()
        .to_string()
        .contains("filename"));
}

#[test]
fn rejects_decompressed_metadata_larger_than_its_limit() {
    let mut image = tree_image(4, false, Encoding::Plain);
    let inode = u64::from_le_bytes(image[64..72].try_into().unwrap()) as usize;
    let oversized = metadata(&vec![0; 8193], false, Encoding::Zlib);
    let directory = inode + oversized.len();
    image.truncate(inode);
    image.extend(oversized);
    image.extend(metadata(&[0; 32], false, Encoding::Plain));
    let size = image.len() as u64;
    image[32..40].fill(0);
    image[40..48].copy_from_slice(&size.to_le_bytes());
    image[72..80].copy_from_slice(&(directory as u64).to_le_bytes());
    let temp = tempfile::tempdir().unwrap();
    let mut output =
        fat_extract::output::OutputTree::new(&temp.path().join("root"), Default::default())
            .unwrap();
    assert!(squashfs::extract(&image, &mut output)
        .unwrap_err()
        .to_string()
        .contains("decompression limit"));
}

#[test]
fn recovers_fragment_tail() {
    let mut image = tree_image(4, false, Encoding::Plain);
    let inode = u64::from_le_bytes(image[64..72].try_into().unwrap()) as usize;
    image[inode + 22..inode + 26].fill(0);
    let mut fragment = vec![0; 16];
    fragment[..8].copy_from_slice(&128u64.to_le_bytes());
    fragment[8..12].copy_from_slice(&(0x0100_0000u32 | 15).to_le_bytes());
    let fragment_block = image.len();
    image.extend(metadata(&fragment, false, Encoding::Plain));
    let table = image.len();
    image.extend_from_slice(&(fragment_block as u64).to_le_bytes());
    let used = image.len() as u64;
    image[16..20].copy_from_slice(&1u32.to_le_bytes());
    image[40..48].copy_from_slice(&used.to_le_bytes());
    image[80..88].copy_from_slice(&(table as u64).to_le_bytes());
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("root");
    let mut output =
        fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
    squashfs::extract(&image, &mut output).unwrap();
    output.finish().unwrap();
    assert_eq!(
        std::fs::read(destination.join("hello.txt")).unwrap(),
        b"hello firmware\n"
    );
}

#[test]
fn honors_v4_compression_identifier() {
    for (encoding, identifier, name) in [
        (Encoding::Zlib, 1u16, "zlib"),
        (Encoding::CompactLzma, 2, "lzma"),
        (Encoding::Xz, 4, "xz"),
    ] {
        let mut image = tree_image(4, false, encoding);
        image[20..22].copy_from_slice(&identifier.to_le_bytes());
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("root");
        let mut output =
            fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
        assert_eq!(
            squashfs::extract(&image, &mut output).unwrap().compression,
            name
        );
        output.finish().unwrap();
        assert_eq!(
            std::fs::read(destination.join("hello.txt")).unwrap(),
            b"hello firmware\n"
        );
    }
}

#[test]
fn distinguishes_unsupported_compression_from_corrupt_input() {
    let mut image = tree_image(4, false, Encoding::Plain);
    image[20..22].copy_from_slice(&99u16.to_le_bytes());
    assert_eq!(squashfs::probe(&image).unwrap().compression, "unknown");
    let temp = tempfile::tempdir().unwrap();
    let mut output =
        fat_extract::output::OutputTree::new(&temp.path().join("root"), Default::default())
            .unwrap();
    assert_eq!(
        squashfs::extract(&image, &mut output).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}

#[test]
fn rejects_file_data_inside_the_superblock() {
    for version in [2, 3, 4] {
        for big in [false, true] {
            let minimum = match version {
                4 => 96,
                3 => 119,
                _ => 63,
            };
            let image = file_start_image(version, big, minimum - 1, false);
            let temp = tempfile::tempdir().unwrap();
            let mut output =
                fat_extract::output::OutputTree::new(&temp.path().join("root"), Default::default())
                    .unwrap();
            let error = squashfs::extract(&image, &mut output).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("outside data region"));
        }
    }
}

#[test]
fn sparse_blocks_do_not_require_a_payload_address() {
    for version in [2, 3, 4] {
        let image = file_start_image(version, false, 0, true);
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("root");
        let mut output =
            fat_extract::output::OutputTree::new(&destination, Default::default()).unwrap();
        squashfs::extract(&image, &mut output).unwrap();
        output.finish().unwrap();
        assert_eq!(
            std::fs::read(destination.join("hello.txt")).unwrap(),
            vec![0; 15]
        );
    }
}

fn file_start_image(version: u16, big: bool, start: u64, sparse: bool) -> Vec<u8> {
    let mut image = tree_image(version, big, Encoding::Plain);
    let inode = 128 + b"hello firmware\n".len() + 2;
    let offset = match version {
        4 => 16,
        3 => 12,
        _ => 8,
    };
    let width = if version == 3 { 8 } else { 4 };
    let bytes = if big {
        start.to_be_bytes()
    } else {
        start.to_le_bytes()
    };
    let value = if big {
        &bytes[8 - width..]
    } else {
        &bytes[..width]
    };
    image[inode + offset..inode + offset + width].copy_from_slice(value);
    if sparse {
        let descriptor = inode + if version == 2 { 24 } else { 32 };
        image[descriptor..descriptor + 4].fill(0);
    }
    image
}
