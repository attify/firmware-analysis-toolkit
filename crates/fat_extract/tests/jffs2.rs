use std::io::Write;

use fat_extract::pipeline::{extract, ArtifactStatus, PipelineOptions};

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
    fn u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

fn crc(bytes: &[u8]) -> u32 {
    let mut value = 0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
        }
    }
    value
}

fn header(kind: u16, size: usize, endian: Endian) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(endian.u16(0x1985));
    bytes.extend(endian.u16(kind));
    bytes.extend(endian.u32(size as u32));
    bytes.extend(endian.u32(crc(&bytes)));
    bytes
}

fn dirent(parent: u32, ino: u32, version: u32, name: &[u8], endian: Endian) -> Vec<u8> {
    let mut bytes = header(0xe001, 40 + name.len(), endian);
    for value in [parent, version, ino, 0] {
        bytes.extend(endian.u32(value));
    }
    bytes.extend([name.len() as u8, 0, 0, 0]);
    bytes.extend(endian.u32(crc(&bytes)));
    bytes.extend(endian.u32(crc(name)));
    bytes.extend(name);
    pad(bytes)
}

fn inode(
    ino: u32,
    version: u32,
    mode: u32,
    size: u32,
    offset: u32,
    data: &[u8],
    endian: Endian,
) -> Vec<u8> {
    let mut bytes = header(0xe002, 68 + data.len(), endian);
    for value in [
        ino,
        version,
        mode,
        0,
        size,
        0,
        0,
        0,
        offset,
        data.len() as u32,
        data.len() as u32,
    ] {
        bytes.extend(endian.u32(value));
    }
    bytes.extend([0, 0, 0, 0]);
    let node_crc = crc(&bytes);
    bytes.extend(endian.u32(crc(data)));
    bytes.extend(endian.u32(node_crc));
    bytes.extend(data);
    pad(bytes)
}

fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize((bytes.len() + 3) & !3, 0xff);
    bytes
}

fn run(
    bytes: &[u8],
    options: PipelineOptions,
) -> (tempfile::TempDir, fat_extract::pipeline::PipelineReport) {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("firmware");
    std::fs::write(&input, bytes).unwrap();
    let report = extract(&input, &temp.path().join("output"), options).unwrap();
    (temp, report)
}

#[test]
fn fragmented_gzip_is_reassembled_before_recursive_decoding() {
    let e = Endian::Little;
    let payload = b"A web asset split across flash filesystem nodes, not a corrupt gzip.";
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(payload).unwrap();
    let gzip = gzip.finish().unwrap();
    let mut image = vec![0xaa; 37]; // Wrapper offsets need not be flash-aligned.
    image.extend(dirent(1, 2, 1, b"asset.gz", e));
    image.extend(inode(2, 1, 0o100644, gzip.len() as u32, 0, &gzip[..16], e));
    image.extend(inode(2, 2, 0o100644, gzip.len() as u32, 16, &gzip[16..], e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert_eq!(
        report
            .artifacts
            .iter()
            .map(|a| a.format.as_str())
            .collect::<Vec<_>>(),
        ["jffs2", "gzip"]
    );
    assert!(!report.has_unresolved());
    assert_eq!(report.artifacts[0].offset, 37);
    assert_eq!(report.artifacts[1].parent, Some(0));
    assert_eq!(
        std::fs::read(
            report.artifacts[0]
                .output
                .as_ref()
                .unwrap()
                .join("asset.gz")
        )
        .unwrap(),
        gzip
    );
    assert_eq!(
        std::fs::read(
            report.artifacts[1]
                .output
                .as_ref()
                .unwrap()
                .join("decompressed.bin")
        )
        .unwrap(),
        payload
    );
}

#[test]
fn versions_truncations_and_deleted_dirents_are_applied_in_both_byte_orders() {
    for e in [Endian::Little, Endian::Big] {
        let mut image = dirent(1, 2, 1, b"value", e);
        image.extend(inode(2, 3, 0o100644, 4, 2, b"XY", e));
        image.extend(inode(2, 1, 0o100644, 6, 0, b"abcdef", e));
        image.extend(inode(2, 2, 0o100644, 2, 0, b"", e));
        image.extend(dirent(1, 3, 2, b"deleted", e));
        image.extend(inode(3, 1, 0o100644, 3, 0, b"old", e));
        image.extend(dirent(1, 0, 3, b"deleted", e));
        let (_temp, report) = run(&image, PipelineOptions::default());
        assert_eq!(report.artifacts.len(), 1);
        assert!(!report.has_unresolved());
        let output = report.artifacts[0].output.as_ref().unwrap();
        assert_eq!(std::fs::read(output.join("value")).unwrap(), b"abXY");
        assert!(!output.join("deleted").exists());
    }
}

#[test]
fn corrupted_data_remains_unresolved_and_is_not_published() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"value", e);
    let mut node = inode(2, 1, 0o100644, 3, 0, b"abc", e);
    node[68] ^= 1;
    image.extend(node);
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(report.has_unresolved());
    assert!(report
        .artifacts
        .iter()
        .any(|a| a.format == "jffs2" && a.status == ArtifactStatus::Failed));
    assert!(report.artifacts.iter().all(|a| a.output.is_none()));
}

#[test]
fn unfilled_file_ranges_are_not_silently_fabricated() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"incomplete", e);
    image.extend(inode(2, 1, 0o100644, 8, 0, b"abc", e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(report.has_unresolved());
    assert!(report.artifacts.iter().all(|a| a.output.is_none()));
}

#[test]
fn file_budget_is_checked_before_allocating_inode_size() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"huge", e);
    image.extend(inode(2, 1, 0o100644, u32::MAX, 0, b"a", e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(report
        .artifacts
        .iter()
        .any(|a| a.status == ArtifactStatus::Limited));
}

#[test]
fn unsafe_dirent_does_not_escape_staged_output() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"../escaped", e);
    image.extend(inode(2, 1, 0o100644, 3, 0, b"abc", e));
    let (temp, report) = run(&image, PipelineOptions::default());
    assert!(report.has_unresolved());
    assert!(!temp.path().join("escaped").exists());
    assert!(report.artifacts.iter().all(|a| a.output.is_none()));
}

fn compressed_inode(ino: u32, codec: u8, decoded: u32, stored: &[u8]) -> Vec<u8> {
    let mut node = inode(ino, 1, 0o100644, decoded, 0, stored, Endian::Little);
    node[52..56].copy_from_slice(&decoded.to_le_bytes());
    node[56] = codec;
    let node_crc = crc(&node[..60]);
    node[64..68].copy_from_slice(&node_crc.to_le_bytes());
    node
}

#[test]
fn zlib_and_explicit_zero_fragments_are_recovered() {
    let mut compressor =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    compressor.write_all(b"compressed").unwrap();
    let mut image = dirent(1, 2, 1, b"zlib", Endian::Little);
    image.extend(compressed_inode(2, 6, 10, &compressor.finish().unwrap()));
    image.extend(dirent(1, 3, 2, b"zero", Endian::Little));
    image.extend(compressed_inode(3, 1, 7, b""));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(!report.has_unresolved(), "{:?}", report.artifacts);
    let output = report.artifacts[0].output.as_ref().unwrap();
    assert_eq!(std::fs::read(output.join("zlib")).unwrap(), b"compressed");
    assert_eq!(std::fs::read(output.join("zero")).unwrap(), [0; 7]);
}

#[test]
fn unsupported_codec_is_visible_and_does_not_publish_a_tree() {
    let mut image = dirent(1, 2, 1, b"lzo", Endian::Little);
    image.extend(compressed_inode(2, 7, 3, b"abc"));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Unsupported);
    assert!(report.artifacts.iter().all(|a| a.output.is_none()));
}

#[test]
fn decompression_cannot_exceed_declared_fragment_size() {
    let mut compressor =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    compressor.write_all(&[b'A'; 4096]).unwrap();
    let mut image = dirent(1, 2, 1, b"bomb", Endian::Little);
    image.extend(compressed_inode(2, 6, 1, &compressor.finish().unwrap()));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Failed);
    assert!(report.artifacts[0].output.is_none());
}

#[test]
fn erased_block_gaps_preserve_fragments_and_large_gaps_separate_copies() {
    let e = Endian::Little;
    let mut volume = dirent(1, 2, 1, b"value", e);
    volume.extend(inode(2, 1, 0o100644, 6, 0, b"abc", e));
    volume.resize(65_536, 0xff);
    volume.extend(inode(2, 2, 0o100644, 6, 3, b"def", e));
    let mut image = volume.clone();
    image.extend(vec![0xff; 131_072]);
    image.extend(volume);
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(!report.has_unresolved());
    assert_eq!(report.artifacts.len(), 2);
    for artifact in &report.artifacts {
        assert_eq!(
            std::fs::read(artifact.output.as_ref().unwrap().join("value")).unwrap(),
            b"abcdef"
        );
    }
}

#[test]
fn obsolete_nodes_and_identical_gc_copies_do_not_override_live_data() {
    for e in [Endian::Little, Endian::Big] {
        let mut image = dirent(1, 2, 1, b"value", e);
        let mut obsolete = inode(2, 3, 0o100644, 3, 0, b"old", e);
        obsolete[2..4].copy_from_slice(&e.u16(0xc002));
        image.extend(obsolete);
        let live = inode(2, 2, 0o100644, 3, 0, b"new", e);
        image.extend(&live);
        image.extend(live);
        let (_temp, report) = run(&image, PipelineOptions::default());
        assert!(!report.has_unresolved());
        assert_eq!(
            std::fs::read(report.artifacts[0].output.as_ref().unwrap().join("value")).unwrap(),
            b"new"
        );
    }
}

#[test]
fn conflicting_versions_and_name_crc_fail_honestly() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"value", e);
    image.extend(inode(2, 1, 0o100644, 3, 0, b"abc", e));
    image.extend(inode(2, 1, 0o100644, 3, 0, b"xyz", e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Failed);
    image[40] ^= 1;
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Failed);
    assert!(report.artifacts[0]
        .detail
        .as_ref()
        .unwrap()
        .contains("name CRC"));
}

#[test]
fn directories_respect_depth_limits_and_unix_symlinks() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"etc", e);
    image.extend(inode(2, 1, 0o040755, 0, 0, b"", e));
    image.extend(dirent(2, 3, 1, b"value", e));
    image.extend(inode(3, 1, 0o100644, 3, 0, b"abc", e));
    #[cfg(unix)]
    {
        image.extend(dirent(1, 4, 2, b"link", e));
        image.extend(inode(4, 1, 0o120777, 9, 0, b"etc/value", e));
    }
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(!report.has_unresolved());
    let output = report.artifacts[0].output.as_ref().unwrap();
    assert_eq!(std::fs::read(output.join("etc/value")).unwrap(), b"abc");
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_link(output.join("link")).unwrap(),
        std::path::Path::new("etc/value")
    );
    let options = PipelineOptions {
        limits: fat_extract::output::ExtractionLimits {
            max_depth: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let (_temp, report) = run(&image, options);
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Limited);
    assert!(report.artifacts[0].output.is_none());
}

#[test]
fn embedded_magic_without_header_crc_is_not_a_filesystem() {
    let mut image = vec![0xaa; 20];
    image.extend(b"\x85\x19\x01\xe0\x0c\0\0\0\0\0\0\0");
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(report.artifacts.is_empty());
}

#[test]
fn deleting_the_last_file_leaves_a_valid_empty_tree() {
    let e = Endian::Little;
    let mut image = dirent(1, 2, 1, b"deleted", e);
    image.extend(inode(2, 1, 0o100644, 3, 0, b"old", e));
    image.extend(dirent(1, 0, 2, b"deleted", e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(!report.has_unresolved());
    assert_eq!(report.artifacts[0].stats.files, 0);
}

#[cfg(unix)]
#[test]
fn recursive_inspection_preserves_restrictive_firmware_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let e = Endian::Little;
    let payload = b"nested file in a directory without search permission";
    let mut compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    compressor.write_all(payload).unwrap();
    let gzip = compressor.finish().unwrap();
    let mut image = dirent(1, 2, 1, b"restricted", e);
    image.extend(inode(2, 1, 0o040644, 0, 0, b"", e));
    image.extend(dirent(2, 3, 1, b"asset.gz", e));
    image.extend(inode(3, 1, 0o100000, gzip.len() as u32, 0, &gzip, e));
    let (_temp, report) = run(&image, PipelineOptions::default());
    assert!(!report.has_unresolved(), "{:?}", report.artifacts);
    assert_eq!(report.artifacts.len(), 2);
    let dir = report.artifacts[0]
        .output
        .as_ref()
        .unwrap()
        .join("restricted");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o744)).unwrap();
    assert_eq!(
        std::fs::metadata(dir.join("asset.gz"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0
    );
    assert_eq!(
        std::fs::read(
            report.artifacts[1]
                .output
                .as_ref()
                .unwrap()
                .join("decompressed.bin")
        )
        .unwrap(),
        payload
    );
    assert_eq!(report.artifacts[1].source, dir.join("asset.gz"));
}
