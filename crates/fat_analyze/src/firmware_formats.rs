use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use fat_core::inspection::{CompressionMember, ContainerHeader, FilesystemHeader};
use memchr::memmem;

const SQUASHFS_MAGIC_LE: [u8; 4] = *b"hsqs";
const SQUASHFS_MAGIC_BE: [u8; 4] = *b"sqsh";
const CRAMFS_MAGIC: u32 = 0x28cd_3d45;
const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const CRAMFS_SUPERBLOCK_SIZE: usize = 64;
const CRAMFS_BLOCK_SIZE: u32 = 4_096;
const JFFS2_MAGIC: u16 = 0x1985;
const UBI_EC_MAGIC: [u8; 4] = *b"UBI#";
const UBI_EC_HEADER_SIZE: usize = 64;
const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
const UBIFS_COMMON_HEADER_SIZE: usize = 24;
const CPIO_NEWC_MAGIC: [u8; 6] = *b"070701";
const CPIO_CRC_MAGIC: [u8; 6] = *b"070702";
const CPIO_NEWC_HEADER_SIZE: usize = 110;
const EXT_MAGIC: [u8; 2] = 0xef53u16.to_le_bytes();
const EXT_MAGIC_OFFSET: usize = 0x438;
const EXT_SUPERBLOCK_OFFSET: usize = 0x400;
const EXT_SUPERBLOCK_SIZE: usize = 1_024;
const EXT_SUPPORTED_INCOMPAT: u32 = 0x0000_0001
    | 0x0000_0002
    | 0x0000_0004
    | 0x0000_0008
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0080
    | 0x0000_0100
    | 0x0000_0200
    | 0x0000_0400
    | 0x0000_1000
    | 0x0000_2000
    | 0x0000_4000
    | 0x0000_8000
    | 0x0001_0000
    | 0x0002_0000;
const EXT4_INCOMPAT_EVIDENCE: u32 = 0x0000_0040
    | 0x0000_0080
    | 0x0000_0100
    | 0x0000_0200
    | 0x0000_0400
    | 0x0000_2000
    | 0x0000_4000
    | 0x0000_8000
    | 0x0001_0000
    | 0x0002_0000;
const FDT_MAGIC: [u8; 4] = 0xd00d_feedu32.to_be_bytes();
const FDT_HEADER_SIZE: usize = 40;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const TRX_MAGIC: [u8; 4] = *b"HDR0";
const TRX_HEADER_SIZE: usize = 28;
const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
const GZIP_FHCRC: u8 = 0x02;
const GZIP_FEXTRA: u8 = 0x04;
const GZIP_FNAME: u8 = 0x08;
const GZIP_FCOMMENT: u8 = 0x10;
const GZIP_MAX_UNCOMPRESSED: usize = 64 * 1024 * 1024;
const GZIP_IDENTITY_PEEK_BYTES: usize = 64;

static CANDIDATE_MATCHER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        FDT_MAGIC.as_slice(),
        TRX_MAGIC.as_slice(),
        GZIP_MAGIC.as_slice(),
        &[0x5d],
        &[0x6d],
        &[0x5e],
        &[0x6e],
        SQUASHFS_MAGIC_LE.as_slice(),
        SQUASHFS_MAGIC_BE.as_slice(),
        CRAMFS_MAGIC.to_be_bytes().as_slice(),
        CRAMFS_MAGIC.to_le_bytes().as_slice(),
        JFFS2_MAGIC.to_le_bytes().as_slice(),
        JFFS2_MAGIC.to_be_bytes().as_slice(),
        UBI_EC_MAGIC.as_slice(),
        UBIFS_NODE_MAGIC.to_le_bytes().as_slice(),
        CPIO_NEWC_MAGIC.as_slice(),
        CPIO_CRC_MAGIC.as_slice(),
        EXT_MAGIC.as_slice(),
    ])
    .expect("native format candidate patterns are valid")
});

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeFormatScan {
    pub container_headers: Vec<ContainerHeader>,
    pub compression_members: Vec<CompressionMember>,
    pub filesystem_headers: Vec<FilesystemHeader>,
}

pub fn scan(bytes: &[u8]) -> NativeFormatScan {
    let candidates = collect_candidates(bytes);
    NativeFormatScan {
        container_headers: parse_native_container_headers(bytes, &candidates.container),
        compression_members: parse_compression_members(bytes, &candidates.compression),
        filesystem_headers: parse_filesystem_headers(bytes, &candidates.filesystem),
    }
}

pub fn parse_gzip_at(bytes: &[u8], offset: u64) -> Option<CompressionMember> {
    let start = usize::try_from(offset).ok()?;
    parse_gzip_member(bytes.get(start..)?, offset)
}

pub fn parse_cramfs_at(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    let start = usize::try_from(offset).ok()?;
    parse_cramfs_header(bytes.get(start..)?, offset)
}

pub fn parse_squashfs_at(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    let start = usize::try_from(offset).ok()?;
    parse_squashfs_header(bytes.get(start..)?, offset)
}

pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    !crc32_ieee_update(0xFFFF_FFFF, data)
}

fn crc32_ieee_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

#[derive(Debug, Default)]
struct CandidateOffsets {
    container: Vec<usize>,
    compression: Vec<usize>,
    filesystem: Vec<usize>,
    #[cfg(test)]
    collection_passes: usize,
}

fn collect_candidates(bytes: &[u8]) -> CandidateOffsets {
    let mut candidates = CandidateOffsets {
        #[cfg(test)]
        collection_passes: 1,
        ..Default::default()
    };
    for candidate in CANDIDATE_MATCHER.find_overlapping_iter(bytes) {
        match candidate.pattern().as_usize() {
            0..=1 => candidates.container.push(candidate.start()),
            2..=6 => candidates.compression.push(candidate.start()),
            7..=17 => candidates.filesystem.push(candidate.start()),
            _ => unreachable!("candidate pattern id"),
        }
    }
    candidates.container.sort_unstable();
    candidates.container.dedup();
    candidates.compression.sort_unstable();
    candidates.compression.dedup();
    candidates.filesystem.sort_unstable();
    candidates.filesystem.dedup();
    candidates
}

fn parse_native_container_headers(bytes: &[u8], offsets: &[usize]) -> Vec<ContainerHeader> {
    let mut containers = Vec::new();
    for &offset in offsets {
        let Some(slice) = bytes.get(offset..) else {
            continue;
        };
        if let Some(header) = parse_fdt_at(slice, offset as u64) {
            containers.push(header);
            continue;
        }
        if let Some(header) = parse_trx_at(slice, offset as u64) {
            containers.push(header);
        }
    }
    containers
}

fn parse_compression_members(bytes: &[u8], offsets: &[usize]) -> Vec<CompressionMember> {
    let mut members = Vec::new();
    let file_len = bytes.len() as u64;
    for &offset in offsets {
        let slice = &bytes[offset..];
        if let Some(member) = parse_gzip_member(slice, offset as u64) {
            members.push(member);
            continue;
        }
        if let Some(member) = parse_lzma_alone_member(slice, offset as u64, file_len) {
            members.push(member);
        }
    }

    members
}

fn parse_filesystem_headers(bytes: &[u8], offsets: &[usize]) -> Vec<FilesystemHeader> {
    let mut filesystems = Vec::new();
    let mut validated_ubi_end = 0usize;
    for &offset in offsets {
        if let Some(header) = parse_ext_header(bytes, offset) {
            filesystems.push(header);
            continue;
        }
        let slice = &bytes[offset..];
        if let Some(header) = parse_squashfs_header(slice, offset as u64) {
            filesystems.push(header);
            continue;
        }
        if let Some(header) = parse_cramfs_header(slice, offset as u64) {
            filesystems.push(header);
            continue;
        }
        if let Some(header) = parse_jffs2_header(slice, offset as u64) {
            filesystems.push(header);
            continue;
        }
        if slice.starts_with(&UBI_EC_MAGIC) && offset < validated_ubi_end {
            continue;
        }
        if let Some(header) = parse_ubi_header(slice, offset as u64) {
            validated_ubi_end = header
                .image_size
                .and_then(|size| usize::try_from(size).ok())
                .and_then(|size| offset.checked_add(size))
                .unwrap_or(offset);
            filesystems.push(header);
            continue;
        }
        if let Some(header) = parse_ubifs_header(slice, offset as u64) {
            filesystems.push(header);
            continue;
        }
        if let Some(header) = parse_cpio_newc_archive(slice, offset as u64) {
            filesystems.push(header);
        }
    }

    filesystems
}

fn parse_lzma_alone_member(bytes: &[u8], offset: u64, file_len: u64) -> Option<CompressionMember> {
    if bytes.len() < 13 {
        return None;
    }

    let properties = bytes[0];
    if !is_valid_lzma_properties(properties) {
        return None;
    }

    let dict_size = u32::from_le_bytes(bytes[1..5].try_into().ok()?);
    if !is_plausible_lzma_dictionary_size(dict_size) {
        return None;
    }

    let uncompressed_size = u64::from_le_bytes(bytes[5..13].try_into().ok()?);
    if uncompressed_size != u64::MAX {
        let max_plausible = std::cmp::max(file_len.saturating_mul(100), 256 * 1024 * 1024);
        if uncompressed_size > max_plausible {
            return None;
        }
    }

    Some(CompressionMember {
        format: "lzma".to_string(),
        offset,
        properties_hex: Some(format!("0x{properties:02X}")),
        dictionary_size: Some(dict_size),
        uncompressed_size: (uncompressed_size != u64::MAX).then_some(uncompressed_size),
        compressed_size: None,
        original_name: None,
        payload_format: None,
        payload_architecture: None,
        operating_system: None,
        timestamp_unix: None,
    })
}

fn parse_gzip_member(bytes: &[u8], offset: u64) -> Option<CompressionMember> {
    if bytes.len() < 18 || bytes.get(..3)? != GZIP_MAGIC || (bytes[3] & 0xE0) != 0 {
        return None;
    }

    let flags = bytes[3];
    let timestamp_unix = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as u64;
    let operating_system = gzip_os_name(*bytes.get(9)?);
    let mut cursor = 10usize;

    if flags & GZIP_FEXTRA != 0 {
        let xlen = u16::from_le_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
        cursor = cursor.checked_add(2)?.checked_add(xlen)?;
        bytes.get(..cursor)?;
    }

    let original_name = if flags & GZIP_FNAME != 0 {
        let tail = bytes.get(cursor..)?;
        let field_len = gzip_cstring_len(tail)?;
        let name = reportable_gzip_name(tail.get(..field_len)?);
        cursor = cursor.checked_add(field_len)?.checked_add(1)?;
        name
    } else {
        None
    };

    if flags & GZIP_FCOMMENT != 0 {
        let field_len = gzip_cstring_len(bytes.get(cursor..)?)?;
        cursor = cursor.checked_add(field_len)?.checked_add(1)?;
    }

    if flags & GZIP_FHCRC != 0 {
        let stored = u16::from_le_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?);
        let header_crc = crc32_ieee(bytes.get(..cursor)?) as u16;
        if stored != header_crc {
            return None;
        }
        cursor = cursor.checked_add(2)?;
    }

    bytes.get(cursor..)?;
    let inflated = inflate_gzip_member(bytes, cursor)?;
    let identity = parse_elf_identity(&inflated.prefix);
    Some(CompressionMember {
        format: "gzip".to_string(),
        offset,
        properties_hex: None,
        dictionary_size: None,
        uncompressed_size: Some(inflated.uncompressed_size),
        compressed_size: Some(inflated.compressed_size),
        original_name,
        payload_format: identity.as_ref().map(|_| "ELF".to_string()),
        payload_architecture: identity.and_then(|identity| identity.architecture),
        operating_system,
        timestamp_unix: Some(timestamp_unix),
    })
}

fn gzip_cstring_len(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&byte| byte == 0)
}

fn reportable_gzip_name(bytes: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(bytes).ok()?;
    (!name.is_empty()
        && name.len() <= 255
        && name.chars().all(|ch| ch.is_ascii_graphic() || ch == ' '))
    .then(|| name.to_string())
}

struct GzipInflateResult {
    uncompressed_size: u64,
    compressed_size: u64,
    prefix: Vec<u8>,
}

fn inflate_gzip_member(bytes: &[u8], deflate_start: usize) -> Option<GzipInflateResult> {
    let input = bytes.get(deflate_start..)?;
    let mut decoder = flate2::Decompress::new(false);
    let mut output = [0u8; 8192];
    let mut uncompressed = 0usize;
    let mut consumed = 0usize;
    let mut crc = 0xFFFF_FFFFu32;
    let mut prefix = Vec::with_capacity(GZIP_IDENTITY_PEEK_BYTES);

    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(
                input.get(consumed..)?,
                &mut output,
                flate2::FlushDecompress::None,
            )
            .ok()?;
        let newly_in = usize::try_from(decoder.total_in().saturating_sub(before_in)).ok()?;
        let newly_out = usize::try_from(decoder.total_out().saturating_sub(before_out)).ok()?;
        crc = crc32_ieee_update(crc, output.get(..newly_out)?);
        let prefix_remaining = GZIP_IDENTITY_PEEK_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(output.get(..newly_out.min(prefix_remaining))?);
        consumed = consumed.saturating_add(newly_in);
        uncompressed = uncompressed.saturating_add(newly_out);
        if uncompressed > GZIP_MAX_UNCOMPRESSED {
            return None;
        }
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError if newly_in > 0 || newly_out > 0 => {}
            _ => return None,
        }
    }

    let trailer_start = deflate_start.checked_add(consumed)?;
    let trailer = bytes.get(trailer_start..trailer_start + 8)?;
    let stored_crc = u32::from_le_bytes(trailer.get(..4)?.try_into().ok()?);
    let isize = u32::from_le_bytes(trailer.get(4..8)?.try_into().ok()?);
    if !crc != stored_crc || uncompressed as u32 != isize {
        return None;
    }
    Some(GzipInflateResult {
        uncompressed_size: uncompressed as u64,
        compressed_size: (trailer_start + 8) as u64,
        prefix,
    })
}

struct ElfIdentity {
    architecture: Option<String>,
}

fn parse_elf_identity(bytes: &[u8]) -> Option<ElfIdentity> {
    if bytes.len() < 20 || bytes.get(..4)? != b"\x7fELF" || *bytes.get(6)? != 1 {
        return None;
    }
    let class_64 = match *bytes.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match *bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let elf_type = read_u16(bytes, 16, little)?;
    let machine = read_u16(bytes, 18, little)?;
    if !matches!(elf_type, 1..=4) || machine == 0 {
        return None;
    }
    let base = match machine {
        3 => "x86",
        8 if class_64 => "mips64",
        8 => "mips",
        20 => "powerpc",
        40 => "arm",
        62 => "x86-64",
        183 => "aarch64",
        243 => "riscv",
        _ => {
            return Some(ElfIdentity { architecture: None });
        }
    };
    Some(ElfIdentity {
        architecture: Some(format!(
            "{base} ({})",
            if little {
                "little-endian"
            } else {
                "big-endian"
            }
        )),
    })
}

fn parse_squashfs_header(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    const SQUASHFS_SUPERBLOCK_SIZE: u64 = 96;
    if bytes.len() < SQUASHFS_SUPERBLOCK_SIZE as usize {
        return None;
    }
    let (endianness, little) = if bytes.starts_with(&SQUASHFS_MAGIC_LE) {
        ("little".to_string(), true)
    } else if bytes.starts_with(&SQUASHFS_MAGIC_BE) {
        ("big".to_string(), false)
    } else {
        return None;
    };

    let inode_count = read_u32(bytes, 4, little)?;
    let created_unix = read_u32(bytes, 8, little)? as u64;
    let block_size = read_u32(bytes, 12, little)?;
    let compression_id = read_u16(bytes, 20, little)?;
    let major = read_u16(bytes, 28, little)?;
    let minor = read_u16(bytes, 30, little)?;
    let image_size = read_u64(bytes, 40, little)?;
    let compression = squashfs_compression_name(compression_id)?;
    if inode_count == 0
        || !(4_096..=1_048_576).contains(&block_size)
        || !block_size.is_power_of_two()
        || major != 4
        || minor != 0
        || image_size < SQUASHFS_SUPERBLOCK_SIZE
        || image_size > bytes.len() as u64
    {
        return None;
    }

    Some(FilesystemHeader {
        format: "squashfs".to_string(),
        offset,
        endianness: Some(endianness),
        version: Some(format!("{major}.{minor}")),
        compression: Some(compression),
        inode_count: Some(inode_count),
        block_size: Some(block_size),
        image_size: Some(image_size),
        created_unix: Some(created_unix),
    })
}

fn parse_cramfs_header(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    if bytes.len() < CRAMFS_SUPERBLOCK_SIZE || bytes.get(16..32)? != CRAMFS_SIGNATURE {
        return None;
    }
    let (endianness, little) = if read_u32(bytes, 0, false)? == CRAMFS_MAGIC {
        ("big".to_string(), false)
    } else if read_u32(bytes, 0, true)? == CRAMFS_MAGIC {
        ("little".to_string(), true)
    } else {
        return None;
    };

    let image_size = u64::from(read_u32(bytes, 4, little)?);
    let inode_count = read_u32(bytes, 44, little)?;
    let remaining = bytes.len() as u64;
    if image_size < CRAMFS_SUPERBLOCK_SIZE as u64
        || image_size > remaining
        || inode_count == 0
        || u64::from(inode_count) > image_size
    {
        return None;
    }

    Some(FilesystemHeader {
        format: "cramfs".to_string(),
        offset,
        endianness: Some(endianness),
        version: None,
        compression: Some("zlib".to_string()),
        inode_count: Some(inode_count),
        block_size: Some(CRAMFS_BLOCK_SIZE),
        image_size: Some(image_size),
        created_unix: None,
    })
}

fn parse_jffs2_header(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    if bytes.len() < 24 {
        return None;
    }
    let little = if read_u16(bytes, 0, true)? == JFFS2_MAGIC {
        true
    } else if read_u16(bytes, 0, false)? == JFFS2_MAGIC {
        false
    } else {
        return None;
    };

    let mut cursor = 0usize;
    let mut node_count = 0u32;
    let mut semantic_nodes = 0u32;
    while bytes.len().saturating_sub(cursor) >= 12 {
        if read_u16(bytes, cursor, little)? != JFFS2_MAGIC {
            break;
        }
        let node_type = read_u16(bytes, cursor + 2, little)?;
        let total_len = usize::try_from(read_u32(bytes, cursor + 4, little)?).ok()?;
        let minimum_len = match node_type {
            0x2003 | 0x2004 => 12,
            0xe001 => 40,
            0xe002 => 68,
            _ => break,
        };
        if total_len < minimum_len {
            break;
        }
        let node_end = cursor.checked_add(total_len)?;
        if node_end > bytes.len() {
            break;
        }
        let stored_crc = read_u32(bytes, cursor + 8, little)?;
        if linux_crc32(0, bytes.get(cursor..cursor + 8)?) != stored_crc {
            break;
        }
        node_count = node_count.checked_add(1)?;
        if matches!(node_type, 0xe001 | 0xe002) {
            semantic_nodes = semantic_nodes.checked_add(1)?;
        }
        cursor = align_up_four(node_end)?;
        if cursor > bytes.len() {
            break;
        }
    }

    if node_count < 2 || semantic_nodes == 0 || cursor == 0 {
        return None;
    }
    Some(FilesystemHeader {
        format: "jffs2".to_string(),
        offset,
        endianness: Some(if little { "little" } else { "big" }.to_string()),
        version: None,
        compression: None,
        inode_count: None,
        block_size: None,
        image_size: Some(cursor as u64),
        created_unix: None,
    })
}

fn align_up_four(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn linux_crc32(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UbiEcHeader {
    vid_header_offset: u32,
    data_offset: u32,
    image_sequence: u32,
}

fn parse_ubi_ec_header(bytes: &[u8]) -> Option<UbiEcHeader> {
    if bytes.get(..4)? != UBI_EC_MAGIC || *bytes.get(4)? != 1 {
        return None;
    }
    if bytes.get(5..8)?.iter().any(|byte| *byte != 0) {
        return None;
    }

    let erase_counter = read_u64(bytes, 8, false)?;
    let vid_header_offset = read_u32(bytes, 16, false)?;
    let data_offset = read_u32(bytes, 20, false)?;
    let image_sequence = read_u32(bytes, 24, false)?;
    let stored_crc = read_u32(bytes, 60, false)?;
    if erase_counter > i64::MAX as u64
        || vid_header_offset < UBI_EC_HEADER_SIZE as u32
        || data_offset <= vid_header_offset
        || !vid_header_offset.is_multiple_of(4)
        || !data_offset.is_multiple_of(4)
        || bytes.get(28..60)?.iter().any(|byte| *byte != 0)
        || linux_crc32(0xffff_ffff, bytes.get(..60)?) != stored_crc
    {
        return None;
    }

    Some(UbiEcHeader {
        vid_header_offset,
        data_offset,
        image_sequence,
    })
}

fn parse_ubi_header(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    if bytes.len() < UBI_EC_HEADER_SIZE * 2 {
        return None;
    }
    let first = parse_ubi_ec_header(bytes)?;

    let peb_size = memmem::find_iter(bytes.get(UBI_EC_HEADER_SIZE..)?, &UBI_EC_MAGIC)
        .map(|relative| relative + UBI_EC_HEADER_SIZE)
        .find(|candidate| {
            *candidate >= first.data_offset as usize
                && candidate.is_multiple_of(4)
                && parse_ubi_ec_header(&bytes[*candidate..]) == Some(first)
        })?;
    if first.data_offset as usize >= peb_size || peb_size > u32::MAX as usize {
        return None;
    }

    let mut eraseblocks = 1usize;
    let mut cursor = peb_size;
    while let Some(header) = bytes.get(cursor..).and_then(parse_ubi_ec_header) {
        if header != first {
            break;
        }
        eraseblocks = eraseblocks.checked_add(1)?;
        cursor = cursor.checked_add(peb_size)?;
    }
    if eraseblocks < 2 {
        return None;
    }

    Some(FilesystemHeader {
        format: "ubi".to_string(),
        offset,
        endianness: Some("big".to_string()),
        version: Some("1".to_string()),
        compression: None,
        inode_count: None,
        block_size: Some(peb_size as u32),
        image_size: Some(cursor as u64),
        created_unix: None,
    })
}

fn parse_ubifs_header(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    if read_u32(bytes, 0, true)? != UBIFS_NODE_MAGIC || bytes.len() < UBIFS_COMMON_HEADER_SIZE {
        return None;
    }

    let node_length = usize::try_from(read_u32(bytes, 16, true)?).ok()?;
    let node_type = *bytes.get(20)?;
    let group_type = *bytes.get(21)?;
    if node_length < UBIFS_COMMON_HEADER_SIZE
        || node_length > bytes.len()
        || node_type > 13
        || group_type > 2
        || bytes.get(22..24)?.iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let stored_crc = read_u32(bytes, 4, true)?;
    if linux_crc32(0xffff_ffff, bytes.get(8..node_length)?) != stored_crc {
        return None;
    }

    Some(FilesystemHeader {
        format: "ubifs".to_string(),
        offset,
        endianness: Some("little".to_string()),
        version: None,
        compression: None,
        inode_count: None,
        block_size: None,
        image_size: Some(node_length as u64),
        created_unix: None,
    })
}

fn parse_cpio_newc_archive(bytes: &[u8], offset: u64) -> Option<FilesystemHeader> {
    if bytes.len() < CPIO_NEWC_HEADER_SIZE {
        return None;
    }

    let mut cursor = 0usize;
    let mut entry_count = 0u32;
    loop {
        let header = bytes.get(cursor..cursor.checked_add(CPIO_NEWC_HEADER_SIZE)?)?;
        let has_checksum = if header.starts_with(&CPIO_NEWC_MAGIC) {
            false
        } else if header.starts_with(&CPIO_CRC_MAGIC) {
            true
        } else {
            return None;
        };
        let mut fields = [0u32; 13];
        for (index, field) in fields.iter_mut().enumerate() {
            let start = 6 + index * 8;
            *field = parse_ascii_hex_u32(header.get(start..start + 8)?)?;
        }

        let mode = fields[1];
        let link_count = fields[4];
        let file_size = usize::try_from(fields[6]).ok()?;
        let name_size = usize::try_from(fields[11]).ok()?;
        let stored_checksum = fields[12];
        if name_size == 0 || name_size > 4_096 {
            return None;
        }

        let name_start = cursor.checked_add(CPIO_NEWC_HEADER_SIZE)?;
        let name_end = name_start.checked_add(name_size)?;
        let name_bytes = bytes.get(name_start..name_end)?;
        if name_bytes.last() != Some(&0) || name_bytes[..name_bytes.len() - 1].contains(&0) {
            return None;
        }
        let name = std::str::from_utf8(&name_bytes[..name_bytes.len() - 1]).ok()?;
        let data_start = align_up_four(name_end)?;
        let data_end = data_start.checked_add(file_size)?;
        let data = bytes.get(data_start..data_end)?;
        cursor = align_up_four(data_end)?;
        if cursor > bytes.len() {
            return None;
        }

        if has_checksum {
            let checksum = data
                .iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
            if checksum != stored_checksum {
                return None;
            }
        } else if stored_checksum != 0 {
            return None;
        }

        if name == "TRAILER!!!" {
            if file_size != 0 || entry_count == 0 {
                return None;
            }
            break;
        }

        let file_type = mode & 0o170000;
        if link_count == 0
            || !matches!(
                file_type,
                0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
            )
        {
            return None;
        }
        entry_count = entry_count.checked_add(1)?;
    }

    Some(FilesystemHeader {
        format: "cpio-newc".to_string(),
        offset,
        endianness: None,
        version: Some("newc".to_string()),
        compression: None,
        inode_count: Some(entry_count),
        block_size: Some(4),
        image_size: Some(cursor as u64),
        created_unix: None,
    })
}

fn parse_ascii_hex_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 8 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(bytes).ok()?, 16).ok()
}

fn parse_ext_header(bytes: &[u8], magic_offset: usize) -> Option<FilesystemHeader> {
    let filesystem_start = magic_offset.checked_sub(EXT_MAGIC_OFFSET)?;
    let superblock_start = filesystem_start.checked_add(EXT_SUPERBLOCK_OFFSET)?;
    let superblock_end = superblock_start.checked_add(EXT_SUPERBLOCK_SIZE)?;
    let superblock = bytes.get(superblock_start..superblock_end)?;
    if superblock.get(56..58)? != EXT_MAGIC {
        return None;
    }

    let inode_count = read_u32(superblock, 0, true)?;
    let blocks_low = read_u32(superblock, 4, true)?;
    let free_blocks = read_u32(superblock, 12, true)?;
    let free_inodes = read_u32(superblock, 16, true)?;
    let first_data_block = read_u32(superblock, 20, true)?;
    let log_block_size = read_u32(superblock, 24, true)?;
    let blocks_per_group = read_u32(superblock, 32, true)?;
    let inodes_per_group = read_u32(superblock, 40, true)?;
    let state = read_u16(superblock, 58, true)?;
    let errors = read_u16(superblock, 60, true)?;
    let revision = read_u32(superblock, 76, true)?;
    let inode_size = if revision == 0 {
        128
    } else {
        u32::from(read_u16(superblock, 88, true)?)
    };
    let feature_compat = read_u32(superblock, 92, true)?;
    let feature_incompat = read_u32(superblock, 96, true)?;
    if inode_count == 0
        || blocks_low == 0
        || revision > 1
        || state == 0
        || state & !0x0003 != 0
        || !(1..=3).contains(&errors)
        || feature_incompat & !EXT_SUPPORTED_INCOMPAT != 0
        || log_block_size > 6
    {
        return None;
    }

    let block_size = 1_024u32.checked_shl(log_block_size)?;
    if inode_size < 128
        || inode_size > block_size
        || !inode_size.is_power_of_two()
        || first_data_block != u32::from(block_size == 1_024)
        || blocks_per_group == 0
        || blocks_per_group > block_size.saturating_mul(8)
        || inodes_per_group == 0
        || inodes_per_group > block_size.saturating_mul(8)
        || free_inodes > inode_count
    {
        return None;
    }

    let has_64_bit = feature_incompat & 0x80 != 0;
    let blocks_high = if has_64_bit {
        u64::from(read_u32(superblock, 336, true)?)
    } else {
        0
    };
    let block_count = (blocks_high << 32) | u64::from(blocks_low);
    if u64::from(first_data_block) >= block_count || u64::from(free_blocks) > block_count {
        return None;
    }

    let data_blocks = block_count.checked_sub(u64::from(first_data_block))?;
    let group_count =
        data_blocks.checked_add(u64::from(blocks_per_group) - 1)? / u64::from(blocks_per_group);
    if group_count.checked_mul(u64::from(inodes_per_group))? < u64::from(inode_count) {
        return None;
    }
    if has_64_bit {
        let descriptor_size = u32::from(read_u16(superblock, 254, true)?);
        if descriptor_size < 64
            || descriptor_size > block_size
            || !descriptor_size.is_multiple_of(8)
        {
            return None;
        }
    }

    let image_size = block_count.checked_mul(u64::from(block_size))?;
    let image_end = (filesystem_start as u64).checked_add(image_size)?;
    if image_end > bytes.len() as u64 {
        return None;
    }

    let format = if feature_incompat & EXT4_INCOMPAT_EVIDENCE != 0 {
        "ext4"
    } else if feature_compat & 0x4 != 0 {
        "ext3"
    } else {
        "ext2"
    };
    Some(FilesystemHeader {
        format: format.to_string(),
        offset: filesystem_start as u64,
        endianness: Some("little".to_string()),
        version: Some(revision.to_string()),
        compression: None,
        inode_count: Some(inode_count),
        block_size: Some(block_size),
        image_size: Some(image_size),
        created_unix: None,
    })
}

fn parse_fdt_at(bytes: &[u8], offset: u64) -> Option<ContainerHeader> {
    if bytes.get(..4)? != FDT_MAGIC || bytes.len() < FDT_HEADER_SIZE {
        return None;
    }
    let total_size = usize::try_from(read_u32(bytes, 4, false)?).ok()?;
    let structure_offset = usize::try_from(read_u32(bytes, 8, false)?).ok()?;
    let strings_offset = usize::try_from(read_u32(bytes, 12, false)?).ok()?;
    let reserve_offset = usize::try_from(read_u32(bytes, 16, false)?).ok()?;
    let version = read_u32(bytes, 20, false)?;
    let last_compatible = read_u32(bytes, 24, false)?;
    let strings_size = usize::try_from(read_u32(bytes, 32, false)?).ok()?;
    let structure_size = usize::try_from(read_u32(bytes, 36, false)?).ok()?;
    if total_size < FDT_HEADER_SIZE
        || total_size > bytes.len()
        || version != 17
        || !(16..=version).contains(&last_compatible)
        || structure_offset < FDT_HEADER_SIZE
        || !structure_offset.is_multiple_of(4)
        || strings_offset < FDT_HEADER_SIZE
        || reserve_offset < FDT_HEADER_SIZE
        || !reserve_offset.is_multiple_of(8)
    {
        return None;
    }
    let structure_end = structure_offset.checked_add(structure_size)?;
    let strings_end = strings_offset.checked_add(strings_size)?;
    if structure_end > total_size
        || strings_end > total_size
        || ranges_overlap(structure_offset, structure_end, strings_offset, strings_end)
    {
        return None;
    }
    let reserve_limit = structure_offset.min(strings_offset);
    if reserve_offset >= reserve_limit
        || !valid_fdt_reserve_map(bytes, reserve_offset, reserve_limit)
    {
        return None;
    }

    let structure = bytes.get(structure_offset..structure_end)?;
    let strings = bytes.get(strings_offset..strings_end)?;
    let is_fit = validate_fdt_structure(structure, strings)?;
    let format = if is_fit { "fit" } else { "fdt" };
    Some(ContainerHeader {
        format: format.to_string(),
        offset,
        header_size: FDT_HEADER_SIZE as u64,
        magic: "D00DFEED".to_string(),
        vendor: None,
        package_name: None,
        timestamp_unix: None,
        declared_payload_size: Some(total_size as u64),
        actual_payload_size: Some(total_size as u64),
        payload_type: Some(
            if is_fit {
                "boot image tree"
            } else {
                "device tree blob"
            }
            .to_string(),
        ),
        payload_marker: None,
        seed_hex: None,
        integrity_algorithm: None,
        stored_digest_hex: None,
        computed_digest_hex: None,
        integrity_status: None,
    })
}

fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

fn valid_fdt_reserve_map(bytes: &[u8], mut cursor: usize, limit: usize) -> bool {
    while let Some(end) = cursor.checked_add(16) {
        if end > limit {
            return false;
        }
        let Some(address) = read_u64(bytes, cursor, false) else {
            return false;
        };
        let Some(size) = read_u64(bytes, cursor + 8, false) else {
            return false;
        };
        if address == 0 && size == 0 {
            return true;
        }
        if address.checked_add(size).is_none() {
            return false;
        }
        cursor = end;
    }
    false
}

fn validate_fdt_structure(structure: &[u8], strings: &[u8]) -> Option<bool> {
    let mut cursor = 0usize;
    let mut node_depth = 0usize;
    let mut saw_root = false;
    let mut saw_images = false;
    let mut saw_configurations = false;

    loop {
        let token = read_u32(structure, cursor, false)?;
        cursor = cursor.checked_add(4)?;
        match token {
            FDT_BEGIN_NODE => {
                let name_tail = structure.get(cursor..)?;
                let terminator = name_tail.iter().position(|byte| *byte == 0)?;
                let name = name_tail.get(..terminator)?;
                if node_depth == 0 {
                    if saw_root || !name.is_empty() {
                        return None;
                    }
                    saw_root = true;
                } else {
                    if name.is_empty() || !valid_fdt_name(name) || node_depth >= 256 {
                        return None;
                    }
                    if node_depth == 1 {
                        saw_images |= name == b"images";
                        saw_configurations |= name == b"configurations";
                    }
                }
                node_depth = node_depth.checked_add(1)?;
                cursor = align_up_four(cursor.checked_add(terminator)?.checked_add(1)?)?;
                if cursor > structure.len() {
                    return None;
                }
            }
            FDT_END_NODE => {
                node_depth = node_depth.checked_sub(1)?;
            }
            FDT_PROP => {
                if node_depth == 0 {
                    return None;
                }
                let value_size = usize::try_from(read_u32(structure, cursor, false)?).ok()?;
                let name_offset = usize::try_from(read_u32(structure, cursor + 4, false)?).ok()?;
                cursor = cursor.checked_add(8)?;
                let property_name = strings.get(name_offset..)?;
                let name_end = property_name.iter().position(|byte| *byte == 0)?;
                let name = property_name.get(..name_end)?;
                if name.is_empty() || !valid_fdt_name(name) {
                    return None;
                }
                cursor = align_up_four(cursor.checked_add(value_size)?)?;
                if cursor > structure.len() {
                    return None;
                }
            }
            FDT_NOP => {}
            FDT_END => {
                if !saw_root
                    || node_depth != 0
                    || structure.get(cursor..)?.iter().any(|byte| *byte != 0)
                {
                    return None;
                }
                return Some(saw_images && saw_configurations);
            }
            _ => return None,
        }
    }
}

fn valid_fdt_name(name: &[u8]) -> bool {
    name.iter()
        .all(|byte| byte.is_ascii_graphic() && *byte != b'/')
}

fn parse_trx_at(bytes: &[u8], offset: u64) -> Option<ContainerHeader> {
    if bytes.get(..4)? != TRX_MAGIC || bytes.len() < TRX_HEADER_SIZE {
        return None;
    }
    let total_size = usize::try_from(read_u32(bytes, 4, true)?).ok()?;
    if total_size < TRX_HEADER_SIZE || total_size > bytes.len() {
        return None;
    }
    let flags_version = read_u32(bytes, 12, true)?;
    let flags = flags_version & 0xffff;
    let version = flags_version >> 16;
    if !matches!(version, 1 | 2) {
        return None;
    }
    let header_size = if version == 2 { 32 } else { TRX_HEADER_SIZE };
    if total_size < header_size {
        return None;
    }

    let mut partitions = Vec::new();
    let mut saw_zero = false;
    for index in 0..if version == 2 { 4 } else { 3 } {
        let partition_offset = read_u32(bytes, 16 + index * 4, true)?;
        if partition_offset == 0 {
            saw_zero = true;
            continue;
        }
        if saw_zero
            || partition_offset < header_size as u32
            || partition_offset as usize >= total_size
            || !partition_offset.is_multiple_of(4)
            || partitions
                .last()
                .is_some_and(|previous| *previous >= partition_offset)
        {
            return None;
        }
        partitions.push(partition_offset);
    }
    if partitions.is_empty() {
        return None;
    }
    if version == 2 && partitions.len() != 4 {
        return None;
    }

    let stored_crc = read_u32(bytes, 8, true)?;
    let computed_crc = if version == 2 {
        let stable_start = usize::try_from(*partitions.get(3)?).ok()?.checked_add(22)?;
        let stable_end = stable_start.checked_add(8)?;
        if stable_end > total_size {
            return None;
        }
        let mut raw_crc = crc32_ieee_update(0xffff_ffff, bytes.get(12..stable_start)?);
        raw_crc = crc32_ieee_update(raw_crc, &[0xff; 8]);
        !crc32_ieee_update(raw_crc, bytes.get(stable_end..total_size)?)
    } else {
        crc32_ieee(bytes.get(12..total_size)?)
    };
    if stored_crc != computed_crc {
        return None;
    }

    let payload_marker = partitions
        .iter()
        .map(|partition| format!("0x{partition:X}"))
        .collect::<Vec<_>>()
        .join(",");
    Some(ContainerHeader {
        format: "trx".to_string(),
        offset,
        header_size: header_size as u64,
        magic: "HDR0".to_string(),
        vendor: Some("Broadcom".to_string()),
        package_name: Some(format!("version {version}, flags 0x{flags:04X}")),
        timestamp_unix: None,
        declared_payload_size: Some(total_size as u64),
        actual_payload_size: Some(total_size as u64),
        payload_type: Some("partitioned firmware".to_string()),
        payload_marker: Some(format!("partitions@{payload_marker}")),
        seed_hex: None,
        integrity_algorithm: Some("CRC32(bytes[12..length])".to_string()),
        stored_digest_hex: Some(format!("0x{stored_crc:08X}")),
        computed_digest_hex: Some(format!("0x{computed_crc:08X}")),
        integrity_status: Some("CRC32 ok".to_string()),
    })
}

fn is_valid_lzma_properties(properties: u8) -> bool {
    if !matches!(properties, 0x5D | 0x6D | 0x5E | 0x6E) {
        return false;
    }
    let value = properties as u32;
    let lc = value % 9;
    let remainder = value / 9;
    let lp = remainder % 5;
    let pb = remainder / 5;
    lc <= 8 && lp <= 4 && pb <= 4
}

fn is_plausible_lzma_dictionary_size(dict_size: u32) -> bool {
    (16..=27).any(|shift| dict_size == (1u32 << shift))
}

fn gzip_os_name(code: u8) -> Option<String> {
    Some(
        match code {
            0 => "fat",
            3 => "unix",
            7 => "macintosh",
            11 => "ntfs",
            255 => "unknown",
            _ => return None,
        }
        .to_string(),
    )
}

fn squashfs_compression_name(code: u16) -> Option<String> {
    Some(
        match code {
            1 => "gzip",
            2 => "lzma",
            3 => "lzo",
            4 => "xz",
            5 => "lz4",
            6 => "zstd",
            _ => return None,
        }
        .to_string(),
    )
}

fn read_u16(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(if little_endian {
        u16::from_le_bytes([slice[0], slice[1]])
    } else {
        u16::from_be_bytes([slice[0], slice[1]])
    })
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
    } else {
        u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
    })
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(if little_endian {
        u64::from_le_bytes(slice.try_into().ok()?)
    } else {
        u64::from_be_bytes(slice.try_into().ok()?)
    })
}

#[cfg(test)]
mod candidate_tests {
    use super::*;

    #[test]
    fn candidate_collection_uses_one_automaton_pass() {
        let bytes = b"HDR0-noise-070701-more-noise-UBI#-D00D";
        let candidates = collect_candidates(bytes);
        assert_eq!(candidates.collection_passes, 1);
        assert!(candidates
            .container
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(candidates
            .filesystem
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(candidates
            .compression
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
    }
}
