use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use fat_core::bootloader::{
    BootEnvVariable, BootFlowHint, BootImageHeader, BootValueSource, BootloaderSnapshot,
    EmbeddedSignature, KernelCmdline, MtdPartition, MtdPartitionMap, SecureBootHint,
};
use fat_core::inspection::{CompressionMember, ContainerHeader, FilesystemHeader};
use fat_core::layout::{
    LayoutOverlap, LayoutRegion, LayoutRegionKind, LayoutRegionPartition, LayoutRegionRole,
    LayoutRegionScope, LayoutReport, LayoutSummary,
};
use md5::{Digest, Md5};
use memchr::memmem;

use crate::firmware_formats::{crc32_ieee, parse_cramfs_at, parse_gzip_at, scan};

const UIMAGE_MAGIC: u32 = 0x2705_1956;
const UIMAGE_HEADER_SIZE: usize = 64;
const UNITREE_UPK_HEADER_SIZE: usize = 112;
const MAX_CMDLINE_SCAN_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

pub fn analyze_text(text: &str) -> BootloaderSnapshot {
    let mut snapshot = BootloaderSnapshot::default();

    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let lower = line.to_ascii_lowercase();

        if snapshot.family.is_none() && lower.contains("u-boot") {
            snapshot.family = Some("u-boot".to_string());
        }

        if snapshot.version_hint.is_none() && lower.contains("u-boot") {
            snapshot.version_hint = Some(line.to_string());
        }

        if let Some((key, value)) = parse_env_assignment(line) {
            snapshot.env_variables.push(BootEnvVariable {
                key: key.to_string(),
                value: value.to_string(),
                source: BootValueSource::Observed,
            });

            match key.to_ascii_lowercase().as_str() {
                "bootdelay" => {
                    if parse_integer(value).is_some() {
                        push_flow_hint(&mut snapshot, line);
                        push_finding(&mut snapshot.findings, "BOOT-ENV-CONTROLLED-FLOW");
                    }
                }
                "bootcmd" | "bootargs" => {
                    push_flow_hint(&mut snapshot, value);
                    push_finding(&mut snapshot.findings, "BOOT-ENV-CONTROLLED-FLOW");
                }
                "verify" => {
                    if !is_truthy(value) {
                        push_finding(&mut snapshot.findings, "BOOT-SIG-BYPASS");
                    }
                }
                "sig_check" => {
                    snapshot.secure_boot_hints.push(SecureBootHint {
                        value: line.to_string(),
                    });
                    if !is_truthy(value) {
                        push_finding(&mut snapshot.findings, "BOOT-SIG-BYPASS");
                    }
                }
                "recovery_mode" => {
                    if is_falsey(value) {
                        push_finding(&mut snapshot.findings, "BOOT-RECOVERY-DISABLED");
                    }
                }
                _ if key.to_ascii_lowercase().contains("rollback")
                    && (is_zeroish(value) || is_falsey(value)) =>
                {
                    push_finding(&mut snapshot.findings, "BOOT-ROLLBACK-BYPASS");
                }
                _ => {}
            }
        } else if lower.contains("verify_sig") || lower.contains("bootm ") {
            push_flow_hint(&mut snapshot, line);
        }
    }

    finalize_snapshot(snapshot)
}

pub fn analyze_firmware_path(path: &Path) -> std::io::Result<BootloaderSnapshot> {
    analyze_firmware_bytes(&fs::read(path)?)
}

pub fn analyze_firmware_bytes(bytes: &[u8]) -> std::io::Result<BootloaderSnapshot> {
    let native_formats = scan(bytes);
    let mut snapshot = BootloaderSnapshot {
        container_headers: parse_container_headers(bytes, native_formats.container_headers),
        ..Default::default()
    };
    if snapshot
        .container_headers
        .iter()
        .any(|header| header.magic == "UTPK")
    {
        return Ok(finalize_snapshot(snapshot));
    }
    snapshot.image_headers = parse_uimage_headers(bytes);
    snapshot.compression_members = native_formats.compression_members;
    snapshot.filesystem_headers = native_formats.filesystem_headers;
    snapshot.embedded_signatures =
        synthesize_embedded_signatures(&snapshot.filesystem_headers, &snapshot.compression_members);
    snapshot.kernel_cmdline = recover_kernel_cmdline(
        bytes,
        &snapshot.image_headers,
        &snapshot.compression_members,
    );
    snapshot.partition_map = snapshot
        .kernel_cmdline
        .as_ref()
        .and_then(|cmdline| parse_mtd_partition_map(&cmdline.value, cmdline.source.clone()));

    if !snapshot.image_headers.is_empty() {
        snapshot.family = Some("u-boot".to_string());
        snapshot.secure_boot_hints.push(SecureBootHint {
            value: "legacy uImage headers expose CRC32 integrity fields but no cryptographic signature metadata".to_string(),
        });
        push_finding(&mut snapshot.findings, "BOOT-UIMAGE-CRC32-ONLY");
    }

    Ok(finalize_snapshot(snapshot))
}

pub fn analyze_layout_path(path: &Path) -> std::io::Result<LayoutReport> {
    analyze_layout_bytes(&fs::read(path)?)
}

pub fn analyze_layout_bytes(bytes: &[u8]) -> std::io::Result<LayoutReport> {
    build_layout_report_with_bytes(&analyze_firmware_bytes(bytes)?, bytes)
}

pub fn build_layout_report(snapshot: &BootloaderSnapshot) -> std::io::Result<LayoutReport> {
    build_layout_report_internal(snapshot, None)
}

pub fn build_layout_report_with_bytes(
    snapshot: &BootloaderSnapshot,
    bytes: &[u8],
) -> std::io::Result<LayoutReport> {
    build_layout_report_internal(snapshot, Some(bytes))
}

fn build_layout_report_internal(
    snapshot: &BootloaderSnapshot,
    bytes: Option<&[u8]>,
) -> std::io::Result<LayoutReport> {
    let dominant_filesystem_offset = snapshot
        .filesystem_headers
        .iter()
        .filter_map(|header| header.image_size.map(|size| (header.offset, size)))
        .max_by_key(|(_, size)| *size)
        .map(|(offset, _)| offset);

    let mut regions = Vec::new();

    for header in &snapshot.container_headers {
        let size = container_region_size(header);
        regions.push(LayoutRegion {
            offset: header.offset,
            kind: LayoutRegionKind::Container,
            format: header.format.clone(),
            size,
            uncompressed_size: None,
            end_offset: exact_region_end(header.offset, size),
            span_is_exact: size.is_some(),
            fills_to_eof: false,
            span_source: size.map(|_| "validated container length".to_string()),
            original_name: None,
            architecture: None,
            kernel_format: None,
            role: LayoutRegionRole::FirmwareContainer,
            partition: None,
            scope: LayoutRegionScope::TopLevel,
            depth: 0,
            parent_offset: None,
            notes: container_notes(header),
        });
    }

    for header in &snapshot.image_headers {
        let size = header.header_size.checked_add(header.data_size);
        regions.push(LayoutRegion {
            offset: header.offset,
            kind: LayoutRegionKind::BootImage,
            format: header.format.clone(),
            size,
            uncompressed_size: None,
            end_offset: exact_region_end(header.offset, size),
            span_is_exact: size.is_some(),
            fills_to_eof: false,
            span_source: size.map(|_| "validated image header and payload length".to_string()),
            original_name: header.name.clone(),
            architecture: header.architecture.clone(),
            kernel_format: None,
            role: infer_uimage_role(header),
            partition: None,
            scope: LayoutRegionScope::TopLevel,
            depth: 0,
            parent_offset: None,
            notes: boot_image_notes(header),
        });
    }

    for member in &snapshot.compression_members {
        let size = member.compressed_size;
        regions.push(LayoutRegion {
            offset: member.offset,
            kind: LayoutRegionKind::Compression,
            format: member.format.clone(),
            size,
            uncompressed_size: member.uncompressed_size,
            end_offset: exact_region_end(member.offset, size),
            span_is_exact: size.is_some(),
            fills_to_eof: false,
            span_source: size.map(|_| "validated compressed member span".to_string()),
            original_name: member.original_name.clone(),
            architecture: member.payload_architecture.clone(),
            kernel_format: member.payload_format.clone(),
            role: infer_compression_role(member, dominant_filesystem_offset),
            partition: None,
            scope: LayoutRegionScope::TopLevel,
            depth: 0,
            parent_offset: None,
            notes: compression_notes(member),
        });
    }

    for header in &snapshot.filesystem_headers {
        let size = header.image_size;
        regions.push(LayoutRegion {
            offset: header.offset,
            kind: LayoutRegionKind::Filesystem,
            format: header.format.clone(),
            size,
            uncompressed_size: None,
            end_offset: exact_region_end(header.offset, size),
            span_is_exact: size.is_some(),
            fills_to_eof: false,
            span_source: size.map(|_| "validated filesystem image length".to_string()),
            original_name: None,
            architecture: None,
            kernel_format: None,
            role: LayoutRegionRole::LikelyRootfs,
            partition: None,
            scope: LayoutRegionScope::TopLevel,
            depth: 0,
            parent_offset: None,
            notes: filesystem_notes(header),
        });
    }

    regions.sort_by_key(|region| region.offset);
    apply_partition_map(&mut regions, snapshot.partition_map.as_ref());
    assign_region_structure(&mut regions);
    if let Some(bytes) = bytes {
        regions.extend(synthesize_uniform_padding(&regions, bytes));
        regions.sort_by_key(|region| region.offset);
        assign_region_structure(&mut regions);
        let file_size = bytes.len() as u64;
        for region in &mut regions {
            region.fills_to_eof = region.span_is_exact && region.end_offset == Some(file_size);
        }
    }
    let overlaps = detect_partial_overlaps(&regions);
    let summary = build_layout_summary(&regions);

    Ok(LayoutReport {
        summary,
        partition_map: snapshot.partition_map.clone(),
        regions,
        overlaps,
    })
}

pub fn merge_snapshots(
    mut base: BootloaderSnapshot,
    overlay: BootloaderSnapshot,
) -> BootloaderSnapshot {
    if base.family.is_none() {
        base.family = overlay.family;
    }
    if base.version_hint.is_none() {
        base.version_hint = overlay.version_hint;
    }

    base.env_variables.extend(overlay.env_variables);
    base.flow_hints.extend(overlay.flow_hints);
    base.secure_boot_hints.extend(overlay.secure_boot_hints);
    if base.kernel_cmdline.is_none() {
        base.kernel_cmdline = overlay.kernel_cmdline;
    }
    if base.partition_map.is_none() {
        base.partition_map = overlay.partition_map;
    }
    base.image_headers.extend(overlay.image_headers);
    base.container_headers.extend(overlay.container_headers);
    base.compression_members.extend(overlay.compression_members);
    base.filesystem_headers.extend(overlay.filesystem_headers);
    base.embedded_signatures.extend(overlay.embedded_signatures);
    base.findings.extend(overlay.findings);

    finalize_snapshot(base)
}

fn finalize_snapshot(mut snapshot: BootloaderSnapshot) -> BootloaderSnapshot {
    snapshot.findings.sort();
    snapshot.findings.dedup();
    snapshot.flow_hints.sort_by(|a, b| a.value.cmp(&b.value));
    snapshot.flow_hints.dedup_by(|a, b| a.value == b.value);
    snapshot.env_variables.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| boot_value_source_rank(a.source).cmp(&boot_value_source_rank(b.source)))
    });
    snapshot.env_variables.dedup_by(|left, right| {
        left.key == right.key && left.value == right.value && left.source == right.source
    });
    snapshot
        .secure_boot_hints
        .sort_by(|a, b| a.value.cmp(&b.value));
    snapshot
        .secure_boot_hints
        .dedup_by(|a, b| a.value == b.value);
    snapshot.image_headers.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.format.cmp(&b.format))
            .then_with(|| a.name.cmp(&b.name))
    });
    snapshot
        .image_headers
        .dedup_by(|left, right| left.offset == right.offset && left.format == right.format);
    snapshot.container_headers.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.format.cmp(&b.format))
            .then_with(|| a.package_name.cmp(&b.package_name))
    });
    snapshot
        .container_headers
        .dedup_by(|left, right| left.offset == right.offset && left.format == right.format);
    snapshot.compression_members.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.format.cmp(&b.format))
            .then_with(|| a.properties_hex.cmp(&b.properties_hex))
    });
    snapshot
        .compression_members
        .dedup_by(|left, right| left.offset == right.offset && left.format == right.format);
    snapshot.filesystem_headers.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.format.cmp(&b.format))
            .then_with(|| a.version.cmp(&b.version))
    });
    snapshot
        .filesystem_headers
        .dedup_by(|left, right| left.offset == right.offset && left.format == right.format);
    snapshot.embedded_signatures.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.format.cmp(&b.format))
            .then_with(|| a.description.cmp(&b.description))
    });
    snapshot.embedded_signatures.dedup_by(|left, right| {
        left.offset == right.offset
            && left.format == right.format
            && left.description == right.description
    });
    snapshot
}

fn parse_container_headers(
    bytes: &[u8],
    native_headers: Vec<ContainerHeader>,
) -> Vec<ContainerHeader> {
    let mut headers = native_headers;
    if let Some(header) = parse_unitree_upk_header(bytes) {
        headers.push(header);
    }
    if let Some(header) = parse_moxa_rom_map(bytes) {
        headers.push(header);
    }
    headers
}

fn parse_moxa_rom_map(bytes: &[u8]) -> Option<ContainerHeader> {
    if bytes.len() < 32 {
        return None;
    }

    let kernel_slot = read_u32(bytes, 0, false)?;
    let rootfs_size = read_u32(bytes, 4, false)?;
    let kernel_offset = read_u32(bytes, 8, false)?;
    let region_count = read_u32(bytes, 12, false)?;
    let version = bytes.get(20..24)?;
    let date = bytes.get(24..28)?;

    if kernel_offset == 0 || kernel_slot == 0 || rootfs_size == 0 {
        return None;
    }
    if region_count == 0 || region_count > 8 {
        return None;
    }

    let rootfs_offset = u64::from(kernel_offset).checked_add(u64::from(kernel_slot))?;
    let declared_end = rootfs_offset.checked_add(u64::from(rootfs_size))?;
    if rootfs_offset as usize >= bytes.len() || declared_end > bytes.len() as u64 {
        return None;
    }
    parse_gzip_at(bytes, u64::from(kernel_offset))?;
    let cramfs = parse_cramfs_at(bytes, rootfs_offset)?;
    if cramfs.image_size != Some(u64::from(rootfs_size)) {
        return None;
    }
    if !is_plausible_moxa_version(version) || !is_plausible_moxa_date(date) {
        return None;
    }

    Some(ContainerHeader {
        format: "moxa-rom-map".to_string(),
        offset: 0,
        header_size: 32,
        magic: "MOXA".to_string(),
        vendor: Some("Moxa".to_string()),
        package_name: Some(format!("{}.{}", version[0], version[1])),
        timestamp_unix: None,
        declared_payload_size: Some(u64::from(rootfs_size)),
        actual_payload_size: Some(bytes.len() as u64),
        payload_type: Some("kernel+cramfs".to_string()),
        payload_marker: Some(format!("rootfs@0x{rootfs_offset:08X}")),
        seed_hex: None,
        integrity_algorithm: None,
        stored_digest_hex: None,
        computed_digest_hex: None,
        integrity_status: None,
    })
}

fn is_plausible_moxa_version(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && bytes[0] > 0
        && bytes[0] < 20
        && bytes[1] < 100
        && bytes[2] == 0
        && bytes[3] == 0
}

fn is_plausible_moxa_date(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && (20..=30).contains(&bytes[0])
        && (1..=12).contains(&bytes[1])
        && (1..=31).contains(&bytes[2])
        && bytes[3] < 24
}

fn parse_unitree_upk_header(bytes: &[u8]) -> Option<ContainerHeader> {
    if bytes.len() < UNITREE_UPK_HEADER_SIZE || bytes.get(..4)? != b"UTPK" {
        return None;
    }

    let declared_payload_size = read_u64(bytes, 16, true)?;
    let actual_payload_size = bytes.len().saturating_sub(UNITREE_UPK_HEADER_SIZE) as u64;
    let payload = bytes.get(UNITREE_UPK_HEADER_SIZE..)?;
    let payload_marker = payload.get(..4).and_then(|marker| {
        if marker == b"TEA\0" {
            Some("TEA".to_string())
        } else {
            parse_c_string(marker)
        }
    });
    let stored_digest = bytes.get(32..48)?;
    let computed_digest = Md5::digest(payload);
    let stored_digest_hex = format_hex_bytes(stored_digest);
    let computed_digest_hex = format_hex_bytes(computed_digest.as_slice());
    let integrity_status = if declared_payload_size == actual_payload_size
        && stored_digest_hex.eq_ignore_ascii_case(&computed_digest_hex)
    {
        "MD5 ok"
    } else {
        "MD5 mismatch"
    };

    Some(ContainerHeader {
        format: "Unitree UPK / UTPK".to_string(),
        offset: 0,
        header_size: UNITREE_UPK_HEADER_SIZE as u64,
        magic: "UTPK".to_string(),
        vendor: Some("Unitree".to_string()),
        package_name: parse_c_string(&bytes[48..112]),
        timestamp_unix: read_u64(bytes, 8, true),
        declared_payload_size: Some(declared_payload_size),
        actual_payload_size: Some(actual_payload_size),
        payload_type: Some(unitree_payload_type(bytes[24]).to_string()),
        payload_marker,
        seed_hex: bytes.get(28..32).map(format_hex_bytes),
        integrity_algorithm: Some("MD5(payload)".to_string()),
        stored_digest_hex: Some(stored_digest_hex),
        computed_digest_hex: Some(computed_digest_hex),
        integrity_status: Some(integrity_status.to_string()),
    })
}

fn parse_uimage_headers(bytes: &[u8]) -> Vec<BootImageHeader> {
    if bytes.len() < UIMAGE_HEADER_SIZE {
        return Vec::new();
    }

    let mut headers = Vec::new();
    for offset in find_magic_offsets(bytes, &UIMAGE_MAGIC.to_be_bytes()) {
        if offset + UIMAGE_HEADER_SIZE > bytes.len() {
            continue;
        }
        let header = &bytes[offset..offset + UIMAGE_HEADER_SIZE];
        // The magic (0x27051956) is only 4 bytes and collides with unrelated
        // data. Validate the header CRC32 so false matches don't surface
        // garbage fields (e.g. non-printable `uimage:name:` signals).
        if !uimage_header_crc_valid(header) {
            continue;
        }
        headers.push(BootImageHeader {
            format: "uimage".to_string(),
            offset: offset as u64,
            header_size: UIMAGE_HEADER_SIZE as u64,
            magic_hex: format_hex_u32(UIMAGE_MAGIC),
            data_size: read_be_u32(header, 12).unwrap_or_default() as u64,
            load_address_hex: format_hex_u32(read_be_u32(header, 16).unwrap_or_default()),
            entry_point_hex: format_hex_u32(read_be_u32(header, 20).unwrap_or_default()),
            header_crc32_hex: format_hex_u32(read_be_u32(header, 4).unwrap_or_default()),
            data_crc32_hex: format_hex_u32(read_be_u32(header, 24).unwrap_or_default()),
            timestamp_unix: read_be_u32(header, 8).unwrap_or_default() as u64,
            name: parse_uimage_name(&header[32..64]),
            os_code_hex: Some(format_hex_u8(header[28])),
            operating_system: uimage_os_name(header[28]),
            architecture_code_hex: Some(format_hex_u8(header[29])),
            architecture: uimage_arch_name(header[29]),
            image_type_code_hex: Some(format_hex_u8(header[30])),
            image_type: uimage_type_name(header[30]),
            compression_code_hex: Some(format_hex_u8(header[31])),
            compression: uimage_compression_name(header[31]),
        });
    }

    headers
}

/// Validate a 64-byte legacy uImage header against its stored CRC32 (big-endian
/// at offset 4). The CRC is computed over the header with the CRC field zeroed.
fn uimage_header_crc_valid(header: &[u8]) -> bool {
    if header.len() < UIMAGE_HEADER_SIZE {
        return false;
    }
    let Some(stored) = read_be_u32(header, 4) else {
        return false;
    };
    let mut buffer = [0u8; UIMAGE_HEADER_SIZE];
    buffer.copy_from_slice(&header[..UIMAGE_HEADER_SIZE]);
    buffer[4..8].fill(0);
    crc32_ieee(&buffer) == stored
}

/// Extract the uImage name field, keeping it only when it is printable ASCII so
/// a validated-but-odd header never emits a garbled `uimage:name:` value.
fn parse_uimage_name(bytes: &[u8]) -> Option<String> {
    parse_c_string(bytes).filter(|name| name.chars().all(|ch| ch.is_ascii_graphic() || ch == ' '))
}

fn synthesize_embedded_signatures(
    filesystems: &[FilesystemHeader],
    members: &[CompressionMember],
) -> Vec<EmbeddedSignature> {
    let mut signatures = Vec::new();
    for header in filesystems {
        let description = match header.format.as_str() {
            "squashfs" => format!(
                "SquashFS filesystem ({})",
                header
                    .endianness
                    .as_deref()
                    .map(|endian| format!("{endian} endian"))
                    .unwrap_or_else(|| "unknown endian".to_string())
            ),
            "cramfs" => format!(
                "CramFS filesystem ({})",
                header
                    .endianness
                    .as_deref()
                    .map(|endian| format!("{endian} endian"))
                    .unwrap_or_else(|| "unknown endian".to_string())
            ),
            other => format!("{other} filesystem"),
        };
        signatures.push(EmbeddedSignature {
            format: header.format.clone(),
            offset: header.offset,
            description,
        });
    }
    for member in members {
        let description = match member.format.as_str() {
            "gzip" => "gzip compressed data".to_string(),
            "lzma" => parse_lzma_alone_signature_from_member(member),
            other => format!("{other} compressed data"),
        };
        signatures.push(EmbeddedSignature {
            format: member.format.clone(),
            offset: member.offset,
            description,
        });
    }
    signatures.sort_by_key(|signature| (signature.offset, signature.format.clone()));
    signatures
}

fn parse_lzma_alone_signature_from_member(member: &CompressionMember) -> String {
    format!(
        "LZMA-alone stream (properties {}, dictionary {} bytes, uncompressed size {})",
        member.properties_hex.as_deref().unwrap_or("unknown"),
        member.dictionary_size.unwrap_or_default(),
        member
            .uncompressed_size
            .map(|size| format!("{size} bytes"))
            .unwrap_or_else(|| "unknown".to_string())
    )
}

fn find_magic_offsets(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || bytes.len() < needle.len() {
        return Vec::new();
    }
    memmem::find_iter(bytes, needle).collect()
}

fn recover_kernel_cmdline(
    bytes: &[u8],
    headers: &[BootImageHeader],
    members: &[CompressionMember],
) -> Option<KernelCmdline> {
    for header in headers
        .iter()
        .filter(|header| header.compression.as_deref() == Some("lzma"))
    {
        let start = header.offset.saturating_add(header.header_size) as usize;
        if start >= bytes.len() {
            continue;
        }
        let end = start
            .saturating_add(header.data_size as usize)
            .min(bytes.len());
        let Some(decompressed) = decompress_lzma_limited(&bytes[start..end]) else {
            continue;
        };
        if let Some(value) = find_kernel_cmdline(&decompressed) {
            return Some(KernelCmdline {
                value,
                source: Some(format!("lzma @ 0x{start:08X}")),
            });
        }
    }

    for member in members.iter().filter(|member| member.format == "lzma") {
        let start = member.offset as usize;
        if start >= bytes.len() {
            continue;
        }

        let Some(decompressed) = decompress_lzma_limited(&bytes[start..]) else {
            continue;
        };
        if let Some(value) = find_kernel_cmdline(&decompressed) {
            return Some(KernelCmdline {
                value,
                source: Some(format!("lzma @ 0x{:08X}", member.offset)),
            });
        }
    }

    find_kernel_cmdline(bytes).map(|value| KernelCmdline {
        value,
        source: Some("raw bytes".to_string()),
    })
}

fn decompress_lzma_limited(input: &[u8]) -> Option<Vec<u8>> {
    decompress_lzma_limited_with_xz2(input).or_else(|| decompress_lzma_limited_with_lzma_rs(input))
}

fn decompress_lzma_limited_with_xz2(input: &[u8]) -> Option<Vec<u8>> {
    let stream = xz2::stream::Stream::new_lzma_decoder(u64::MAX).ok()?;
    let mut decoder = xz2::bufread::XzDecoder::new_stream(Cursor::new(input), stream);
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if output.len().saturating_add(read) > MAX_CMDLINE_SCAN_DECOMPRESSED_BYTES {
                    return None;
                }
                output.extend_from_slice(&buffer[..read]);
            }
            Err(_) if !output.is_empty() => break,
            Err(_) => return None,
        }
    }

    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

fn decompress_lzma_limited_with_lzma_rs(input: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Cursor::new(input);
    let mut writer = LimitedVecWriter::new(MAX_CMDLINE_SCAN_DECOMPRESSED_BYTES);
    let result = lzma_rs::lzma_decompress(&mut reader, &mut writer);
    if result.is_ok() || !writer.is_empty() {
        return Some(writer.into_inner());
    }
    None
}

struct LimitedVecWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl LimitedVecWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Write for LimitedVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed payload exceeds cmdline scan limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn find_kernel_cmdline(bytes: &[u8]) -> Option<String> {
    // High-signal cmdline markers. Search with an optimized substring scan
    // rather than materializing a String for every printable run, which is
    // pathological on large high-entropy blobs (thousands of allocations).
    const MARKERS: [&[u8]; 2] = [b"mtdparts=", b"root=/dev/mtdblock"];
    let mut first_hit: Option<usize> = None;
    for marker in MARKERS {
        if let Some(pos) = memmem::find(bytes, marker) {
            first_hit = Some(match first_hit {
                Some(prev) => prev.min(pos),
                None => pos,
            });
        }
    }
    let pos = first_hit?;

    // Expand to the surrounding printable run so we capture the whole cmdline,
    // not just the marker.
    let start = bytes[..pos]
        .iter()
        .rposition(|&b| !(b.is_ascii_graphic() || matches!(b, b' ' | b'\t')))
        .map(|i| i + 1)
        .unwrap_or(0);
    let end = bytes[pos..]
        .iter()
        .position(|&b| !(b.is_ascii_graphic() || matches!(b, b' ' | b'\t')))
        .map(|i| pos + i)
        .unwrap_or(bytes.len());

    let candidate = String::from_utf8_lossy(&bytes[start..end])
        .trim()
        .to_string();
    if candidate.contains("mtdparts=") || candidate.contains("root=/dev/mtdblock") {
        Some(normalize_cmdline(&candidate))
    } else {
        None
    }
}

fn normalize_cmdline(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_mtd_partition_map(value: &str, source: Option<String>) -> Option<MtdPartitionMap> {
    let mtdparts = cmdline_value(value, "mtdparts")?;
    let first_device = mtdparts.split(';').next().unwrap_or(mtdparts);
    let (device, partitions_raw) = first_device.split_once(':')?;
    let mut partitions = Vec::new();
    let mut flash_offset = 0u64;

    for (index, raw) in partitions_raw.split(',').enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (size_raw, rest) = raw.split_once('(')?;
        let name = rest.split_once(')')?.0.trim();
        let size_bytes = parse_size_bytes(size_raw.trim())?;
        partitions.push(MtdPartition {
            index: index as u32,
            name: name.to_string(),
            size_bytes,
            flash_offset,
        });
        flash_offset = flash_offset.saturating_add(size_bytes);
    }

    if partitions.is_empty() {
        return None;
    }

    Some(MtdPartitionMap {
        source: source.unwrap_or_else(|| "kernel cmdline".to_string()),
        device: device.to_string(),
        root_device: cmdline_value(value, "root").map(str::to_string),
        root_fstype: cmdline_value(value, "rootfstype").map(str::to_string),
        partitions,
    })
}

fn cmdline_value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
}

fn parse_size_bytes(value: &str) -> Option<u64> {
    let mut digits = String::new();
    let mut suffix = String::new();
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            suffix.push(ch);
        }
    }
    let base = digits.parse::<u64>().ok()?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" => 1024,
        "m" => 1024 * 1024,
        "g" => 1024 * 1024 * 1024,
        _ => return None,
    };
    Some(base.saturating_mul(multiplier))
}

fn apply_partition_map(regions: &mut [LayoutRegion], map: Option<&MtdPartitionMap>) {
    let Some(map) = map else {
        return;
    };
    let Some(delta) = best_partition_offset_delta(regions, map) else {
        return;
    };
    let root_mtdblock = map.root_device.as_deref().and_then(parse_mtdblock_number);

    for region in regions
        .iter_mut()
        .filter(|region| region.kind == LayoutRegionKind::Filesystem)
    {
        let Some(partition) = map.partitions.iter().find(|partition| {
            partition.flash_offset as i128 - region.offset as i128 == delta as i128
                && region
                    .size
                    .map(|size| size <= partition.size_bytes.saturating_add(4096))
                    .unwrap_or(true)
        }) else {
            continue;
        };

        let mount_point = if Some(partition.index) == root_mtdblock {
            Some("/".to_string())
        } else {
            None
        };
        region.role = if mount_point.as_deref() == Some("/") || partition.name == "rootfs" {
            LayoutRegionRole::LikelyRootfs
        } else {
            LayoutRegionRole::LikelyAppPartition
        };
        region.partition = Some(LayoutRegionPartition {
            mtdblock: partition.index,
            name: partition.name.clone(),
            flash_offset: partition.flash_offset,
            size_bytes: partition.size_bytes,
            firmware_offset_delta: delta,
            mount_point,
        });
    }
}

fn best_partition_offset_delta(regions: &[LayoutRegion], map: &MtdPartitionMap) -> Option<i64> {
    let mut counts: BTreeMap<i64, usize> = BTreeMap::new();
    for region in regions
        .iter()
        .filter(|region| region.kind == LayoutRegionKind::Filesystem)
    {
        for partition in &map.partitions {
            if region
                .size
                .map(|size| size > partition.size_bytes.saturating_add(4096))
                .unwrap_or(false)
            {
                continue;
            }
            let delta = partition.flash_offset as i128 - region.offset as i128;
            let Ok(delta) = i64::try_from(delta) else {
                continue;
            };
            *counts.entry(delta).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .max_by(|(left_delta, left_count), (right_delta, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_delta.abs().cmp(&left_delta.abs()))
        })
        .map(|(delta, _)| delta)
}

fn parse_mtdblock_number(value: &str) -> Option<u32> {
    value
        .rsplit_once("mtdblock")
        .and_then(|(_, number)| number.parse::<u32>().ok())
}

fn infer_uimage_role(header: &BootImageHeader) -> LayoutRegionRole {
    match header.image_type.as_deref() {
        Some("firmware") if header.offset == 0 => LayoutRegionRole::LikelyBootImage,
        Some("kernel") => LayoutRegionRole::LikelyKernelPayload,
        _ => LayoutRegionRole::UnknownRole,
    }
}

fn infer_compression_role(
    member: &CompressionMember,
    dominant_filesystem_offset: Option<u64>,
) -> LayoutRegionRole {
    if gzip_name_looks_like_kernel(member.original_name.as_deref()) {
        return LayoutRegionRole::LikelyKernelPayload;
    }
    match dominant_filesystem_offset {
        Some(filesystem_offset) if member.offset > filesystem_offset => {
            LayoutRegionRole::LikelyArchiveTail
        }
        Some(filesystem_offset) if member.offset < filesystem_offset => {
            LayoutRegionRole::LikelyCompressedPayload
        }
        _ => LayoutRegionRole::UnknownRole,
    }
}

fn gzip_name_looks_like_kernel(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.contains("vmlinux")
        || lower.contains("vmlinuz")
        || lower == "zimage"
        || lower.ends_with("/zimage")
        || lower == "image"
        || lower.ends_with("/image")
}

fn exact_region_end(offset: u64, size: Option<u64>) -> Option<u64> {
    offset.checked_add(size?)
}

fn container_region_size(header: &ContainerHeader) -> Option<u64> {
    match header.format.as_str() {
        "Unitree UPK / UTPK" => header.header_size.checked_add(header.actual_payload_size?),
        _ => header.actual_payload_size,
    }
}

fn container_notes(header: &ContainerHeader) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(payload_type) = header.payload_type.as_deref() {
        notes.push(format!("payload type {payload_type}"));
    }
    if let Some(integrity_status) = header.integrity_status.as_deref() {
        notes.push(format!("integrity {integrity_status}"));
    }
    notes
}

fn boot_image_notes(header: &BootImageHeader) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(image_type) = header.image_type.as_deref() {
        notes.push(format!("image type {image_type}"));
    }
    if let Some(compression) = header.compression.as_deref() {
        notes.push(format!("compression {compression}"));
    }
    notes
}

fn compression_notes(member: &CompressionMember) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(properties) = member.properties_hex.as_deref() {
        notes.push(format!("properties {properties}"));
    }
    if let Some(dictionary_size) = member.dictionary_size {
        notes.push(format!("dict {dictionary_size}"));
    }
    if let Some(compressed_size) = member.compressed_size {
        notes.push(format!("csize {compressed_size}"));
    }
    if let Some(uncompressed_size) = member.uncompressed_size {
        notes.push(format!("usize {uncompressed_size}"));
    }
    if let Some(operating_system) = member.operating_system.as_deref() {
        notes.push(format!("os {operating_system}"));
    }
    if let Some(timestamp_unix) = member.timestamp_unix {
        match format_unix_date(timestamp_unix) {
            Some(date) => notes.push(format!("mtime {timestamp_unix} ({date})")),
            None => notes.push(format!("mtime {timestamp_unix}")),
        }
    }
    notes
}

/// Render a Unix timestamp as a `YYYY-MM-DD` UTC date without pulling in a date
/// crate. Uses Howard Hinnant's civil-from-days algorithm. Returns `None` for
/// pre-epoch timestamps, which never appear in firmware build metadata.
fn format_unix_date(timestamp_unix: u64) -> Option<String> {
    let days = (timestamp_unix / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn filesystem_notes(header: &FilesystemHeader) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(endianness) = header.endianness.as_deref() {
        notes.push(format!("endian {endianness}"));
    }
    if let Some(version) = header.version.as_deref() {
        notes.push(format!("version {version}"));
    }
    if let Some(compression) = header.compression.as_deref() {
        notes.push(format!("compression {compression}"));
    }
    if let Some(inode_count) = header.inode_count {
        notes.push(format!("inodes {inode_count}"));
    }
    notes
}

fn assign_region_structure(regions: &mut [LayoutRegion]) {
    for index in 0..regions.len() {
        let parent_offset = smallest_containing_parent(index, regions);
        regions[index].parent_offset = parent_offset;
        regions[index].scope = if parent_offset.is_some() {
            LayoutRegionScope::Nested
        } else {
            LayoutRegionScope::TopLevel
        };
    }

    for index in 0..regions.len() {
        regions[index].depth = region_depth(index, regions);
    }
}

fn synthesize_uniform_padding(regions: &[LayoutRegion], bytes: &[u8]) -> Vec<LayoutRegion> {
    let mut siblings: BTreeMap<Option<u64>, Vec<&LayoutRegion>> = BTreeMap::new();
    for region in regions.iter().filter(|region| {
        region.span_is_exact
            && region.kind != LayoutRegionKind::Container
            && region.kind != LayoutRegionKind::Padding
    }) {
        siblings
            .entry(region.parent_offset)
            .or_default()
            .push(region);
    }

    let mut padding = Vec::new();
    for (parent_offset, mut group) in siblings {
        group.sort_by_key(|region| region.offset);
        for pair in group.windows(2) {
            let Some(gap_start) = pair[0].end_offset else {
                continue;
            };
            let gap_end = pair[1].offset;
            if gap_start >= gap_end {
                continue;
            }
            let (Ok(start), Ok(end)) = (usize::try_from(gap_start), usize::try_from(gap_end))
            else {
                continue;
            };
            let Some(gap) = bytes.get(start..end) else {
                continue;
            };
            let Some(fill) = gap.first().copied() else {
                continue;
            };
            if !matches!(fill, 0x00 | 0xff) || gap.iter().any(|byte| *byte != fill) {
                continue;
            }
            let format = if fill == 0 {
                "zero-padding"
            } else {
                "erased-padding"
            };
            padding.push(LayoutRegion {
                offset: gap_start,
                kind: LayoutRegionKind::Padding,
                format: format.to_string(),
                size: Some(gap_end - gap_start),
                uncompressed_size: None,
                end_offset: Some(gap_end),
                span_is_exact: true,
                fills_to_eof: false,
                span_source: Some(format!(
                    "uniform 0x{fill:02X} bytes between exact sibling spans"
                )),
                original_name: None,
                architecture: None,
                kernel_format: None,
                role: LayoutRegionRole::Padding,
                partition: None,
                scope: if parent_offset.is_some() {
                    LayoutRegionScope::Nested
                } else {
                    LayoutRegionScope::TopLevel
                },
                depth: u32::from(parent_offset.is_some()),
                parent_offset,
                notes: vec![format!("uniform fill 0x{fill:02X}")],
            });
        }
    }
    padding
}

fn detect_partial_overlaps(regions: &[LayoutRegion]) -> Vec<LayoutOverlap> {
    let mut overlaps = Vec::new();
    for left_index in 0..regions.len() {
        let left = &regions[left_index];
        let Some(left_end) = left.end_offset.filter(|_| left.span_is_exact) else {
            continue;
        };
        for right in &regions[left_index + 1..] {
            let Some(right_end) = right.end_offset.filter(|_| right.span_is_exact) else {
                continue;
            };
            let start = left.offset.max(right.offset);
            let end = left_end.min(right_end);
            if start >= end {
                continue;
            }
            let left_contains_right = left.offset <= right.offset && left_end >= right_end;
            let right_contains_left = right.offset <= left.offset && right_end >= left_end;
            if left_contains_right || right_contains_left {
                continue;
            }
            overlaps.push(LayoutOverlap {
                left_offset: left.offset,
                right_offset: right.offset,
                start_offset: start,
                end_offset: end,
            });
        }
    }
    overlaps
}

fn smallest_containing_parent(index: usize, regions: &[LayoutRegion]) -> Option<u64> {
    let child = &regions[index];
    if !child.span_is_exact {
        return None;
    }
    let mut best_parent: Option<(u64, u64)> = None;

    for (candidate_index, candidate) in regions.iter().enumerate() {
        if candidate_index == index || !candidate.span_is_exact {
            continue;
        }

        let Some(candidate_end) = region_end(candidate) else {
            continue;
        };

        if child.offset < candidate.offset
            || child.offset >= candidate_end
            || child.offset == candidate.offset
            || child
                .end_offset
                .filter(|_| child.span_is_exact)
                .is_some_and(|child_end| child_end > candidate_end)
        {
            continue;
        }

        let candidate_span = candidate_end.saturating_sub(candidate.offset);
        match best_parent {
            Some((_, best_span)) if candidate_span >= best_span => {}
            _ => best_parent = Some((candidate.offset, candidate_span)),
        }
    }

    best_parent.map(|(offset, _)| offset)
}

fn region_depth(index: usize, regions: &[LayoutRegion]) -> u32 {
    let mut depth = 0;
    let mut current_parent = regions[index].parent_offset;

    while let Some(parent_offset) = current_parent {
        if depth as usize >= regions.len() {
            break;
        }
        depth += 1;
        current_parent = regions
            .iter()
            .find(|region| region.offset == parent_offset)
            .and_then(|region| region.parent_offset);
    }

    depth
}

fn region_end(region: &LayoutRegion) -> Option<u64> {
    region.end_offset
}

fn build_layout_summary(regions: &[LayoutRegion]) -> LayoutSummary {
    let top_level_region_count = regions
        .iter()
        .filter(|region| region.scope == LayoutRegionScope::TopLevel)
        .count();
    let nested_region_count = regions
        .iter()
        .filter(|region| region.scope == LayoutRegionScope::Nested)
        .count();
    let dominant_boot_image_offset = regions
        .iter()
        .filter(|region| {
            region.kind == LayoutRegionKind::BootImage
                && region.scope == LayoutRegionScope::TopLevel
        })
        .max_by_key(|region| region.size.unwrap_or(0))
        .map(|region| region.offset);
    let dominant_rootfs_offset = regions
        .iter()
        .filter(|region| {
            region.kind == LayoutRegionKind::Filesystem
                && region.role == LayoutRegionRole::LikelyRootfs
        })
        .max_by_key(|region| region.size.unwrap_or(0))
        .or_else(|| {
            regions
                .iter()
                .filter(|region| region.kind == LayoutRegionKind::Filesystem)
                .max_by_key(|region| region.size.unwrap_or(0))
        })
        .map(|region| region.offset);

    LayoutSummary {
        top_level_region_count,
        nested_region_count,
        dominant_boot_image_offset,
        dominant_rootfs_offset,
    }
}

fn parse_env_assignment(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let value = value.trim();

    if !is_plausible_env_key(key) {
        None
    } else {
        Some((key, value))
    }
}

fn is_plausible_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    let sane_shape = key.len() <= 64
        && key.is_ascii()
        && !key.contains(char::is_whitespace)
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'));

    sane_shape && is_interesting_env_key(key)
}

fn is_interesting_env_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();

    matches!(
        lower.as_str(),
        "bootdelay"
            | "bootcmd"
            | "bootargs"
            | "boot_targets"
            | "boot_target"
            | "boot_slot"
            | "boot_part"
            | "loadaddr"
            | "kernel_addr_r"
            | "fdt_addr_r"
            | "fdtfile"
            | "initrd_addr_r"
            | "verify"
            | "verify_sig"
            | "sig_check"
            | "recovery_mode"
            | "recovery_bootcmd"
            | "fitboot"
            | "ethaddr"
            | "ipaddr"
            | "serverip"
            | "baudrate"
            | "mtdparts"
            | "mtdids"
            | "fw_version"
    ) || lower.starts_with("boot")
        || lower.starts_with("verify")
        || lower.starts_with("recovery")
        || lower.starts_with("rollback")
        || lower.starts_with("slot")
        || lower.ends_with("_addr")
        || lower.ends_with("_addr_r")
}

fn parse_integer(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

fn is_falsey(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off" | "disabled"
    )
}

fn is_zeroish(value: &str) -> bool {
    value
        .trim()
        .parse::<u64>()
        .map(|value| value == 0)
        .unwrap_or(false)
}

fn push_flow_hint(snapshot: &mut BootloaderSnapshot, value: &str) {
    snapshot.flow_hints.push(BootFlowHint {
        value: value.trim().to_string(),
    });
}

fn push_finding(findings: &mut Vec<String>, finding: &str) {
    if !findings.iter().any(|existing| existing == finding) {
        findings.push(finding.to_string());
    }
}

fn boot_value_source_rank(source: BootValueSource) -> u8 {
    match source {
        BootValueSource::Imported => 0,
        BootValueSource::Observed => 1,
        BootValueSource::Derived => 2,
    }
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    } else {
        u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    })
}

fn format_hex_u32(value: u32) -> String {
    format!("0x{value:08X}")
}

fn format_hex_u8(value: u8) -> String {
    format!("0x{value:02X}")
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn parse_c_string(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let raw = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

fn unitree_payload_type(code: u8) -> &'static str {
    match code {
        3 => "tar",
        2 => "tea",
        _ => "raw",
    }
}

fn uimage_os_name(code: u8) -> Option<String> {
    Some(
        match code {
            5 => "linux",
            17 => "openrtos",
            18 => "arm-trusted-firmware",
            _ => return None,
        }
        .to_string(),
    )
}

fn uimage_arch_name(code: u8) -> Option<String> {
    Some(
        match code {
            2 => "arm",
            5 => "mips",
            20 => "aarch64",
            _ => return None,
        }
        .to_string(),
    )
}

fn uimage_type_name(code: u8) -> Option<String> {
    Some(
        match code {
            2 => "kernel",
            5 => "firmware",
            7 => "ramdisk",
            11 => "filesystem",
            _ => return None,
        }
        .to_string(),
    )
}

fn uimage_compression_name(code: u8) -> Option<String> {
    Some(
        match code {
            0 => "none",
            1 => "gzip",
            2 => "bzip2",
            3 => "lzma",
            4 => "lzo",
            5 => "lz4",
            6 => "zstd",
            _ => return None,
        }
        .to_string(),
    )
}

#[cfg(test)]
mod date_tests {
    use super::format_unix_date;

    #[test]
    fn formats_known_firmware_timestamps() {
        assert_eq!(format_unix_date(1639479107).as_deref(), Some("2021-12-14"));
        assert_eq!(format_unix_date(1200687773).as_deref(), Some("2008-01-18"));
        assert_eq!(format_unix_date(0).as_deref(), Some("1970-01-01"));
    }

    #[test]
    fn handles_leap_day() {
        // 2020-02-29T00:00:00Z
        assert_eq!(format_unix_date(1582934400).as_deref(), Some("2020-02-29"));
    }
}

#[cfg(test)]
mod uimage_tests {
    use super::*;

    fn build_uimage_header(name: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; UIMAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
        header[28] = 5; // OS: linux
        header[29] = 2; // arch: arm
        header[30] = 2; // type: kernel
        let copy_len = name.len().min(32);
        header[32..32 + copy_len].copy_from_slice(&name[..copy_len]);
        // CRC over the header with the CRC field (4..8) zeroed.
        let crc = crc32_ieee(&header);
        header[4..8].copy_from_slice(&crc.to_be_bytes());
        header
    }

    #[test]
    fn valid_header_is_accepted_with_name() {
        let header = build_uimage_header(b"Linux-4.9.37-hi3516ev200");
        let parsed = parse_uimage_headers(&header);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name.as_deref(), Some("Linux-4.9.37-hi3516ev200"));
    }

    #[test]
    fn false_magic_match_without_valid_crc_is_rejected() {
        // Magic present but the rest is arbitrary → CRC will not validate.
        let mut blob = vec![0u8; UIMAGE_HEADER_SIZE + 16];
        blob[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
        for (i, byte) in blob.iter_mut().enumerate().skip(4) {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        assert!(parse_uimage_headers(&blob).is_empty());
    }

    #[test]
    fn non_printable_name_is_dropped_even_when_crc_valid() {
        let header = build_uimage_header(&[0x01, 0x02, 0xff, 0x00]);
        let parsed = parse_uimage_headers(&header);
        assert_eq!(parsed.len(), 1, "header itself is valid");
        assert_eq!(parsed[0].name, None, "garbled name must be suppressed");
    }
}
