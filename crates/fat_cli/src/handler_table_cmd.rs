use crate::elf_addr::{self, Endianness, PointerHit, PointerKind};
use crate::elf_inspect::{ElfProgramHeaderSummary, ElfSectionSummary};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

const DEFAULT_PATTERNS: &[&str] = &[
    "/setform/",
    "/cgi/",
    "/goform/",
    "/HNAP1/",
    "/UPnP/",
    "/api/",
];
const DEFAULT_STRIDES: &[usize] = &[8, 12, 16];
const MIN_TABLE_ENTRIES: usize = 2;

#[derive(Debug, Clone)]
pub struct MatchedString {
    pub vaddr: u64,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct HandlerTableReport {
    pub file: String,
    pub arch: String,
    pub bits: u32,
    pub endianness: String,
    pub segment_map: Vec<elf_addr::LoadRange>,
    pub tables: Vec<DiscoveredTable>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize)]
pub struct DiscoveredTable {
    pub id: String,
    pub location: TableLocation,
    pub structure: TableStructure,
    pub entries: Vec<HandlerEntry>,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
pub struct TableLocation {
    pub file_offset_start: u64,
    pub file_offset_end: u64,
    pub vaddr_start: u64,
    pub vaddr_end: u64,
    pub section_name: String,
    pub segment_index: usize,
    pub segment_permissions: String,
}

#[derive(Debug, Serialize)]
pub struct TableStructure {
    pub entry_stride: usize,
    pub entry_count: usize,
    pub entry_format: String,
    pub total_size: usize,
}

#[derive(Debug, Serialize)]
pub struct HandlerEntry {
    pub index: usize,
    pub file_offset: u64,
    pub vaddr: u64,
    pub fields: Vec<EntryField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontend_match: Option<FrontendMatch>,
}

#[derive(Debug, Serialize)]
pub struct EntryField {
    pub offset_within_entry: usize,
    pub raw_value: u64,
    pub kind: PointerKind,
    pub resolved: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrontendMatch {
    pub file: String,
    pub form_action: String,
    pub method: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub patterns_used: Vec<String>,
    pub strings_matched: usize,
    pub pointer_hits: usize,
    pub tables_discovered: usize,
    pub total_handlers: usize,
}

pub fn run(
    file: &Path,
    patterns: Option<&str>,
    entry_size: Option<usize>,
    scan_filter_str: &str,
    source_map: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let mut report = scan(file, patterns, entry_size, scan_filter_str)?;
    if let Some(source_map_path) = source_map {
        apply_source_map(&mut report, source_map_path)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_handler_table_report(&report));
    }
    Ok(())
}

pub fn scan(
    file: &Path,
    patterns: Option<&str>,
    entry_size: Option<usize>,
    scan_filter_str: &str,
) -> DynResult<HandlerTableReport> {
    let pattern_list = parse_patterns(patterns);
    let elf_bytes = std::fs::read(file)?;
    let elf_report = crate::elf_inspect::parse_elf_bytes(&elf_bytes)?;
    let endianness = elf_addr::endianness_from_header(&elf_report.header);
    let word_size = if elf_report.header.class.contains("64") {
        8
    } else {
        4
    };
    let scan_filter = elf_addr::parse_scan_filter(scan_filter_str)?;
    let matched_strings = matched_strings(file, &pattern_list)?;

    let mut hits = Vec::new();
    for matched in &matched_strings {
        hits.extend(elf_addr::scan_for_pointer(
            &elf_bytes,
            matched.vaddr,
            word_size,
            endianness,
            &elf_report.program_headers,
            scan_filter,
        ));
    }

    let mut tables = decode_tables_from_hits(
        &elf_bytes,
        &elf_report.sections,
        &elf_report.program_headers,
        &elf_report.header.machine,
        endianness,
        word_size,
        &matched_strings,
        &hits,
        entry_size,
    );
    for (idx, table) in tables.iter_mut().enumerate() {
        table.id = format!("table-{idx}");
    }

    let total_handlers = tables.iter().map(|table| table.entries.len()).sum();
    Ok(HandlerTableReport {
        file: file.display().to_string(),
        arch: elf_report.header.machine,
        bits: if elf_report.header.class.contains("64") {
            64
        } else {
            32
        },
        endianness: format!("{endianness:?}"),
        segment_map: elf_addr::load_segment_ranges(&elf_report.program_headers),
        summary: ScanSummary {
            patterns_used: pattern_list,
            strings_matched: matched_strings.len(),
            pointer_hits: hits.len(),
            tables_discovered: tables.len(),
            total_handlers,
        },
        tables,
    })
}

fn parse_patterns(patterns: Option<&str>) -> Vec<String> {
    patterns
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_PATTERNS.iter().map(|p| p.to_string()).collect())
}

fn matched_strings(file: &Path, patterns: &[String]) -> DynResult<Vec<MatchedString>> {
    Ok(fat_taint::recon::r2::strings(file, 4)?
        .into_iter()
        .filter(|entry| patterns.iter().any(|pattern| entry.value.contains(pattern)))
        .map(|entry| MatchedString {
            vaddr: entry.address,
            value: entry.value,
        })
        .collect())
}

fn decode_tables_from_hits(
    elf_bytes: &[u8],
    sections: &[ElfSectionSummary],
    segments: &[ElfProgramHeaderSummary],
    arch: &str,
    endianness: Endianness,
    word_size: usize,
    matched_strings: &[MatchedString],
    hits: &[PointerHit],
    entry_size: Option<usize>,
) -> Vec<DiscoveredTable> {
    let string_by_vaddr: BTreeMap<u64, String> = matched_strings
        .iter()
        .map(|entry| (entry.vaddr, entry.value.clone()))
        .collect();
    let strides: Vec<usize> = entry_size
        .map(|size| vec![size])
        .unwrap_or_else(|| DEFAULT_STRIDES.to_vec());
    let ranges = ClassificationRanges::from_sections(sections);

    let mut seen_starts = BTreeSet::new();
    let mut tables = Vec::new();
    for hit in hits {
        let mut best: Option<DiscoveredTable> = None;
        for stride in &strides {
            let Some(candidate) = decode_table_at_hit(
                elf_bytes,
                sections,
                segments,
                endianness,
                word_size,
                &string_by_vaddr,
                &ranges,
                hit,
                *stride,
            ) else {
                continue;
            };
            if best
                .as_ref()
                .map(|current| candidate.entries.len() > current.entries.len())
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }

        if let Some(table) = best {
            if seen_starts.insert(table.location.file_offset_start) {
                tables.push(table);
            }
        }
    }

    tables.sort_by_key(|table| table.location.file_offset_start);
    if tables.is_empty() && arch.eq_ignore_ascii_case("MIPS") && word_size == 4 {
        tables = discover_mips_registration_tables(
            elf_bytes,
            sections,
            segments,
            endianness,
            &string_by_vaddr,
            &ranges,
        );
    }
    tables
}

#[derive(Debug, Clone)]
struct MipsRecoveredArg {
    register: u32,
    value: u64,
    kind: PointerKind,
}

#[derive(Debug, Clone)]
struct MipsRegistrationRecord {
    call_target: u64,
    callsite_file_offset: u64,
    callsite_vaddr: u64,
    string_vaddr: u64,
    fields: Vec<MipsRecoveredArg>,
}

fn discover_mips_registration_tables(
    elf_bytes: &[u8],
    sections: &[ElfSectionSummary],
    segments: &[ElfProgramHeaderSummary],
    endianness: Endianness,
    string_by_vaddr: &BTreeMap<u64, String>,
    ranges: &ClassificationRanges,
) -> Vec<DiscoveredTable> {
    let mut records = Vec::new();

    for segment in segments
        .iter()
        .filter(|segment| segment.segment_type == "LOAD" && segment.flags.contains('X'))
    {
        let Some(end) = segment.offset.checked_add(segment.file_size) else {
            continue;
        };
        let start = segment.offset as usize;
        let end = end as usize;
        if end > elf_bytes.len() || start > end {
            continue;
        }

        let region = &elf_bytes[start..end];
        let mut offset = 0usize;
        while offset + 4 <= region.len() {
            let Some(instruction) = read_mips_u32(region, offset, endianness) else {
                break;
            };
            let callsite_vaddr = segment.virtual_address + offset as u64;
            let Some(call_target) = decode_mips_jal_target(instruction, callsite_vaddr) else {
                offset += 4;
                continue;
            };
            let constant_args = collect_mips_constant_args_around_call(region, offset, endianness);
            let Some((string_reg, string_vaddr)) =
                constant_args.iter().find_map(|(register, value)| {
                    string_by_vaddr
                        .contains_key(value)
                        .then_some((*register, *value))
                })
            else {
                offset += 4;
                continue;
            };
            let fields = constant_args
                .iter()
                .filter(|(register, _)| is_mips_arg_register(**register))
                .map(|(register, value)| MipsRecoveredArg {
                    register: *register,
                    value: *value,
                    kind: if *register == string_reg {
                        PointerKind::StringPointer
                    } else {
                        elf_addr::classify_value(*value, ranges.text, ranges.rodata, ranges.data)
                    },
                })
                .collect::<Vec<_>>();
            if fields.len() < 2 {
                offset += 4;
                continue;
            }

            records.push(MipsRegistrationRecord {
                call_target,
                callsite_file_offset: segment.offset + offset as u64,
                callsite_vaddr,
                string_vaddr,
                fields,
            });
            offset += 4;
        }
    }

    let mut grouped: BTreeMap<(u64, String), Vec<MipsRegistrationRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry((
                record.call_target,
                mips_registration_layout_signature(&record.fields),
            ))
            .or_default()
            .push(record);
    }

    let mut tables = Vec::new();
    for ((call_target, _layout_signature), mut records) in grouped {
        records.sort_by_key(|record| record.callsite_file_offset);
        records.dedup_by_key(|record| (record.string_vaddr, record.callsite_vaddr));
        if records.len() < MIN_TABLE_ENTRIES {
            continue;
        }

        let first = records.first().expect("records non-empty");
        let last = records.last().expect("records non-empty");
        let layout = first
            .fields
            .iter()
            .map(|field| (field.register, field.kind))
            .collect::<Vec<_>>();
        let location_start = first.callsite_file_offset;
        let location_end = last.callsite_file_offset + 4;
        let vaddr_start = first.callsite_vaddr;
        let vaddr_end = last.callsite_vaddr + 4;
        let (segment_index, segment_permissions) = segment_for_vaddr(vaddr_start, segments)
            .map(|(idx, segment)| (idx, segment.flags.clone()))
            .unwrap_or((0, String::new()));

        let entries = records
            .iter()
            .enumerate()
            .map(|(index, record)| HandlerEntry {
                index,
                file_offset: record.callsite_file_offset,
                vaddr: record.callsite_vaddr,
                fields: record
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(field_index, field)| EntryField {
                        offset_within_entry: field_index * 4,
                        raw_value: field.value,
                        kind: field.kind,
                        resolved: resolve_field(
                            field.value,
                            field.kind,
                            string_by_vaddr,
                            elf_bytes,
                            segments,
                        ),
                    })
                    .collect(),
                frontend_match: None,
            })
            .collect::<Vec<_>>();
        let entry_format = layout
            .iter()
            .map(|(register, kind)| {
                format!(
                    "{}:{}",
                    mips_register_name(*register),
                    match kind {
                        PointerKind::StringPointer => "string_ptr",
                        PointerKind::CodePointer => "func_ptr",
                        PointerKind::SmallInteger => "flags",
                        PointerKind::DataPointer => "data_ptr",
                        PointerKind::Unknown => "unknown",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let confidence = if layout
            .iter()
            .any(|(_, kind)| *kind == PointerKind::CodePointer)
        {
            0.9
        } else {
            0.8
        };

        tables.push(DiscoveredTable {
            id: String::new(),
            location: TableLocation {
                file_offset_start: location_start,
                file_offset_end: location_end,
                vaddr_start,
                vaddr_end,
                section_name: section_for_vaddr(vaddr_start, sections)
                    .map(|section| section.name.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                segment_index,
                segment_permissions,
            },
            structure: TableStructure {
                entry_stride: 0,
                entry_count: entries.len(),
                entry_format: format!(
                    "mips-registration-calls(callee=0x{call_target:x}, args=[{entry_format}])"
                ),
                total_size: entries.len() * layout.len() * 4,
            },
            entries,
            confidence,
        });
    }

    tables
}

fn decode_table_at_hit(
    elf_bytes: &[u8],
    sections: &[ElfSectionSummary],
    segments: &[ElfProgramHeaderSummary],
    endianness: Endianness,
    word_size: usize,
    string_by_vaddr: &BTreeMap<u64, String>,
    ranges: &ClassificationRanges,
    hit: &PointerHit,
    stride: usize,
) -> Option<DiscoveredTable> {
    if stride < word_size * 2 || !stride.is_multiple_of(word_size) {
        return None;
    }

    let mut start = hit.file_offset;
    while start >= stride as u64 {
        let prev = start - stride as u64;
        if decode_entry(
            elf_bytes,
            segments,
            endianness,
            word_size,
            string_by_vaddr,
            ranges,
            prev,
            stride,
            0,
        )
        .is_some()
        {
            start = prev;
        } else {
            break;
        }
    }

    let mut entries = Vec::new();
    let mut offset = start;
    while let Some(mut entry) = decode_entry(
        elf_bytes,
        segments,
        endianness,
        word_size,
        string_by_vaddr,
        ranges,
        offset,
        stride,
        entries.len(),
    ) {
        entry.index = entries.len();
        entries.push(entry);
        offset += stride as u64;
    }

    if entries.len() < MIN_TABLE_ENTRIES {
        return None;
    }

    let entry_format = infer_entry_format(&entries, word_size);
    let file_offset_end = start + (entries.len() * stride) as u64;
    let vaddr_start = elf_addr::file_offset_to_vaddr(start, segments)?;
    let vaddr_end = elf_addr::file_offset_to_vaddr(file_offset_end - 1, segments)? + 1;
    let (segment_index, segment_permissions) = segment_for_vaddr(vaddr_start, segments)
        .map(|(idx, segment)| (idx, segment.flags.clone()))
        .unwrap_or((hit.segment_index, String::new()));
    let string_entries = entries
        .iter()
        .filter(|entry| {
            entry
                .fields
                .first()
                .map(|field| field.kind == PointerKind::StringPointer)
                .unwrap_or(false)
        })
        .count();
    let confidence = string_entries as f32 / entries.len() as f32;

    Some(DiscoveredTable {
        id: String::new(),
        location: TableLocation {
            file_offset_start: start,
            file_offset_end,
            vaddr_start,
            vaddr_end,
            section_name: section_for_vaddr(vaddr_start, sections)
                .map(|section| section.name.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            segment_index,
            segment_permissions,
        },
        structure: TableStructure {
            entry_stride: stride,
            entry_count: entries.len(),
            entry_format,
            total_size: entries.len() * stride,
        },
        entries,
        confidence,
    })
}

fn decode_entry(
    elf_bytes: &[u8],
    segments: &[ElfProgramHeaderSummary],
    endianness: Endianness,
    word_size: usize,
    string_by_vaddr: &BTreeMap<u64, String>,
    ranges: &ClassificationRanges,
    file_offset: u64,
    stride: usize,
    index: usize,
) -> Option<HandlerEntry> {
    let fields_per_entry = stride / word_size;
    if fields_per_entry < 2 {
        return None;
    }

    let mut fields = Vec::new();
    for field_index in 0..fields_per_entry {
        let offset_within_entry = field_index * word_size;
        let field_offset = file_offset + offset_within_entry as u64;
        let raw_value = read_word(elf_bytes, field_offset, word_size, endianness)?;
        let mut kind = elf_addr::classify_value(raw_value, ranges.text, ranges.rodata, ranges.data);
        if string_by_vaddr.contains_key(&raw_value) {
            kind = PointerKind::StringPointer;
        }
        let resolved = resolve_field(raw_value, kind, string_by_vaddr, elf_bytes, segments);
        fields.push(EntryField {
            offset_within_entry,
            raw_value,
            kind,
            resolved,
        });
    }

    if fields.first()?.kind != PointerKind::StringPointer {
        return None;
    }
    if fields
        .iter()
        .skip(1)
        .all(|field| field.kind == PointerKind::Unknown)
    {
        return None;
    }

    Some(HandlerEntry {
        index,
        file_offset,
        vaddr: elf_addr::file_offset_to_vaddr(file_offset, segments)?,
        fields,
        frontend_match: None,
    })
}

fn collect_mips_constant_args_around_call(
    region: &[u8],
    call_offset: usize,
    endianness: Endianness,
) -> BTreeMap<u32, u64> {
    let mut values = BTreeMap::new();
    let window_start = call_offset.saturating_sub(24);
    let window_end = usize::min(region.len(), call_offset + 8);
    let mut offset = window_start;
    while offset + 4 <= window_end {
        let Some(instruction) = read_mips_u32(region, offset, endianness) else {
            break;
        };
        if let Some((register, value)) = decode_mips_constant_for_register(
            region,
            offset,
            call_offset,
            window_end,
            instruction,
            endianness,
        ) {
            if is_mips_arg_register(register) {
                values.insert(register, value);
            }
        }
        offset += 4;
    }
    values
}

fn decode_mips_constant_for_register(
    region: &[u8],
    offset: usize,
    call_offset: usize,
    window_end: usize,
    instruction: u32,
    endianness: Endianness,
) -> Option<(u32, u64)> {
    if let Some(register) = decode_mips_lui_register(instruction) {
        let mut lookahead = offset + 4;
        while lookahead + 4 <= window_end && lookahead <= offset + 24 {
            let candidate = read_mips_u32(region, lookahead, endianness)?;
            if let Some(target) = decode_mips_load_from_lui(instruction, candidate) {
                return Some((register, target));
            }
            if mips_instruction_writes_register(candidate, register) {
                break;
            }
            lookahead += 4;
        }
        return None;
    }

    if let Some((register, value)) = decode_mips_immediate_constant(instruction) {
        let instruction_end = offset + 4;
        if instruction_end >= call_offset.saturating_sub(24) && instruction_end <= window_end {
            return Some((register, value));
        }
    }

    None
}

fn read_mips_u32(bytes: &[u8], offset: usize, endianness: Endianness) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endianness {
        Endianness::Little => u32::from_le_bytes(raw),
        Endianness::Big => u32::from_be_bytes(raw),
    })
}

fn decode_mips_jal_target(instruction: u32, callsite_vaddr: u64) -> Option<u64> {
    let opcode = (instruction >> 26) & 0x3f;
    if opcode != 0x03 {
        return None;
    }
    let target = u64::from(instruction & 0x03ff_ffff) << 2;
    Some(((callsite_vaddr + 4) & 0xf000_0000) | target)
}

fn decode_mips_lui_register(instruction: u32) -> Option<u32> {
    (((instruction >> 26) & 0x3f) == 0x0f)
        .then_some((instruction >> 16) & 0x1f)
        .filter(|register| *register != 0)
}

fn decode_mips_load_from_lui(first: u32, second: u32) -> Option<u64> {
    let register = decode_mips_lui_register(first)?;
    let second_opcode = (second >> 26) & 0x3f;
    let second_rs = (second >> 21) & 0x1f;
    let second_rt = (second >> 16) & 0x1f;
    if second_rs != register || second_rt != register {
        return None;
    }

    let high = (first & 0xffff) << 16;
    let low = second & 0xffff;
    match second_opcode {
        0x0d => Some((high | low) as u64),
        0x09 => Some(high.wrapping_add((low as i16 as i32) as u32) as u64),
        _ => None,
    }
}

fn decode_mips_immediate_constant(instruction: u32) -> Option<(u32, u64)> {
    let opcode = (instruction >> 26) & 0x3f;
    let rs = (instruction >> 21) & 0x1f;
    let rt = (instruction >> 16) & 0x1f;
    if !is_mips_arg_register(rt) {
        return None;
    }

    match opcode {
        0x09 if rs == 0 => Some((rt, (instruction & 0xffff) as i16 as i32 as u64)),
        0x0d if rs == 0 => Some((rt, u64::from(instruction & 0xffff))),
        0x00 => {
            let funct = instruction & 0x3f;
            let rd = (instruction >> 11) & 0x1f;
            let rt = (instruction >> 16) & 0x1f;
            let rs = (instruction >> 21) & 0x1f;
            (rd != 0 && rs == 0 && rt == 0 && funct == 0x25).then_some((rd, 0))
        }
        _ => None,
    }
}

fn mips_instruction_writes_register(instruction: u32, register: u32) -> bool {
    let opcode = (instruction >> 26) & 0x3f;
    match opcode {
        0x00 => {
            let funct = instruction & 0x3f;
            match funct {
                0x08 | 0x09 => false,
                _ => ((instruction >> 11) & 0x1f) == register,
            }
        }
        0x02..=0x07 => false,
        0x28..=0x2e => false,
        _ => ((instruction >> 16) & 0x1f) == register,
    }
}

fn is_mips_arg_register(register: u32) -> bool {
    (4..=7).contains(&register)
}

fn mips_registration_layout_signature(fields: &[MipsRecoveredArg]) -> String {
    fields
        .iter()
        .map(|field| {
            format!(
                "{}:{}",
                mips_register_name(field.register),
                match field.kind {
                    PointerKind::StringPointer => "string_ptr",
                    PointerKind::CodePointer => "func_ptr",
                    PointerKind::SmallInteger => "flags",
                    PointerKind::DataPointer => "data_ptr",
                    PointerKind::Unknown => "unknown",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn mips_register_name(register: u32) -> &'static str {
    match register {
        4 => "a0",
        5 => "a1",
        6 => "a2",
        7 => "a3",
        _ => "r?",
    }
}

fn read_word(
    elf_bytes: &[u8],
    file_offset: u64,
    word_size: usize,
    endianness: Endianness,
) -> Option<u64> {
    let start = file_offset as usize;
    match (word_size, endianness) {
        (4, Endianness::Little) => {
            let bytes: [u8; 4] = elf_bytes.get(start..start + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(bytes) as u64)
        }
        (4, Endianness::Big) => {
            let bytes: [u8; 4] = elf_bytes.get(start..start + 4)?.try_into().ok()?;
            Some(u32::from_be_bytes(bytes) as u64)
        }
        (8, Endianness::Little) => {
            let bytes: [u8; 8] = elf_bytes.get(start..start + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        }
        (8, Endianness::Big) => {
            let bytes: [u8; 8] = elf_bytes.get(start..start + 8)?.try_into().ok()?;
            Some(u64::from_be_bytes(bytes))
        }
        _ => None,
    }
}

fn resolve_field(
    raw_value: u64,
    kind: PointerKind,
    string_by_vaddr: &BTreeMap<u64, String>,
    elf_bytes: &[u8],
    segments: &[ElfProgramHeaderSummary],
) -> Option<String> {
    match kind {
        PointerKind::StringPointer => string_by_vaddr.get(&raw_value).cloned().or_else(|| {
            let file_offset = elf_addr::vaddr_to_file_offset(raw_value, segments)?;
            elf_addr::read_c_string_at_offset(elf_bytes, file_offset)
                .or_else(|| Some(format!("string: 0x{raw_value:x}")))
        }),
        PointerKind::CodePointer => Some(format!("code: 0x{raw_value:x}")),
        PointerKind::SmallInteger => Some(format!("flags: 0x{raw_value:x}")),
        PointerKind::DataPointer => Some(format!("data: 0x{raw_value:x}")),
        PointerKind::Unknown => None,
    }
}

fn infer_entry_format(entries: &[HandlerEntry], word_size: usize) -> String {
    let Some(first) = entries.first() else {
        return "unknown".to_string();
    };
    let parts: Vec<&str> = first
        .fields
        .iter()
        .map(|field| match field.kind {
            PointerKind::StringPointer => "string_ptr",
            PointerKind::CodePointer => "func_ptr",
            PointerKind::SmallInteger => "flags",
            PointerKind::DataPointer => "data_ptr",
            PointerKind::Unknown => "unknown",
        })
        .collect();
    format!("({}) @ {}-byte words", parts.join(", "), word_size)
}

#[derive(Debug, Clone)]
struct ClassificationRanges {
    text: Option<(u64, u64)>,
    rodata: Option<(u64, u64)>,
    data: Option<(u64, u64)>,
}

impl ClassificationRanges {
    fn from_sections(sections: &[ElfSectionSummary]) -> Self {
        Self {
            text: elf_addr::section_vaddr_range(sections, ".text"),
            rodata: elf_addr::section_vaddr_range(sections, ".rodata"),
            data: elf_addr::section_vaddr_range(sections, ".data"),
        }
    }
}

fn section_for_vaddr(vaddr: u64, sections: &[ElfSectionSummary]) -> Option<&ElfSectionSummary> {
    sections.iter().find(|section| {
        section
            .virtual_address
            .checked_add(section.size)
            .map(|end| vaddr >= section.virtual_address && vaddr < end)
            .unwrap_or(false)
    })
}

fn segment_for_vaddr(
    vaddr: u64,
    segments: &[ElfProgramHeaderSummary],
) -> Option<(usize, &ElfProgramHeaderSummary)> {
    segments.iter().enumerate().find(|(_, segment)| {
        segment
            .virtual_address
            .checked_add(segment.memory_size)
            .map(|end| {
                segment.segment_type == "LOAD" && vaddr >= segment.virtual_address && vaddr < end
            })
            .unwrap_or(false)
    })
}

fn apply_source_map(report: &mut HandlerTableReport, source_map_path: &Path) -> DynResult<()> {
    let bytes = std::fs::read(source_map_path)?;
    let source_map: SourceMapJson = serde_json::from_slice(&bytes)?;
    let matches: BTreeMap<String, FrontendMatch> = source_map
        .frontend_surfaces
        .into_iter()
        .map(|surface| {
            let endpoint = surface.endpoint.clone();
            (
                endpoint.clone(),
                FrontendMatch {
                    file: surface.path,
                    form_action: endpoint,
                    method: surface.methods.join(","),
                    parameters: surface
                        .parameters
                        .into_iter()
                        .map(|param| param.name)
                        .collect(),
                },
            )
        })
        .collect();

    for table in &mut report.tables {
        for entry in &mut table.entries {
            let endpoint = entry
                .fields
                .first()
                .and_then(|field| field.resolved.as_deref());
            if let Some(frontend_match) = endpoint.and_then(|value| matches.get(value)) {
                entry.frontend_match = Some(frontend_match.clone());
            }
        }
    }
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct SourceMapJson {
    #[serde(default)]
    frontend_surfaces: Vec<SourceMapSurfaceJson>,
}

#[derive(Debug, serde::Deserialize)]
struct SourceMapSurfaceJson {
    #[serde(default)]
    path: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    parameters: Vec<SourceMapParameterJson>,
}

#[derive(Debug, serde::Deserialize)]
struct SourceMapParameterJson {
    #[serde(default)]
    name: String,
}

fn render_handler_table_report(report: &HandlerTableReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("handler-table: {}\n\n", report.file));
    for table in &report.tables {
        out.push_str(&format!(
            "{}: {} entries, stride {} bytes, confidence {:.2}\n",
            table.id,
            table.entries.len(),
            table.structure.entry_stride,
            table.confidence
        ));
        out.push_str(&format!(
            "  location: file 0x{:08x}-0x{:08x}, vaddr 0x{:08x}-0x{:08x}, section {}, LOAD{}\n",
            table.location.file_offset_start,
            table.location.file_offset_end,
            table.location.vaddr_start,
            table.location.vaddr_end,
            table.location.section_name,
            table.location.segment_index
        ));
        for entry in &table.entries {
            let label = entry
                .fields
                .first()
                .and_then(|field| field.resolved.as_deref())
                .unwrap_or("<unresolved>");
            out.push_str(&format!(
                "  [{}] 0x{:08x}: {}\n",
                entry.index, entry.vaddr, label
            ));
        }
    }
    out.push_str(&format!(
        "\nSummary: {} strings matched, {} pointer hits, {} tables, {} handlers\n",
        report.summary.strings_matched,
        report.summary.pointer_hits,
        report.summary.tables_discovered,
        report.summary.total_handlers
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_addr::{Endianness, PointerHit};
    use crate::elf_inspect::{ElfProgramHeaderSummary, ElfSectionSummary};

    fn segment(
        index_offset: u64,
        vaddr: u64,
        file_size: u64,
        memory_size: u64,
        flags: &str,
    ) -> ElfProgramHeaderSummary {
        ElfProgramHeaderSummary {
            segment_type: "LOAD".to_string(),
            offset: index_offset,
            virtual_address: vaddr,
            file_size,
            memory_size,
            flags: flags.to_string(),
            align: 0x1000,
        }
    }

    fn section(name: &str, offset: u64, vaddr: u64, size: u64, flags: &str) -> ElfSectionSummary {
        ElfSectionSummary {
            name: name.to_string(),
            offset,
            virtual_address: vaddr,
            size,
            section_type: "PROGBITS".to_string(),
            flags: flags.to_string(),
            role: "data".to_string(),
        }
    }

    #[test]
    fn decode_tables_groups_contiguous_string_code_entries() {
        let mut bytes = vec![0u8; 0x3000];
        bytes[0x1100..0x110b].copy_from_slice(b"/setform/a\0");
        bytes[0x1120..0x112b].copy_from_slice(b"/setform/b\0");
        bytes[0x2000..0x2004].copy_from_slice(&0x500100u32.to_le_bytes());
        bytes[0x2004..0x2008].copy_from_slice(&0x400800u32.to_le_bytes());
        bytes[0x2008..0x200c].copy_from_slice(&0x500120u32.to_le_bytes());
        bytes[0x200c..0x2010].copy_from_slice(&0x400900u32.to_le_bytes());

        let segments = vec![
            segment(0x0000, 0x400000, 0x1000, 0x1000, "XR"),
            segment(0x1000, 0x500000, 0x1000, 0x1000, "R"),
            segment(0x2000, 0x600000, 0x1000, 0x1000, "WR"),
        ];
        let sections = vec![
            section(".text", 0x0000, 0x400000, 0x1000, "AX"),
            section(".rodata", 0x1000, 0x500000, 0x1000, "A"),
            section(".data", 0x2000, 0x600000, 0x1000, "WA"),
        ];
        let strings = vec![
            MatchedString {
                vaddr: 0x500100,
                value: "/setform/a".to_string(),
            },
            MatchedString {
                vaddr: 0x500120,
                value: "/setform/b".to_string(),
            },
        ];
        let hits = vec![PointerHit {
            file_offset: 0x2000,
            vaddr: 0x600000,
            target_vaddr: 0x500100,
            segment_index: 2,
        }];

        let tables = decode_tables_from_hits(
            &bytes,
            &sections,
            &segments,
            "MIPS",
            Endianness::Little,
            4,
            &strings,
            &hits,
            Some(8),
        );

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].structure.entry_stride, 8);
        assert_eq!(tables[0].entries.len(), 2);
        assert_eq!(tables[0].confidence, 1.0);
        assert_eq!(
            tables[0].entries[0].fields[0].resolved.as_deref(),
            Some("/setform/a")
        );
        assert_eq!(
            tables[0].entries[0].fields[1].resolved.as_deref(),
            Some("code: 0x400800")
        );
    }

    #[test]
    fn apply_source_map_attaches_exact_endpoint_matches() {
        let tempdir = tempfile::tempdir().unwrap();
        let source_map_path = tempdir.path().join("source-map.json");
        std::fs::write(
            &source_map_path,
            r#"{
                "frontend_surfaces": [{
                    "path": "www/form.html",
                    "endpoint": "/setform/a",
                    "methods": ["POST"],
                    "parameters": [{"name": "cmd"}]
                }]
            }"#,
        )
        .unwrap();
        let mut report = HandlerTableReport {
            file: "synthetic".to_string(),
            arch: "MIPS".to_string(),
            bits: 32,
            endianness: "Little".to_string(),
            segment_map: Vec::new(),
            summary: ScanSummary {
                patterns_used: vec!["/setform/".to_string()],
                strings_matched: 1,
                pointer_hits: 1,
                tables_discovered: 1,
                total_handlers: 1,
            },
            tables: vec![DiscoveredTable {
                id: "table-0".to_string(),
                location: TableLocation {
                    file_offset_start: 0x2000,
                    file_offset_end: 0x2008,
                    vaddr_start: 0x600000,
                    vaddr_end: 0x600008,
                    section_name: ".data".to_string(),
                    segment_index: 2,
                    segment_permissions: "WR".to_string(),
                },
                structure: TableStructure {
                    entry_stride: 8,
                    entry_count: 1,
                    entry_format: "(string_ptr, func_ptr)".to_string(),
                    total_size: 8,
                },
                confidence: 1.0,
                entries: vec![HandlerEntry {
                    index: 0,
                    file_offset: 0x2000,
                    vaddr: 0x600000,
                    frontend_match: None,
                    fields: vec![EntryField {
                        offset_within_entry: 0,
                        raw_value: 0x500100,
                        kind: crate::elf_addr::PointerKind::StringPointer,
                        resolved: Some("/setform/a".to_string()),
                    }],
                }],
            }],
        };

        apply_source_map(&mut report, &source_map_path).unwrap();

        let frontend_match = report.tables[0].entries[0].frontend_match.as_ref().unwrap();
        assert_eq!(frontend_match.file, "www/form.html");
        assert_eq!(frontend_match.method, "POST");
        assert_eq!(frontend_match.parameters, vec!["cmd"]);
    }
}
