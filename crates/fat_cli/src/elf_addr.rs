use crate::elf_inspect::{ElfHeaderSummary, ElfProgramHeaderSummary, ElfSectionSummary};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanFilter {
    NonExecutable,
    WritableOnly,
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadRange {
    pub index: usize,
    pub vaddr_start: u64,
    pub vaddr_end: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PointerHit {
    pub file_offset: u64,
    pub vaddr: u64,
    pub target_vaddr: u64,
    pub segment_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PointerKind {
    StringPointer,
    CodePointer,
    SmallInteger,
    DataPointer,
    Unknown,
}

pub fn endianness_from_header(header: &ElfHeaderSummary) -> Endianness {
    if header.endianness.starts_with("little") {
        Endianness::Little
    } else {
        Endianness::Big
    }
}

pub fn file_offset_to_vaddr(file_offset: u64, segments: &[ElfProgramHeaderSummary]) -> Option<u64> {
    for seg in segments {
        if seg.segment_type != "LOAD" {
            continue;
        }
        let seg_file_end = seg.offset.checked_add(seg.file_size)?;
        if file_offset >= seg.offset && file_offset < seg_file_end {
            return Some(seg.virtual_address + (file_offset - seg.offset));
        }
    }
    None
}

pub fn vaddr_to_file_offset(vaddr: u64, segments: &[ElfProgramHeaderSummary]) -> Option<u64> {
    for seg in segments {
        if seg.segment_type != "LOAD" {
            continue;
        }
        let seg_vaddr_end = seg.virtual_address.checked_add(seg.memory_size)?;
        if vaddr >= seg.virtual_address && vaddr < seg_vaddr_end {
            let offset_within = vaddr - seg.virtual_address;
            if offset_within < seg.file_size {
                return Some(seg.offset + offset_within);
            }
            return None;
        }
    }
    None
}

pub fn section_vaddr_range(sections: &[ElfSectionSummary], name: &str) -> Option<(u64, u64)> {
    sections
        .iter()
        .find(|section| section.name == name)
        .and_then(|section| {
            section
                .virtual_address
                .checked_add(section.size)
                .map(|end| (section.virtual_address, end))
        })
}

pub fn load_segment_ranges(segments: &[ElfProgramHeaderSummary]) -> Vec<LoadRange> {
    segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.segment_type == "LOAD")
        .map(|(index, segment)| LoadRange {
            index,
            vaddr_start: segment.virtual_address,
            vaddr_end: segment.virtual_address + segment.memory_size,
            file_offset: segment.offset,
            file_size: segment.file_size,
            permissions: segment.flags.clone(),
        })
        .collect()
}

pub fn scan_for_pointer(
    elf_bytes: &[u8],
    target_vaddr: u64,
    word_size: usize,
    endianness: Endianness,
    segments: &[ElfProgramHeaderSummary],
    scan_filter: ScanFilter,
) -> Vec<PointerHit> {
    let needle = pack_word(target_vaddr, word_size, endianness);
    if needle.is_empty() {
        return Vec::new();
    }

    let mut hits = Vec::new();
    for (seg_idx, seg) in segments.iter().enumerate() {
        if seg.segment_type != "LOAD" || !matches_filter(&seg.flags, scan_filter) {
            continue;
        }

        let Some(seg_end) = seg.offset.checked_add(seg.file_size) else {
            continue;
        };
        let seg_start = seg.offset as usize;
        let seg_end = seg_end as usize;
        if seg_end > elf_bytes.len() || seg_start > seg_end {
            continue;
        }

        let region = &elf_bytes[seg_start..seg_end];
        let mut pos = 0;
        while pos + word_size <= region.len() {
            let Some(idx) = find_bytes(region, &needle, pos) else {
                break;
            };
            let file_offset = (seg_start + idx) as u64;
            if let Some(vaddr) = file_offset_to_vaddr(file_offset, segments) {
                hits.push(PointerHit {
                    file_offset,
                    vaddr,
                    target_vaddr,
                    segment_index: seg_idx,
                });
            }
            pos = idx + word_size;
        }
    }
    hits
}

pub fn classify_value(
    value: u64,
    text_range: Option<(u64, u64)>,
    rodata_range: Option<(u64, u64)>,
    data_range: Option<(u64, u64)>,
) -> PointerKind {
    if value <= 0xff {
        return PointerKind::SmallInteger;
    }
    if range_contains(rodata_range, value) {
        return PointerKind::StringPointer;
    }
    if range_contains(text_range, value) {
        return PointerKind::CodePointer;
    }
    if range_contains(data_range, value) {
        return PointerKind::DataPointer;
    }
    PointerKind::Unknown
}

pub fn parse_scan_filter(raw: &str) -> Result<ScanFilter, String> {
    match raw {
        "non-executable" | "nonexec" => Ok(ScanFilter::NonExecutable),
        "writable-only" | "writable" => Ok(ScanFilter::WritableOnly),
        "all" => Ok(ScanFilter::All),
        other => Err(format!(
            "invalid scan filter '{other}'; expected non-executable, writable-only, or all"
        )),
    }
}

pub fn read_c_string_at_offset(elf_bytes: &[u8], file_offset: u64) -> Option<String> {
    let tail = elf_bytes.get(file_offset as usize..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn pack_word(value: u64, word_size: usize, endianness: Endianness) -> Vec<u8> {
    match (word_size, endianness) {
        (4, Endianness::Little) => (value as u32).to_le_bytes().to_vec(),
        (4, Endianness::Big) => (value as u32).to_be_bytes().to_vec(),
        (8, Endianness::Little) => value.to_le_bytes().to_vec(),
        (8, Endianness::Big) => value.to_be_bytes().to_vec(),
        _ => Vec::new(),
    }
}

fn matches_filter(flags: &str, filter: ScanFilter) -> bool {
    match filter {
        ScanFilter::All => true,
        ScanFilter::WritableOnly => flags.contains('W'),
        ScanFilter::NonExecutable => !flags.contains('X'),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|idx| start + idx)
}

fn range_contains(range: Option<(u64, u64)>, value: u64) -> bool {
    range
        .map(|(start, end)| value >= start && value < end)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_inspect::ElfProgramHeaderSummary;

    fn synthetic_load_segment_with_flags(
        offset: u64,
        vaddr: u64,
        file_size: u64,
        flags: &str,
    ) -> ElfProgramHeaderSummary {
        ElfProgramHeaderSummary {
            segment_type: "LOAD".to_string(),
            offset,
            virtual_address: vaddr,
            file_size,
            memory_size: file_size,
            flags: flags.to_string(),
            align: 0x1000,
        }
    }

    fn synthetic_load_segment(offset: u64, vaddr: u64, file_size: u64) -> ElfProgramHeaderSummary {
        synthetic_load_segment_with_flags(offset, vaddr, file_size, "WR")
    }

    fn load0() -> ElfProgramHeaderSummary {
        synthetic_load_segment_with_flags(0x0, 0x400000, 0xb1a34, "XR")
    }

    fn load1() -> ElfProgramHeaderSummary {
        ElfProgramHeaderSummary {
            segment_type: "LOAD".to_string(),
            offset: 0x0b2000,
            virtual_address: 0x4f2000,
            file_size: 0x96e0,
            memory_size: 0xe750,
            flags: "WR".to_string(),
            align: 0x1000,
        }
    }

    #[test]
    fn file_offset_to_vaddr_maps_load_segments() {
        let segs = vec![load0(), load1()];
        assert_eq!(file_offset_to_vaddr(0x6a5b0, &segs), Some(0x46a5b0));
        assert_eq!(file_offset_to_vaddr(0xb2ed0, &segs), Some(0x4f2ed0));
    }

    #[test]
    fn file_offset_to_vaddr_rejects_unmapped_gaps() {
        let segs = vec![load0(), load1()];
        assert_eq!(file_offset_to_vaddr(0xb1b00, &segs), None);
    }

    #[test]
    fn vaddr_to_file_offset_rejects_unmapped_and_bss_ranges() {
        let segs = vec![load0(), load1()];
        assert_eq!(vaddr_to_file_offset(0x4b2ed0, &segs), None);
        assert_eq!(vaddr_to_file_offset(0x4ffc00, &segs), None);
    }

    #[test]
    fn scan_for_pointer_finds_packed_little_endian_values() {
        let mut data = vec![0u8; 0x1000];
        data[0x800..0x804].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
        let segs = vec![synthetic_load_segment(0x0, 0x400000, 0x1000)];

        let hits = scan_for_pointer(
            &data,
            0x0046a5b0,
            4,
            Endianness::Little,
            &segs,
            ScanFilter::All,
        );

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file_offset, 0x800);
        assert_eq!(hits[0].vaddr, 0x400800);
    }

    #[test]
    fn scan_filter_non_executable_excludes_text_but_includes_rodata_and_data() {
        let mut data = vec![0u8; 0x3000];
        data[0x100..0x104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
        data[0x1100..0x1104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
        data[0x2100..0x2104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
        let segs = vec![
            synthetic_load_segment_with_flags(0x0, 0x400000, 0x1000, "XR"),
            synthetic_load_segment_with_flags(0x1000, 0x500000, 0x1000, "R"),
            synthetic_load_segment_with_flags(0x2000, 0x600000, 0x1000, "WR"),
        ];

        let hits = scan_for_pointer(
            &data,
            0x0046a5b0,
            4,
            Endianness::Little,
            &segs,
            ScanFilter::NonExecutable,
        );
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].file_offset, 0x1100);
        assert_eq!(hits[1].file_offset, 0x2100);

        let writable_hits = scan_for_pointer(
            &data,
            0x0046a5b0,
            4,
            Endianness::Little,
            &segs,
            ScanFilter::WritableOnly,
        );
        assert_eq!(writable_hits.len(), 1);
        assert_eq!(writable_hits[0].file_offset, 0x2100);
    }
}
