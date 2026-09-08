use crate::elf_addr::{self, PointerHit};
use serde::Serialize;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub struct XrefSearchReport {
    pub file: String,
    pub architecture: String,
    pub endianness: String,
    pub word_size: usize,
    pub targets: Vec<TargetResult>,
}

#[derive(Debug, Serialize)]
pub struct TargetResult {
    pub vaddr: u64,
    pub label: String,
    pub hits: Vec<PointerHit>,
    pub code_hits: Vec<CodeHit>,
}

#[derive(Debug, Serialize)]
pub struct CodeHit {
    pub instruction_vaddr: u64,
    pub function_vaddr: Option<u64>,
    pub function_name: Option<String>,
    pub register: String,
    pub pattern: String,
}

pub fn run(
    file: &Path,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
    raw: bool,
    arch: Option<&str>,
    base: Option<&str>,
    scan_filter_str: &str,
    json: bool,
) -> DynResult<()> {
    let report = if raw {
        let bytes = std::fs::read(file)?;
        let arch = arch.unwrap_or("mips-pic");
        let base = base
            .map(crate::raw_mips_pic::parse_hex_value)
            .transpose()?
            .unwrap_or(0);
        search_raw(
            &bytes,
            &file.display().to_string(),
            arch,
            base,
            vaddr,
            string_pattern,
        )?
    } else {
        search(file, vaddr, string_pattern, scan_filter_str)?
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_xref_report(&report));
    }
    Ok(())
}

pub fn search(
    file: &Path,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
    scan_filter_str: &str,
) -> DynResult<XrefSearchReport> {
    let elf_bytes = std::fs::read(file)?;
    let elf_report = crate::elf_inspect::parse_elf_bytes(&elf_bytes)?;
    let endianness = elf_addr::endianness_from_header(&elf_report.header);
    let word_size = if elf_report.header.class.contains("64") {
        8
    } else {
        4
    };
    let scan_filter = elf_addr::parse_scan_filter(scan_filter_str)?;

    let targets = resolve_targets(file, vaddr, string_pattern)?;
    let mut report = XrefSearchReport {
        file: file.display().to_string(),
        architecture: elf_report.header.machine.clone(),
        endianness: format!("{endianness:?}"),
        word_size,
        targets: Vec::new(),
    };
    let function_index = load_function_index(file, &elf_report);

    for (target_vaddr, label) in targets {
        let hits = elf_addr::scan_for_pointer(
            &elf_bytes,
            target_vaddr,
            word_size,
            endianness,
            &elf_report.program_headers,
            scan_filter,
        );
        let code_hits = if elf_report.header.machine.eq_ignore_ascii_case("MIPS") && word_size == 4
        {
            find_mips_direct_load_code_hits(
                &elf_bytes,
                &elf_report.program_headers,
                endianness,
                &function_index,
                target_vaddr,
            )
        } else {
            Vec::new()
        };
        report.targets.push(TargetResult {
            vaddr: target_vaddr,
            label,
            hits,
            code_hits,
        });
    }

    Ok(report)
}

fn resolve_targets(
    file: &Path,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<Vec<(u64, String)>> {
    if let Some(raw) = vaddr {
        let addr = parse_hex_value(raw)?;
        return Ok(vec![(addr, format!("0x{addr:x}"))]);
    }

    if let Some(pattern) = string_pattern {
        let strings = fat_taint::recon::r2::strings(file, 4)?;
        return Ok(strings
            .into_iter()
            .filter(|entry| entry.value.contains(pattern))
            .map(|entry| (entry.address, entry.value))
            .collect());
    }

    Err("provide --vaddr or --string-pattern".into())
}

fn parse_hex_value(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("hex value cannot be empty".to_string());
    }
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.is_empty() {
        return Err("hex value cannot be empty".to_string());
    }
    u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex value '{raw}': {err}"))
}

fn search_raw(
    raw_bytes: &[u8],
    file_label: &str,
    arch: &str,
    base: u64,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<XrefSearchReport> {
    let targets = if arch.eq_ignore_ascii_case("cortex-m") {
        crate::raw_cortex_m::search_targets(raw_bytes, base, vaddr, string_pattern)?
    } else if arch.eq_ignore_ascii_case("mips-pic") || arch.eq_ignore_ascii_case("mips") {
        crate::raw_mips_pic::search_targets(raw_bytes, arch, base, vaddr, string_pattern)?
    } else {
        return Err(format!(
            "raw xref-search supports --arch cortex-m, mips-pic, or mips; got {arch}"
        )
        .into());
    };
    let mut report = XrefSearchReport {
        file: file_label.to_string(),
        architecture: arch.to_string(),
        endianness: "Little".to_string(),
        word_size: 4,
        targets: Vec::new(),
    };

    for target in targets {
        report.targets.push(TargetResult {
            vaddr: target.vaddr,
            label: target.label,
            hits: Vec::new(),
            code_hits: target
                .code_hits
                .into_iter()
                .map(|hit| CodeHit {
                    instruction_vaddr: hit.instruction_vaddr,
                    function_vaddr: hit.function_vaddr,
                    function_name: hit.function_name,
                    register: hit.register,
                    pattern: hit.pattern,
                })
                .collect(),
        });
    }

    Ok(report)
}

fn render_xref_report(report: &XrefSearchReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("xref-search: {}\n\n", report.file));
    for target in &report.targets {
        out.push_str(&format!(
            "Target: 0x{:08x} ({})\n",
            target.vaddr, target.label
        ));
        if target.hits.is_empty() {
            out.push_str("  no pointer hits\n");
        } else {
            for hit in &target.hits {
                out.push_str(&format!(
                    "  pointer hit at file 0x{:08x} -> vaddr 0x{:08x} (LOAD{})\n",
                    hit.file_offset, hit.vaddr, hit.segment_index
                ));
            }
        }
        if target.code_hits.is_empty() {
            out.push_str("  no code hits\n");
        } else {
            for hit in &target.code_hits {
                if let Some(function_name) = &hit.function_name {
                    out.push_str(&format!(
                        "  code hit at 0x{:08x} in {} via {} {}\n",
                        hit.instruction_vaddr, function_name, hit.pattern, hit.register
                    ));
                } else if let Some(function_vaddr) = hit.function_vaddr {
                    out.push_str(&format!(
                        "  code hit at 0x{:08x} in 0x{:08x} via {} {}\n",
                        hit.instruction_vaddr, function_vaddr, hit.pattern, hit.register
                    ));
                } else {
                    out.push_str(&format!(
                        "  code hit at 0x{:08x} via {} {}\n",
                        hit.instruction_vaddr, hit.pattern, hit.register
                    ));
                }
            }
        }
    }

    let pointer_hit_count: usize = report.targets.iter().map(|target| target.hits.len()).sum();
    let code_hit_count: usize = report
        .targets
        .iter()
        .map(|target| target.code_hits.len())
        .sum();
    out.push_str(&format!(
        "\nSummary: {} targets, {} pointer hits, {} code hits\n",
        report.targets.len(),
        pointer_hit_count,
        code_hit_count,
    ));
    out
}

#[derive(Debug, Clone, Default)]
struct FunctionIndex {
    functions: Vec<FunctionRange>,
}

#[derive(Debug, Clone)]
struct FunctionRange {
    name: Option<String>,
    start: u64,
    end: u64,
}

impl FunctionIndex {
    fn containing(&self, vaddr: u64) -> Option<&FunctionRange> {
        self.functions
            .iter()
            .find(|function| vaddr >= function.start && vaddr < function.end)
    }
}

fn load_function_index(
    file: &Path,
    elf_report: &crate::elf_inspect::ElfInspectReport,
) -> FunctionIndex {
    let mut functions = fat_taint::recon::r2::function_list(file)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|function| {
            let end = function.address.checked_add(function.size)?;
            if function.size == 0 || end <= function.address {
                return None;
            }
            Some(FunctionRange {
                name: Some(function.name),
                start: function.address,
                end,
            })
        })
        .collect::<Vec<_>>();

    if functions.is_empty() {
        if let Some(fallback) = entrypoint_function_range(elf_report) {
            functions.push(fallback);
        }
    }

    functions.sort_by_key(|function| (function.start, function.end));
    functions.dedup_by_key(|function| (function.start, function.end));
    FunctionIndex { functions }
}

fn entrypoint_function_range(
    elf_report: &crate::elf_inspect::ElfInspectReport,
) -> Option<FunctionRange> {
    let entry = elf_report.header.entry_point;
    elf_report
        .program_headers
        .iter()
        .filter(|segment| segment.segment_type == "LOAD" && segment.flags.contains('X'))
        .find_map(|segment| {
            let end = segment.virtual_address.checked_add(segment.file_size)?;
            if entry >= segment.virtual_address && entry < end {
                Some(FunctionRange {
                    name: Some("entry0".to_string()),
                    start: entry,
                    end,
                })
            } else {
                None
            }
        })
}

fn find_mips_direct_load_code_hits(
    elf_bytes: &[u8],
    program_headers: &[crate::elf_inspect::ElfProgramHeaderSummary],
    endianness: crate::elf_addr::Endianness,
    function_index: &FunctionIndex,
    target_vaddr: u64,
) -> Vec<CodeHit> {
    let mut hits = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for segment in program_headers
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
        while offset + 8 <= region.len() {
            let Some(first) = read_u32(region, offset, endianness) else {
                break;
            };
            let Some(register) = decode_mips_lui_register(first) else {
                offset += 4;
                continue;
            };

            let mut lookahead = offset + 4;
            while lookahead + 4 <= region.len() && lookahead <= offset + 24 {
                let Some(candidate) = read_u32(region, lookahead, endianness) else {
                    break;
                };
                if let Some((target, pattern)) = decode_mips_load_from_lui(first, candidate) {
                    if target == target_vaddr {
                        let instruction_vaddr = segment.virtual_address + lookahead as u64;
                        let function = function_index.containing(instruction_vaddr);
                        let key = (
                            instruction_vaddr,
                            function.map(|function| function.start).unwrap_or(0),
                            target,
                        );
                        if seen.insert(key) {
                            hits.push(CodeHit {
                                instruction_vaddr,
                                function_vaddr: function.map(|function| function.start),
                                function_name: function.and_then(|function| function.name.clone()),
                                register: mips_register_name(register).to_string(),
                                pattern: pattern.to_string(),
                            });
                        }
                    }
                    break;
                }
                if mips_instruction_writes_register(candidate, register) {
                    break;
                }
                lookahead += 4;
            }
            offset += 4;
        }
    }

    hits
}

fn decode_mips_lui_register(first: u32) -> Option<u32> {
    let lui_opcode = (first >> 26) & 0x3f;
    if lui_opcode != 0x0f {
        return None;
    }
    let rt = (first >> 16) & 0x1f;
    if rt == 0 {
        return None;
    }
    Some(rt)
}

fn decode_mips_load_from_lui(first: u32, second: u32) -> Option<(u64, &'static str)> {
    let rt = decode_mips_lui_register(first)?;

    let second_opcode = (second >> 26) & 0x3f;
    let second_rs = (second >> 21) & 0x1f;
    let second_rt = (second >> 16) & 0x1f;
    if second_rs != rt || second_rt != rt {
        return None;
    }

    let high = (first & 0xffff) << 16;
    let low = second & 0xffff;
    let (target, pattern) = match second_opcode {
        0x0d => ((high | low) as u64, "lui+ori"),
        0x09 => (
            high.wrapping_add((low as i16 as i32) as u32) as u64,
            "lui+addiu",
        ),
        _ => return None,
    };
    Some((target, pattern))
}

fn read_u32(bytes: &[u8], offset: usize, endianness: crate::elf_addr::Endianness) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endianness {
        crate::elf_addr::Endianness::Little => u32::from_le_bytes(raw),
        crate::elf_addr::Endianness::Big => u32::from_be_bytes(raw),
    })
}

fn mips_instruction_writes_register(instruction: u32, register: u32) -> bool {
    let opcode = (instruction >> 26) & 0x3f;
    match opcode {
        0x00 => {
            let funct = instruction & 0x3f;
            match funct {
                0x08 | 0x09 => false, // jr/jalr
                _ => ((instruction >> 11) & 0x1f) == register,
            }
        }
        0x02..=0x07 => false,
        0x28..=0x2e => false,
        _ => ((instruction >> 16) & 0x1f) == register,
    }
}

fn mips_register_name(register: u32) -> &'static str {
    match register {
        0 => "zero",
        1 => "at",
        2 => "v0",
        3 => "v1",
        4 => "a0",
        5 => "a1",
        6 => "a2",
        7 => "a3",
        8 => "t0",
        9 => "t1",
        10 => "t2",
        11 => "t3",
        12 => "t4",
        13 => "t5",
        14 => "t6",
        15 => "t7",
        16 => "s0",
        17 => "s1",
        18 => "s2",
        19 => "s3",
        20 => "s4",
        21 => "s5",
        22 => "s6",
        23 => "s7",
        24 => "t8",
        25 => "t9",
        26 => "k0",
        27 => "k1",
        28 => "gp",
        29 => "sp",
        30 => "fp",
        31 => "ra",
        _ => "r?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mips_pic_string_search_reports_low16_code_hit_and_function_candidate() {
        let mut bytes = vec![0u8; 0x17000];
        bytes[0x169d4..0x169dc].copy_from_slice(b"bootargs");

        // MIPS PIC prologue: lui gp, 2; addiu gp, gp, 0xb8c; addu gp, gp, t9.
        bytes[0x0f24..0x0f28].copy_from_slice(&0x3c1c_0002u32.to_le_bytes());
        bytes[0x0f28..0x0f2c].copy_from_slice(&0x279c_0b8cu32.to_le_bytes());
        bytes[0x0f2c..0x0f30].copy_from_slice(&0x0399_e021u32.to_le_bytes());

        // addiu a0, a0, 0x69d4 references the low half of the raw string offset.
        bytes[0x0f9c..0x0fa0].copy_from_slice(&0x2484_69d4u32.to_le_bytes());

        let report = search_raw(&bytes, "fixture.bin", "mips-pic", 0, None, Some("bootargs"))
            .expect("raw search report");

        assert_eq!(report.architecture, "mips-pic");
        assert_eq!(report.targets.len(), 1);
        assert_eq!(report.targets[0].vaddr, 0x169d4);
        assert_eq!(report.targets[0].label, "bootargs");
        assert!(report.targets[0].hits.is_empty());
        assert_eq!(report.targets[0].code_hits.len(), 1);
        assert_eq!(report.targets[0].code_hits[0].instruction_vaddr, 0x0f9c);
        assert_eq!(report.targets[0].code_hits[0].function_vaddr, Some(0x0f24));
        assert_eq!(
            report.targets[0].code_hits[0].function_name.as_deref(),
            Some("candidate_mips_pic_0x00000f24")
        );
        assert_eq!(report.targets[0].code_hits[0].register, "a0");
        assert_eq!(report.targets[0].code_hits[0].pattern, "mips-pic-low16");
    }

    #[test]
    fn parse_hex_accepts_prefixed_and_bare_values() {
        assert_eq!(parse_hex_value("0x0046a5b0").unwrap(), 0x0046a5b0);
        assert_eq!(parse_hex_value("46a5b0").unwrap(), 0x46a5b0);
    }

    #[test]
    fn parse_hex_rejects_empty_values() {
        assert!(parse_hex_value("").is_err());
        assert!(parse_hex_value("0x").is_err());
    }
}
