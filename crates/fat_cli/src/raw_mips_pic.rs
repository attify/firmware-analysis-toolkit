use crate::elf_addr::Endianness;
use std::collections::BTreeSet;
use std::error::Error;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone)]
pub(crate) struct RawTargetResult {
    pub vaddr: u64,
    pub label: String,
    pub code_hits: Vec<RawCodeHit>,
}

#[derive(Debug, Clone)]
pub(crate) struct RawCodeHit {
    pub instruction_vaddr: u64,
    pub function_vaddr: Option<u64>,
    pub function_name: Option<String>,
    pub register: String,
    pub pattern: String,
}

#[derive(Debug, Clone)]
struct FunctionRange {
    name: Option<String>,
    start: u64,
}

pub(crate) fn parse_hex_value(raw: &str) -> Result<u64, String> {
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

pub(crate) fn search_targets(
    raw_bytes: &[u8],
    arch: &str,
    base: u64,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<Vec<RawTargetResult>> {
    if !arch.eq_ignore_ascii_case("mips-pic") && !arch.eq_ignore_ascii_case("mips") {
        return Err(format!(
            "raw MIPS-PIC search currently supports --arch mips-pic or mips; got {arch}"
        )
        .into());
    }

    let targets = resolve_raw_targets(raw_bytes, base, vaddr, string_pattern)?;
    let prologues = find_mips_pic_prologues(raw_bytes, base, Endianness::Little);
    Ok(targets
        .into_iter()
        .map(|(target_vaddr, label)| RawTargetResult {
            vaddr: target_vaddr,
            label,
            code_hits: find_raw_mips_pic_low16_hits(
                raw_bytes,
                base,
                Endianness::Little,
                target_vaddr,
                &prologues,
            ),
        })
        .collect())
}

fn resolve_raw_targets(
    raw_bytes: &[u8],
    base: u64,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<Vec<(u64, String)>> {
    if let Some(raw) = vaddr {
        let addr = parse_hex_value(raw)?;
        return Ok(vec![(addr, format!("0x{addr:x}"))]);
    }

    let Some(pattern) = string_pattern else {
        return Err("provide --vaddr or --string-pattern".into());
    };
    if pattern.is_empty() {
        return Err("string pattern cannot be empty".into());
    }

    let mut targets = Vec::new();
    let pattern_bytes = pattern.as_bytes();
    let mut offset = 0usize;
    while offset + pattern_bytes.len() <= raw_bytes.len() {
        if &raw_bytes[offset..offset + pattern_bytes.len()] == pattern_bytes {
            let start = string_start(raw_bytes, offset);
            let end = string_end(raw_bytes, offset + pattern_bytes.len());
            let value = String::from_utf8_lossy(&raw_bytes[start..end]).to_string();
            targets.push((base + start as u64, value));
            offset = end.saturating_add(1);
        } else {
            offset += 1;
        }
    }

    Ok(targets)
}

fn string_start(bytes: &[u8], offset: usize) -> usize {
    let mut cursor = offset;
    while cursor > 0 && is_printable_string_byte(bytes[cursor - 1]) {
        cursor -= 1;
    }
    cursor
}

fn string_end(bytes: &[u8], offset: usize) -> usize {
    let mut cursor = offset;
    while cursor < bytes.len() && is_printable_string_byte(bytes[cursor]) {
        cursor += 1;
    }
    cursor
}

fn is_printable_string_byte(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

fn find_mips_pic_prologues(
    raw_bytes: &[u8],
    base: u64,
    endianness: Endianness,
) -> Vec<FunctionRange> {
    let mut prologues = Vec::new();
    let mut offset = 0usize;
    while offset + 12 <= raw_bytes.len() {
        let Some(first) = read_u32(raw_bytes, offset, endianness) else {
            break;
        };
        let Some(second) = read_u32(raw_bytes, offset + 4, endianness) else {
            break;
        };
        let Some(third) = read_u32(raw_bytes, offset + 8, endianness) else {
            break;
        };
        if is_mips_lui_gp(first) && is_mips_addiu_gp_gp(second) && third == 0x0399_e021 {
            let start = base + offset as u64;
            prologues.push(FunctionRange {
                name: Some(format!("candidate_mips_pic_0x{start:08x}")),
                start,
            });
        }
        offset += 4;
    }
    prologues
}

fn find_raw_mips_pic_low16_hits(
    raw_bytes: &[u8],
    base: u64,
    endianness: Endianness,
    target_vaddr: u64,
    prologues: &[FunctionRange],
) -> Vec<RawCodeHit> {
    let target_low16 = (target_vaddr & 0xffff) as u32;
    let mut hits = Vec::new();
    let mut seen = BTreeSet::new();
    let mut offset = 0usize;
    while offset + 4 <= raw_bytes.len() {
        let Some(instruction) = read_u32(raw_bytes, offset, endianness) else {
            break;
        };
        if is_mips_reference_immediate(instruction) && (instruction & 0xffff) == target_low16 {
            let instruction_vaddr = base + offset as u64;
            let function = nearest_preceding_function(prologues, instruction_vaddr);
            let key = (
                instruction_vaddr,
                function.map(|function| function.start).unwrap_or(0),
                target_vaddr,
            );
            if seen.insert(key) {
                hits.push(RawCodeHit {
                    instruction_vaddr,
                    function_vaddr: function.map(|function| function.start),
                    function_name: function.and_then(|function| function.name.clone()),
                    register: mips_register_name((instruction >> 16) & 0x1f).to_string(),
                    pattern: "mips-pic-low16".to_string(),
                });
            }
        }
        offset += 4;
    }
    hits
}

fn nearest_preceding_function(
    functions: &[FunctionRange],
    instruction_vaddr: u64,
) -> Option<&FunctionRange> {
    functions
        .iter()
        .take_while(|function| function.start <= instruction_vaddr)
        .last()
}

fn is_mips_lui_gp(instruction: u32) -> bool {
    ((instruction >> 26) & 0x3f) == 0x0f && ((instruction >> 16) & 0x1f) == 28
}

fn is_mips_addiu_gp_gp(instruction: u32) -> bool {
    ((instruction >> 26) & 0x3f) == 0x09
        && ((instruction >> 21) & 0x1f) == 28
        && ((instruction >> 16) & 0x1f) == 28
}

fn is_mips_reference_immediate(instruction: u32) -> bool {
    let opcode = (instruction >> 26) & 0x3f;
    let rt = (instruction >> 16) & 0x1f;
    matches!(opcode, 0x09 | 0x0d) && rt != 0
}

fn read_u32(bytes: &[u8], offset: usize, endianness: Endianness) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endianness {
        Endianness::Little => u32::from_le_bytes(raw),
        Endianness::Big => u32::from_be_bytes(raw),
    })
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
        _ => "?",
    }
}
