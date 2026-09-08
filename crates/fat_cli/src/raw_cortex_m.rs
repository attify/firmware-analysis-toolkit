use crate::raw_mips_pic::{RawCodeHit, RawTargetResult};
use std::error::Error;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone)]
struct FunctionCandidate {
    start: u64,
    name: String,
}

pub(crate) fn search_targets(
    raw_bytes: &[u8],
    base: u64,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<Vec<RawTargetResult>> {
    let targets = resolve_targets(raw_bytes, base, vaddr, string_pattern)?;
    let functions = find_thumb_function_candidates(raw_bytes, base);

    Ok(targets
        .into_iter()
        .map(|(target_vaddr, label)| RawTargetResult {
            vaddr: target_vaddr,
            label,
            code_hits: find_thumb_adr_hits(raw_bytes, base, target_vaddr, &functions),
        })
        .collect())
}

fn resolve_targets(
    raw_bytes: &[u8],
    base: u64,
    vaddr: Option<&str>,
    string_pattern: Option<&str>,
) -> DynResult<Vec<(u64, String)>> {
    if let Some(raw) = vaddr {
        let addr = crate::raw_mips_pic::parse_hex_value(raw)?;
        return Ok(vec![(addr, format!("0x{addr:x}"))]);
    }

    let Some(pattern) = string_pattern else {
        return Err("provide --vaddr or --string-pattern".into());
    };
    if pattern.is_empty() {
        return Err("string pattern cannot be empty".into());
    }

    let pattern_bytes = pattern.as_bytes();
    let mut targets = Vec::new();
    let mut offset = 0usize;
    while offset + pattern_bytes.len() <= raw_bytes.len() {
        if &raw_bytes[offset..offset + pattern_bytes.len()] == pattern_bytes {
            let start = string_start(raw_bytes, offset);
            let end = string_end(raw_bytes, offset + pattern_bytes.len());
            targets.push((
                base + start as u64,
                String::from_utf8_lossy(&raw_bytes[start..end]).to_string(),
            ));
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

fn find_thumb_function_candidates(raw_bytes: &[u8], base: u64) -> Vec<FunctionCandidate> {
    raw_bytes
        .chunks_exact(2)
        .enumerate()
        .filter_map(|(index, chunk)| {
            let instruction = u16::from_le_bytes([chunk[0], chunk[1]]);
            // Thumb PUSH with LR and at least one low register is a useful raw-image
            // function-boundary candidate. It is evidence, not a symbol recovery claim.
            if instruction & 0xfe00 != 0xb400
                || instruction & 0x0100 == 0
                || instruction & 0x00ff == 0
            {
                return None;
            }
            let start = base + (index * 2) as u64;
            Some(FunctionCandidate {
                start,
                name: format!("candidate_cortex_m_0x{start:08x}"),
            })
        })
        .collect()
}

fn find_thumb_adr_hits(
    raw_bytes: &[u8],
    base: u64,
    target_vaddr: u64,
    functions: &[FunctionCandidate],
) -> Vec<RawCodeHit> {
    let mut hits = Vec::new();
    for (index, chunk) in raw_bytes.chunks_exact(2).enumerate() {
        let instruction = u16::from_le_bytes([chunk[0], chunk[1]]);
        if instruction & 0xf800 != 0xa000 {
            continue;
        }

        let instruction_vaddr = base + (index * 2) as u64;
        let pc = instruction_vaddr.saturating_add(4) & !3;
        let referenced_vaddr = pc.saturating_add(((instruction & 0x00ff) as u64) * 4);
        if referenced_vaddr != target_vaddr {
            continue;
        }

        let function = functions
            .iter()
            .take_while(|function| function.start <= instruction_vaddr)
            .last();
        hits.push(RawCodeHit {
            instruction_vaddr,
            function_vaddr: function.map(|function| function.start),
            function_name: function.map(|function| function.name.clone()),
            register: format!("r{}", (instruction >> 8) & 0x7),
            pattern: "thumb-adr".to_string(),
        });
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_adr_uses_aligned_pc_and_attributes_nearest_push_candidate() {
        let mut bytes = vec![0u8; 0x80];
        bytes[0x20..0x22].copy_from_slice(&0xb510u16.to_le_bytes());
        bytes[0x26..0x28].copy_from_slice(&0xa30bu16.to_le_bytes());
        bytes[0x54..0x6f].copy_from_slice(b"../LWIP/Target/ethernetif.c");

        let results = search_targets(&bytes, 0x0800_0000, None, Some("ethernetif.c"))
            .expect("raw Cortex-M search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vaddr, 0x0800_0054);
        assert_eq!(results[0].code_hits.len(), 1);
        assert_eq!(results[0].code_hits[0].instruction_vaddr, 0x0800_0026);
        assert_eq!(results[0].code_hits[0].function_vaddr, Some(0x0800_0020));
    }
}
