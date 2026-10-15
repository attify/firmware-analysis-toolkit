//! Bounded discovery of CRC-validated U-Boot environment regions in raw flash.
use std::collections::BTreeSet;

use fat_core::boot_env::{BootEnvScan, BootEnvironment, EnvironmentVariable};

const COMMON_SIZES: &[u64] = &[0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000];
const ALIGNMENT: usize = 0x1000;
const MAX_ENV_SIZE: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_RESULTS: usize = 128;

#[derive(Debug, Clone)]
pub struct EnvScanOptions {
    /// Explicit (offset, total stored size), including CRC and redundant flag.
    pub region: Option<(u64, u64)>,
    pub max_scan_bytes: u64,
}

impl Default for EnvScanOptions {
    fn default() -> Self {
        Self {
            region: None,
            max_scan_bytes: 64 * 1024 * 1024,
        }
    }
}

pub fn scan(bytes: &[u8], options: &EnvScanOptions) -> Result<BootEnvScan, String> {
    let mut result = BootEnvScan::default();
    if let Some((offset, size)) = options.region {
        if !(6..=MAX_ENV_SIZE).contains(&size) {
            return Err(
                "environment size must be between 6 bytes and 1 MiB, including the header".into(),
            );
        }
        let end = offset
            .checked_add(size)
            .ok_or("environment range overflows")?;
        if end > bytes.len() as u64 {
            return Err("environment region extends beyond the input image".into());
        }
        result.explicit_region = true;
        result.scanned_bytes = size;
        result.candidate_sizes.push(size);
        result.environments = parse_region(&bytes[offset as usize..end as usize], offset);
        if result.environments.is_empty() {
            result.diagnostics.push(format!("No CRC-valid legacy or redundant environment in supplied region 0x{offset:x}+0x{size:x}"));
        }
        return Ok(result);
    }

    let limit = bytes
        .len()
        .min(usize::try_from(options.max_scan_bytes).unwrap_or(usize::MAX));
    result.scanned_bytes = limit as u64;
    result.alignment = ALIGNMENT as u64;
    result.candidate_sizes = COMMON_SIZES.to_vec();
    result.search_limited = limit < bytes.len();
    for offset in (0..limit).step_by(ALIGNMENT) {
        let tail = &bytes[offset..limit];
        // Reject fill and binary data before hashing candidate regions. A valid
        // first entry is required for both header variants; baudrate is optional.
        if !plausible_first_entry(tail.get(4..).unwrap_or_default())
            && !plausible_first_entry(tail.get(5..).unwrap_or_default())
        {
            continue;
        }
        for &size in COMMON_SIZES {
            let Some(region) = tail.get(..size as usize) else {
                continue;
            };
            result
                .environments
                .extend(parse_region(region, offset as u64));
            if result.environments.len() >= MAX_RESULTS {
                result.search_limited = true;
                result
                    .diagnostics
                    .push("Environment result limit reached (128 regions)".into());
                return Ok(result);
            }
        }
    }
    Ok(result)
}

fn plausible_first_entry(data: &[u8]) -> bool {
    let prefix = &data[..data.len().min(4096)];
    prefix
        .iter()
        .position(|b| *b == 0)
        .is_some_and(|end| valid_entry(&prefix[..end]))
}

fn valid_entry(entry: &[u8]) -> bool {
    let Some(eq) = entry.iter().position(|b| *b == b'=') else {
        return false;
    };
    let key = &entry[..eq];
    !key.is_empty()
        && key.len() <= 128
        && key
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
        && entry[eq + 1..]
            .iter()
            .all(|b| b.is_ascii_graphic() || b" \t\n\r".contains(b))
}

fn parse_region(region: &[u8], offset: u64) -> Vec<BootEnvironment> {
    let mut results = Vec::new();
    let Some(stored) = region.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
        return results;
    };
    for (header_size, format) in [(4, "legacy"), (5, "redundant")] {
        let Some(data) = region.get(header_size..) else {
            continue;
        };
        if !plausible_first_entry(data) {
            continue;
        }
        let computed = crc32fast::hash(data);
        let endian = if computed == u32::from_le_bytes(stored) {
            "little"
        } else if computed == u32::from_be_bytes(stored) {
            "big"
        } else {
            continue;
        };
        let Some(variables) = parse_variables(data, offset + header_size as u64) else {
            continue;
        };
        results.push(BootEnvironment {
            offset,
            size: region.len() as u64,
            format: format.into(),
            crc_endianness: endian.into(),
            crc_valid: true,
            stored_crc32: format!("{computed:08x}"),
            redundancy_flag: (header_size == 5).then(|| region[4]),
            variables,
        });
    }
    results
}

fn parse_variables(data: &[u8], offset: u64) -> Option<Vec<EnvironmentVariable>> {
    let mut variables = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = 0;
    while cursor < data.len() && variables.len() < MAX_ENTRIES {
        let tail = &data[cursor..];
        let end = tail.iter().position(|b| *b == 0)?;
        if end == 0 {
            return (!variables.is_empty()).then_some(variables);
        }
        let entry = &tail[..end];
        if !valid_entry(entry) {
            return None;
        }
        let text = std::str::from_utf8(entry).ok()?;
        let (key, value) = text.split_once('=')?;
        if !seen.insert(key) {
            return None;
        }
        variables.push(EnvironmentVariable {
            key: key.into(),
            value: value.into(),
            offset: offset + cursor as u64,
        });
        cursor += end + 1;
    }
    None
}
