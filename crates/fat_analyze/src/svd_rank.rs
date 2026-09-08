use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

pub const SVD_RANK_SCHEMA_VERSION: &str = "svd-rank/v1";

#[derive(Debug, Clone)]
pub struct SvdRankRequest {
    pub firmware: PathBuf,
    pub svd_corpus: PathBuf,
    pub max_results: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SvdRankReport {
    pub schema_version: String,
    pub artifact_path: String,
    pub corpus_path: String,
    pub observed_mmio_literals: usize,
    pub candidate_count: usize,
    pub candidates: Vec<SvdRankCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SvdRankCandidate {
    pub device: String,
    pub source_path: String,
    pub score: f32,
    pub mmio_score: f32,
    pub string_hint_score: f32,
    pub vector_hint_score: f32,
    pub matched_register_count: usize,
    pub matched_peripheral_count: usize,
    pub svd_register_count: usize,
    pub coverage: f32,
    #[serde(default)]
    pub matched_registers: Vec<SvdRegisterMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvdRegisterMatch {
    pub address: u32,
    pub peripheral: String,
    pub register: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SvdRegister {
    address: u32,
    peripheral: String,
    register: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSvd {
    device: String,
    registers: Vec<SvdRegister>,
}

#[derive(Debug, Clone, PartialEq)]
struct FirmwareHints {
    mmio_literals: BTreeSet<u32>,
    lowercase_ascii: String,
    vector: Option<VectorHints>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct VectorHints {
    initial_sp: u32,
    reset_vector: u32,
    active_vector_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XmlBlock {
    attrs: BTreeMap<String, String>,
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeripheralTemplate {
    name: String,
    registers: Vec<RegisterTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisterTemplate {
    name: String,
    offset: u32,
    dim: Option<u32>,
    dim_increment: Option<u32>,
}

pub fn rank_svd_corpus(request: &SvdRankRequest) -> Result<SvdRankReport, String> {
    if !request.firmware.is_file() {
        return Err(format!(
            "firmware file not found: {}",
            request.firmware.display()
        ));
    }
    if !request.svd_corpus.is_dir() {
        return Err(format!(
            "SVD corpus path is not a directory: {}",
            request.svd_corpus.display()
        ));
    }

    let bytes = fs::read(&request.firmware)
        .map_err(|err| format!("failed to read {}: {err}", request.firmware.display()))?;
    let hints = extract_firmware_hints(&bytes);
    let svd_paths = collect_svd_paths(&request.svd_corpus);
    let mut diagnostics = Vec::new();
    let mut candidates = Vec::new();

    for svd_path in svd_paths {
        let content = match fs::read_to_string(&svd_path) {
            Ok(content) => content,
            Err(err) => {
                diagnostics.push(format!("skipped {}: {err}", svd_path.display()));
                continue;
            }
        };
        let parsed = match parse_svd(&content) {
            Ok(parsed) => parsed,
            Err(err) => {
                diagnostics.push(format!("skipped {}: {err}", svd_path.display()));
                continue;
            }
        };
        candidates.push(score_svd(&parsed, &svd_path, &hints));
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                right
                    .matched_register_count
                    .cmp(&left.matched_register_count)
            })
            .then_with(|| {
                right
                    .coverage
                    .partial_cmp(&left.coverage)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.device.cmp(&right.device))
            .then_with(|| left.source_path.cmp(&right.source_path))
    });

    let candidate_count = candidates.len();
    let max_results = request.max_results.max(1);
    candidates.truncate(max_results);

    Ok(SvdRankReport {
        schema_version: SVD_RANK_SCHEMA_VERSION.to_string(),
        artifact_path: request.firmware.display().to_string(),
        corpus_path: request.svd_corpus.display().to_string(),
        observed_mmio_literals: hints.mmio_literals.len(),
        candidate_count,
        candidates,
        diagnostics,
    })
}

fn extract_firmware_hints(bytes: &[u8]) -> FirmwareHints {
    FirmwareHints {
        mmio_literals: extract_mmio_literals(bytes),
        lowercase_ascii: extract_lowercase_ascii(bytes),
        vector: extract_vector_hints(bytes),
    }
}

fn extract_mmio_literals(bytes: &[u8]) -> BTreeSet<u32> {
    let mut literals = BTreeSet::new();
    for offset in (0..bytes.len().saturating_sub(3)).step_by(4) {
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if is_cortex_m_mmio_literal(word) {
            literals.insert(word);
        }
    }
    literals
}

fn extract_lowercase_ascii(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            out.push((*byte as char).to_ascii_lowercase());
        } else {
            out.push(' ');
        }
    }
    out
}

fn extract_vector_hints(bytes: &[u8]) -> Option<VectorHints> {
    if bytes.len() < 8 {
        return None;
    }
    let initial_sp = read_u32_at(bytes, 0)?;
    let reset_vector = read_u32_at(bytes, 4)?;
    if !(0x2000_0000..=0x3FFF_FFFF).contains(&initial_sp) {
        return None;
    }
    if reset_vector & 1 == 0 {
        return None;
    }
    let reset_address = reset_vector & !1;
    if !(0x0000_0000..=0x1FFF_FFFF).contains(&reset_address) {
        return None;
    }

    let mut active_vector_entries = 0;
    for offset in (4..bytes.len().min(0x400).saturating_sub(3)).step_by(4) {
        let Some(value) = read_u32_at(bytes, offset) else {
            continue;
        };
        let address = value & !1;
        if value & 1 == 1 && (0x0000_0000..=0x1FFF_FFFF).contains(&address) {
            active_vector_entries += 1;
        }
    }

    Some(VectorHints {
        initial_sp,
        reset_vector,
        active_vector_entries,
    })
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let window = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([
        window[0], window[1], window[2], window[3],
    ]))
}

fn is_cortex_m_mmio_literal(value: u32) -> bool {
    (0x4000_0000..=0x5FFF_FFFF).contains(&value) || (0xE000_0000..=0xE00F_FFFF).contains(&value)
}

fn collect_svd_paths(corpus: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = WalkDir::new(corpus)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("svd") || ext.eq_ignore_ascii_case("xml"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    paths
}

fn score_svd(parsed: &ParsedSvd, source_path: &Path, hints: &FirmwareHints) -> SvdRankCandidate {
    let mut registers_by_address = BTreeMap::<u32, Vec<&SvdRegister>>::new();
    for register in &parsed.registers {
        registers_by_address
            .entry(register.address)
            .or_default()
            .push(register);
    }

    let mut matched_registers = Vec::new();
    let mut matched_peripherals = BTreeSet::new();
    for address in &hints.mmio_literals {
        if let Some(registers) = registers_by_address.get(address) {
            for register in registers {
                matched_peripherals.insert(register.peripheral.clone());
                matched_registers.push(SvdRegisterMatch {
                    address: *address,
                    peripheral: register.peripheral.clone(),
                    register: register.register.clone(),
                });
            }
        }
    }
    matched_registers.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.peripheral.cmp(&right.peripheral))
            .then_with(|| left.register.cmp(&right.register))
    });

    let svd_register_count = parsed.registers.len();
    let matched_register_count = matched_registers.len();
    let mmio_score = matched_register_count as f32;
    let string_hint_score = score_string_hints(&parsed.device, &hints.lowercase_ascii);
    let vector_hint_score = score_vector_hints(&parsed.device, hints.vector);
    let coverage = if svd_register_count == 0 {
        0.0
    } else {
        matched_register_count as f32 / svd_register_count as f32
    };

    SvdRankCandidate {
        device: parsed.device.clone(),
        source_path: source_path.display().to_string(),
        score: mmio_score + string_hint_score + vector_hint_score,
        mmio_score,
        string_hint_score,
        vector_hint_score,
        matched_register_count,
        matched_peripheral_count: matched_peripherals.len(),
        svd_register_count,
        coverage,
        matched_registers,
    }
}

fn score_string_hints(device: &str, lowercase_ascii: &str) -> f32 {
    let mut score = 0.0_f32;
    for token in device_hint_tokens(device) {
        if lowercase_ascii.contains(&token) {
            score += if token.len() >= 6 { 0.5 } else { 0.2 };
        }
    }
    score.min(1.0)
}

fn device_hint_tokens(device: &str) -> Vec<String> {
    let normalized = normalize_hint_token(device);
    let mut tokens = BTreeSet::new();
    if normalized.len() >= 3 {
        tokens.insert(normalized.clone());
    }
    for segment in device
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(normalize_hint_token)
    {
        if segment.len() >= 3 {
            tokens.insert(segment.clone());
        }
        for prefix in ["stm32", "nrf", "esp32", "sam", "lpc"] {
            if let Some(suffix) = segment.strip_prefix(prefix) {
                if suffix.len() >= 3 {
                    tokens.insert(suffix.to_string());
                }
            }
        }
    }
    tokens.into_iter().collect()
}

fn normalize_hint_token(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn score_vector_hints(device: &str, vector: Option<VectorHints>) -> f32 {
    let Some(vector) = vector else {
        return 0.0;
    };
    let mut score = 0.0;
    if (0x2000_0000..=0x3FFF_FFFF).contains(&vector.initial_sp) && vector.reset_vector & 1 == 1 {
        score += 0.15;
    }
    let device = normalize_hint_token(device);
    if vector.active_vector_entries >= 40
        && (device.contains("stm32f4")
            || device.contains("stm32h")
            || device.contains("nrf52")
            || device.contains("samd5"))
    {
        score += 0.15;
    }
    score
}

fn parse_svd(content: &str) -> Result<ParsedSvd, String> {
    let device = extract_first_tag(content, "name")
        .ok_or_else(|| "SVD device is missing <name>".to_string())?;
    let peripheral_blocks = extract_xml_blocks(content, "peripheral");
    let mut templates = BTreeMap::<String, PeripheralTemplate>::new();
    let mut registers = Vec::new();

    for peripheral_block in &peripheral_blocks {
        let peripheral = extract_first_tag(&peripheral_block.body, "name")
            .ok_or_else(|| "SVD peripheral is missing <name>".to_string())?;
        let direct_template = parse_peripheral_template(&peripheral, &peripheral_block.body)?;
        templates.insert(peripheral.clone(), direct_template);
    }

    for peripheral_block in peripheral_blocks {
        let peripheral = extract_first_tag(&peripheral_block.body, "name")
            .ok_or_else(|| "SVD peripheral is missing <name>".to_string())?;
        let base = extract_first_tag(&peripheral_block.body, "baseAddress")
            .ok_or_else(|| format!("SVD peripheral {peripheral} is missing <baseAddress>"))
            .and_then(|value| parse_u32_literal(&value))?;
        let template = if let Some(parent) = peripheral_block.attrs.get("derivedFrom") {
            let parent_name = parent
                .rsplit('.')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(parent);
            templates
                .get(parent_name)
                .ok_or_else(|| {
                    format!("SVD peripheral {peripheral} derives from unknown {parent}")
                })?
                .clone()
        } else {
            templates
                .get(&peripheral)
                .ok_or_else(|| format!("SVD peripheral {peripheral} template missing"))?
                .clone()
        };

        for register in expand_register_templates(&template.registers) {
            registers.push(SvdRegister {
                address: base.wrapping_add(register.offset),
                peripheral: peripheral.clone(),
                register: register.name,
            });
        }
    }

    Ok(ParsedSvd { device, registers })
}

fn parse_peripheral_template(peripheral: &str, body: &str) -> Result<PeripheralTemplate, String> {
    let mut registers = Vec::new();
    for register_block in extract_xml_blocks(body, "register") {
        let register = extract_first_tag(&register_block.body, "name")
            .ok_or_else(|| format!("SVD register in {peripheral} is missing <name>"))?;
        let offset = extract_first_tag(&register_block.body, "addressOffset")
            .ok_or_else(|| {
                format!("SVD register {peripheral}.{register} is missing <addressOffset>")
            })
            .and_then(|value| parse_u32_literal(&value))?;
        let dim = extract_first_tag(&register_block.body, "dim")
            .map(|value| parse_u32_literal(&value))
            .transpose()?;
        let dim_increment = extract_first_tag(&register_block.body, "dimIncrement")
            .map(|value| parse_u32_literal(&value))
            .transpose()?;
        registers.push(RegisterTemplate {
            name: register,
            offset,
            dim,
            dim_increment,
        });
    }
    Ok(PeripheralTemplate {
        name: peripheral.to_string(),
        registers,
    })
}

fn expand_register_templates(registers: &[RegisterTemplate]) -> Vec<RegisterTemplate> {
    let mut expanded = Vec::new();
    for register in registers {
        let Some(dim) = register.dim else {
            expanded.push(register.clone());
            continue;
        };
        let dim = dim.max(1);
        let increment = register.dim_increment.unwrap_or(0);
        for index in 0..dim {
            let mut item = register.clone();
            item.name = expand_dimmed_name(&register.name, index);
            item.offset = register
                .offset
                .wrapping_add(index.saturating_mul(increment));
            item.dim = None;
            item.dim_increment = None;
            expanded.push(item);
        }
    }
    expanded
}

fn expand_dimmed_name(name: &str, index: u32) -> String {
    if name.contains("%s") {
        name.replace("%s", &index.to_string())
    } else if name.contains("%d") {
        name.replace("%d", &index.to_string())
    } else if name.contains("{}") {
        name.replace("{}", &index.to_string())
    } else {
        format!("{name}{index}")
    }
}

fn extract_first_tag(content: &str, tag: &str) -> Option<String> {
    extract_blocks(content, tag)
        .into_iter()
        .next()
        .map(|value| value.trim().to_string())
}

fn extract_blocks(content: &str, tag: &str) -> Vec<String> {
    extract_xml_blocks(content, tag)
        .into_iter()
        .map(|block| block.body)
        .collect()
}

fn extract_xml_blocks(content: &str, tag: &str) -> Vec<XmlBlock> {
    let mut blocks = Vec::new();
    let mut cursor = 0;
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    while let Some(open_rel) = content[cursor..].find(&open) {
        let open_start = cursor + open_rel;
        let after_tag = open_start + open.len();
        let Some(next) = content[after_tag..].chars().next() else {
            break;
        };
        if next != '>' && !next.is_ascii_whitespace() {
            cursor = after_tag;
            continue;
        }
        let Some(open_end_rel) = content[open_start..].find('>') else {
            break;
        };
        let tag_text = &content[after_tag..open_start + open_end_rel];
        let body_start = open_start + open_end_rel + 1;
        let Some(close_rel) = content[body_start..].find(&close) else {
            break;
        };
        let body_end = body_start + close_rel;
        blocks.push(XmlBlock {
            attrs: parse_attrs(tag_text),
            body: content[body_start..body_end].to_string(),
        });
        cursor = body_end + close.len();
    }
    blocks
}

fn parse_attrs(tag_text: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let bytes = tag_text.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let key_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor == key_start {
            cursor += 1;
            continue;
        }
        let key = &tag_text[key_start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'=' {
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || (bytes[cursor] != b'"' && bytes[cursor] != b'\'') {
            continue;
        }
        let quote = bytes[cursor];
        cursor += 1;
        let value_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != quote {
            cursor += 1;
        }
        if cursor <= bytes.len() {
            attrs.insert(key.to_string(), tag_text[value_start..cursor].to_string());
        }
        cursor += 1;
    }
    attrs
}

fn parse_u32_literal(value: &str) -> Result<u32, String> {
    let trimmed = value.trim().replace('_', "");
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|err| format!("invalid hex value {value:?}: {err}"))
    } else {
        trimmed
            .parse::<u32>()
            .map_err(|err| format!("invalid integer value {value:?}: {err}"))
    }
}
