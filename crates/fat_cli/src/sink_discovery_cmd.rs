use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use fat_taint::{
    recon::r2,
    shell_scan::{scan_rootfs, ShellScanReport, ShellScanSummary},
    sink_discovery::{
        parse_sink_profile, score_candidate, BinaryContext, Confidence, FamilyProfile, Severity,
        SinkCandidate, SinkDiscoveryReport, SinkDiscoverySummary, SinkEvidence, SinkProfile,
        StringSeed, LINUX_COMMAND_EXEC_PROFILE_YAML, SHELL_COMMAND_EXEC_PROFILE_YAML,
    },
};
use std::collections::{BTreeMap, BTreeSet};

type DynResult<T> = Result<T, Box<dyn Error>>;

const BUILTIN_PROFILE_YAML: &str = LINUX_COMMAND_EXEC_PROFILE_YAML;

/// (name, yaml, fallback display target) for every built-in sink profile.
const BUILTIN_PROFILES: &[(&str, &str, &str)] = &[
    ("linux-command-exec", LINUX_COMMAND_EXEC_PROFILE_YAML, "elf"),
    (
        "shell-command-exec",
        SHELL_COMMAND_EXEC_PROFILE_YAML,
        "shell",
    ),
];

fn builtin_profile_yaml(name: &str) -> Option<&'static str> {
    BUILTIN_PROFILES
        .iter()
        .find(|(builtin, _, _)| *builtin == name)
        .map(|(_, yaml, _)| *yaml)
}

#[derive(Debug, Clone, Args)]
pub struct SinkDiscoveryArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// Scan a rootfs directory of shell scripts instead of an ELF binary.
    /// Requires a shell-target profile (built-in: shell-command-exec).
    #[arg(long, conflicts_with = "file")]
    pub rootfs: Option<PathBuf>,
    #[arg(long)]
    pub profile: Vec<PathBuf>,
    #[arg(long)]
    pub family: Option<String>,
    #[arg(long, default_value = "weak")]
    pub min_confidence: String,
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<SinkDiscoveryCommand>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SinkDiscoveryCommand {
    #[command(about = "Inspect sink discovery profiles.")]
    Profiles {
        #[command(subcommand)]
        command: SinkDiscoveryProfilesCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SinkDiscoveryProfilesCommand {
    #[command(about = "List built-in sink discovery profiles.")]
    List,
    #[command(about = "Show a built-in sink discovery profile.")]
    Show { name: String },
    #[command(about = "Validate a sink discovery profile YAML file.")]
    Validate { path: std::path::PathBuf },
}

pub fn run(args: SinkDiscoveryArgs) -> DynResult<()> {
    match args.command {
        Some(SinkDiscoveryCommand::Profiles { command }) => match command {
            SinkDiscoveryProfilesCommand::List => list_profiles(),
            SinkDiscoveryProfilesCommand::Show { name } => show_profile(&name),
            SinkDiscoveryProfilesCommand::Validate { path } => validate_profile(&path),
        },
        None => {
            if let Some(rootfs) = args.rootfs.as_ref() {
                let report = scan_rootfs_cmd(rootfs, &args.profile, args.family.as_deref())?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", render_shell_report(&report));
                }
                return Ok(());
            }
            let Some(file) = args.file.as_ref() else {
                return Err(
                    "provide a firmware binary with `--file`, or inspect profiles with `fat sink-discovery profiles ...`"
                        .into(),
                );
            };
            let report = scan_file(
                file,
                &args.profile,
                args.family.as_deref(),
                &args.min_confidence,
            )?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render_report(&report));
            }
            Ok(())
        }
    }
}

fn list_profiles() -> DynResult<()> {
    for (name, yaml, fallback_target) in BUILTIN_PROFILES {
        let profile = parse_sink_profile(yaml)?;
        let target = profile.target.as_deref().unwrap_or(fallback_target);
        let description = profile.description.as_deref().unwrap_or("");
        println!("{name}\t{target}\t{description}");
    }
    Ok(())
}

fn show_profile(name: &str) -> DynResult<()> {
    let Some(yaml) = builtin_profile_yaml(name) else {
        let available: Vec<&str> = BUILTIN_PROFILES.iter().map(|(n, _, _)| *n).collect();
        return Err(format!(
            "unknown sink discovery profile '{name}'. Available profiles: {}",
            available.join(", ")
        )
        .into());
    };
    print!("{yaml}");
    if !yaml.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn validate_profile(path: &Path) -> DynResult<()> {
    let yaml = fs::read_to_string(path)?;
    let profile = fat_taint::sink_discovery::parse_sink_profile(&yaml)
        .map_err(|err| format!("invalid sink profile '{}': {err}", path.display()))?;
    println!("valid sink profile: {} ({})", profile.name, path.display());
    Ok(())
}

fn scan_file(
    file: &Path,
    profile_paths: &[PathBuf],
    family_filter: Option<&str>,
    min_confidence_raw: &str,
) -> DynResult<SinkDiscoveryReport> {
    let elf_bytes = fs::read(file)?;
    let elf_report = crate::elf_inspect::parse_elf_bytes(&elf_bytes)?;
    let endianness = crate::elf_addr::endianness_from_header(&elf_report.header);
    let word_size = if elf_report.header.class.contains("64") {
        8
    } else {
        4
    };
    let min_confidence = parse_confidence(min_confidence_raw)?;
    let merged = load_profiles(profile_paths)?;
    let function_index = load_function_index(file, &elf_report);

    let mut candidates = Vec::new();
    let mut families = BTreeMap::new();

    for loaded_family in merged.families {
        let family_name = loaded_family.name;
        if family_filter.is_some_and(|filter| filter != family_name) {
            continue;
        }

        let Some(mut candidate) = discover_family(
            file,
            &elf_bytes,
            &elf_report.header.machine,
            &elf_report.program_headers,
            endianness,
            word_size,
            &function_index,
            &family_name,
            &loaded_family.profile_name,
            &loaded_family.family,
        )?
        else {
            continue;
        };

        if candidate.confidence < min_confidence {
            continue;
        }

        *families.entry(family_name).or_insert(0) += 1;
        candidate.id = format!("sink-{}", candidates.len());
        candidates.push(candidate);
    }

    Ok(SinkDiscoveryReport {
        file: file.display().to_string(),
        binary: BinaryContext {
            format: "ELF".into(),
            arch: elf_report.header.machine.clone(),
            bits: if elf_report.header.class.contains("64") {
                64
            } else {
                32
            },
            endianness: if elf_report.header.endianness.starts_with("little") {
                "little".into()
            } else {
                "big".into()
            },
            class: elf_report.header.class.clone(),
            stripped: Some(true),
        },
        profiles: merged.names,
        summary: SinkDiscoverySummary {
            candidates: candidates.len(),
            families,
        },
        candidates,
    })
}

/// Load and parse profiles from `--profile` paths. Built-in profiles may be
/// referenced by name (`linux-command-exec`, `shell-command-exec`); anything
/// else is treated as a YAML file path. With no arguments the default ELF
/// bundle (linux-command-exec) is loaded.
fn load_profile_yamls(profile_paths: &[PathBuf]) -> Result<Vec<SinkProfile>, String> {
    let mut loaded = Vec::new();
    if profile_paths.is_empty() {
        loaded.push(parse_sink_profile(BUILTIN_PROFILE_YAML)?);
        return Ok(loaded);
    }

    for path in profile_paths {
        let yaml = match path.to_str().and_then(builtin_profile_yaml) {
            Some(builtin) => builtin.to_string(),
            None => fs::read_to_string(path).map_err(|err| {
                format!("failed to read sink profile '{}': {err}", path.display())
            })?,
        };
        let profile = parse_sink_profile(&yaml)
            .map_err(|err| format!("invalid sink profile '{}': {err}", path.display()))?;
        loaded.push(profile);
    }

    Ok(loaded)
}

fn load_profiles(profile_paths: &[PathBuf]) -> Result<LoadedProfiles, String> {
    let mut loaded = LoadedProfiles::default();
    for profile in load_profile_yamls(profile_paths)? {
        loaded.merge(profile);
    }
    Ok(loaded)
}

/// Scan a rootfs of shell scripts with a shell-target sink profile.
fn scan_rootfs_cmd(
    rootfs: &Path,
    profile_paths: &[PathBuf],
    family_filter: Option<&str>,
) -> DynResult<ShellScanReport> {
    let profiles = if profile_paths.is_empty() {
        vec![parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML)?]
    } else {
        load_profile_yamls(profile_paths)?
    };

    let shell_profiles: Vec<&SinkProfile> = profiles
        .iter()
        .filter(|profile| profile.target.as_deref() == Some("shell"))
        .collect();
    if shell_profiles.is_empty() {
        return Err(
            "--rootfs requires a shell-target profile (built-in: shell-command-exec); the loaded profiles only target ELF binaries"
                .into(),
        );
    }

    let mut report = scan_rootfs(rootfs, &shell_profiles)?;
    if let Some(filter) = family_filter {
        report.findings.retain(|finding| finding.family == filter);
        report.summary = summarize_findings(&report);
    }
    Ok(report)
}

fn summarize_findings(report: &ShellScanReport) -> ShellScanSummary {
    let mut families = BTreeMap::new();
    for finding in &report.findings {
        *families.entry(finding.family.clone()).or_insert(0) += 1;
    }
    ShellScanSummary {
        files_scanned: report.summary.files_scanned,
        findings: report.findings.len(),
        families,
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

fn render_shell_report(report: &ShellScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("root: {}\n", report.root));
    out.push_str(&format!("profiles: {}\n", report.profiles.join(", ")));
    out.push_str(&format!(
        "scanned {} script file(s); {} finding(s)\n",
        report.summary.files_scanned, report.summary.findings
    ));
    for finding in &report.findings {
        out.push_str(&format!(
            "  {:<6} {}:{} [{}] {}\n",
            severity_label(finding.severity),
            finding.file,
            finding.line,
            finding.family,
            finding.matched_text
        ));
    }
    out
}

#[derive(Default)]
struct LoadedProfiles {
    names: Vec<String>,
    families: Vec<LoadedFamily>,
}

struct LoadedFamily {
    profile_name: String,
    name: String,
    family: FamilyProfile,
}

impl LoadedProfiles {
    fn merge(&mut self, profile: SinkProfile) {
        let profile_name = profile.name;
        self.names.push(profile_name.clone());
        for (family_name, family) in profile.families {
            self.families.push(LoadedFamily {
                profile_name: profile_name.clone(),
                name: family_name,
                family,
            });
        }
    }
}

fn discover_family(
    _file: &Path,
    elf_bytes: &[u8],
    arch: &str,
    program_headers: &[crate::elf_inspect::ElfProgramHeaderSummary],
    endianness: crate::elf_addr::Endianness,
    word_size: usize,
    function_index: &FunctionIndex,
    family_name: &str,
    profile_name: &str,
    family: &FamilyProfile,
) -> DynResult<Option<SinkCandidate>> {
    let mut evidence = Vec::new();
    let mut providers = BTreeSet::new();
    let mut string_vaddrs = BTreeSet::new();
    let mut attributed_functions = BTreeSet::new();

    for seed in &family.string_seeds {
        let hits = find_seed_hits(elf_bytes, program_headers, seed)?;
        if hits.is_empty() {
            continue;
        }
        providers.insert("string_ref".to_string());
        for (vaddr, value) in hits {
            string_vaddrs.insert(vaddr);
            evidence.push(SinkEvidence::StringRef {
                profile: profile_name.to_string(),
                rule: format!("string_seeds:{}", seed.value),
                value,
                vaddr,
                score_delta: seed.weight,
            });
        }
    }

    if let Some(pointer_xrefs) = &family.pointer_xrefs {
        if pointer_xrefs.enabled {
            let scan_filter = crate::elf_addr::parse_scan_filter(&pointer_xrefs.scan)?;
            let mut seen_hits = BTreeSet::new();
            for &target_vaddr in &string_vaddrs {
                for hit in crate::elf_addr::scan_for_pointer(
                    elf_bytes,
                    target_vaddr,
                    word_size,
                    endianness,
                    program_headers,
                    scan_filter,
                ) {
                    let key = (hit.file_offset, hit.vaddr, hit.target_vaddr);
                    if !seen_hits.insert(key) {
                        continue;
                    }
                    providers.insert("pointer_xref".to_string());
                    evidence.push(SinkEvidence::PointerXref {
                        profile: profile_name.to_string(),
                        rule: "pointer_xrefs".to_string(),
                        pointer_vaddr: hit.vaddr,
                        points_to: hit.target_vaddr,
                        score_delta: pointer_xrefs.weight,
                    });
                }
            }
        }
    }

    if arch.to_ascii_lowercase().contains("mips") {
        if let Some(pattern_weight) = mips_direct_string_load_weight(family) {
            for code_ref in find_mips_direct_string_loads(
                elf_bytes,
                program_headers,
                endianness,
                function_index,
                &string_vaddrs,
                family.dangerous_arg,
            ) {
                providers.insert("mips-direct-string-load".to_string());
                attributed_functions.insert(code_ref.function);
                evidence.push(SinkEvidence::CodeRef {
                    profile: profile_name.to_string(),
                    rule: "mips-direct-string-load".to_string(),
                    function: code_ref.function,
                    score_delta: pattern_weight,
                });
            }
        }
    }

    if evidence.is_empty() {
        return Ok(None);
    }

    let candidate_address = if attributed_functions.len() == 1 {
        attributed_functions.first().copied()
    } else {
        None
    };

    let mut candidate = score_candidate(
        family_name,
        candidate_address,
        providers.into_iter().collect(),
        evidence,
        family.confidence.clone(),
    );

    if attributed_functions.len() > 1 {
        if let Some(candidate) = candidate.as_mut() {
            candidate
                .limitations
                .push("multiple functions matched sink evidence; address not assigned".to_string());
        }
    } else if let Some(address) = candidate_address {
        if let Some(candidate) = candidate.as_mut() {
            candidate.symbolic_name = function_index.name_for_start(address);
        }
    }

    Ok(candidate)
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

    fn name_for_start(&self, start: u64) -> Option<String> {
        self.functions
            .iter()
            .find(|function| function.start == start)
            .and_then(|function| function.name.clone())
    }
}

fn load_function_index(
    file: &Path,
    elf_report: &crate::elf_inspect::ElfInspectReport,
) -> FunctionIndex {
    let mut functions = r2::function_list(file)
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

#[derive(Debug, Clone, Copy)]
struct CodeRef {
    function: u64,
}

fn mips_direct_string_load_weight(family: &FamilyProfile) -> Option<f64> {
    family
        .code_patterns
        .iter()
        .find(|pattern| {
            pattern.id == "mips-direct-string-load"
                && pattern
                    .arch
                    .as_deref()
                    .is_none_or(|arch| arch.eq_ignore_ascii_case("mips"))
        })
        .map(|pattern| pattern.weight)
}

fn find_mips_direct_string_loads(
    elf_bytes: &[u8],
    program_headers: &[crate::elf_inspect::ElfProgramHeaderSummary],
    endianness: crate::elf_addr::Endianness,
    function_index: &FunctionIndex,
    string_vaddrs: &BTreeSet<u64>,
    dangerous_arg: u8,
) -> Vec<CodeRef> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();
    let required_register = mips_argument_register(dangerous_arg);

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
            let Some(second) = read_u32(region, offset + 4, endianness) else {
                break;
            };
            let Some((register, target)) = decode_mips_direct_load(first, second) else {
                offset += 4;
                continue;
            };
            if required_register.is_some_and(|required| register != required) {
                offset += 4;
                continue;
            }
            if !string_vaddrs.contains(&target) {
                offset += 4;
                continue;
            }
            let instruction_vaddr = segment.virtual_address + offset as u64;
            let Some(function) = function_index.containing(instruction_vaddr) else {
                offset += 4;
                continue;
            };
            let key = (function.start, target);
            if seen.insert(key) {
                refs.push(CodeRef {
                    function: function.start,
                });
            }
            offset += 4;
        }
    }

    refs
}

fn mips_argument_register(dangerous_arg: u8) -> Option<u32> {
    if dangerous_arg <= 3 {
        Some(4 + u32::from(dangerous_arg))
    } else {
        None
    }
}

fn decode_mips_direct_load(lui: u32, second: u32) -> Option<(u32, u64)> {
    let lui_opcode = (lui >> 26) & 0x3f;
    if lui_opcode != 0x0f {
        return None;
    }
    let rt = (lui >> 16) & 0x1f;
    if rt == 0 {
        return None;
    }

    let second_opcode = (second >> 26) & 0x3f;
    let second_rs = (second >> 21) & 0x1f;
    let second_rt = (second >> 16) & 0x1f;
    if second_rs != rt || second_rt != rt {
        return None;
    }

    let high = (lui & 0xffff) << 16;
    let low = second & 0xffff;
    let target = match second_opcode {
        0x0d => (high | low) as u64, // ori rt, rt, imm
        0x09 => high.wrapping_add((low as i16 as i32) as u32) as u64, // addiu rt, rt, imm
        _ => return None,
    };
    Some((rt, target))
}

fn read_u32(bytes: &[u8], offset: usize, endianness: crate::elf_addr::Endianness) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endianness {
        crate::elf_addr::Endianness::Little => u32::from_le_bytes(raw),
        crate::elf_addr::Endianness::Big => u32::from_be_bytes(raw),
    })
}

fn find_seed_hits(
    elf_bytes: &[u8],
    program_headers: &[crate::elf_inspect::ElfProgramHeaderSummary],
    seed: &StringSeed,
) -> DynResult<Vec<(u64, String)>> {
    let needle = seed.value.as_bytes();
    if needle.is_empty() {
        return Ok(Vec::new());
    }

    let mut hits = Vec::new();
    for segment in program_headers
        .iter()
        .filter(|segment| segment.segment_type == "LOAD")
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
        let mut pos = 0usize;
        while pos <= region.len().saturating_sub(needle.len()) {
            let Some(found) = find_bytes(region, needle, pos) else {
                break;
            };
            let file_offset = segment.offset + found as u64;
            if let Some(vaddr) = crate::elf_addr::file_offset_to_vaddr(file_offset, program_headers)
            {
                if let Some(value) = read_c_string_in_region(region, found) {
                    hits.push((vaddr, value));
                }
            }
            pos = found + 1;
        }
    }

    Ok(hits)
}

fn parse_confidence(raw: &str) -> Result<Confidence, String> {
    match raw {
        "weak" => Ok(Confidence::Weak),
        "probable" => Ok(Confidence::Probable),
        "strong" => Ok(Confidence::Strong),
        "confirmed" => Ok(Confidence::Confirmed),
        other => Err(format!(
            "invalid confidence '{other}'; expected weak, probable, strong, or confirmed"
        )),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|idx| start + idx)
}

fn read_c_string_in_region(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn render_report(report: &SinkDiscoveryReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("sink-discovery: {}\n\n", report.file));
    if report.candidates.is_empty() {
        out.push_str("no sink candidates found\n");
        return out;
    }

    for candidate in &report.candidates {
        out.push_str(&format!(
            "{}: {:?} score {:.2} evidence {}\n",
            candidate.id,
            candidate.confidence,
            candidate.score,
            candidate.evidence.len()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_family_keeps_ambiguous_code_refs_addressless() {
        let mut elf_bytes = vec![0u8; 0x300];
        elf_bytes[0x000..0x004].copy_from_slice(&0x3c04_004fu32.to_le_bytes());
        elf_bytes[0x004..0x008].copy_from_slice(&0x2484_0000u32.to_le_bytes());
        elf_bytes[0x040..0x044].copy_from_slice(&0x3c04_004fu32.to_le_bytes());
        elf_bytes[0x044..0x048].copy_from_slice(&0x2484_0000u32.to_le_bytes());
        elf_bytes[0x200..0x208].copy_from_slice(b"/bin/sh\0");

        let segments = vec![
            synthetic_load_segment(0x000, 0x0040_0100, 0x100, "XR"),
            synthetic_load_segment(0x200, 0x004f_0000, 0x40, "WR"),
        ];
        let function_index = FunctionIndex {
            functions: vec![
                FunctionRange {
                    name: Some("candidate_a".to_string()),
                    start: 0x0040_0100,
                    end: 0x0040_0120,
                },
                FunctionRange {
                    name: Some("candidate_b".to_string()),
                    start: 0x0040_0140,
                    end: 0x0040_0160,
                },
            ],
        };
        let family = fat_taint::sink_discovery::FamilyProfile {
            dangerous_arg: 0,
            pattern: None,
            severity: None,
            note: None,
            string_seeds: vec![fat_taint::sink_discovery::StringSeed {
                value: "/bin/sh".to_string(),
                weight: 0.35,
                tags: Vec::new(),
            }],
            pointer_xrefs: None,
            code_patterns: vec![fat_taint::sink_discovery::CodePatternRule {
                id: "mips-direct-string-load".to_string(),
                arch: Some("mips".to_string()),
                weight: 0.20,
            }],
            wrapper_names: Vec::new(),
            confidence: Some(fat_taint::sink_discovery::ConfidenceThresholds {
                weak: 0.25,
                probable: 0.55,
                strong: 0.80,
                confirmed: None,
            }),
        };

        let candidate = discover_family(
            Path::new("fixture"),
            &elf_bytes,
            "mips",
            &segments,
            crate::elf_addr::Endianness::Little,
            4,
            &function_index,
            "command-exec",
            "test-profile",
            &family,
        )
        .expect("discovery runs")
        .expect("candidate");

        assert_eq!(candidate.confidence, Confidence::Probable);
        assert_eq!(candidate.address, None);
        assert!(
            candidate
                .evidence
                .iter()
                .filter(|evidence| matches!(evidence, SinkEvidence::CodeRef { .. }))
                .count()
                >= 2
        );
        assert!(candidate
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("multiple functions matched sink evidence") }));
    }

    #[test]
    fn builtin_shell_profile_resolves_by_name() {
        let profiles = load_profile_yamls(&[PathBuf::from("shell-command-exec")]).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "shell-command-exec");
        assert_eq!(profiles[0].target.as_deref(), Some("shell"));
    }

    #[test]
    fn builtin_elf_profile_resolves_by_name() {
        let profiles = load_profile_yamls(&[PathBuf::from("linux-command-exec")]).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "linux-command-exec");
        assert_eq!(profiles[0].target, None);
    }

    #[test]
    fn shell_scan_cmd_reports_finding_lines() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("stage.sh"),
            "#!/bin/sh\ncp /tmp/updater /tmp/run.sh\nsh /tmp/run.sh\n",
        )
        .unwrap();

        let report = scan_rootfs_cmd(dir.path(), &[PathBuf::from("shell-command-exec")], None)
            .expect("rootfs scan runs");

        assert_eq!(report.summary.files_scanned, 1);
        let staged = report
            .findings
            .iter()
            .find(|f| f.family == "tmpfs-staged-exec")
            .expect("tmpfs-staged-exec finding");
        assert_eq!(staged.line, 3);
        assert_eq!(staged.severity, Severity::High);
    }

    #[test]
    fn shell_scan_cmd_requires_shell_target_profile() {
        let dir = tempfile::tempdir().unwrap();
        let err = scan_rootfs_cmd(dir.path(), &[PathBuf::from("linux-command-exec")], None)
            .expect_err("non-shell profile must be rejected");
        assert!(err.to_string().contains("requires a shell-target profile"));
    }

    fn synthetic_load_segment(
        offset: u64,
        vaddr: u64,
        file_size: u64,
        flags: &str,
    ) -> crate::elf_inspect::ElfProgramHeaderSummary {
        crate::elf_inspect::ElfProgramHeaderSummary {
            segment_type: "LOAD".to_string(),
            offset,
            virtual_address: vaddr,
            file_size,
            memory_size: file_size,
            flags: flags.to_string(),
            align: 0x1000,
        }
    }
}
