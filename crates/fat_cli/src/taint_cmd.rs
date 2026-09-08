use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;
use std::process::Command;

use crate::runtime_augment::{self, RuntimeAugmentationReport};
use crate::trace_ingest_cmd;
use fat_core::finding::FindingSeverity;
use fat_taint::proof::angr;
use fat_taint::sink_discovery::{
    Confidence as SinkConfidence, SinkCandidate as SinkDiscoveryCandidate, SinkDiscoveryReport,
};
use fat_taint::{EdgeType, TaintFinding};

use regex::Regex;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// Maximum number of decompiled lines to display per function.
const MAX_DECOMPILE_LINES: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawBlobKind {
    GenericRawBlob,
    PackedOrEncrypted,
    LikelyUnsupportedMcuFamily,
}

/// Entry point for `fat taint`.
///
/// `--lang shell` routes to the tree-sitter-bash source-to-sink pass in
/// `fat_taint::shell_taint`; everything else is the angr binary engine.
#[allow(clippy::too_many_arguments)]
pub fn run(
    file: Option<&Path>,
    lang: Option<&str>,
    rootfs: Option<&Path>,
    arch: Option<&str>,
    base: Option<&str>,
    severity_filter: Option<&str>,
    summary: bool,
    json: bool,
    decompile: bool,
    no_cache: bool,
    augment: Option<&Path>,
    marker: Option<&str>,
    sink_candidates: Option<&Path>,
    source_profile: Option<&Path>,
) -> DynResult<()> {
    match lang.map(str::to_ascii_lowercase).as_deref() {
        Some("shell") => {
            reject_binary_only_flags(arch, base, decompile, augment, marker, sink_candidates)
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            return run_shell(file, rootfs, severity_filter, summary, json, source_profile);
        }
        Some(other) => {
            return Err(format!("unknown --lang '{other}'; supported languages: shell").into());
        }
        None => {}
    }

    if rootfs.is_some() {
        return Err(
            "--rootfs is only supported with --lang shell; binary taint takes --file".into(),
        );
    }
    let file = file.ok_or_else(|| -> Box<dyn Error> {
        "taint requires --file <binary>, or --lang shell with --file/--rootfs".into()
    })?;

    run_binary(
        file,
        arch,
        base,
        severity_filter,
        summary,
        json,
        decompile,
        no_cache,
        augment,
        marker,
        sink_candidates,
        source_profile,
    )
}

/// Flags that only mean something for the angr binary engine.
fn reject_binary_only_flags(
    arch: Option<&str>,
    base: Option<&str>,
    decompile: bool,
    augment: Option<&Path>,
    marker: Option<&str>,
    sink_candidates: Option<&Path>,
) -> Result<(), String> {
    let unsupported = [
        ("--arch", arch.is_some()),
        ("--base", base.is_some()),
        ("--decompile", decompile),
        ("--augment", augment.is_some()),
        ("--marker", marker.is_some()),
        ("--sink-candidates", sink_candidates.is_some()),
    ];
    for (flag, present) in unsupported {
        if present {
            return Err(format!(
                "{flag} applies to binary taint only and is not supported with --lang shell"
            ));
        }
    }
    Ok(())
}

/// `fat taint --lang shell` — tree-sitter-bash source-to-sink over scripts.
///
/// Findings are emitted in the same [`TaintFinding`] shape as the binary
/// engine, so anything that already deserializes `fat taint --json` output
/// reads them unchanged.
fn run_shell(
    file: Option<&Path>,
    rootfs: Option<&Path>,
    severity_filter: Option<&str>,
    summary: bool,
    json: bool,
    source_profile: Option<&Path>,
) -> DynResult<()> {
    let err_palette = crate::style::Palette::stderr();

    let profile = fat_taint::shell_profile::load_shell_profile(source_profile)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let sinks = fat_taint::shell_profile::load_shell_sink_profiles(&profile)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let flows = match (file, rootfs) {
        (Some(_), Some(_)) => {
            return Err("--lang shell takes either --file or --rootfs, not both".into());
        }
        (None, None) => {
            return Err("--lang shell requires --file <script> or --rootfs <dir>".into());
        }
        (Some(path), None) => {
            if !path.is_file() {
                return Err(format!("file not found: {}", path.display()).into());
            }
            let bytes = fs::read(path)?;
            if is_elf_binary(&bytes) {
                return Err(format!(
                    "{} is an ELF binary; drop --lang shell to run the binary taint engine",
                    path.display()
                )
                .into());
            }
            let display = path.display().to_string();
            eprintln!(
                "{} {} {}",
                err_palette.heading("Analyzing shell script:"),
                err_palette.info(&display),
                err_palette.muted(format!("(profile {})", profile.name)),
            );
            let text = String::from_utf8_lossy(&bytes);
            fat_taint::shell_taint::analyze_script(&display, &text, &profile, &sinks)
                .map_err(|e| -> Box<dyn Error> { e.into() })?
        }
        (None, Some(root)) => {
            if !root.is_dir() {
                return Err(format!("rootfs directory not found: {}", root.display()).into());
            }
            eprintln!(
                "{} {} {}",
                err_palette.heading("Analyzing shell scripts under:"),
                err_palette.info(root.display().to_string()),
                err_palette.muted(format!("(profile {})", profile.name)),
            );
            let report = fat_taint::shell_taint::analyze_rootfs(root, &profile, &sinks)
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            eprintln!(
                "{}",
                err_palette.muted(format!(
                    "  {} script(s) scanned, {} with taint flows",
                    report.summary.files_scanned, report.summary.scripts_with_flows
                ))
            );
            report.flows
        }
    };

    let all_findings = fat_taint::shell_taint::flows_to_findings(&flows);
    emit_findings(
        &all_findings,
        severity_filter,
        summary,
        json,
        "No shell taint findings. Shell taint reports only source-to-sink flows; \
         run `fat sink-discovery --rootfs` for sink hits without provenance.",
    )
}

/// Filter by severity and render, shared by every taint output mode that does
/// not need decompilation or runtime augmentation.
fn emit_findings(
    all_findings: &[TaintFinding],
    severity_filter: Option<&str>,
    summary: bool,
    json: bool,
    empty_hint: &str,
) -> DynResult<()> {
    let out_palette = crate::style::Palette::stdout();
    let err_palette = crate::style::Palette::stderr();
    let min_severity = parse_severity_filter(severity_filter)?;
    let findings: Vec<&TaintFinding> = all_findings
        .iter()
        .filter(|f| severity_rank(&f.severity) >= severity_rank(&min_severity))
        .collect();

    if all_findings.is_empty() {
        if json {
            println!("[]");
        }
        eprintln!("{}", err_palette.warn(empty_hint));
        return Ok(());
    }
    if findings.is_empty() {
        if json {
            println!("[]");
        }
        eprintln!(
            "{} {} finding(s) total, 0 at {:?} or above.",
            err_palette.warn("Filtered:"),
            all_findings.len(),
            min_severity
        );
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if summary {
        render_summary(&findings, all_findings, &out_palette);
    } else {
        render_findings(&findings, all_findings, &HashMap::new(), &out_palette);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_binary(
    file: &Path,
    arch: Option<&str>,
    base: Option<&str>,
    severity_filter: Option<&str>,
    summary: bool,
    json: bool,
    decompile: bool,
    no_cache: bool,
    augment: Option<&Path>,
    marker: Option<&str>,
    sink_candidates: Option<&Path>,
    source_profile: Option<&Path>,
) -> DynResult<()> {
    let out_palette = crate::style::Palette::stdout();
    let err_palette = crate::style::Palette::stderr();
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    // Validate the selected profile before analysis runs, so an unreadable or
    // malformed profile fails here rather than part-way through a run. With no
    // profile selected the core models are used and nothing else is loaded.
    let selected_profile = source_profile
        .map(fat_taint::profile::ExternalTaintProfile::load)
        .transpose()
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let provenance = selected_profile
        .as_ref()
        .map(|profile| profile.provenance().clone())
        .unwrap_or(fat_taint::profile::CatalogProvenance::Core);
    eprintln!("  taint models: {}", provenance.label());

    let sink_candidate_content = if let Some(path) = sink_candidates {
        Some(fs::read_to_string(path)?)
    } else {
        None
    };
    let sink_candidate_extensions = if let Some(content) = sink_candidate_content.as_deref() {
        let extensions = load_sink_candidates(content)?;
        if extensions.is_empty() {
            eprintln!(
                "sink discovery candidates loaded from {} but none were eligible for taint metadata",
                sink_candidates.expect("path checked").display()
            );
        } else {
            eprintln!(
                "loaded {} sink discovery candidate(s) from {}; passing address-backed sinks into angr proof execution",
                extensions.len(),
                sink_candidates.expect("path checked").display()
            );
        }
        extensions
    } else {
        Vec::new()
    };

    validate_raw_blob_inputs(file, arch, base).map_err(|e| -> Box<dyn Error> { e.into() })?;

    let is_baremetal = arch.is_some();

    if is_baremetal {
        eprintln!(
            "{} {} (arch={}, base={})",
            err_palette.heading("Analyzing bare-metal firmware:"),
            err_palette.info(file.display().to_string()),
            arch.unwrap_or("auto"),
            base.unwrap_or("auto"),
        );
    } else {
        eprintln!(
            "{} {}",
            err_palette.heading("Analyzing ELF binary:"),
            err_palette.info(file.display().to_string())
        );
    }

    // Include the exact selected bytes and their provenance. A changed profile
    // must not reuse old findings or retain another path's attribution.
    let profiles = angr::embedded_profile_contents();
    let sink_candidate_cache_fragment = if sink_candidate_extensions.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&sink_candidate_extensions)?)
    };
    let mut profile_refs: Vec<&str> = profiles.to_vec();
    let provenance_cache_fragment = serde_json::to_string(&provenance)?;
    profile_refs.push(&provenance_cache_fragment);
    if let Some(selected) = selected_profile.as_ref() {
        profile_refs.push(selected.contents());
    }
    if let Some(fragment) = sink_candidate_cache_fragment.as_deref() {
        profile_refs.push(fragment);
    }
    let cache_key = fat_taint::cache::compute_cache_key(file, &profile_refs);
    let cache_dir = fat_taint::cache::cache_dir();
    let mut from_cache = false;

    // Try cache first (unless --no-cache)
    let all_findings: Vec<TaintFinding> = if !no_cache {
        if let Some(cached_json) = fat_taint::cache::load_from(&cache_dir, &cache_key) {
            from_cache = true;
            serde_json::from_str(&cached_json).map_err(|e| -> Box<dyn Error> {
                format!("corrupt cache ({cache_key}), re-run with --no-cache: {e}").into()
            })?
        } else {
            run_and_cache(
                file,
                arch,
                base,
                eligible_sink_candidates_path(sink_candidates, &sink_candidate_extensions),
                selected_profile.as_ref(),
                &cache_dir,
                &cache_key,
            )?
        }
    } else {
        run_and_cache(
            file,
            arch,
            base,
            eligible_sink_candidates_path(sink_candidates, &sink_candidate_extensions),
            selected_profile.as_ref(),
            &cache_dir,
            &cache_key,
        )?
    };

    // Apply severity filter
    let min_severity = parse_severity_filter(severity_filter)?;
    let findings: Vec<&TaintFinding> = all_findings
        .iter()
        .filter(|f| severity_rank(&f.severity) >= severity_rank(&min_severity))
        .collect();

    if all_findings.is_empty() {
        if is_baremetal {
            eprintln!(
                "{}",
                err_palette.warn(
                    "No taint findings. Consider adding target-specific source/sink definitions."
                )
            );
        } else {
            eprintln!("{}", err_palette.warn("No taint findings."));
        }
        return Ok(());
    }

    if findings.is_empty() {
        eprintln!(
            "{} {} finding(s) total, 0 at {:?} or above.",
            err_palette.warn("Filtered:"),
            all_findings.len(),
            min_severity
        );
        return Ok(());
    }

    if let Some(trace_path) = augment {
        let selected_findings = findings
            .iter()
            .map(|finding| (*finding).clone())
            .collect::<Vec<_>>();
        let report = augment_findings_with_trace(&selected_findings, trace_path, marker)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print!(
                "{}",
                runtime_augment::render_runtime_augmentation_summary(&report)
            );
        }
        return Ok(());
    }

    // Decompile functions if requested (only for non-JSON, non-summary output)
    let decomp_map = if decompile && !json && !summary {
        let targets = collect_decompile_targets(&findings);
        if targets.is_empty() {
            HashMap::new()
        } else {
            decompile_functions(file, &targets)
        }
    } else {
        HashMap::new()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if summary {
        render_summary(&findings, &all_findings, &out_palette);
    } else {
        render_findings(&findings, &all_findings, &decomp_map, &out_palette);
    }

    // Display cache status
    if from_cache {
        if let Some(age) = fat_taint::cache::cache_age_in(&cache_dir, &cache_key) {
            let secs = age.as_secs();
            let age_str = if secs < 60 {
                format!("{secs}s ago")
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else {
                format!("{}h ago", secs / 3600)
            };
            eprintln!("{}", err_palette.muted(format!("(cached — {age_str})")));
        } else {
            eprintln!("{}", err_palette.muted("(cached)"));
        }
    }

    Ok(())
}

fn augment_findings_with_trace(
    findings: &[TaintFinding],
    trace_path: &Path,
    marker: Option<&str>,
) -> DynResult<RuntimeAugmentationReport> {
    let report = trace_ingest_cmd::load_trace_report(trace_path)?;
    Ok(runtime_augment::augment_findings(findings, &report, marker))
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SinkCandidateExtension {
    pub profile: String,
    pub family_key: String,
    pub address: Option<u64>,
    pub symbolic_name: Option<String>,
    pub confidence: SinkConfidence,
    pub evidence: Vec<fat_taint::sink_discovery::SinkEvidence>,
    pub limitations: Vec<String>,
}

pub(crate) fn load_sink_candidates(content: &str) -> DynResult<Vec<SinkCandidateExtension>> {
    let report: SinkDiscoveryReport = serde_json::from_str(content)?;
    let profile = report
        .profiles
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    Ok(report
        .candidates
        .into_iter()
        .filter_map(|candidate| candidate_to_extension(&profile, candidate))
        .collect())
}

fn candidate_to_extension(
    profile: &str,
    candidate: SinkDiscoveryCandidate,
) -> Option<SinkCandidateExtension> {
    if candidate.confidence < SinkConfidence::Probable {
        return None;
    }

    let address = candidate.address?;

    Some(SinkCandidateExtension {
        profile: profile.to_string(),
        family_key: candidate.family_key,
        address: Some(address),
        symbolic_name: candidate.symbolic_name,
        confidence: candidate.confidence,
        evidence: candidate.evidence,
        limitations: candidate.limitations,
    })
}

fn eligible_sink_candidates_path<'a>(
    sink_candidates: Option<&'a Path>,
    extensions: &[SinkCandidateExtension],
) -> Option<&'a Path> {
    if extensions.is_empty() {
        None
    } else {
        sink_candidates
    }
}

fn validate_raw_blob_inputs(
    file: &Path,
    arch: Option<&str>,
    base: Option<&str>,
) -> Result<(), String> {
    let bytes = fs::read(file).map_err(|e| format!("failed to read {}: {}", file.display(), e))?;
    if is_elf_binary(&bytes) {
        return Ok(());
    }

    // Route obvious non-firmware inputs to the right command before falling into
    // raw-blob/MCU classification (which otherwise hands out a misleading
    // "try --arch cortex-m" hint for shell scripts, filesystems, and archives).
    if let Some(hint) = non_elf_routing_hint(&bytes) {
        return Err(hint);
    }

    match arch.map(|value| value.to_ascii_lowercase()) {
        None => match classify_raw_blob(&bytes) {
            RawBlobKind::PackedOrEncrypted => Err(
                "raw blob appears packed, encrypted, or vendor-container wrapped; extract or unwrap it before taint analysis".into(),
            ),
            RawBlobKind::LikelyUnsupportedMcuFamily => Err(
                "raw blob looks like an unsupported MCU family image (possibly 8051-class or banked firmware); taint is not available for this family yet".into(),
            ),
            RawBlobKind::GenericRawBlob => Err(
                "raw blob detected; rerun with --arch and --base. If this is Cortex-M firmware, try --arch cortex-m --base 0x08000000".into(),
            ),
        },
        Some(arch_name) if arch_name == "cortex-m" => {
            let base_addr = parse_base_address(base)
                .ok_or_else(|| "cortex-m raw blobs require --base (for example 0x08000000)".to_string())?;
            if looks_like_cortex_m_blob(&bytes, base_addr) {
                Ok(())
            } else if classify_raw_blob(&bytes) == RawBlobKind::PackedOrEncrypted {
                Err("raw blob appears packed, encrypted, or vendor-container wrapped; it does not look like a plain Cortex-M image".into())
            } else {
                Err("raw blob does not look like a valid Cortex-M image at the supplied base; stack pointer/reset vector are not plausible".into())
            }
        }
        Some(_) => Ok(()),
    }
}

fn is_elf_binary(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"\x7fELF"
}

/// If `bytes` is an obvious non-firmware input (a shell script, or an
/// archive/filesystem container), return a hint routing the user to the command
/// that actually handles it, instead of the raw-blob/MCU classifier.
fn non_elf_routing_hint(bytes: &[u8]) -> Option<String> {
    // Shell script: shebang naming a shell.
    if bytes.starts_with(b"#!") {
        let first_line = bytes
            .split(|&b| b == b'\n')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if [b"sh".as_slice(), b"bash", b"dash", b"ash", b"zsh", b"ksh"]
            .iter()
            .any(|shell| first_line.windows(shell.len()).any(|w| w == *shell))
        {
            return Some(
                "input is a shell script, not an ELF binary; rerun with `--lang shell` \
                 for source-to-sink shell taint, or search it with `fat search`"
                    .into(),
            );
        }
    }

    // Archive / filesystem container: extract it first, then taint the carved
    // ELF binaries.
    let container = detect_container_format(bytes)?;
    Some(format!(
        "input looks like a {container} archive/filesystem, not an ELF binary; \
         extract it first with `fat extract`, then run taint on the carved binaries"
    ))
}

/// Detect a common archive/filesystem container by magic bytes.
fn detect_container_format(bytes: &[u8]) -> Option<&'static str> {
    let starts = |magic: &[u8]| bytes.starts_with(magic);
    if starts(b"hsqs") || starts(b"sqsh") {
        Some("squashfs")
    } else if starts(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if starts(b"BZh") {
        Some("bzip2")
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if starts(b"PK\x03\x04") {
        Some("zip")
    } else if starts(b"070701") || starts(b"070707") || starts(&[0xc7, 0x71]) {
        Some("cpio")
    } else if starts(&[0x45, 0x3d, 0xcd, 0x28]) || starts(&[0x28, 0xcd, 0x3d, 0x45]) {
        Some("cramfs")
    } else if starts(&[0x85, 0x19]) || starts(&[0x19, 0x85]) {
        Some("jffs2")
    } else if starts(b"UBI#") || starts(b"UBI!") {
        Some("ubi")
    } else if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        Some("tar")
    } else {
        None
    }
}

fn parse_base_address(base: Option<&str>) -> Option<u32> {
    let value = base?;
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn looks_like_cortex_m_blob(bytes: &[u8], base_addr: u32) -> bool {
    if bytes.len() < 8 {
        return false;
    }

    let initial_sp = u32::from_le_bytes(bytes[0..4].try_into().expect("sp"));
    let reset_vector = u32::from_le_bytes(bytes[4..8].try_into().expect("rv"));

    let sp_plausible = (0x2000_0000..=0x3fff_ffff).contains(&initial_sp);
    let rv_plausible = (reset_vector & 1) == 1;
    let reset_addr = reset_vector & !1;
    let code_window_end = base_addr
        .saturating_add(bytes.len() as u32)
        .saturating_add(0x1000);
    let reset_in_range = (base_addr..=code_window_end).contains(&reset_addr);

    sp_plausible && rv_plausible && reset_in_range
}

fn classify_raw_blob(bytes: &[u8]) -> RawBlobKind {
    let entropy = shannon_entropy(bytes);
    if bytes.len() >= 1024 && entropy >= 7.8 {
        return RawBlobKind::PackedOrEncrypted;
    }

    let prefix_len = bytes.len().min(256);
    let zero_prefix = bytes[..prefix_len].iter().filter(|&&b| b == 0).count();
    let has_embedded_asset_marker = bytes.windows(6).any(|w| w == b"GIF89a" || w == b"GIF87a")
        || bytes.windows(2).any(|w| w == [0xff, 0xd8]);
    if bytes.len() >= 1024
        && prefix_len > 0
        && zero_prefix * 100 / prefix_len >= 75
        && has_embedded_asset_marker
    {
        return RawBlobKind::LikelyUnsupportedMcuFamily;
    }

    RawBlobKind::GenericRawBlob
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Run angr analysis and save the results to cache.
/// Cache write failures are silently ignored (cache is best-effort).
fn run_and_cache(
    file: &Path,
    arch: Option<&str>,
    base: Option<&str>,
    sink_candidates: Option<&Path>,
    source_profile: Option<&fat_taint::profile::ExternalTaintProfile>,
    cache_dir: &Path,
    cache_key: &str,
) -> DynResult<Vec<TaintFinding>> {
    let findings =
        angr::analyze_binary_with_profile(file, arch, base, sink_candidates, source_profile)
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
    // Save to cache (silently ignore failures)
    if let Ok(json) = serde_json::to_string(&findings) {
        let _ = fat_taint::cache::save_to(cache_dir, cache_key, &json);
    }
    Ok(findings)
}

fn parse_severity_filter(filter: Option<&str>) -> DynResult<FindingSeverity> {
    match filter {
        None => Ok(FindingSeverity::Info),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "critical" | "crit" => Ok(FindingSeverity::Critical),
            "high" => Ok(FindingSeverity::High),
            "medium" | "med" => Ok(FindingSeverity::Medium),
            "low" => Ok(FindingSeverity::Low),
            "info" => Ok(FindingSeverity::Info),
            _ => Err(
                format!("unknown severity: '{s}' (use: critical, high, medium, low, info)").into(),
            ),
        },
    }
}

fn severity_rank(s: &FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 5,
        FindingSeverity::High => 4,
        FindingSeverity::Medium => 3,
        FindingSeverity::Low => 2,
        FindingSeverity::Info => 1,
    }
}

fn render_summary(
    findings: &[&TaintFinding],
    all: &[TaintFinding],
    palette: &crate::style::Palette,
) {
    let total = all.len();
    let shown = findings.len();

    println!("{}", palette.heading("Taint Analysis"));
    println!(
        "{}",
        palette.kv(
            "summary",
            format!("{total} finding(s) total, {shown} shown")
        )
    );
    println!();

    for finding in findings {
        let sev = palette.severity_tag(&finding.severity);
        let source = finding
            .chain
            .first()
            .map(|s| s.action.as_str())
            .unwrap_or("?");
        let sink = finding
            .chain
            .last()
            .map(|s| s.action.as_str())
            .unwrap_or("?");
        let func = finding
            .chain
            .first()
            .map(|s| s.function.as_str())
            .unwrap_or("?");
        println!(
            "  [{}] {} {} -> {}  in {}",
            sev,
            palette.accent(&finding.id),
            source,
            sink,
            palette.info(func)
        );
    }
    println!();
}

fn render_findings(
    findings: &[&TaintFinding],
    all: &[TaintFinding],
    decomp_map: &HashMap<String, String>,
    palette: &crate::style::Palette,
) {
    let total = all.len();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, FindingSeverity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, FindingSeverity::Medium))
        .count();
    let low = findings
        .iter()
        .filter(|f| matches!(f.severity, FindingSeverity::Low))
        .count();

    if findings.len() < total {
        println!("{}", palette.heading("Taint Analysis"));
        println!(
            "{}",
            palette.kv(
                "summary",
                format!(
                    "{} finding(s) total, {} shown (filtered) [high={}, medium={}, low={}]",
                    total,
                    findings.len(),
                    high,
                    medium,
                    low
                )
            )
        );
        println!();
    } else {
        println!("{}", palette.heading("Taint Analysis"));
        println!(
            "{}",
            palette.kv(
                "summary",
                format!(
                    "{} finding(s) [high={}, medium={}, low={}]",
                    findings.len(),
                    high,
                    medium,
                    low
                )
            )
        );
        println!();
    }

    for finding in findings {
        let sev = palette.severity_tag(&finding.severity);

        let status_tag = match finding.status {
            fat_taint::FindingStatus::Proven => "proven",
            fat_taint::FindingStatus::Attested => "attested",
            fat_taint::FindingStatus::Candidate => "candidate",
            fat_taint::FindingStatus::DynamicallyConfirmed => "confirmed",
            fat_taint::FindingStatus::Rejected => "rejected",
        };

        let source_tag = match finding.source_class {
            fat_taint::SourceClass::Primary => "direct input",
            fat_taint::SourceClass::Secondary => "persisted state",
        };

        let styled_status = palette.status_word(status_tag);
        println!(
            "[{}] [{}] [{}] {} ({}, score={:.2}, {:.0}% confidence)",
            sev,
            palette.accent(&finding.id),
            finding.strength_band(),
            finding.title,
            styled_status,
            finding.confidence,
            finding.confidence * 100.0,
        );
        println!(
            "  {} {}",
            palette.key("Source class:"),
            palette.info(source_tag)
        );
        println!(
            "  {} {}",
            palette.key("Method:"),
            palette.info(&finding.status_reason)
        );

        if !finding.chain.is_empty() {
            println!("  {}", palette.heading("Chain"));
            for step in &finding.chain {
                // Surface the step location (address/offset) when known, matching
                // the byte-offset context `fat search` prints.
                let location = if step.location.is_empty() {
                    String::new()
                } else {
                    format!(" {}", palette.muted(format!("@ {}", step.location)))
                };
                println!(
                    "    {} [{}] {} in {}{}",
                    palette.bullet("->"),
                    palette.code(format_edge_type(&step.edge_type)),
                    step.action,
                    palette.info(&step.function),
                    location,
                );
            }
        }

        // Print decompiled source context if available
        if !decomp_map.is_empty() {
            // Determine source and sink actions from the chain
            let source_action = finding
                .chain
                .first()
                .map(|s| s.action.as_str())
                .unwrap_or("");
            let sink_action = finding
                .chain
                .last()
                .map(|s| s.action.as_str())
                .unwrap_or("");

            // Collect unique functions in this finding's chain
            let mut printed_funcs = std::collections::HashSet::new();
            for step in &finding.chain {
                if printed_funcs.contains(&step.function) {
                    continue;
                }
                printed_funcs.insert(&step.function);

                if let Some(raw_source) = decomp_map.get(&step.function) {
                    let annotated = annotate_decompilation(raw_source, source_action, sink_action);
                    let truncated = truncate_decompilation(&annotated, MAX_DECOMPILE_LINES);
                    println!(
                        "  {} {} ({})",
                        palette.key("Decompiled:"),
                        palette.info(&step.function),
                        step.location
                    );
                    println!("  {}", palette.muted("-".repeat(60)));
                    for line in truncated.lines() {
                        println!("    {line}");
                    }
                    println!("  {}", palette.muted("-".repeat(60)));
                }
            }
        }

        println!();
    }
}

fn format_edge_type(edge: &EdgeType) -> &'static str {
    match edge {
        EdgeType::DirectFlow => "direct",
        EdgeType::SymbolResolution { .. } => "symbol",
        EdgeType::ConfigKeyBridge { .. } => "config",
        EdgeType::ShellModel { .. } => "shell",
        EdgeType::SemanticSummary { .. } => "semantic",
    }
}

// ---------------------------------------------------------------------------
// Decompilation support (r2ghidra)
// ---------------------------------------------------------------------------

/// Strip ANSI escape codes from r2 output.
fn strip_ansi(s: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(s, "").to_string()
}

/// A function to decompile, identified by name and address.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct DecompileTarget {
    name: String,
    addr: String,
}

/// Build an r2 script that analyses the binary once, then decompiles each
/// target function, separated by marker lines.
fn build_r2_script(targets: &[DecompileTarget]) -> String {
    let mut script = String::from("aaa\n");
    for t in targets {
        writeln!(script, "echo ===FAT_FUNC:{}===", t.name).unwrap();
        writeln!(script, "s {}", t.addr).unwrap();
        script.push_str("pdg\n");
    }
    script
}

/// Parse the output of the r2 script into a map from function name to
/// decompiled C source.
fn parse_r2_output(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let marker_re = Regex::new(r"===FAT_FUNC:([^=]+)===").unwrap();
    let cleaned = strip_ansi(output);
    let mut current_name: Option<String> = None;
    let mut current_lines: Vec<&str> = Vec::new();

    for line in cleaned.lines() {
        if let Some(caps) = marker_re.captures(line) {
            // Flush previous function
            if let Some(name) = current_name.take() {
                let body = current_lines.join("\n").trim().to_string();
                if !body.is_empty() {
                    map.insert(name, body);
                }
            }
            current_name = Some(caps[1].to_string());
            current_lines.clear();
        } else if current_name.is_some() {
            current_lines.push(line);
        }
    }

    // Flush last function
    if let Some(name) = current_name {
        let body = current_lines.join("\n").trim().to_string();
        if !body.is_empty() {
            map.insert(name, body);
        }
    }

    map
}

/// Annotate lines in `source` that contain a call to `source_action` with
/// `// <-- SOURCE` and lines containing `sink_action` with `// <-- SINK`.
fn annotate_decompilation(source: &str, source_action: &str, sink_action: &str) -> String {
    source
        .lines()
        .map(|line| {
            if !source_action.is_empty() && line.contains(source_action) {
                format!("{line}  // <-- SOURCE")
            } else if !sink_action.is_empty() && line.contains(sink_action) {
                format!("{line}  // <-- SINK")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Truncate decompiled output to at most `max_lines` lines. If truncated,
/// append a note with the total line count.
fn truncate_decompilation(source: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.len() <= max_lines {
        return source.to_string();
    }
    let truncated_lines: Vec<&str> = lines[..max_lines].to_vec();
    let note = format!("... (truncated, {} lines total)", lines.len());
    let mut out = truncated_lines.join("\n");
    out.push('\n');
    out.push_str(&note);
    out
}

/// Collect unique (function_name, address) pairs from a set of findings
/// for decompilation.
fn collect_decompile_targets(findings: &[&TaintFinding]) -> Vec<DecompileTarget> {
    let mut seen = HashMap::new();
    for finding in findings {
        for step in &finding.chain {
            if !seen.contains_key(&step.function) {
                seen.insert(
                    step.function.clone(),
                    DecompileTarget {
                        name: step.function.clone(),
                        addr: step.location.clone(),
                    },
                );
            }
        }
    }
    seen.into_values().collect()
}

/// Run r2 with r2ghidra on `binary` to decompile every function in `targets`.
/// Returns a map from function name to decompiled C.
/// If r2 is not available, prints a warning and returns an empty map.
fn decompile_functions(binary: &Path, targets: &[DecompileTarget]) -> HashMap<String, String> {
    if targets.is_empty() {
        return HashMap::new();
    }

    // Check that r2 is available
    let r2_check = Command::new("r2").arg("-v").output();
    if r2_check.is_err() {
        eprintln!("warning: r2 (radare2) not found in PATH; skipping decompilation");
        eprintln!("  Install: https://github.com/radareorg/radare2");
        return HashMap::new();
    }

    // Write the r2 script to a temp file
    let script = build_r2_script(targets);
    let mut tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("warning: failed to create temp file for r2 script: {e}");
            return HashMap::new();
        }
    };
    if let Err(e) = tmp.write_all(script.as_bytes()) {
        eprintln!("warning: failed to write r2 script: {e}");
        return HashMap::new();
    }

    let script_path = tmp.path().to_path_buf();

    eprintln!("Decompiling {} function(s) with r2ghidra...", targets.len());

    let output = Command::new("r2")
        .args(["-q", "-e", "log.level=0", "-i"])
        .arg(&script_path)
        .arg(binary)
        .output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!("warning: r2 exited with {}: {}", out.status, stderr.trim());
                return HashMap::new();
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_r2_output(&stdout)
        }
        Err(e) => {
            eprintln!("warning: failed to run r2: {e}");
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn shell_script_routes_to_search() {
        let hint = super::non_elf_routing_hint(b"#!/bin/sh\necho hi\n").expect("hint");
        assert!(hint.contains("fat search"), "got: {hint}");
        assert!(hint.contains("shell script"));
    }

    #[test]
    fn squashfs_routes_to_extract() {
        let mut bytes = b"hsqs".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        let hint = super::non_elf_routing_hint(&bytes).expect("hint");
        assert!(hint.contains("fat extract"), "got: {hint}");
        assert!(hint.contains("squashfs"));
    }

    #[test]
    fn gzip_and_zip_route_to_extract() {
        assert!(super::detect_container_format(&[0x1f, 0x8b, 0x08, 0x00]) == Some("gzip"));
        assert!(super::detect_container_format(b"PK\x03\x04rest") == Some("zip"));
    }

    #[test]
    fn source_profile_flag_loads_a_supplied_profile() {
        use std::io::Write;

        let mut profile = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .expect("profile file");
        profile
            .write_all(
                br#"
name: example-cli
sources:
  primary:
    - name: getopt_long
      note: flagged CLI argument values
sinks:
  - name: platform_exec
    arg: 0
    note: OS command execution
"#,
            )
            .expect("write profile");
        profile.flush().expect("flush profile");

        let entries = fat_taint::profile::load_sink_catalog_from_path(profile.path())
            .expect("supplied profile loads");
        assert!(entries.iter().any(|entry| entry.name == "getopt_long"));
        assert!(entries.iter().any(|entry| entry.name == "platform_exec"));
        // The core models remain available alongside it.
        assert!(entries.iter().any(|entry| entry.name == "system"));
    }

    #[test]
    fn source_profile_flag_rejects_a_path_that_does_not_exist() {
        let err = fat_taint::profile::load_sink_catalog_from_path(Path::new(
            "/nonexistent/source-profile.yaml",
        ))
        .expect_err("a missing profile must error");
        assert!(err.contains("failed to read taint profile"), "{err}");
    }

    #[test]
    fn plain_firmware_blob_is_not_routed() {
        // A generic binary blob with no container/shell magic is left to the
        // raw-blob/MCU classifier.
        let blob = vec![0x00u8, 0x04, 0x00, 0x20, 0x11, 0x02, 0x00, 0x08];
        assert!(super::non_elf_routing_hint(&blob).is_none());
    }
    use super::*;

    // -----------------------------------------------------------------------
    // strip_ansi
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_ansi_removes_color_codes() {
        let input = "\x1b[31mERROR\x1b[0m: something failed";
        assert_eq!(strip_ansi(input), "ERROR: something failed");
    }

    #[test]
    fn test_strip_ansi_preserves_plain_text() {
        let input = "int main(void) { return 0; }";
        assert_eq!(strip_ansi(input), input);
    }

    #[test]
    fn test_strip_ansi_handles_multidigit_codes() {
        let input = "\x1b[38;5;196mred text\x1b[0m";
        assert_eq!(strip_ansi(input), "red text");
    }

    // -----------------------------------------------------------------------
    // build_r2_script
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_r2_script_starts_with_analysis() {
        let targets = vec![DecompileTarget {
            name: "sub_993fc".into(),
            addr: "0x993fc".into(),
        }];
        let script = build_r2_script(&targets);
        assert!(
            script.starts_with("aaa\n"),
            "script must start with aaa analysis command"
        );
    }

    #[test]
    fn test_build_r2_script_contains_marker_and_seek() {
        let targets = vec![DecompileTarget {
            name: "sub_993fc".into(),
            addr: "0x993fc".into(),
        }];
        let script = build_r2_script(&targets);
        assert!(
            script.contains("===FAT_FUNC:sub_993fc==="),
            "script must contain function marker"
        );
        assert!(
            script.contains("s 0x993fc"),
            "script must seek to the function address"
        );
        assert!(script.contains("pdg"), "script must call pdg to decompile");
    }

    #[test]
    fn test_build_r2_script_multiple_functions() {
        let targets = vec![
            DecompileTarget {
                name: "sub_993fc".into(),
                addr: "0x993fc".into(),
            },
            DecompileTarget {
                name: "main".into(),
                addr: "0x10000".into(),
            },
        ];
        let script = build_r2_script(&targets);
        assert!(script.contains("===FAT_FUNC:sub_993fc==="));
        assert!(script.contains("===FAT_FUNC:main==="));
        // aaa should appear only once
        assert_eq!(
            script.matches("aaa").count(),
            1,
            "aaa should appear exactly once"
        );
    }

    #[test]
    fn test_build_r2_script_empty_targets() {
        let targets: Vec<DecompileTarget> = vec![];
        let script = build_r2_script(&targets);
        assert_eq!(script, "aaa\n", "empty targets should produce only aaa");
    }

    // -----------------------------------------------------------------------
    // parse_r2_output
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_r2_output_single_function() {
        let output = "\
===FAT_FUNC:sub_993fc===
void sub_993fc(void) {
    system(cmd);
}
";
        let map = parse_r2_output(output);
        assert_eq!(map.len(), 1);
        let decomp = map.get("sub_993fc").unwrap();
        assert!(decomp.contains("void sub_993fc(void)"));
        assert!(decomp.contains("system(cmd)"));
    }

    #[test]
    fn test_parse_r2_output_multiple_functions() {
        let output = "\
===FAT_FUNC:sub_993fc===
void sub_993fc(void) {
    system(cmd);
}
===FAT_FUNC:main===
int main(int argc, char **argv) {
    return 0;
}
";
        let map = parse_r2_output(output);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("sub_993fc"));
        assert!(map.contains_key("main"));
        assert!(map.get("main").unwrap().contains("return 0"));
    }

    #[test]
    fn test_parse_r2_output_strips_ansi() {
        let output = "\
===FAT_FUNC:sub_993fc===
\x1b[31mvoid\x1b[0m sub_993fc(void) {
    system(cmd);
}
";
        let map = parse_r2_output(output);
        let decomp = map.get("sub_993fc").unwrap();
        assert!(!decomp.contains("\x1b["), "ANSI codes should be stripped");
        assert!(decomp.contains("void sub_993fc(void)"));
    }

    #[test]
    fn test_parse_r2_output_trims_whitespace() {
        let output = "\
===FAT_FUNC:sub_993fc===

  void sub_993fc(void) {
      return;
  }

";
        let map = parse_r2_output(output);
        let decomp = map.get("sub_993fc").unwrap();
        // The trimmed output should not start or end with blank lines
        assert!(
            !decomp.starts_with('\n'),
            "leading newlines should be trimmed"
        );
        assert!(
            !decomp.ends_with('\n'),
            "trailing newlines should be trimmed"
        );
    }

    #[test]
    fn test_parse_r2_output_empty() {
        let map = parse_r2_output("");
        assert!(map.is_empty());
    }

    // -----------------------------------------------------------------------
    // annotate_decompilation
    // -----------------------------------------------------------------------

    #[test]
    fn test_annotate_marks_source_line() {
        let source = "\
void handler(void) {
    char *val = getenv(\"QUERY_STRING\");
    process(val);
}";
        let result = annotate_decompilation(source, "getenv", "process");
        assert!(
            result.contains("getenv(\"QUERY_STRING\");  // <-- SOURCE"),
            "source line should be annotated, got:\n{result}"
        );
    }

    #[test]
    fn test_annotate_marks_sink_line() {
        let source = "\
void handler(void) {
    char *val = getenv(\"QUERY_STRING\");
    system(val);
}";
        let result = annotate_decompilation(source, "getenv", "system");
        assert!(
            result.contains("system(val);  // <-- SINK"),
            "sink line should be annotated, got:\n{result}"
        );
    }

    #[test]
    fn test_annotate_no_match_unchanged() {
        let source = "\
void handler(void) {
    return;
}";
        let result = annotate_decompilation(source, "getenv", "system");
        assert_eq!(result, source, "no matches should leave source unchanged");
    }

    #[test]
    fn test_annotate_both_source_and_sink_on_different_lines() {
        let source = "\
void handler(void) {
    char *val = CGI_Find_Parameter(\"name\");
    popen(val, \"r\");
}";
        let result = annotate_decompilation(source, "CGI_Find_Parameter", "popen");
        assert!(result.contains("// <-- SOURCE"));
        assert!(result.contains("// <-- SINK"));
    }

    // -----------------------------------------------------------------------
    // truncate_decompilation
    // -----------------------------------------------------------------------

    #[test]
    fn test_truncate_short_unchanged() {
        let source = "line1\nline2\nline3";
        let result = truncate_decompilation(source, 60);
        assert_eq!(result, source, "short source should not be truncated");
    }

    #[test]
    fn test_truncate_at_limit() {
        // Build a source with exactly 60 lines
        let lines: Vec<String> = (1..=60).map(|i| format!("line {i}")).collect();
        let source = lines.join("\n");
        let result = truncate_decompilation(&source, 60);
        assert_eq!(result, source, "exactly 60 lines should not be truncated");
    }

    #[test]
    fn test_truncate_over_limit() {
        let lines: Vec<String> = (1..=100).map(|i| format!("line {i}")).collect();
        let source = lines.join("\n");
        let result = truncate_decompilation(&source, 60);
        let result_lines: Vec<&str> = result.lines().collect();
        // 60 content lines + 1 truncation note = 61
        assert_eq!(result_lines.len(), 61);
        assert_eq!(result_lines[0], "line 1");
        assert_eq!(result_lines[59], "line 60");
        assert!(
            result_lines[60].contains("truncated"),
            "last line should contain truncation notice, got: {}",
            result_lines[60]
        );
        assert!(
            result_lines[60].contains("100"),
            "truncation notice should show total line count"
        );
    }

    // -----------------------------------------------------------------------
    // decompile_functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_decompile_functions_nonexistent_binary_returns_empty() {
        let targets = vec![DecompileTarget {
            name: "sub_993fc".into(),
            addr: "0x993fc".into(),
        }];
        let result = decompile_functions(Path::new("/nonexistent/binary"), &targets);
        assert!(
            result.is_empty(),
            "nonexistent binary should return empty map"
        );
    }

    #[test]
    fn test_decompile_functions_empty_targets_returns_empty() {
        let result = decompile_functions(Path::new("/nonexistent/binary"), &[]);
        assert!(result.is_empty(), "no targets should return empty map");
    }

    // -----------------------------------------------------------------------
    // collect_decompile_targets
    // -----------------------------------------------------------------------

    fn make_finding(func: &str, loc: &str, source_action: &str, sink_action: &str) -> TaintFinding {
        use fat_taint::{FindingStatus, SourceClass};
        TaintFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: "TAINT-001".into(),
            title: "test finding".into(),
            severity: FindingSeverity::High,
            chain: vec![
                fat_taint::ChainStep {
                    binary: "test.cgi".into(),
                    function: func.into(),
                    location: loc.into(),
                    action: source_action.into(),
                    edge_type: EdgeType::DirectFlow,
                },
                fat_taint::ChainStep {
                    binary: "test.cgi".into(),
                    function: func.into(),
                    location: loc.into(),
                    action: sink_action.into(),
                    edge_type: EdgeType::DirectFlow,
                },
            ],
            status: FindingStatus::Proven,
            status_reason: "test".into(),
            confidence: 0.95,
            source_class: SourceClass::Primary,
        }
    }

    #[test]
    fn augment_findings_with_trace_report_confirms_marker_path() {
        use crate::runtime_augment::RuntimeDecision;
        use fat_taint::{ChainStep, FindingStatus, SourceClass};

        let dir = tempfile::tempdir().expect("tempdir");
        let trace_path = dir.path().join("hooks.jsonl");
        std::fs::write(
            &trace_path,
            r#"{"hook":"cgibin_get_var","addr":"0x00412000","a0_str":"MARKER"}
{"hook":"system","addr":"0x00413f10","a0_str":"MARKER"}
"#,
        )
        .expect("write trace");
        let finding = TaintFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: "TAINT-001".into(),
            title: "command injection".into(),
            severity: FindingSeverity::High,
            chain: vec![
                ChainStep {
                    binary: "httpd".into(),
                    function: "cgibin_get_var".into(),
                    location: "0x00412000".into(),
                    action: "source".into(),
                    edge_type: EdgeType::DirectFlow,
                },
                ChainStep {
                    binary: "httpd".into(),
                    function: "system".into(),
                    location: "0x00413f10".into(),
                    action: "sink".into(),
                    edge_type: EdgeType::DirectFlow,
                },
            ],
            status: FindingStatus::Proven,
            status_reason: "static flow".into(),
            confidence: 0.95,
            source_class: SourceClass::Primary,
        };

        let report = augment_findings_with_trace(&[finding], &trace_path, Some("MARKER"))
            .expect("augment findings");

        assert_eq!(
            report.findings[0].decision,
            RuntimeDecision::RuntimeConfirmed
        );
    }

    #[test]
    fn test_collect_decompile_targets_extracts_unique_functions() {
        let f1 = make_finding("sub_993fc", "0x993fc", "getenv", "system");
        let f2 = make_finding("sub_993fc", "0x993fc", "getenv", "popen"); // same func
        let f3 = make_finding("main", "0x10000", "read", "exec");
        let findings: Vec<&TaintFinding> = vec![&f1, &f2, &f3];
        let targets = collect_decompile_targets(&findings);
        assert_eq!(targets.len(), 2, "should deduplicate sub_993fc");
        let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"sub_993fc"));
        assert!(names.contains(&"main"));
    }

    #[test]
    fn test_collect_decompile_targets_uses_location_as_addr() {
        let f = make_finding("sub_993fc", "0x993fc", "getenv", "system");
        let findings: Vec<&TaintFinding> = vec![&f];
        let targets = collect_decompile_targets(&findings);
        assert_eq!(targets[0].addr, "0x993fc");
    }

    #[test]
    fn test_cortex_m_vector_table_looks_plausible() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0x2401_a058u32.to_le_bytes());
        blob.extend_from_slice(&0x0800_02adu32.to_le_bytes());
        blob.resize(64, 0);

        assert!(looks_like_cortex_m_blob(&blob, 0x0800_0000));
    }

    #[test]
    fn test_cortex_m_vector_table_rejects_opaque_blob() {
        let blob = vec![0xBA, 0x33, 0x98, 0xD9, 0x0E, 0x2D, 0x2D, 0x6E];

        assert!(!looks_like_cortex_m_blob(&blob, 0x0800_0000));
    }

    #[test]
    fn test_validate_raw_blob_inputs_rejects_non_elf_without_arch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob_path = dir.path().join("opaque.bin");
        std::fs::write(&blob_path, [0u8; 64]).expect("write blob");

        let err = validate_raw_blob_inputs(&blob_path, None, None).expect_err("should reject");
        assert!(err.contains("raw blob"));
        assert!(err.contains("--arch"));
    }

    #[test]
    fn test_validate_raw_blob_inputs_rejects_invalid_cortex_m_blob() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob_path = dir.path().join("opaque.bin");
        std::fs::write(&blob_path, [0u8; 64]).expect("write blob");

        let err = validate_raw_blob_inputs(&blob_path, Some("cortex-m"), Some("0x08000000"))
            .expect_err("should reject");
        assert!(err.contains("does not look like a valid Cortex-M image"));
    }

    #[test]
    fn test_validate_raw_blob_inputs_flags_high_entropy_blob_as_packed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob_path = dir.path().join("packed.bin");
        let payload: Vec<u8> = (0..8192u32).map(|i| ((i * 73 + 41) & 0xff) as u8).collect();
        std::fs::write(&blob_path, payload).expect("write blob");

        let err = validate_raw_blob_inputs(&blob_path, None, None).expect_err("should reject");
        assert!(err.contains("packed, encrypted, or vendor-container"));
    }

    #[test]
    fn test_validate_raw_blob_inputs_flags_likely_unsupported_mcu_family() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob_path = dir.path().join("8051ish.bin");
        let mut payload = vec![0u8; 512];
        payload.extend_from_slice(b"GIF89a");
        payload.resize(4096, 0x41);
        std::fs::write(&blob_path, payload).expect("write blob");

        let err = validate_raw_blob_inputs(&blob_path, None, None).expect_err("should reject");
        assert!(err.contains("unsupported MCU family"));
        assert!(err.contains("8051"));
    }

    #[test]
    fn sink_candidates_load_probable_address_backed_extensions() {
        let report = serde_json::json!({
            "file": "./bin/httpd",
            "binary": {
                "format": "elf",
                "arch": "mips",
                "bits": 32,
                "endianness": "little",
                "class": "elf32"
            },
            "profiles": ["linux-command-exec"],
            "summary": {
                "candidates": 1,
                "families": {
                    "command-exec": 1
                }
            },
            "candidates": [{
                "id": "sink-0",
                "family": "command-exec",
                "family_key": "command-exec",
                "confidence": "probable",
                "symbolic_name": "candidate_system",
                "address": "0x00413f10",
                "score": 0.75,
                "evidence": [],
                "limitations": []
            }]
        });
        let content = serde_json::to_string(&report).expect("json");

        let loaded = load_sink_candidates(&content).expect("load candidates");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, Some(0x00413f10));
        assert_eq!(loaded[0].symbolic_name.as_deref(), Some("candidate_system"));
        assert_eq!(loaded[0].family_key, "command-exec");
    }
}
