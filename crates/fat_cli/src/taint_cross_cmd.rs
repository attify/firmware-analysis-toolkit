use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use fat_core::finding::FindingSeverity;
use fat_taint::profile::{CatalogProvenance, ExternalTaintProfile};
use fat_taint::proof::angr;
use fat_taint::shared_state_families::{
    families_match, OpDirection, SharedStateCatalog, SharedStateProvenance,
};
use fat_taint::{ChainStep, EdgeType, FindingStatus, SourceClass, TaintFinding};

use serde::Serialize;
use walkdir::WalkDir;

type DynResult<T> = Result<T, Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Evidence grade model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceGrade {
    /// angr RD-confirmed taint path (source → write or read → sink)
    Confirmed,
    /// angr co-occurrence, cross-function callgraph, or Secondary source class
    Derived,
    /// Strings-only pattern match — must be corroborated to produce a CrossBinaryFinding
    Hint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CrossConfidence {
    High,
    Medium,
    Low,
}

impl CrossConfidence {
    fn as_str(&self) -> &'static str {
        match self {
            CrossConfidence::High => "high",
            CrossConfidence::Medium => "medium",
            CrossConfidence::Low => "low",
        }
    }
}

// ---------------------------------------------------------------------------
// SharedStateObservation — the core in-memory type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SharedStateObservation {
    pub binary: String,
    pub direction: OpDirection,
    /// Id of the family the selected profile resolved this function to, if
    /// any. `None` means the name was observed but no profile gave it a role.
    pub family: Option<String>,
    pub function: String,
    pub key: Option<String>,
    pub sink: Option<String>,
    pub source: Option<String>,
    pub containing_function: Option<String>,
    pub provenance: Provenance,
    pub grade: EvidenceGrade,
}

#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub tool: String,
    pub finding_id: Option<String>,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// CrossBinaryFinding — output type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct CrossBinaryFinding {
    #[serde(skip_serializing_if = "Option::is_none")]
    model_provenance: Option<CatalogProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_model_provenance: Option<SharedStateProvenance>,
    id: String,
    title: String,
    severity: String,
    write_obs: SharedStateObservation,
    read_obs: SharedStateObservation,
    shared_key: Option<String>,
    shared_family: String,
    confidence: CrossConfidence,
    note: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(
    binaries: &[PathBuf],
    rootfs: Option<&Path>,
    state_profile: Option<&Path>,
    source_profile: Option<&Path>,
    json: bool,
    as_taint_json: bool,
) -> DynResult<()> {
    // Which function names write and which read shared state is a claim about
    // one platform, so it comes from a profile the operator names by path.
    // With none selected the catalog is empty: no name is given a role and
    // nothing stitches. This command emits findings, not a raw symbol inventory.
    let catalog = match state_profile {
        Some(path) => SharedStateCatalog::load(path)?,
        None => SharedStateCatalog::empty(),
    };
    // Read once: the bytes sent to the producer are the bytes whose digest we save.
    let selected_models = source_profile.map(ExternalTaintProfile::load).transpose()?;
    let model_provenance = selected_models
        .as_ref()
        .map(|profile| profile.provenance().clone())
        .unwrap_or(CatalogProvenance::Core);
    let no_flows = |message: &str| -> DynResult<()> {
        eprintln!("{message}");
        if json || as_taint_json {
            println!("[]");
        }
        Ok(())
    };

    let binary_paths = if let Some(rootfs) = rootfs {
        discover_binaries(rootfs)?
    } else {
        binaries.to_vec()
    };

    if binary_paths.is_empty() {
        return Err("no binaries to analyze (provide --file paths or --rootfs)".into());
    }

    eprintln!(
        "Analyzing {} binaries for cross-binary flows...",
        binary_paths.len()
    );
    eprintln!("Shared-state catalog: {}", catalog.provenance().label());
    eprintln!("Binary models: {}", model_provenance.label());
    if catalog.is_empty() {
        eprintln!(
            "Shared-state catalog is empty (--state-profile <file.yaml>): \
             read/write role assignment and cross-binary stitching are disabled."
        );
    }

    // Stage 1: Collect observations from all providers
    let mut all_observations: Vec<SharedStateObservation> = Vec::new();

    for binary in &binary_paths {
        let name = binary
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        eprintln!("  Analyzing {name}...");

        // Provider 1: angr
        let angr_obs = match angr::analyze_binary_with_profile(
            binary,
            None,
            None,
            None,
            selected_models.as_ref(),
        ) {
            Ok(findings) => {
                let obs = observations_from_angr(&name, &findings, &catalog);
                if !findings.is_empty() {
                    eprintln!(
                        "    angr: {} findings → {} observations",
                        findings.len(),
                        obs.len()
                    );
                }
                obs
            }
            Err(e) => {
                eprintln!("    angr: skipped ({e})");
                Vec::new()
            }
        };

        let angr_produced_results = !angr_obs.is_empty();
        all_observations.extend(angr_obs);

        // Provider 2: strings heuristic (only for binaries where angr found nothing)
        if !angr_produced_results {
            if let Ok(data) = std::fs::read(binary) {
                let strings_obs = observations_from_strings(&name, &data, &catalog);
                if !strings_obs.is_empty() {
                    eprintln!("    strings: {} hint observations", strings_obs.len());
                }
                all_observations.extend(strings_obs);
            }
        }
    }

    if all_observations.is_empty() {
        return no_flows("No shared-state observations found across binaries.");
    }

    // Separate writes and reads
    let writes: Vec<&SharedStateObservation> = all_observations
        .iter()
        .filter(|o| o.direction == OpDirection::Write)
        .collect();
    let reads: Vec<&SharedStateObservation> = all_observations
        .iter()
        .filter(|o| o.direction == OpDirection::Read)
        .collect();

    eprintln!(
        "  Total: {} write observations, {} read observations",
        writes.len(),
        reads.len()
    );

    if writes.is_empty() {
        return no_flows("No shared-state write observations found.");
    }
    if reads.is_empty() {
        return no_flows("No shared-state read-to-sink observations found.");
    }

    // Stage 2: Stitch
    let mut cross_findings = stitch(&writes, &reads);
    for finding in &mut cross_findings {
        finding.model_provenance = Some(model_provenance.clone());
        finding.state_model_provenance = Some(catalog.provenance().clone());
    }

    if cross_findings.is_empty() {
        return no_flows("No cross-binary flows found.");
    }

    // Stage 3: Output
    if as_taint_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&cross_findings_to_taint_findings(&cross_findings))?
        );
    } else if json {
        println!("{}", serde_json::to_string_pretty(&cross_findings)?);
    } else {
        render_cross_findings(&cross_findings);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Provider 1: angr observations
// ---------------------------------------------------------------------------

fn observations_from_angr(
    binary_name: &str,
    findings: &[TaintFinding],
    catalog: &SharedStateCatalog,
) -> Vec<SharedStateObservation> {
    let mut obs = Vec::new();

    for finding in findings {
        let first = finding.chain.first();
        let last = finding.chain.last();

        // Write observation: finding where sink is a shared-state write
        if let Some(last_step) = last {
            let sink_name = extract_function_name(&last_step.action);
            if let Some((family, OpDirection::Write)) = catalog.classify(&sink_name) {
                let source_name = first
                    .map(|s| extract_function_name(&s.action))
                    .unwrap_or_default();
                obs.push(SharedStateObservation {
                    binary: binary_name.to_string(),
                    direction: OpDirection::Write,
                    family: Some(family.id.clone()),
                    function: sink_name,
                    key: extract_state_key_from_finding(finding, catalog),
                    sink: None,
                    source: Some(source_name),
                    containing_function: first.map(|s| s.function.clone()),
                    provenance: Provenance {
                        tool: "angr".into(),
                        finding_id: Some(finding.id.clone()),
                        detail: finding.title.clone(),
                    },
                    grade: angr_grade(&finding.status),
                });
            }
        }

        // Read observation path 1: registry recognizes the read function
        if let Some(first_step) = first {
            let source_name = extract_function_name(&first_step.action);
            if let Some((family, OpDirection::Read)) = catalog.classify(&source_name) {
                let sink_name = last
                    .map(|s| extract_function_name(&s.action))
                    .unwrap_or_default();
                obs.push(SharedStateObservation {
                    binary: binary_name.to_string(),
                    direction: OpDirection::Read,
                    family: Some(family.id.clone()),
                    function: source_name,
                    key: extract_state_key_from_finding(finding, catalog),
                    sink: Some(sink_name),
                    source: None,
                    containing_function: Some(first_step.function.clone()),
                    provenance: Provenance {
                        tool: "angr".into(),
                        finding_id: Some(finding.id.clone()),
                        detail: finding.title.clone(),
                    },
                    grade: angr_grade(&finding.status),
                });
            }
            // Read observation path 2: SourceClass::Secondary fallback
            else if finding.source_class == SourceClass::Secondary {
                let sink_name = last
                    .map(|s| extract_function_name(&s.action))
                    .unwrap_or_default();
                obs.push(SharedStateObservation {
                    binary: binary_name.to_string(),
                    direction: OpDirection::Read,
                    // Unresolved: pairs with any family the selected profile
                    // declares, never with another unresolved observation.
                    family: None,
                    function: source_name,
                    key: extract_state_key_from_finding(finding, catalog),
                    sink: Some(sink_name),
                    source: None,
                    containing_function: Some(first_step.function.clone()),
                    provenance: Provenance {
                        tool: "angr".into(),
                        finding_id: Some(finding.id.clone()),
                        detail: format!("{} (secondary source, family unresolved)", finding.title),
                    },
                    grade: EvidenceGrade::Derived, // never Confirmed without registry match
                });
            }
        }
    }

    obs
}

fn angr_grade(status: &FindingStatus) -> EvidenceGrade {
    match status {
        FindingStatus::Proven | FindingStatus::Attested => EvidenceGrade::Confirmed,
        _ => EvidenceGrade::Derived,
    }
}

// ---------------------------------------------------------------------------
// Provider 2: strings heuristic
// ---------------------------------------------------------------------------

fn observations_from_strings(
    binary_name: &str,
    binary_data: &[u8],
    catalog: &SharedStateCatalog,
) -> Vec<SharedStateObservation> {
    let strings = extract_printable_strings(binary_data, 4);
    let mut obs = Vec::new();

    for (offset, s) in &strings {
        for family in catalog.families() {
            // Use the same precedence and flush exclusions as the finding provider.
            if family.classify(s) != Some(OpDirection::Write) {
                continue;
            }
            for pattern in &family.write_patterns {
                if s.contains(pattern.as_str()) {
                    obs.push(SharedStateObservation {
                        binary: binary_name.to_string(),
                        direction: OpDirection::Write,
                        family: Some(family.id.clone()),
                        function: pattern.clone(),
                        key: extract_quoted_key_for_pattern(&strings, *offset, pattern),
                        sink: None,
                        source: None,
                        containing_function: None,
                        provenance: Provenance {
                            tool: "strings".into(),
                            finding_id: None,
                            detail: format!("{pattern} at offset 0x{offset:x}"),
                        },
                        grade: EvidenceGrade::Hint,
                    });
                }
            }
            // Strings-only reads are NOT emitted. A read pattern in strings
            // does not prove a read→dangerous-sink path. The read side must
            // come from angr (Confirmed/Derived) which proves the actual
            // data flow to system()/popen()/strcpy().
        }
    }

    // Dedup by (binary, direction, family, function, key) — preserve distinct keyed hints
    dedup_observations(&mut obs);
    obs
}

/// Extract printable strings of at least `min_len` characters from binary data.
fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start = 0;

    for (i, &byte) in data.iter().enumerate() {
        if (0x20..0x7f).contains(&byte) {
            if current.is_empty() {
                start = i;
            }
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                results.push((start, current.clone()));
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push((start, current));
    }
    results
}

/// Extract a key from a quoted-argument pattern tied to a specific function pattern.
/// Only accepts `pattern("key")` syntax where the quotes follow the matched pattern.
/// Raw adjacency or quotes before the pattern name are NOT accepted.
fn extract_quoted_key_for_pattern(
    strings: &[(usize, String)],
    offset: usize,
    matched_pattern: &str,
) -> Option<String> {
    let s = strings.iter().find(|(o, _)| *o == offset).map(|(_, s)| s)?;

    // Find the matched pattern in the string, then extract quoted arg AFTER it
    let pattern_pos = s.find(matched_pattern)?;
    let after_pattern = &s[pattern_pos + matched_pattern.len()..];

    // Look for ("key") immediately after the pattern name
    let trimmed = after_pattern.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
    extract_quoted_arg(&format!("x{trimmed}")) // prefix with dummy char for extract_quoted_arg
        .or_else(|| extract_quoted_arg(after_pattern))
}

// ---------------------------------------------------------------------------
// Stitching
// ---------------------------------------------------------------------------

const MAX_CANDIDATES_PER_TRIPLE: usize = 3;

fn stitch(
    writes: &[&SharedStateObservation],
    reads: &[&SharedStateObservation],
) -> Vec<CrossBinaryFinding> {
    // Phase 1: collect ALL qualifying candidates (no cap yet)
    let mut candidates = Vec::new();

    for write in writes {
        for read in reads {
            if write.binary == read.binary {
                continue;
            }
            if !families_match(write.family.as_deref(), read.family.as_deref()) {
                continue;
            }
            if !should_emit(write, read) {
                continue;
            }
            if !keys_match(write, read) {
                continue;
            }

            let family_id = write
                .family
                .clone()
                .or_else(|| read.family.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let shared_key = write.key.clone().or(read.key.clone());
            let confidence = cross_confidence(write, read);

            let severity = if write.source.as_deref().is_some_and(is_high_severity_source)
                || confidence == CrossConfidence::High
            {
                "High"
            } else {
                "Medium"
            };

            candidates.push(CrossBinaryFinding {
                model_provenance: None,
                state_model_provenance: None,
                id: String::new(), // assigned after ranking
                title: format!(
                    "{} ({}) → {} ({}) → {} → {} in {}",
                    write.binary,
                    write.provenance.tool,
                    write.function,
                    family_id,
                    read.function,
                    read.sink.as_deref().unwrap_or("?"),
                    read.binary,
                ),
                severity: severity.to_string(),
                write_obs: (*write).clone(),
                read_obs: (*read).clone(),
                shared_key,
                shared_family: family_id,
                confidence,
                note: format!(
                    "Write: {} in {} ({}). Read→sink: {} → {} in {} ({}).",
                    write.function,
                    write.binary,
                    write.provenance.tool,
                    read.function,
                    read.sink.as_deref().unwrap_or("?"),
                    read.binary,
                    read.provenance.tool,
                ),
            });
        }
    }

    // Phase 2: rank — keyed first, then confidence, then sink danger
    candidates.sort_by(|a, b| {
        let a_keyed = a.shared_key.is_some() as u8;
        let b_keyed = b.shared_key.is_some() as u8;
        b_keyed
            .cmp(&a_keyed)
            .then(confidence_rank(b.confidence).cmp(&confidence_rank(a.confidence)))
            .then(sink_danger_rank(&b.read_obs).cmp(&sink_danger_rank(&a.read_obs)))
    });

    // Phase 3: cap unknown-key candidates per triple AFTER ranking
    let mut triple_counts: HashMap<(String, String, String), usize> = HashMap::new();
    let mut findings = Vec::new();
    let mut id_counter: u32 = 0;

    for mut candidate in candidates {
        let triple_key = (
            candidate.write_obs.binary.clone(),
            candidate.read_obs.binary.clone(),
            candidate.shared_family.clone(),
        );
        let count = triple_counts.entry(triple_key).or_insert(0);
        if *count >= MAX_CANDIDATES_PER_TRIPLE && candidate.shared_key.is_none() {
            continue;
        }
        *count += 1;
        id_counter += 1;
        candidate.id = format!("CROSS-{id_counter:04}");
        findings.push(candidate);
    }

    findings
}

fn sink_danger_rank(obs: &SharedStateObservation) -> u8 {
    match obs.sink.as_deref() {
        Some("system") | Some("popen") | Some("execve") | Some("exec") => 2,
        Some("strcpy") | Some("sprintf") | Some("strcat") => 1,
        _ => 0,
    }
}

fn should_emit(write: &SharedStateObservation, read: &SharedStateObservation) -> bool {
    // Check Hint FIRST — Hints require key corroboration regardless of the other side
    if write.grade == EvidenceGrade::Hint || read.grade == EvidenceGrade::Hint {
        return matches!((&write.key, &read.key), (Some(wk), Some(rk)) if wk == rk);
    }
    // Both non-Hint: Confirmed or Derived on both sides → emit
    true
}

fn keys_match(write: &SharedStateObservation, read: &SharedStateObservation) -> bool {
    match (&write.key, &read.key) {
        (Some(wk), Some(rk)) => wk == rk,
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => {
            // Both unknown: only match if neither is a Hint
            write.grade != EvidenceGrade::Hint && read.grade != EvidenceGrade::Hint
        }
    }
}

fn cross_confidence(
    write: &SharedStateObservation,
    read: &SharedStateObservation,
) -> CrossConfidence {
    match (write.grade, read.grade) {
        (EvidenceGrade::Confirmed, EvidenceGrade::Confirmed) => CrossConfidence::High,
        (EvidenceGrade::Confirmed, _) | (_, EvidenceGrade::Confirmed) => CrossConfidence::Medium,
        _ => CrossConfidence::Low,
    }
}

fn confidence_rank(c: CrossConfidence) -> u8 {
    match c {
        CrossConfidence::High => 2,
        CrossConfidence::Medium => 1,
        CrossConfidence::Low => 0,
    }
}

fn cross_findings_to_taint_findings(findings: &[CrossBinaryFinding]) -> Vec<TaintFinding> {
    findings
        .iter()
        .map(|finding| {
            let shared_key = finding.shared_key.as_deref().unwrap_or("unknown");
            let confidence = match finding.confidence {
                CrossConfidence::High => 0.85,
                CrossConfidence::Medium => 0.70,
                CrossConfidence::Low => 0.50,
            };

            let mut chain = Vec::new();
            let source_function = finding
                .write_obs
                .containing_function
                .as_deref()
                .unwrap_or(&finding.write_obs.function);
            chain.push(ChainStep {
                binary: finding.write_obs.binary.clone(),
                function: source_function.to_string(),
                location: format!(
                    "symbolic cross-binary write: {} shared state {} key {}",
                    finding.write_obs.function, finding.shared_family, shared_key
                ),
                action: finding
                    .write_obs
                    .source
                    .as_deref()
                    .map(|source| format!("{source}()"))
                    .unwrap_or_else(|| format!("{}()", finding.write_obs.function)),
                edge_type: EdgeType::DirectFlow,
            });

            chain.push(ChainStep {
                binary: finding.read_obs.binary.clone(),
                function: finding.read_obs.function.clone(),
                location: format!(
                    "symbolic cross-binary read: {} shared state {} key {}",
                    finding.read_obs.function, finding.shared_family, shared_key
                ),
                action: format!("{}()", finding.read_obs.function),
                edge_type: EdgeType::ConfigKeyBridge {
                    config_file: finding.shared_family.clone(),
                    config_key: shared_key.to_string(),
                },
            });

            if let Some(sink) = &finding.read_obs.sink {
                chain.push(ChainStep {
                    binary: finding.read_obs.binary.clone(),
                    function: sink.clone(),
                    location: format!(
                        "symbolic cross-binary sink: {} reached from {}",
                        sink, finding.read_obs.function
                    ),
                    action: format!("{sink}()"),
                    edge_type: EdgeType::DirectFlow,
                });
            }

            TaintFinding {
                model_provenance: finding.model_provenance.clone(),
                state_model_provenance: finding.state_model_provenance.clone(),
                id: finding.id.clone(),
                title: finding.title.clone(),
                severity: if finding.severity.eq_ignore_ascii_case("high") {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                status: TaintFinding::classify(&chain),
                status_reason: format!(
                    "Adapted from taint-cross {} confidence finding; {}",
                    finding.confidence.as_str(),
                    finding.note
                ),
                confidence,
                source_class: SourceClass::Secondary,
                chain,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_cross_findings(findings: &[CrossBinaryFinding]) {
    println!(
        "Cross-binary taint analysis: {} finding(s)\n",
        findings.len()
    );

    for f in findings {
        let sev_tag = if f.severity == "High" { "HIGH" } else { " MED" };
        println!(
            "[{}] [{}] [confidence:{}] {}",
            sev_tag,
            f.id,
            f.confidence.as_str(),
            f.title
        );
        println!(
            "  Write: {} in {} [{}] ({})",
            f.write_obs.function,
            f.write_obs.binary,
            grade_label(f.write_obs.grade),
            f.write_obs.provenance.detail,
        );
        println!(
            "  Read→sink: {} → {} in {} [{}] ({})",
            f.read_obs.function,
            f.read_obs.sink.as_deref().unwrap_or("?"),
            f.read_obs.binary,
            grade_label(f.read_obs.grade),
            f.read_obs.provenance.detail,
        );
        if let Some(key) = &f.shared_key {
            println!("  Shared state: {} key \"{}\"", f.shared_family, key);
        } else {
            println!(
                "  Shared state: {} (key unknown — manual verification needed)",
                f.shared_family
            );
        }
        println!();
    }
}

fn grade_label(grade: EvidenceGrade) -> &'static str {
    match grade {
        EvidenceGrade::Confirmed => "confirmed",
        EvidenceGrade::Derived => "derived",
        EvidenceGrade::Hint => "hint",
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_function_name(action: &str) -> String {
    action.trim_end_matches("()").to_string()
}

fn extract_quoted_arg(action: &str) -> Option<String> {
    let start = action.find('"')?;
    let rest = &action[start + 1..];
    let end = rest.find('"')?;
    let key = &rest[..end];
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

fn extract_state_key_from_finding(
    finding: &TaintFinding,
    catalog: &SharedStateCatalog,
) -> Option<String> {
    for step in &finding.chain {
        if let fat_taint::EdgeType::ConfigKeyBridge { config_key, .. } = &step.edge_type {
            if !config_key.is_empty() {
                return Some(config_key.clone());
            }
        }
    }
    for step in &finding.chain {
        if let Some(key) = extract_quoted_arg(&step.action) {
            let func = extract_function_name(&step.action);
            if catalog.classify(&func).is_some() {
                return Some(key);
            }
        }
    }
    None
}

/// Sources whose ingress is specified rather than assumed.
///
/// `getenv` is ISO C; `read`, `recv` and `fgets` are POSIX/ISO C reads of data
/// the process did not produce. Platform request-parameter getters are not
/// listed: which of those exist, and whether they carry request data, is a
/// per-target claim and belongs in the operator's profile, not here.
fn is_high_severity_source(source: &str) -> bool {
    matches!(source, "getenv" | "read" | "recv" | "fgets")
}

fn dedup_observations(obs: &mut Vec<SharedStateObservation>) {
    let mut seen = std::collections::HashSet::new();
    obs.retain(|o| {
        let key = (
            o.binary.clone(),
            format!("{:?}", o.direction),
            o.family.clone().unwrap_or_default(),
            o.function.clone(),
            o.key.clone().unwrap_or_default(),
        );
        seen.insert(key)
    });
}

fn discover_binaries(rootfs: &Path) -> DynResult<Vec<PathBuf>> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs not found: {}", rootfs.display()).into());
    }

    let mut binaries = Vec::new();
    let search_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib"];

    for dir in &search_dirs {
        let full_path = rootfs.join(dir);
        if !full_path.is_dir() {
            continue;
        }

        for entry in WalkDir::new(&full_path).max_depth(2) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }

            if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                if name.contains(".so") {
                    continue;
                }
            }

            if let Ok(bytes) = std::fs::read(entry.path()) {
                if bytes.len() >= 4 && bytes[..4] == *b"\x7fELF" {
                    binaries.push(entry.path().to_path_buf());
                }
            }
        }
    }

    eprintln!(
        "Discovered {} ELF binaries in {}",
        binaries.len(),
        rootfs.display()
    );
    Ok(binaries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fat_core::finding::FindingSeverity;
    use fat_taint::{ChainStep, EdgeType, FindingStatus, SourceClass};
    use std::io::Write;

    /// A profile an operator would write for one target. The function names are
    /// invented for this test on purpose: the point is that the catalog comes
    /// from the file, not that FAT recognises any particular platform's API.
    const EXAMPLE_STATE_PROFILE: &str = r#"
name: example-state
families:
  - id: example-store
    write: [example_store_set, example_bufset]
    read: [example_store_get, example_bufget]
    flush: [example_store_commit]
"#;

    struct SelectedProfile {
        _file: tempfile::NamedTempFile,
        catalog: SharedStateCatalog,
    }

    fn selected_catalog() -> SelectedProfile {
        let mut file = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .expect("profile file");
        file.write_all(EXAMPLE_STATE_PROFILE.as_bytes())
            .expect("write profile");
        file.flush().expect("flush profile");
        let catalog = SharedStateCatalog::load(file.path()).expect("profile loads");
        SelectedProfile {
            _file: file,
            catalog,
        }
    }

    fn make_angr_finding(
        source_action: &str,
        sink_action: &str,
        function: &str,
        id: &str,
        source_class: SourceClass,
        status: FindingStatus,
    ) -> TaintFinding {
        TaintFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: id.into(),
            title: format!("{source_action} → {sink_action} in {function}"),
            severity: FindingSeverity::High,
            chain: vec![
                ChainStep {
                    binary: "test".into(),
                    function: function.into(),
                    location: "0x1000".into(),
                    action: format!("{source_action}()"),
                    edge_type: EdgeType::DirectFlow,
                },
                ChainStep {
                    binary: "test".into(),
                    function: function.into(),
                    location: "0x1010".into(),
                    action: format!("{sink_action}()"),
                    edge_type: EdgeType::DirectFlow,
                },
            ],
            status,
            status_reason: "test".into(),
            confidence: 0.80,
            source_class,
        }
    }

    #[test]
    fn angr_write_observation_uses_the_selected_profile() {
        let selected = selected_catalog();
        let finding = make_angr_finding(
            "getenv",
            "example_store_set",
            "handle_request",
            "ANGR-0001",
            SourceClass::Primary,
            FindingStatus::Proven,
        );
        let obs = observations_from_angr("httpd", &[finding], &selected.catalog);
        let writes: Vec<_> = obs
            .iter()
            .filter(|o| o.direction == OpDirection::Write)
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].family.as_deref(), Some("example-store"));
        assert_eq!(writes[0].grade, EvidenceGrade::Confirmed);
    }

    /// The no-profile negative at this consumer. The same finding that yields a
    /// classified write above yields no write observation at all when nothing
    /// was selected — a function name on its own never earns a role.
    #[test]
    fn without_a_profile_no_observation_is_given_a_role() {
        let catalog = SharedStateCatalog::empty();
        for sink in ["example_store_set", "nvram_set", "acosNvramConfig_set"] {
            let finding = make_angr_finding(
                "getenv",
                sink,
                "handle_request",
                "ANGR-0001",
                SourceClass::Primary,
                FindingStatus::Proven,
            );
            let obs = observations_from_angr("httpd", &[finding], &catalog);
            assert!(
                obs.iter().all(|o| o.direction != OpDirection::Write),
                "{sink} was classified as a write with no profile selected"
            );
        }
    }

    /// Nothing stitches without a profile, even when both halves of a chain are
    /// present and their names would pair under a profile that declared them.
    #[test]
    fn without_a_profile_nothing_stitches() {
        let catalog = SharedStateCatalog::empty();
        let writer = observations_from_angr(
            "httpd",
            &[make_angr_finding(
                "getenv",
                "example_store_set",
                "handle_request",
                "ANGR-0001",
                SourceClass::Primary,
                FindingStatus::Proven,
            )],
            &catalog,
        );
        let reader = observations_from_angr(
            "daemon",
            &[make_angr_finding(
                "example_store_get",
                "system",
                "apply",
                "ANGR-0002",
                SourceClass::Secondary,
                FindingStatus::Proven,
            )],
            &catalog,
        );
        let writes: Vec<&SharedStateObservation> = writer
            .iter()
            .filter(|o| o.direction == OpDirection::Write)
            .collect();
        let reads: Vec<&SharedStateObservation> = reader
            .iter()
            .filter(|o| o.direction == OpDirection::Read)
            .collect();
        assert!(writes.is_empty());
        assert!(stitch(&writes, &reads).is_empty());
    }

    /// Strings evidence is catalog-driven too: with no profile there are no
    /// patterns to match, so the heuristic contributes nothing.
    #[test]
    fn without_a_profile_the_strings_provider_contributes_nothing() {
        let catalog = SharedStateCatalog::empty();
        let data = b"\x00nvram_set(\"AdminPassword\")\x00example_bufset(\"x\")\x00";
        assert!(observations_from_strings("alphapd", data, &catalog).is_empty());
    }

    #[test]
    fn angr_read_observation_uses_the_selected_profile() {
        let selected = selected_catalog();
        let finding = make_angr_finding(
            "example_bufget",
            "system",
            "ipd_send",
            "ANGR-0002",
            SourceClass::Secondary,
            FindingStatus::Proven,
        );
        let obs = observations_from_angr("lanconfig", &[finding], &selected.catalog);
        let reads: Vec<_> = obs
            .iter()
            .filter(|o| o.direction == OpDirection::Read)
            .collect();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].family.as_deref(), Some("example-store"));
        assert_eq!(reads[0].sink.as_deref(), Some("system"));
        assert_eq!(reads[0].grade, EvidenceGrade::Confirmed);
    }

    #[test]
    fn secondary_fallback_produces_derived_observation_with_no_family() {
        let selected = selected_catalog();
        let finding = make_angr_finding(
            "unlisted_read_config",
            "system",
            "apply_config",
            "ANGR-0003",
            SourceClass::Secondary,
            FindingStatus::Candidate,
        );
        let obs = observations_from_angr("apply_daemon", &[finding], &selected.catalog);
        let reads: Vec<_> = obs
            .iter()
            .filter(|o| o.direction == OpDirection::Read)
            .collect();
        assert_eq!(reads.len(), 1);
        assert!(reads[0].family.is_none());
        assert_eq!(reads[0].grade, EvidenceGrade::Derived);
    }

    #[test]
    fn strings_observations_are_always_hints() {
        let selected = selected_catalog();
        let data = b"some text example_bufset(\"AdminPassword\") more text";
        let obs = observations_from_strings("alphapd", data, &selected.catalog);
        assert!(!obs.is_empty());
        for o in &obs {
            assert_eq!(o.grade, EvidenceGrade::Hint);
        }
    }

    #[test]
    fn strings_extracts_quoted_key() {
        let selected = selected_catalog();
        let data = b"\x00example_bufset(\"AdminPassword\")\x00other\x00";
        let obs = observations_from_strings("alphapd", data, &selected.catalog);
        let writes: Vec<_> = obs
            .iter()
            .filter(|o| o.direction == OpDirection::Write)
            .collect();
        assert!(!writes.is_empty());
        assert_eq!(writes[0].key.as_deref(), Some("AdminPassword"));
    }

    #[test]
    fn strings_dedup_preserves_distinct_keys() {
        let selected = selected_catalog();
        let data =
            b"\x00example_bufset(\"AdminPassword\")\x00\x00example_bufset(\"GuestPassword\")\x00";
        let obs = observations_from_strings("alphapd", data, &selected.catalog);
        let writes: Vec<_> = obs
            .iter()
            .filter(|o| o.direction == OpDirection::Write)
            .collect();
        let keys: Vec<_> = writes.iter().filter_map(|w| w.key.as_deref()).collect();
        assert!(keys.contains(&"AdminPassword"));
        assert!(keys.contains(&"GuestPassword"));
    }

    #[test]
    fn hint_without_key_corroboration_suppressed() {
        let write = SharedStateObservation {
            binary: "alphapd".into(),
            direction: OpDirection::Write,
            family: Some("example-store".to_string()),
            function: "example_bufset".into(),
            key: None, // no key
            sink: None,
            source: None,
            containing_function: None,
            provenance: Provenance {
                tool: "strings".into(),
                finding_id: None,
                detail: "".into(),
            },
            grade: EvidenceGrade::Hint,
        };
        let read = SharedStateObservation {
            binary: "lanconfig".into(),
            direction: OpDirection::Read,
            family: Some("example-store".to_string()),
            function: "example_bufget".into(),
            key: None,
            sink: Some("system".into()),
            source: None,
            containing_function: Some("ipd_send".into()),
            provenance: Provenance {
                tool: "angr".into(),
                finding_id: Some("ANGR-0005".into()),
                detail: "".into(),
            },
            grade: EvidenceGrade::Confirmed,
        };
        assert!(
            !should_emit(&write, &read),
            "Hint without key should be suppressed"
        );
    }

    #[test]
    fn hint_with_matching_key_emitted() {
        let write = SharedStateObservation {
            binary: "alphapd".into(),
            direction: OpDirection::Write,
            family: Some("example-store".to_string()),
            function: "example_bufset".into(),
            key: Some("AdminPassword".into()),
            sink: None,
            source: None,
            containing_function: None,
            provenance: Provenance {
                tool: "strings".into(),
                finding_id: None,
                detail: "".into(),
            },
            grade: EvidenceGrade::Hint,
        };
        let read = SharedStateObservation {
            binary: "lanconfig".into(),
            direction: OpDirection::Read,
            family: Some("example-store".to_string()),
            function: "example_bufget".into(),
            key: Some("AdminPassword".into()),
            sink: Some("system".into()),
            source: None,
            containing_function: Some("landap_change_idpassword".into()),
            provenance: Provenance {
                tool: "angr".into(),
                finding_id: Some("ANGR-0005".into()),
                detail: "".into(),
            },
            grade: EvidenceGrade::Confirmed,
        };
        assert!(
            should_emit(&write, &read),
            "Hint with matching key should be emitted"
        );
    }

    #[test]
    fn family_none_matches_a_declared_family() {
        assert!(families_match(Some("example-store"), None));
        assert!(families_match(None, Some("example-store")));
    }

    #[test]
    fn family_none_none_rejects() {
        assert!(!families_match(None, None));
    }

    #[test]
    fn unknown_key_cap_limits_candidates() {
        let write = SharedStateObservation {
            binary: "httpd".into(),
            direction: OpDirection::Write,
            family: Some("example-store".to_string()),
            function: "example_store_set".into(),
            key: None,
            sink: None,
            source: Some("getenv".into()),
            containing_function: Some("handler".into()),
            provenance: Provenance {
                tool: "angr".into(),
                finding_id: Some("A1".into()),
                detail: "".into(),
            },
            grade: EvidenceGrade::Confirmed,
        };

        // Create 5 reads with unknown keys
        let reads: Vec<SharedStateObservation> = (0..5)
            .map(|i| SharedStateObservation {
                binary: "daemon".into(),
                direction: OpDirection::Read,
                family: Some("example-store".to_string()),
                function: "example_store_get".into(),
                key: None,
                sink: Some("system".into()),
                source: None,
                containing_function: Some(format!("func_{i}")),
                provenance: Provenance {
                    tool: "angr".into(),
                    finding_id: Some(format!("R{i}")),
                    detail: "".into(),
                },
                grade: EvidenceGrade::Derived,
            })
            .collect();

        let write_refs = vec![&write];
        let read_refs: Vec<&SharedStateObservation> = reads.iter().collect();
        let findings = stitch(&write_refs, &read_refs);

        assert!(
            findings.len() <= MAX_CANDIDATES_PER_TRIPLE,
            "should cap at {} but got {}",
            MAX_CANDIDATES_PER_TRIPLE,
            findings.len()
        );
    }

    #[test]
    fn converts_cross_binary_findings_to_taint_contract() {
        let finding = CrossBinaryFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: "CROSS-0001".into(),
            title: "cross-binary admin password flow".into(),
            severity: "High".into(),
            write_obs: SharedStateObservation {
                binary: "/bin/writer".into(),
                direction: OpDirection::Write,
                family: Some("example-store".to_string()),
                function: "write_state".into(),
                key: Some("AdminPassword".into()),
                sink: None,
                source: Some("getenv".into()),
                containing_function: Some("handle_post".into()),
                provenance: Provenance {
                    tool: "angr".into(),
                    finding_id: Some("ANGR-WRITE".into()),
                    detail: "write detail".into(),
                },
                grade: EvidenceGrade::Confirmed,
            },
            read_obs: SharedStateObservation {
                binary: "/bin/reader".into(),
                direction: OpDirection::Read,
                family: Some("example-store".to_string()),
                function: "read_state".into(),
                key: Some("AdminPassword".into()),
                sink: Some("system".into()),
                source: None,
                containing_function: Some("apply_config".into()),
                provenance: Provenance {
                    tool: "angr".into(),
                    finding_id: Some("ANGR-READ".into()),
                    detail: "read detail".into(),
                },
                grade: EvidenceGrade::Confirmed,
            },
            shared_key: Some("AdminPassword".into()),
            shared_family: "example-store".into(),
            confidence: CrossConfidence::High,
            note: "test note".into(),
        };

        let taint_findings = cross_findings_to_taint_findings(&[finding]);

        assert_eq!(taint_findings.len(), 1);
        assert_eq!(taint_findings[0].id, "CROSS-0001");
        assert_eq!(taint_findings[0].chain.len(), 3);
        assert_eq!(taint_findings[0].chain[0].binary, "/bin/writer");
        assert_eq!(taint_findings[0].chain[0].function, "handle_post");
        assert!(taint_findings[0].chain[0]
            .location
            .contains("shared state example-store key AdminPassword"));
        assert_eq!(taint_findings[0].chain[1].function, "read_state");
        assert_eq!(
            taint_findings[0].chain.last().unwrap().binary,
            "/bin/reader"
        );
        assert_eq!(taint_findings[0].chain.last().unwrap().function, "system");
    }

    #[test]
    fn discover_binaries_nonexistent_rootfs() {
        let result = discover_binaries(Path::new("/nonexistent/rootfs"));
        assert!(result.is_err());
    }
}
