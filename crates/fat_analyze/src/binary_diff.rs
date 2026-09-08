// Binary-level diff module using radare2 as the primary backend.
//
// Compares two ELF binaries by extracting function lists and strings via r2,
// then matching functions across versions and detecting security-relevant changes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::string_diff::{classify_string, diff_library_versions, LibraryVersionDiff};

pub mod types {
    use super::*;

    /// A function entry as returned by `r2 -q -c "aaa; aflj"`.
    /// Modern r2 (6.x+) uses `addr`; older versions used `offset`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct R2Function {
        pub name: String,
        /// Function address. Modern r2 emits `addr`, older emits `offset`.
        #[serde(alias = "offset")]
        pub addr: u64,
        pub size: u64,
        #[serde(default)]
        pub ninstrs: u64,
    }

    /// A string entry as returned by `r2 -q -c "izj"`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct R2String {
        pub vaddr: u64,
        pub string: String,
        #[serde(default)]
        pub length: u64,
    }

    /// Summary of function-level differences between two binaries.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct FunctionDiffSummary {
        pub total_base: usize,
        pub total_head: usize,
        pub matched: usize,
        pub changed: usize,
        pub added: usize,
        pub removed: usize,
        pub changed_functions: Vec<FunctionChange>,
        pub added_functions: Vec<FunctionEntry>,
        pub removed_functions: Vec<FunctionEntry>,
    }

    /// A matched function that changed between base and head.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct FunctionChange {
        pub name: String,
        pub base_address: String,
        pub head_address: String,
        pub base_size: u64,
        pub head_size: u64,
        pub similarity: f64,
        pub change_summary: String,
        pub security_tags: Vec<String>,
    }

    /// A function entry present in only one side of the diff.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct FunctionEntry {
        pub name: String,
        pub address: String,
        pub size: u64,
    }

    /// Result of a function match between base and head.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct FunctionMatch {
        pub base_name: String,
        pub head_name: String,
        pub base_offset: u64,
        pub head_offset: u64,
        pub base_size: u64,
        pub head_size: u64,
        pub base_ninstrs: u64,
        pub head_ninstrs: u64,
        pub similarity: f64,
        pub match_method: String,
    }

    /// Diff of strings between two binaries.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct StringDiff {
        pub added: Vec<StringEntry>,
        pub removed: Vec<StringEntry>,
    }

    /// A string entry with optional security classification.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct StringEntry {
        pub value: String,
        pub address: String,
        pub security_tag: Option<String>,
    }

    /// A security-relevant change detected during binary diff.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct SecurityRelevantChange {
        pub change_type: String,
        pub function_name: String,
        pub detail: String,
        pub severity: String,
    }

    /// An import entry from a binary's import table.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ImportEntry {
        pub name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub library: Option<String>,
    }

    /// An export entry from a binary's export table.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ExportEntry {
        pub name: String,
        pub size: u64,
    }

    /// Diff of imports and exports between two binaries.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ImportExportDiff {
        pub added_imports: Vec<ImportEntry>,
        pub removed_imports: Vec<ImportEntry>,
        pub added_exports: Vec<ExportEntry>,
        pub removed_exports: Vec<ExportEntry>,
    }

    /// Exploit mitigation comparison between two versions of a binary.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct MitigationDiff {
        pub base_canary: bool,
        pub head_canary: bool,
        pub base_nx: bool,
        pub head_nx: bool,
        pub base_pie: bool,
        pub head_pie: bool,
        pub base_relro: String,
        pub head_relro: String,
        pub regressions: Vec<String>,
        pub improvements: Vec<String>,
    }

    /// Top-level result of comparing two binaries.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct BinaryDiffResult {
        pub binary_path: String,
        pub base_size: u64,
        pub head_size: u64,
        pub base_hash: String,
        pub head_hash: String,
        pub function_summary: FunctionDiffSummary,
        pub string_diff: StringDiff,
        pub import_export_diff: ImportExportDiff,
        pub mitigation_diff: Option<MitigationDiff>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub library_versions: Vec<LibraryVersionDiff>,
        pub security_relevant_changes: Vec<SecurityRelevantChange>,
    }
}

// ====================================================================
// R2 deserialization helpers for imports/exports
// ====================================================================

#[derive(Debug, Clone, Deserialize)]
struct R2ImportEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    lib: String,
}

#[derive(Debug, Clone, Deserialize)]
struct R2ExportEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: u64,
}

// ====================================================================
// R2 invocation functions
// ====================================================================

/// Call r2 to extract the import table from a binary.
///
/// Runs `r2 -q -c "iij" <binary>` and parses the JSON output.
pub fn r2_imports(binary: &Path) -> anyhow::Result<Vec<types::ImportEntry>> {
    let output = Command::new("r2")
        .args(["-q", "-c", "iij", &binary.display().to_string()])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "r2 (radare2) not found or failed to execute: {e}. \
                 Install radare2 for binary diff support."
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "r2 iij exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let entries: Vec<R2ImportEntry> = serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse r2 iij JSON output: {e}"))?;

    Ok(entries
        .into_iter()
        .map(|e| types::ImportEntry {
            name: e.name,
            library: if e.lib.is_empty() { None } else { Some(e.lib) },
        })
        .collect())
}

/// Call r2 to extract the export table from a binary.
///
/// Runs `r2 -q -c "iEj" <binary>` and parses the JSON output.
pub fn r2_exports(binary: &Path) -> anyhow::Result<Vec<types::ExportEntry>> {
    let output = Command::new("r2")
        .args(["-q", "-c", "iEj", &binary.display().to_string()])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "r2 (radare2) not found or failed to execute: {e}. \
                 Install radare2 for binary diff support."
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "r2 iEj exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let entries: Vec<R2ExportEntry> = serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse r2 iEj JSON output: {e}"))?;

    Ok(entries
        .into_iter()
        .map(|e| types::ExportEntry {
            name: e.name,
            size: e.size,
        })
        .collect())
}

/// Call r2 to extract the full symbol table from a binary.
///
/// Runs `r2 -q -c "isj" <binary>` and returns symbol names.
pub fn r2_symbols(binary: &Path) -> anyhow::Result<Vec<String>> {
    let output = Command::new("r2")
        .args(["-q", "-c", "isj", &binary.display().to_string()])
        .output()
        .map_err(|e| anyhow::anyhow!("r2 (radare2) not found or failed to execute: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "r2 isj exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let entries: Vec<serde_json::Value> = serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse r2 isj JSON output: {e}"))?;

    Ok(entries
        .into_iter()
        .filter_map(|e| {
            e.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect())
}

/// Call r2 to extract function list from a binary.
///
/// Runs `r2 -q -c "aaa; aflj" <binary>` and parses the JSON output.
/// Architecture is auto-detected by r2 from the ELF headers.
/// Returns a clear error if r2 is not found on PATH.
pub fn r2_function_list(binary: &Path) -> anyhow::Result<Vec<types::R2Function>> {
    let output = Command::new("r2")
        .args(["-q", "-c", "aaa; aflj", &binary.display().to_string()])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "r2 (radare2) not found or failed to execute: {e}. \
                 Install radare2 for binary diff support."
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "r2 exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse r2 aflj JSON output: {e}"))
}

/// Call r2 to extract strings from a binary.
///
/// Runs `r2 -q -c "izj" <binary>` and parses the JSON output.
/// Returns a clear error if r2 is not found on PATH.
pub fn r2_strings(binary: &Path) -> anyhow::Result<Vec<types::R2String>> {
    let output = Command::new("r2")
        .args(["-q", "-c", "izj", &binary.display().to_string()])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "r2 (radare2) not found or failed to execute: {e}. \
                 Install radare2 for binary diff support."
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "r2 exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse r2 izj JSON output: {e}"))
}

// ====================================================================
// Function matching algorithm
// ====================================================================

/// Compute similarity between two functions based on size and instruction count.
///
/// Returns 1.0 for identical sizes, decreasing toward 0.0 as sizes diverge.
fn compute_similarity(base: &types::R2Function, head: &types::R2Function) -> f64 {
    let max_size = base.size.max(head.size) as f64;
    if max_size == 0.0 {
        return 1.0;
    }
    let size_ratio = 1.0 - ((base.size as f64 - head.size as f64).abs() / max_size);

    let max_instrs = base.ninstrs.max(head.ninstrs) as f64;
    let instrs_ratio = if max_instrs == 0.0 {
        1.0
    } else {
        1.0 - ((base.ninstrs as f64 - head.ninstrs as f64).abs() / max_instrs)
    };

    // Weighted average: size contributes 60%, instruction count 40%
    (size_ratio * 0.6) + (instrs_ratio * 0.4)
}

/// Returns true if the function name looks auto-generated (stripped binary).
fn is_synthetic_name(name: &str) -> bool {
    name.starts_with("fcn.") || name.starts_with("sub_") || name.starts_with("entry")
}

/// Multi-pass function matching between base and head function lists.
///
/// Matching passes in priority order:
/// 1. Exact name match (only for non-synthetic names)
/// 2. Exact size + instruction count match
/// 3. Fuzzy size within 20% threshold
///
/// Once a head function is matched, it is removed from the candidate pool
/// to prevent double-matching.
pub fn match_functions(
    base: &[types::R2Function],
    head: &[types::R2Function],
) -> Vec<types::FunctionMatch> {
    let mut matches = Vec::new();
    let mut matched_head_indices: BTreeSet<usize> = BTreeSet::new();
    let mut matched_base_indices: BTreeSet<usize> = BTreeSet::new();

    // Pass 1: Exact name match (skip synthetic names like fcn.*, sub_*, entry*)
    for (bi, base_fn) in base.iter().enumerate() {
        if is_synthetic_name(&base_fn.name) {
            continue;
        }
        for (hi, head_fn) in head.iter().enumerate() {
            if matched_head_indices.contains(&hi) {
                continue;
            }
            if base_fn.name == head_fn.name {
                let similarity = compute_similarity(base_fn, head_fn);
                matches.push(types::FunctionMatch {
                    base_name: base_fn.name.clone(),
                    head_name: head_fn.name.clone(),
                    base_offset: base_fn.addr,
                    head_offset: head_fn.addr,
                    base_size: base_fn.size,
                    head_size: head_fn.size,
                    base_ninstrs: base_fn.ninstrs,
                    head_ninstrs: head_fn.ninstrs,
                    similarity,
                    match_method: "exact_name".to_string(),
                });
                matched_head_indices.insert(hi);
                matched_base_indices.insert(bi);
                break;
            }
        }
    }

    // Pass 2: Exact size + instruction count match (for unmatched functions)
    for (bi, base_fn) in base.iter().enumerate() {
        if matched_base_indices.contains(&bi) {
            continue;
        }
        for (hi, head_fn) in head.iter().enumerate() {
            if matched_head_indices.contains(&hi) {
                continue;
            }
            if base_fn.size == head_fn.size && base_fn.ninstrs == head_fn.ninstrs {
                matches.push(types::FunctionMatch {
                    base_name: base_fn.name.clone(),
                    head_name: head_fn.name.clone(),
                    base_offset: base_fn.addr,
                    head_offset: head_fn.addr,
                    base_size: base_fn.size,
                    head_size: head_fn.size,
                    base_ninstrs: base_fn.ninstrs,
                    head_ninstrs: head_fn.ninstrs,
                    similarity: 1.0,
                    match_method: "size_instrs".to_string(),
                });
                matched_head_indices.insert(hi);
                matched_base_indices.insert(bi);
                break;
            }
        }
    }

    // Pass 3: Fuzzy size match within 20% threshold (for remaining unmatched)
    for (bi, base_fn) in base.iter().enumerate() {
        if matched_base_indices.contains(&bi) {
            continue;
        }
        let mut best_candidate: Option<(usize, f64)> = None;

        for (hi, head_fn) in head.iter().enumerate() {
            if matched_head_indices.contains(&hi) {
                continue;
            }
            let max_size = base_fn.size.max(head_fn.size) as f64;
            if max_size == 0.0 {
                continue;
            }
            let size_diff_ratio = (base_fn.size as f64 - head_fn.size as f64).abs() / max_size;

            // Within 20% size threshold
            if size_diff_ratio <= 0.20 {
                let sim = compute_similarity(base_fn, head_fn);
                if best_candidate.is_none_or(|(_, best_sim)| sim > best_sim) {
                    best_candidate = Some((hi, sim));
                }
            }
        }

        if let Some((hi, similarity)) = best_candidate {
            let head_fn = &head[hi];
            matches.push(types::FunctionMatch {
                base_name: base_fn.name.clone(),
                head_name: head_fn.name.clone(),
                base_offset: base_fn.addr,
                head_offset: head_fn.addr,
                base_size: base_fn.size,
                head_size: head_fn.size,
                base_ninstrs: base_fn.ninstrs,
                head_ninstrs: head_fn.ninstrs,
                similarity,
                match_method: "fuzzy_size".to_string(),
            });
            matched_head_indices.insert(hi);
            matched_base_indices.insert(bi);
        }
    }

    matches
}

// ====================================================================
// String diff for r2-extracted strings
// ====================================================================

/// Diff strings from two binaries and classify them by security relevance.
///
/// Comparison is value-based (addresses may differ between versions).
pub fn diff_strings(base: &[types::R2String], head: &[types::R2String]) -> types::StringDiff {
    let base_values: BTreeSet<&str> = base.iter().map(|s| s.string.as_str()).collect();
    let head_values: BTreeSet<&str> = head.iter().map(|s| s.string.as_str()).collect();

    let added = head
        .iter()
        .filter(|s| !base_values.contains(s.string.as_str()))
        .map(|s| types::StringEntry {
            value: s.string.clone(),
            address: format!("0x{:x}", s.vaddr),
            security_tag: classify_string(&s.string).map(|t| t.to_string()),
        })
        .collect::<Vec<_>>();

    let removed = base
        .iter()
        .filter(|s| !head_values.contains(s.string.as_str()))
        .map(|s| types::StringEntry {
            value: s.string.clone(),
            address: format!("0x{:x}", s.vaddr),
            security_tag: classify_string(&s.string).map(|t| t.to_string()),
        })
        .collect::<Vec<_>>();

    // Deduplicate by value (same string may appear at multiple addresses)
    let mut seen_added = BTreeSet::new();
    let added = added
        .into_iter()
        .filter(|e| seen_added.insert(e.value.clone()))
        .collect();

    let mut seen_removed = BTreeSet::new();
    let removed = removed
        .into_iter()
        .filter(|e| seen_removed.insert(e.value.clone()))
        .collect();

    types::StringDiff { added, removed }
}

// ====================================================================
// Import/export diffing
// ====================================================================

/// Diff imports between two binaries.
pub fn diff_imports_exports(
    base_imports: &[types::ImportEntry],
    head_imports: &[types::ImportEntry],
    base_exports: &[types::ExportEntry],
    head_exports: &[types::ExportEntry],
) -> types::ImportExportDiff {
    let base_import_names: BTreeSet<&str> = base_imports.iter().map(|i| i.name.as_str()).collect();
    let head_import_names: BTreeSet<&str> = head_imports.iter().map(|i| i.name.as_str()).collect();
    let base_export_names: BTreeSet<&str> = base_exports.iter().map(|e| e.name.as_str()).collect();
    let head_export_names: BTreeSet<&str> = head_exports.iter().map(|e| e.name.as_str()).collect();

    let added_imports = head_imports
        .iter()
        .filter(|i| !base_import_names.contains(i.name.as_str()))
        .cloned()
        .collect();
    let removed_imports = base_imports
        .iter()
        .filter(|i| !head_import_names.contains(i.name.as_str()))
        .cloned()
        .collect();
    let added_exports = head_exports
        .iter()
        .filter(|e| !base_export_names.contains(e.name.as_str()))
        .cloned()
        .collect();
    let removed_exports = base_exports
        .iter()
        .filter(|e| !head_export_names.contains(e.name.as_str()))
        .cloned()
        .collect();

    types::ImportExportDiff {
        added_imports,
        removed_imports,
        added_exports,
        removed_exports,
    }
}

// ====================================================================
// Exploit mitigation extraction and diff
// ====================================================================

/// Simple mitigation profile extracted from `rabin2 -Ij`.
#[derive(Debug, Clone)]
struct MitigationProfile {
    canary: bool,
    nx: bool,
    pie: bool,
    relro: String,
}

/// Extract mitigation profile via rabin2.
fn extract_mitigations(binary: &Path) -> Option<MitigationProfile> {
    let output = Command::new("rabin2")
        .args(["-Ij", &binary.display().to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let info = val.get("info")?;

    Some(MitigationProfile {
        canary: info
            .get("canary")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        nx: info.get("nx").and_then(|v| v.as_bool()).unwrap_or(false),
        pie: info.get("pic").and_then(|v| v.as_bool()).unwrap_or(false),
        relro: info
            .get("relro")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string(),
    })
}

/// Compare mitigation profiles and identify regressions/improvements.
fn diff_mitigations(base: &MitigationProfile, head: &MitigationProfile) -> types::MitigationDiff {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();

    if base.canary && !head.canary {
        regressions.push("stack canary removed".to_string());
    } else if !base.canary && head.canary {
        improvements.push("stack canary added".to_string());
    }

    if base.nx && !head.nx {
        regressions.push("NX (no-execute) removed".to_string());
    } else if !base.nx && head.nx {
        improvements.push("NX (no-execute) added".to_string());
    }

    if base.pie && !head.pie {
        regressions.push("PIE removed".to_string());
    } else if !base.pie && head.pie {
        improvements.push("PIE added".to_string());
    }

    let relro_level = |s: &str| match s {
        "full" => 2,
        "partial" => 1,
        _ => 0,
    };
    let base_relro = relro_level(&base.relro);
    let head_relro = relro_level(&head.relro);
    if head_relro < base_relro {
        regressions.push(format!(
            "RELRO downgraded: {} -> {}",
            base.relro, head.relro
        ));
    } else if head_relro > base_relro {
        improvements.push(format!("RELRO upgraded: {} -> {}", base.relro, head.relro));
    }

    types::MitigationDiff {
        base_canary: base.canary,
        head_canary: head.canary,
        base_nx: base.nx,
        head_nx: head.nx,
        base_pie: base.pie,
        head_pie: head.pie,
        base_relro: base.relro.clone(),
        head_relro: head.relro.clone(),
        regressions,
        improvements,
    }
}

// ====================================================================
// Security change detection
// ====================================================================

/// Security-relevant function name patterns that indicate validation/auth logic.
const SECURITY_FUNCTION_PATTERNS: &[&str] = &[
    "check", "auth", "valid", "verify", "sanitize", "filter", "guard",
];

/// Detect security-relevant changes from function matches, string diff, and import/export diff.
///
/// Detects:
/// - New dangerous imports (system/popen/exec from import table — ground truth)
/// - New dangerous calls (system/popen/exec strings added — heuristic)
/// - Removed validation (security-related functions significantly shrunk)
/// - New/removed endpoints
/// - Credential changes
pub fn detect_security_changes(
    matches: &[types::FunctionMatch],
    strings: &types::StringDiff,
    ie_diff: &types::ImportExportDiff,
) -> Vec<types::SecurityRelevantChange> {
    let mut changes = Vec::new();

    // Detect dangerous imports (ground truth from import table)
    const DANGEROUS_IMPORTS: &[&str] = &[
        "system", "popen", "execve", "execvp", "execl", "execlp", "dlopen",
    ];
    for imp in &ie_diff.added_imports {
        let name_lower = imp.name.to_lowercase();
        if DANGEROUS_IMPORTS.iter().any(|d| name_lower.contains(d)) {
            changes.push(types::SecurityRelevantChange {
                change_type: "dangerous_import_added".to_string(),
                function_name: String::new(),
                detail: format!(
                    "New import: {} (from {})",
                    imp.name,
                    imp.library.as_deref().unwrap_or("unknown")
                ),
                severity: "high".to_string(),
            });
        }
    }

    // Detect security-relevant string additions
    for entry in &strings.added {
        if let Some(ref tag) = entry.security_tag {
            let (change_type, severity) = match tag.as_str() {
                "DANGEROUS_CALL" => ("dangerous_call_added", "high"),
                "CREDENTIAL" => ("credential_added", "high"),
                "ENDPOINT" => ("endpoint_added", "medium"),
                "CRYPTO" => ("crypto_change_added", "medium"),
                "DEBUG" => ("debug_interface_added", "medium"),
                "NETWORK" => ("network_change_added", "low"),
                _ => continue,
            };
            changes.push(types::SecurityRelevantChange {
                change_type: change_type.to_string(),
                function_name: String::new(),
                detail: format!("New {} string: \"{}\"", tag, entry.value),
                severity: severity.to_string(),
            });
        }
    }

    // Detect security-relevant string removals
    for entry in &strings.removed {
        if let Some(ref tag) = entry.security_tag {
            let (change_type, severity) = match tag.as_str() {
                "DANGEROUS_CALL" => ("dangerous_call_removed", "info"),
                "ENDPOINT" => ("endpoint_removed", "info"),
                "CREDENTIAL" => ("credential_removed", "info"),
                "CRYPTO" => ("crypto_change_removed", "medium"),
                _ => continue,
            };
            changes.push(types::SecurityRelevantChange {
                change_type: change_type.to_string(),
                function_name: String::new(),
                detail: format!("Removed {} string: \"{}\"", tag, entry.value),
                severity: severity.to_string(),
            });
        }
    }

    // Detect significantly shrunk security-related functions (possible validation removal)
    for m in matches {
        let name_lower = m.base_name.to_lowercase();
        let is_security_fn = SECURITY_FUNCTION_PATTERNS
            .iter()
            .any(|pat| name_lower.contains(pat));

        if !is_security_fn {
            continue;
        }

        // Significant shrinkage: head size is less than 50% of base size
        if m.base_size > 0 && m.head_size < m.base_size / 2 {
            changes.push(types::SecurityRelevantChange {
                change_type: "validation_possibly_removed".to_string(),
                function_name: m.base_name.clone(),
                detail: format!(
                    "Security function \"{}\" shrunk from {} to {} bytes ({:.0}% reduction)",
                    m.base_name,
                    m.base_size,
                    m.head_size,
                    (1.0 - (m.head_size as f64 / m.base_size as f64)) * 100.0
                ),
                severity: "high".to_string(),
            });
        }
    }

    changes
}

// ====================================================================
// Top-level orchestration
// ====================================================================

/// Compute SHA-256 hash of a file.
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Orchestrate a full binary diff between base and head.
///
/// Extracts function lists and strings via r2, matches functions across versions,
/// diffs strings, and detects security-relevant changes.
pub fn diff_binary(base: &Path, head: &Path) -> anyhow::Result<types::BinaryDiffResult> {
    let base_meta = std::fs::metadata(base)?;
    let head_meta = std::fs::metadata(head)?;
    let base_hash = sha256_file(base)?;
    let head_hash = sha256_file(head)?;

    let base_functions = r2_function_list(base)?;
    let head_functions = r2_function_list(head)?;

    let base_strings = r2_strings(base)?;
    let head_strings = r2_strings(head)?;

    let base_imports = r2_imports(base).unwrap_or_default();
    let head_imports = r2_imports(head).unwrap_or_default();
    let base_exports = r2_exports(base).unwrap_or_default();
    let head_exports = r2_exports(head).unwrap_or_default();

    let function_matches = match_functions(&base_functions, &head_functions);
    let string_diff = diff_strings(&base_strings, &head_strings);

    // Extract library versions from strings
    let base_str_values: Vec<String> = base_strings.iter().map(|s| s.string.clone()).collect();
    let head_str_values: Vec<String> = head_strings.iter().map(|s| s.string.clone()).collect();
    let library_versions = diff_library_versions(&base_str_values, &head_str_values);

    let import_export_diff =
        diff_imports_exports(&base_imports, &head_imports, &base_exports, &head_exports);

    // Exploit mitigation comparison via rabin2
    let mitigation_diff = match (extract_mitigations(base), extract_mitigations(head)) {
        (Some(base_mit), Some(head_mit)) => Some(diff_mitigations(&base_mit, &head_mit)),
        _ => None,
    };

    let mut security_relevant_changes =
        detect_security_changes(&function_matches, &string_diff, &import_export_diff);

    // Add mitigation regressions as high-severity security changes
    if let Some(ref mit) = mitigation_diff {
        for regression in &mit.regressions {
            security_relevant_changes.push(types::SecurityRelevantChange {
                change_type: "mitigation_regression".to_string(),
                function_name: String::new(),
                detail: regression.clone(),
                severity: "high".to_string(),
            });
        }
    }

    // Build function summary
    let matched_base_names: BTreeSet<&str> = function_matches
        .iter()
        .map(|m| m.base_name.as_str())
        .collect();
    let matched_head_names: BTreeSet<&str> = function_matches
        .iter()
        .map(|m| m.head_name.as_str())
        .collect();

    let changed_functions: Vec<types::FunctionChange> = function_matches
        .iter()
        .filter(|m| m.similarity < 1.0)
        .map(|m| types::FunctionChange {
            name: m.base_name.clone(),
            base_address: format!("0x{:x}", m.base_offset),
            head_address: format!("0x{:x}", m.head_offset),
            base_size: m.base_size,
            head_size: m.head_size,
            similarity: m.similarity,
            change_summary: format!(
                "Matched by {}; similarity {:.2}",
                m.match_method, m.similarity
            ),
            security_tags: Vec::new(),
        })
        .collect();

    let added_functions: Vec<types::FunctionEntry> = head_functions
        .iter()
        .filter(|f| !matched_head_names.contains(f.name.as_str()))
        .map(|f| types::FunctionEntry {
            name: f.name.clone(),
            address: format!("0x{:x}", f.addr),
            size: f.size,
        })
        .collect();

    let removed_functions: Vec<types::FunctionEntry> = base_functions
        .iter()
        .filter(|f| !matched_base_names.contains(f.name.as_str()))
        .map(|f| types::FunctionEntry {
            name: f.name.clone(),
            address: format!("0x{:x}", f.addr),
            size: f.size,
        })
        .collect();

    let function_summary = types::FunctionDiffSummary {
        total_base: base_functions.len(),
        total_head: head_functions.len(),
        matched: function_matches.len(),
        changed: changed_functions.len(),
        added: added_functions.len(),
        removed: removed_functions.len(),
        changed_functions,
        added_functions,
        removed_functions,
    };

    Ok(types::BinaryDiffResult {
        binary_path: base.display().to_string(),
        base_size: base_meta.len(),
        head_size: head_meta.len(),
        base_hash,
        head_hash,
        function_summary,
        string_diff,
        import_export_diff,
        mitigation_diff,
        library_versions,
        security_relevant_changes,
    })
}
