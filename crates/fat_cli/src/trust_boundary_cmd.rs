use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use crate::schema_versions;
use fat_taint::recon::trust_boundary::{
    analyze_rootfs, check_rabin2, BinaryRole, DependencyChain, Evidence, TrustBoundaryReport,
};
use serde::Serialize;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderMode {
    TrustBoundary,
    TrustMap,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq, Eq)]
pub(crate) struct TrustTierCounts {
    pub(crate) executed_entrypoint: usize,
    pub(crate) linked_dependency: usize,
    pub(crate) crypto_or_verify_symbol: usize,
    pub(crate) string_hint: usize,
    pub(crate) artifact_only: usize,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct TrustCandidateSummary {
    pub(crate) candidate_classification: String,
    pub(crate) score: f64,
    pub(crate) path_confidence: String,
    pub(crate) tier_counts: TrustTierCounts,
    pub(crate) negative_evidence: Vec<String>,
    pub(crate) why: Vec<String>,
}

pub fn run(rootfs: &Path, json: bool, mode: RenderMode) -> DynResult<()> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }

    check_rabin2().map_err(|e| -> Box<dyn Error> { e.into() })?;

    eprintln!("Scanning rootfs: {}", rootfs.display());

    let report = analyze_rootfs(rootfs).map_err(|e| -> Box<dyn Error> { e.into() })?;

    if json {
        match mode {
            RenderMode::TrustBoundary => println!("{}", serde_json::to_string_pretty(&report)?),
            RenderMode::TrustMap => {
                let trust_map = build_trust_map_json_report(&report);
                println!("{}", serde_json::to_string_pretty(&trust_map)?);
            }
        }
    } else {
        match mode {
            RenderMode::TrustBoundary => render_report(&report),
            RenderMode::TrustMap => render_trust_map_report(&report),
        }
    }

    Ok(())
}

fn render_report(report: &TrustBoundaryReport) {
    println!(
        "Trust boundary analysis: {} ({} binaries scanned)\n",
        report.rootfs_path, report.binaries_scanned,
    );

    // -- Firmware update path --
    if !report.update_binaries.is_empty() {
        println!("Firmware update path");
        for bin in &report.update_binaries {
            render_binary_role(bin);
        }
        println!();
    } else {
        println!("Firmware update path: (none identified)\n");
    }

    // -- Authentication --
    if !report.auth_binaries.is_empty() {
        println!("Authentication");
        for bin in &report.auth_binaries {
            render_binary_role(bin);
        }
        println!();
    } else {
        println!("Authentication: (none identified)\n");
    }

    // -- Crypto usage --
    if !report.crypto_binaries.is_empty() {
        println!("Crypto usage");
        for bin in &report.crypto_binaries {
            render_binary_role(bin);
        }
        println!();
    } else {
        println!("Crypto usage: (none identified)\n");
    }

    // -- Dependency chains --
    if !report.dependency_chains.is_empty() {
        println!("Dependency chains");
        for chain in &report.dependency_chains {
            render_chain(chain);
        }
        println!();
    }
}

#[derive(Clone)]
struct TrustBearingBinary {
    path: String,
    labels: Vec<String>,
    evidence: Vec<Evidence>,
    linked_libraries: Vec<String>,
    score: f64,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct TrustMapJsonReport {
    pub(crate) schema_version: &'static str,
    pub(crate) rootfs_path: String,
    pub(crate) binaries_scanned: usize,
    pub(crate) classification: String,
    pub(crate) confidence: String,
    pub(crate) reason: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) governing_update_path: Option<TrustMapCandidateJson>,
    pub(crate) candidates: Vec<TrustMapCandidateJson>,
    pub(crate) dependency_chains: Vec<DependencyChain>,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct TrustMapCandidateJson {
    pub(crate) path: String,
    pub(crate) candidate_role: String,
    pub(crate) candidate_classification: String,
    pub(crate) score: f64,
    pub(crate) update_path_score: f64,
    pub(crate) path_confidence: String,
    pub(crate) tier_counts: TrustTierCounts,
    pub(crate) negative_evidence: Vec<String>,
    pub(crate) why: Vec<String>,
    pub(crate) on_governing_path: bool,
    pub(crate) linked_libraries: Vec<String>,
    pub(crate) evidence: Vec<Evidence>,
}

pub(crate) fn stable_score_bucket(candidate_classification: &str) -> u8 {
    match candidate_classification {
        "governing-updater" => 0,
        "supporting-boundary" | "supporting-crypto-lib" => 1,
        "helper-only" => 2,
        _ => 3,
    }
}

fn render_trust_map_report(report: &TrustBoundaryReport) {
    let trust_map = build_trust_map_json_report(report);

    println!(
        "Trust map: {} ({} binaries scanned)\n",
        trust_map.rootfs_path, trust_map.binaries_scanned,
    );

    if let Some(primary) = &trust_map.governing_update_path {
        println!("Governing update path");
        println!("  {}", primary.path);
        println!(
            "    candidate classification: {}",
            primary.candidate_classification
        );
        println!("    score: {:.2}", primary.score);
        println!("    path confidence: {}", primary.path_confidence);
        println!("    why:");
        for line in primary.why.iter().take(3) {
            println!("      - {line}");
        }
        println!();
    } else {
        println!("Governing update path: (none identified)\n");
    }

    println!("Trust-bearing binaries");
    for binary in &trust_map.candidates {
        println!("  {}", binary.path);
        println!("    role: {}", binary.candidate_role);
        println!(
            "    candidate classification: {}",
            binary.candidate_classification
        );
        println!("    score: {:.2}", binary.score);
        println!("    path confidence: {}", binary.path_confidence);
        if !binary.linked_libraries.is_empty() {
            println!("    links: {}", binary.linked_libraries.join(", "));
        }
        println!("    why:");
        for line in binary.why.iter().take(3) {
            println!("      - {line}");
        }
        if !binary.negative_evidence.is_empty() {
            println!("    negative evidence:");
            for line in binary.negative_evidence.iter().take(3) {
                println!("      - {line}");
            }
        }
    }
    println!();

    if !trust_map.dependency_chains.is_empty() {
        println!("Dependency chains");
        for chain in &trust_map.dependency_chains {
            render_chain(chain);
        }
        println!();
    }
}

fn merge_roles(report: &TrustBoundaryReport) -> Vec<TrustBearingBinary> {
    let mut merged: BTreeMap<String, TrustBearingBinary> = BTreeMap::new();
    for role in report
        .update_binaries
        .iter()
        .chain(report.auth_binaries.iter())
        .chain(report.crypto_binaries.iter())
    {
        let entry = merged
            .entry(role.path.clone())
            .or_insert_with(|| TrustBearingBinary {
                path: role.path.clone(),
                labels: Vec::new(),
                evidence: Vec::new(),
                linked_libraries: role.linked_libraries.clone(),
                score: 0.0,
            });
        let label = role_label(role);
        if !entry.labels.contains(&label) {
            entry.labels.push(label);
        }
        entry.linked_libraries = role.linked_libraries.clone();
        for ev in role.evidence.iter().take(4) {
            if !entry
                .evidence
                .iter()
                .any(|existing| existing.detail == ev.detail)
            {
                entry.evidence.push(ev.clone());
            }
        }
        entry.score = entry.score.max(score_role(role));
    }
    merged.into_values().collect()
}

pub(crate) fn build_trust_map_json_report(report: &TrustBoundaryReport) -> TrustMapJsonReport {
    let governing = report
        .update_binaries
        .iter()
        .max_by(|a, b| score_role(a).total_cmp(&score_role(b)));
    let governing_path = governing.map(|role| role.path.clone());
    let governing_libs = governing
        .map(|role| role.linked_libraries.clone())
        .unwrap_or_default();
    let merged = merge_roles(report);

    let mut candidates = merged
        .into_iter()
        .map(|binary| {
            let source_role = report
                .update_binaries
                .iter()
                .chain(report.auth_binaries.iter())
                .chain(report.crypto_binaries.iter())
                .find(|role| role.path == binary.path);
            let candidate_role = binary
                .labels
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            let on_governing_path = governing_path
                .as_ref()
                .is_some_and(|path| *path == binary.path);
            let linked_from_governing_path = source_role
                .map(|_| {
                    linked_from_governing_path(
                        &binary.path,
                        governing_path.as_deref(),
                        &governing_libs,
                        &report.dependency_chains,
                    )
                })
                .unwrap_or(false);
            let summary = source_role
                .map(|role| {
                    summarize_candidate(role, on_governing_path, linked_from_governing_path)
                })
                .unwrap_or_else(|| TrustCandidateSummary {
                    candidate_classification: "out-of-path".into(),
                    score: 0.0,
                    path_confidence: "low".into(),
                    tier_counts: TrustTierCounts::default(),
                    negative_evidence: vec!["artifact present without trust evidence".into()],
                    why: Vec::new(),
                });
            let why = binary
                .evidence
                .iter()
                .take(3)
                .map(|evidence| evidence.detail.clone())
                .collect();
            TrustMapCandidateJson {
                path: binary.path.clone(),
                candidate_role,
                candidate_classification: summary.candidate_classification,
                score: summary.score,
                update_path_score: summary.score,
                path_confidence: summary.path_confidence,
                tier_counts: summary.tier_counts,
                negative_evidence: summary.negative_evidence,
                why: if summary.why.is_empty() {
                    why
                } else {
                    summary.why
                },
                on_governing_path,
                linked_libraries: binary.linked_libraries.clone(),
                evidence: binary.evidence.clone(),
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        stable_score_bucket(&left.candidate_classification)
            .cmp(&stable_score_bucket(&right.candidate_classification))
            .then_with(|| right.score.total_cmp(&left.score))
            .then_with(|| left.path.cmp(&right.path))
    });

    let governing_update_path = governing.map(|role| {
        let summary = summarize_candidate(role, true, false);
        TrustMapCandidateJson {
            path: role.path.clone(),
            candidate_role: role_label(role),
            candidate_classification: summary.candidate_classification,
            score: summary.score,
            update_path_score: summary.score,
            path_confidence: summary.path_confidence,
            tier_counts: summary.tier_counts,
            negative_evidence: summary.negative_evidence,
            why: summary.why,
            on_governing_path: true,
            linked_libraries: role.linked_libraries.clone(),
            evidence: role.evidence.clone(),
        }
    });
    let (classification, confidence, reason, evidence) =
        summarize_trust_map_contract(&governing_update_path, &candidates);

    TrustMapJsonReport {
        schema_version: schema_versions::TRUST_PATH_ANALYSIS_V1,
        rootfs_path: report.rootfs_path.clone(),
        binaries_scanned: report.binaries_scanned,
        classification,
        confidence,
        reason,
        evidence,
        governing_update_path,
        candidates,
        dependency_chains: report.dependency_chains.clone(),
    }
}

pub(crate) fn summarize_candidate(
    role: &BinaryRole,
    on_governing_path: bool,
    linked_from_governing_path: bool,
) -> TrustCandidateSummary {
    let tier_counts = count_tiers(role);
    let candidate_classification = candidate_classification(
        role,
        on_governing_path,
        linked_from_governing_path,
        &tier_counts,
    );
    let score = trust_score(
        role,
        on_governing_path,
        linked_from_governing_path,
        &tier_counts,
        &candidate_classification,
    );
    let path_confidence = path_confidence_for(&candidate_classification, &tier_counts);
    let negative_evidence = build_negative_evidence(
        role,
        on_governing_path,
        linked_from_governing_path,
        &candidate_classification,
        &tier_counts,
    );
    let why = role
        .evidence
        .iter()
        .take(3)
        .map(|evidence| evidence.detail.clone())
        .collect();

    TrustCandidateSummary {
        candidate_classification,
        score,
        path_confidence,
        tier_counts,
        negative_evidence,
        why,
    }
}

fn summarize_trust_map_contract(
    governing_update_path: &Option<TrustMapCandidateJson>,
    candidates: &[TrustMapCandidateJson],
) -> (String, String, String, Vec<String>) {
    if let Some(governing) = governing_update_path {
        let evidence = governing.why.clone();
        return (
            governing.candidate_classification.clone(),
            governing.path_confidence.clone(),
            governing
                .why
                .first()
                .cloned()
                .unwrap_or_else(|| "governing updater path identified".into()),
            evidence,
        );
    }

    if let Some(candidate) = candidates.first() {
        let evidence = candidate.why.clone();
        return (
            candidate.candidate_classification.clone(),
            candidate.path_confidence.clone(),
            candidate
                .why
                .first()
                .cloned()
                .unwrap_or_else(|| "highest-ranking trust candidate identified".into()),
            evidence,
        );
    }

    (
        "out-of-path".into(),
        "low".into(),
        "no governing updater path was identified".into(),
        Vec::new(),
    )
}

pub(crate) fn count_tiers(role: &BinaryRole) -> TrustTierCounts {
    let mut counts = TrustTierCounts::default();
    for evidence in &role.evidence {
        match evidence.tier.as_str() {
            "executed-entrypoint" => counts.executed_entrypoint += 1,
            "linked-dependency" => counts.linked_dependency += 1,
            "crypto-or-verify-symbol" => counts.crypto_or_verify_symbol += 1,
            "string-hint" => counts.string_hint += 1,
            "artifact-only" => counts.artifact_only += 1,
            _ => {}
        }
    }
    if role.evidence.is_empty() {
        counts.artifact_only = 1;
    }
    counts
}

pub(crate) fn candidate_classification(
    role: &BinaryRole,
    on_governing_path: bool,
    linked_from_governing_path: bool,
    tier_counts: &TrustTierCounts,
) -> String {
    let strong_evidence = tier_counts.executed_entrypoint > 0
        || tier_counts.linked_dependency > 0
        || tier_counts.crypto_or_verify_symbol > 0;
    if on_governing_path {
        "governing-updater".into()
    } else if role.role == "crypto" {
        if linked_from_governing_path && strong_evidence {
            "supporting-crypto-lib".into()
        } else if strong_evidence {
            "helper-only".into()
        } else {
            "out-of-path".into()
        }
    } else if strong_evidence {
        "supporting-boundary".into()
    } else {
        "out-of-path".into()
    }
}

fn trust_score(
    role: &BinaryRole,
    on_governing_path: bool,
    linked_from_governing_path: bool,
    tier_counts: &TrustTierCounts,
    candidate_classification: &str,
) -> f64 {
    let mut score = match role.role.as_str() {
        "firmware-update" => 0.55,
        "authentication" => 0.40,
        "crypto" => 0.35,
        _ => 0.20,
    };

    score += tier_counts.executed_entrypoint as f64 * 0.20;
    score += tier_counts.linked_dependency as f64 * 0.12;
    score += tier_counts.crypto_or_verify_symbol as f64 * 0.10;
    score += tier_counts.string_hint as f64 * 0.03;

    if on_governing_path {
        score += 0.18;
    }
    if linked_from_governing_path {
        score += 0.10;
    }
    if candidate_classification == "helper-only" {
        score -= 0.05;
    } else if candidate_classification == "out-of-path" {
        score -= 0.08;
    }

    score.clamp(0.0, 0.99)
}

fn path_confidence_for(candidate_classification: &str, tier_counts: &TrustTierCounts) -> String {
    match candidate_classification {
        "governing-updater" => {
            if tier_counts.executed_entrypoint > 0 && tier_counts.crypto_or_verify_symbol > 0 {
                "high".into()
            } else {
                "medium".into()
            }
        }
        "supporting-crypto-lib" => "medium".into(),
        "supporting-boundary" => {
            if tier_counts.linked_dependency > 0 || tier_counts.crypto_or_verify_symbol > 0 {
                "medium".into()
            } else {
                "low".into()
            }
        }
        _ => "low".into(),
    }
}

fn build_negative_evidence(
    role: &BinaryRole,
    on_governing_path: bool,
    linked_from_governing_path: bool,
    candidate_classification: &str,
    tier_counts: &TrustTierCounts,
) -> Vec<String> {
    let mut negative_evidence = Vec::new();
    if !on_governing_path {
        negative_evidence.push("not on the governing updater path".into());
    }
    if role.role == "crypto" && candidate_classification == "helper-only" {
        negative_evidence.push("helper-only crypto library".into());
    } else if candidate_classification == "supporting-boundary" {
        negative_evidence.push("supporting boundary rather than the governing updater".into());
    } else if candidate_classification == "out-of-path" {
        negative_evidence.push("artifact present without governing-path evidence".into());
    }
    if tier_counts.executed_entrypoint == 0 {
        negative_evidence.push("no executed-entrypoint evidence".into());
    }
    if !linked_from_governing_path
        && (tier_counts.linked_dependency > 0 || tier_counts.crypto_or_verify_symbol > 0)
    {
        negative_evidence.push("supporting evidence present, but no governing-path linkage".into());
    }
    if tier_counts.artifact_only > 0 && tier_counts.executed_entrypoint == 0 {
        negative_evidence.push("artifact-only evidence is the weakest signal".into());
    }
    if role.role == "crypto" && candidate_classification != "governing-updater" {
        negative_evidence.push("crypto helper does not govern the update path by itself".into());
    }
    negative_evidence
}

pub(crate) fn linked_from_governing_path(
    binary_path: &str,
    governing_path: Option<&str>,
    governing_libs: &[String],
    dependency_chains: &[DependencyChain],
) -> bool {
    let Some(governing_path) = governing_path else {
        return false;
    };
    let basename = Path::new(binary_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    governing_libs.iter().any(|lib| lib == basename)
        || dependency_chains.iter().any(|chain| {
            chain.binary == governing_path
                && chain.imports_from.iter().any(|imp| imp.library == basename)
        })
}

fn role_label(role: &BinaryRole) -> String {
    match role.role.as_str() {
        "firmware-update" => "firmware updater".into(),
        "authentication" => "authentication boundary".into(),
        "crypto" => {
            if role.path.to_ascii_lowercase().contains("decrypt") {
                "crypto helper".into()
            } else {
                "crypto boundary".into()
            }
        }
        _ => role.role.clone(),
    }
}

fn score_role(role: &BinaryRole) -> f64 {
    let tier_counts = count_tiers(role);
    let candidate_classification = candidate_classification(role, false, false, &tier_counts);
    trust_score(role, false, false, &tier_counts, &candidate_classification)
}

/// Maximum number of symbol evidence lines to print per binary in text mode.
/// JSON output is not capped.
const MAX_SYMBOL_EVIDENCE: usize = 8;

fn render_binary_role(role: &BinaryRole) {
    println!("  {}", role.path);
    if !role.linked_libraries.is_empty() {
        println!("    Links: {}", role.linked_libraries.join(", "));
    }
    let mut symbol_count = 0usize;
    let total_symbols = role
        .evidence
        .iter()
        .filter(|e| e.kind == "import" || e.kind == "export")
        .count();
    for ev in &role.evidence {
        let is_symbol = ev.kind == "import" || ev.kind == "export";
        if is_symbol {
            symbol_count += 1;
            if symbol_count > MAX_SYMBOL_EVIDENCE {
                continue; // skip excess symbol lines, show summary below
            }
        }
        let tag = match ev.strength.as_str() {
            "strong" => "STRONG",
            "medium" => "MEDIUM",
            "weak" => "  WEAK",
            _ => "      ",
        };
        println!("    [{}] {}", tag, ev.detail);
    }
    if total_symbols > MAX_SYMBOL_EVIDENCE {
        println!(
            "    ... and {} more symbols",
            total_symbols - MAX_SYMBOL_EVIDENCE
        );
    }
}

fn render_chain(chain: &DependencyChain) {
    if chain.imports_from.is_empty() {
        println!("  {} \u{2192} {}", chain.binary, chain.links.join(", "),);
    } else {
        for imp in &chain.imports_from {
            let syms: Vec<&str> = imp
                .symbols
                .iter()
                .map(|s| {
                    // Truncate long symbol names for readability
                    if s.len() > 30 {
                        &s[..30]
                    } else {
                        s.as_str()
                    }
                })
                .take(5)
                .collect();
            let suffix = if imp.symbols.len() > 5 {
                format!(", ... +{} more", imp.symbols.len() - 5)
            } else {
                String::new()
            };
            println!(
                "  {} \u{2192} {} ({}{})",
                chain.binary,
                imp.library,
                syms.join(", "),
                suffix,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(tier: &str, kind: &str, detail: &str) -> Evidence {
        Evidence {
            tier: tier.into(),
            kind: kind.into(),
            strength: "strong".into(),
            detail: detail.into(),
        }
    }

    #[test]
    fn authentication_boundary_is_not_labeled_helper_only() {
        let role = BinaryRole {
            path: "/usr/bin/check_auth".into(),
            role: "authentication".into(),
            evidence: vec![
                evidence(
                    "linked-dependency",
                    "import",
                    "imports verify_token from auth helper",
                ),
                evidence(
                    "crypto-or-verify-symbol",
                    "import",
                    "imports SHA256 for session validation",
                ),
            ],
            linked_libraries: vec!["libauth.so".into()],
        };
        let tier_counts = count_tiers(&role);

        let classification = candidate_classification(&role, false, false, &tier_counts);

        assert_ne!(classification, "helper-only");
        assert_eq!(classification, "supporting-boundary");
    }

    #[test]
    fn crypto_role_still_uses_helper_only_for_non_governing_support() {
        let role = BinaryRole {
            path: "/usr/lib/libdecrypter.so".into(),
            role: "crypto".into(),
            evidence: vec![evidence(
                "crypto-or-verify-symbol",
                "import",
                "imports RSA_private_decrypt",
            )],
            linked_libraries: vec!["libcrypto.so".into()],
        };
        let tier_counts = count_tiers(&role);

        let classification = candidate_classification(&role, false, false, &tier_counts);

        assert_eq!(classification, "helper-only");
    }
}
