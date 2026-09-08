use crate::crypto_cmd::{
    analyze_crypto_shallow, build_trust_context_for_binary, collect_rootfs_elfs, CryptoReport,
    CryptoTrustContext,
};
use crate::schema_versions;
use fat_taint::recon::trust_boundary::{analyze_rootfs, TrustBoundaryReport};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub struct CryptoCensusReport {
    pub schema_version: &'static str,
    pub rootfs_path: String,
    pub group_by: String,
    pub only_filters: Vec<String>,
    pub confidence: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub clusters: Vec<CryptoReuseCluster>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CryptoReuseCluster {
    pub fingerprint: String,
    pub artifact_type: String,
    pub confidence: String,
    pub candidate_classifications: Vec<String>,
    pub governing_path_hits: Vec<String>,
    pub trust_summary: ClusterTrustSummary,
    pub occurrences: Vec<CryptoArtifactOccurrence>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CryptoCensusSummary {
    pub cluster_count: usize,
    pub governing_path_hit_clusters: Vec<String>,
    pub candidate_classifications: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ClusterTrustSummary {
    pub summary: String,
    pub total_occurrences: usize,
    pub governing_path_hits: Vec<String>,
    pub helper_only_occurrences: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct CryptoArtifactOccurrence {
    pub binary_path: String,
    pub offset: String,
    pub referenced_by: Option<String>,
    pub trust_path_relevance: String,
    pub candidate_role: String,
    pub candidate_classification: String,
    pub on_governing_path: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
struct ClusterBuilder {
    fingerprint: String,
    artifact_type: String,
    confidence: String,
    occurrences: Vec<CryptoArtifactOccurrence>,
    governing_path_hits: BTreeSet<String>,
    candidate_classifications: BTreeSet<String>,
    evidence: Vec<String>,
}

impl ClusterBuilder {
    fn new(fingerprint: String, artifact_type: String, confidence: String) -> Self {
        Self {
            fingerprint,
            artifact_type,
            confidence,
            occurrences: Vec::new(),
            governing_path_hits: BTreeSet::new(),
            candidate_classifications: BTreeSet::new(),
            evidence: Vec::new(),
        }
    }

    fn add_occurrence(&mut self, occurrence: CryptoArtifactOccurrence) {
        if occurrence.on_governing_path {
            self.governing_path_hits
                .insert(occurrence.binary_path.clone());
        }
        self.candidate_classifications
            .insert(occurrence.candidate_classification.clone());
        if let Some(reason) = &occurrence.reason {
            if !self.evidence.iter().any(|existing| existing == reason) {
                self.evidence.push(reason.clone());
            }
        }
        self.occurrences.push(occurrence);
    }

    fn finalize(mut self) -> CryptoReuseCluster {
        self.occurrences.sort_by(|left, right| {
            left.binary_path
                .cmp(&right.binary_path)
                .then_with(|| parse_hex_offset(&left.offset).cmp(&parse_hex_offset(&right.offset)))
        });
        let governing_path_hits = self.governing_path_hits.into_iter().collect::<Vec<_>>();
        let candidate_classifications = self
            .candidate_classifications
            .into_iter()
            .collect::<Vec<_>>();
        let helper_only_occurrences = self
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.candidate_classification == "helper-only")
            .count();
        let out_of_path_occurrences = self
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.candidate_classification == "out-of-path")
            .count();
        let has_helper_only = candidate_classifications
            .iter()
            .any(|classification| classification == "helper-only");
        let has_out_of_path = candidate_classifications
            .iter()
            .any(|classification| classification == "out-of-path");
        let summary = if governing_path_hits.is_empty() {
            match (has_helper_only, has_out_of_path) {
                (true, false) => format!(
                    "{} helper-only occurrence{} without governing updater hits",
                    helper_only_occurrences,
                    if helper_only_occurrences == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                (false, true) => format!(
                    "{} out-of-path occurrence{} without governing updater hits",
                    out_of_path_occurrences,
                    if out_of_path_occurrences == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                (true, true) => format!(
                    "{} helper-only and {} out-of-path occurrence{} without governing updater hits",
                    helper_only_occurrences,
                    out_of_path_occurrences,
                    if helper_only_occurrences + out_of_path_occurrences == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                (false, false) => format!(
                    "{} occurrences without governing updater hits",
                    self.occurrences.len()
                ),
            }
        } else if helper_only_occurrences == 0 {
            "present only on the governing updater path".into()
        } else {
            format!(
                "reused in governing updater path and {} other occurrence{}",
                helper_only_occurrences,
                if helper_only_occurrences == 1 {
                    ""
                } else {
                    "s"
                }
            )
        };
        CryptoReuseCluster {
            fingerprint: self.fingerprint,
            artifact_type: self.artifact_type,
            confidence: self.confidence,
            candidate_classifications,
            governing_path_hits: governing_path_hits.clone(),
            trust_summary: ClusterTrustSummary {
                summary,
                total_occurrences: self.occurrences.len(),
                governing_path_hits,
                helper_only_occurrences,
            },
            occurrences: self.occurrences,
            evidence: self.evidence,
        }
    }
}

fn parse_hex_offset(offset: &str) -> u64 {
    offset
        .strip_prefix("0x")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or(0)
}

fn summarize_contract_fields(clusters: &[CryptoReuseCluster]) -> (String, String, Vec<String>) {
    if clusters.is_empty() {
        return (
            "context-only".into(),
            "no crypto reuse clusters found".into(),
            Vec::new(),
        );
    }

    let has_governing_hit = clusters
        .iter()
        .any(|cluster| !cluster.governing_path_hits.is_empty());
    let reason = if has_governing_hit {
        "at least one reuse cluster intersects the governing updater path"
    } else {
        "reuse clusters were found, but none intersect the governing updater path"
    };
    let evidence = clusters
        .iter()
        .take(3)
        .map(|cluster| format!("{}: {}", cluster.fingerprint, cluster.trust_summary.summary))
        .collect::<Vec<_>>();
    (
        if has_governing_hit {
            "probable".into()
        } else {
            "context-only".into()
        },
        reason.into(),
        evidence,
    )
}

pub(crate) fn build_report(
    rootfs: &Path,
    only: Option<&str>,
    group_by: &str,
) -> DynResult<CryptoCensusReport> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }
    if group_by != "fingerprint" {
        return Err(format!("unsupported group-by mode: {group_by}").into());
    }

    let only_filters = parse_only_filters(only);
    let trust_report = analyze_rootfs(rootfs).map_err(|e| -> Box<dyn Error> { e.into() })?;
    build_report_from_trust_report(rootfs, &trust_report, only_filters, group_by)
}

pub(crate) fn build_report_from_trust_report(
    rootfs: &Path,
    trust_report: &TrustBoundaryReport,
    only_filters: Vec<String>,
    group_by: &str,
) -> DynResult<CryptoCensusReport> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }
    if group_by != "fingerprint" {
        return Err(format!("unsupported group-by mode: {group_by}").into());
    }

    let reports = analyze_rootfs_binaries(rootfs, trust_report)?;
    let clusters = build_clusters(rootfs, &reports, &only_filters);
    let (confidence, reason, evidence) = summarize_contract_fields(&clusters);
    Ok(CryptoCensusReport {
        schema_version: schema_versions::CRYPTO_REUSE_CLUSTER_V1,
        rootfs_path: rootfs.display().to_string(),
        group_by: group_by.to_string(),
        only_filters,
        confidence,
        reason,
        evidence,
        clusters,
    })
}

pub fn summarize(report: &CryptoCensusReport) -> CryptoCensusSummary {
    let mut governing_path_hit_clusters = Vec::new();
    let mut candidate_classifications = BTreeSet::new();

    for cluster in &report.clusters {
        if !cluster.governing_path_hits.is_empty() {
            governing_path_hit_clusters.push(cluster.fingerprint.clone());
        }
        for classification in &cluster.candidate_classifications {
            candidate_classifications.insert(classification.clone());
        }
    }

    let has_helper_only = candidate_classifications.contains("helper-only");
    let has_out_of_path = candidate_classifications.contains("out-of-path");

    let summary = if report.clusters.is_empty() {
        "no crypto reuse clusters found".into()
    } else if governing_path_hit_clusters.is_empty() {
        match (has_helper_only, has_out_of_path) {
            (true, false) => format!(
                "{} cluster{} found; no governing updater path hits; helper-only occurrences present",
                report.clusters.len(),
                if report.clusters.len() == 1 { "" } else { "s" }
            ),
            (false, true) => format!(
                "{} cluster{} found; no governing updater path hits; out-of-path occurrences present",
                report.clusters.len(),
                if report.clusters.len() == 1 { "" } else { "s" }
            ),
            (true, true) => format!(
                "{} cluster{} found; no governing updater path hits; helper-only and out-of-path occurrences present",
                report.clusters.len(),
                if report.clusters.len() == 1 { "" } else { "s" }
            ),
            (false, false) => format!(
                "{} cluster{} found; no governing updater path hits",
                report.clusters.len(),
                if report.clusters.len() == 1 { "" } else { "s" }
            ),
        }
    } else {
        format!(
            "{} cluster{} found; {} cluster{} intersect the governing updater path",
            report.clusters.len(),
            if report.clusters.len() == 1 { "" } else { "s" },
            governing_path_hit_clusters.len(),
            if governing_path_hit_clusters.len() == 1 {
                ""
            } else {
                "s"
            }
        )
    };

    CryptoCensusSummary {
        cluster_count: report.clusters.len(),
        governing_path_hit_clusters,
        candidate_classifications: candidate_classifications.into_iter().collect(),
        summary,
    }
}

pub fn run(rootfs: &Path, only: Option<&str>, group_by: &str, json: bool) -> DynResult<()> {
    let report = build_report(rootfs, only, group_by)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_report(&report);
    }

    Ok(())
}

fn analyze_rootfs_binaries(
    rootfs: &Path,
    trust_report: &TrustBoundaryReport,
) -> DynResult<Vec<(PathBuf, CryptoReport, Option<CryptoTrustContext>)>> {
    let mut reports = Vec::new();
    for elf in collect_rootfs_elfs(rootfs) {
        let report = analyze_crypto_shallow(&elf)?;
        let binary_path = relative_display(rootfs, &elf);
        let trust_context = build_trust_context_for_binary(trust_report, &binary_path);
        reports.push((elf, report, trust_context));
    }
    Ok(reports)
}

fn build_clusters(
    rootfs: &Path,
    reports: &[(PathBuf, CryptoReport, Option<CryptoTrustContext>)],
    only_filters: &[String],
) -> Vec<CryptoReuseCluster> {
    let mut builders: BTreeMap<String, ClusterBuilder> = BTreeMap::new();

    for (path, report, trust_context) in reports {
        let binary_path = relative_display(rootfs, path);
        for key in &report.embedded_keys {
            if !matches_only_filters(key, only_filters) {
                continue;
            }

            let Some(fingerprint) = key.fingerprint.clone() else {
                continue;
            };
            let artifact_type = key.key_type.clone();
            let confidence = key.confidence.clone();
            let candidate_role = trust_context
                .as_ref()
                .and_then(|context| context.candidate_role.clone())
                .unwrap_or_else(|| report.classification.role.clone());
            let candidate_classification = trust_context
                .as_ref()
                .and_then(|context| context.candidate_classification.clone())
                .unwrap_or_else(|| "out-of-path".into());
            let trust_path_relevance = key
                .trust_path_relevance
                .clone()
                .or_else(|| {
                    trust_context
                        .as_ref()
                        .map(|context| context.trust_path_relevance.clone())
                })
                .unwrap_or_else(|| "unknown".into());
            let referenced_by = key.referenced_by.clone();
            let reason = key
                .reason
                .clone()
                .or_else(|| trust_context.as_ref().map(|context| context.reason.clone()));
            let on_governing_path = trust_context
                .as_ref()
                .and_then(|context| context.governing_update_binary.as_ref())
                .is_some_and(|governing| governing == &binary_path);

            let occurrence = CryptoArtifactOccurrence {
                binary_path: binary_path.clone(),
                offset: key.offset.clone(),
                referenced_by,
                trust_path_relevance,
                candidate_role,
                candidate_classification,
                on_governing_path,
                reason,
            };

            let builder = builders
                .entry(fingerprint.clone())
                .or_insert_with(|| ClusterBuilder::new(fingerprint, artifact_type, confidence));
            builder.add_occurrence(occurrence);
        }
    }

    let mut clusters = builders
        .into_values()
        .map(ClusterBuilder::finalize)
        .collect::<Vec<_>>();
    clusters.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    clusters
}

fn parse_only_filters(only: Option<&str>) -> Vec<String> {
    only.unwrap_or_default()
        .split(',')
        .map(|token| token.trim().to_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn matches_only_filters(key: &crate::crypto_cmd::EmbeddedKey, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    let key_type = key.key_type.to_lowercase();
    let confidence = key.confidence.to_lowercase();
    filters.iter().any(|filter| {
        key_type.contains(filter)
            || confidence.contains(filter)
            || (filter == "rsa" && key_type.contains("rsa"))
            || (filter == "blob" && key_type.contains("blob"))
    })
}

fn relative_display(rootfs: &Path, path: &Path) -> String {
    path.strip_prefix(rootfs)
        .map(|relative| format!("/{}", relative.display()))
        .unwrap_or_else(|_| path.display().to_string())
}

fn render_report(report: &CryptoCensusReport) {
    println!("Crypto census: {}\n", report.rootfs_path);
    if report.clusters.is_empty() {
        println!("No crypto reuse clusters found.");
        return;
    }

    for (index, cluster) in report.clusters.iter().enumerate() {
        println!("Cluster {}", index + 1);
        println!("  fingerprint: {}", cluster.fingerprint);
        println!("  type: {}", cluster.artifact_type);
        println!("  confidence: {}", cluster.confidence);
        println!("  trust summary: {}", cluster.trust_summary.summary);
        if cluster.candidate_classifications.is_empty() {
            println!("  candidate classifications: none");
        } else {
            println!(
                "  candidate classifications: {}",
                cluster.candidate_classifications.join(", ")
            );
        }
        if cluster.governing_path_hits.is_empty() {
            println!("  governing path hits: none");
        } else {
            println!(
                "  governing path hits: {}",
                cluster.governing_path_hits.join(", ")
            );
        }
        println!("  occurrences:");
        for occurrence in &cluster.occurrences {
            println!("    {} @ {}", occurrence.binary_path, occurrence.offset);
            println!("      candidate role: {}", occurrence.candidate_role);
            println!(
                "      candidate classification: {}",
                occurrence.candidate_classification
            );
            println!("      trust relevance: {}", occurrence.trust_path_relevance);
            if let Some(reference) = &occurrence.referenced_by {
                println!("      referenced_by: {reference}");
            }
            if let Some(reason) = &occurrence.reason {
                println!("      reason: {reason}");
            }
        }
        println!();
    }
}
