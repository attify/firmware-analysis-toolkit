use crate::result::{
    AdapterDiagnostics, AdequacyForQuery, AdequacyIntent, AdequacyTier, ConfidenceSource,
    DerivedAnalysis, EvidenceBasis, LocalityStatus, ParseStatus, ScoreTrace, SourceAnalysisSummary,
    SourceBackendKind, SourceCallFact, SourceEvidenceReport, SourceMethodFact, VisibilityStatus,
};
use crate::{adapters::source, planner::ResourceBudgets, toolchain_profile::ToolchainProfile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceStage {
    WholeTuInput,
    PreDeriveSliceRepair,
    AdequacyDrivenReExpansion,
    NotNeeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceExpansionReport {
    pub pre_stage: SliceStage,
    pub post_stage: SliceStage,
    #[serde(default)]
    pub repaired_reports: usize,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

pub fn evaluate_slice_expansion(
    summary: Option<&SourceAnalysisSummary>,
    derived: &DerivedAnalysis,
) -> SliceExpansionReport {
    let Some(summary) = summary else {
        return SliceExpansionReport {
            pre_stage: SliceStage::NotNeeded,
            post_stage: SliceStage::NotNeeded,
            repaired_reports: 0,
            observed: vec!["no source analysis available for slice expansion".into()],
            inferred: vec!["slice expansion skipped".into()],
        };
    };
    let has_methods = summary
        .reports
        .iter()
        .any(|report| !report.methods.is_empty());
    let has_calls = summary
        .reports
        .iter()
        .any(|report| !report.calls.is_empty());
    let pre_stage = if has_methods && has_calls {
        SliceStage::WholeTuInput
    } else {
        SliceStage::PreDeriveSliceRepair
    };
    let post_stage = if derived.facts.is_empty() {
        SliceStage::AdequacyDrivenReExpansion
    } else {
        SliceStage::NotNeeded
    };
    SliceExpansionReport {
        pre_stage,
        post_stage,
        repaired_reports: 0,
        observed: vec![
            format!("source reports={}", summary.reports.len()),
            format!("derived facts={}", derived.facts.len()),
        ],
        inferred: vec![if derived.facts.is_empty() {
            "derived facts were insufficient; re-expansion would be justified".into()
        } else {
            "whole-TU evidence was already adequate for current derived facts".into()
        }],
    }
}

pub fn repair_source_analysis(
    root: &Path,
    summary: &mut SourceAnalysisSummary,
    budgets: &ResourceBudgets,
) -> Result<Option<SourceEvidenceReport>, String> {
    let needs_repair = summary.reports.iter().any(|report| {
        report.diagnostics.parse == ParseStatus::Failed
            || report.methods.is_empty()
            || report.calls.is_empty()
    });
    if !needs_repair || budgets.max_pre_repair_depth == 0 {
        return Ok(None);
    }

    let scanned = source::scan_source_facts(root)?;
    if scanned.methods.is_empty() && scanned.calls.is_empty() {
        return Ok(None);
    }

    let report = SourceEvidenceReport {
        adapter_id: "source-slice-repair".into(),
        backend: SourceBackendKind::SyntheticSliceRepair,
        backend_version: "scanner-v1".into(),
        tu_file: scanned
            .primary_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("<unknown>")),
        tu_spec_hash: summary
            .metadata
            .get("tu_spec_hash")
            .cloned()
            .unwrap_or_else(|| "<unknown>".into()),
        toolchain_profile_hash: summary
            .metadata
            .get("toolchain_profile_hash")
            .cloned()
            .unwrap_or_else(|| ToolchainProfile::default().hash()),
        diagnostics: AdapterDiagnostics {
            visibility: VisibilityStatus::Present,
            parse: ParseStatus::Degraded,
            locality: LocalityStatus::RepoLocal,
            confidence_source: ConfidenceSource::Indirect,
            observed: vec![
                format!(
                    "scanner repair recovered {} methods and {} calls",
                    scanned.methods.len(),
                    scanned.calls.len()
                ),
                format!("repair_budget_pre_depth={}", budgets.max_pre_repair_depth),
            ],
            inferred: vec![
                "parser-backed facts were insufficient; scanner repair provided fallback facts"
                    .into(),
            ],
            adequacy: vec![
                AdequacyForQuery {
                    family: "source-visibility".into(),
                    intent: AdequacyIntent::ReplaySiting,
                    tier: AdequacyTier::ReplaySitingAdequate,
                    required_facts_satisfied: vec!["method_identity".into(), "callsites".into()],
                },
                AdequacyForQuery {
                    family: "source-visibility".into(),
                    intent: AdequacyIntent::VariantHunting,
                    tier: AdequacyTier::VariantHuntingAdequate,
                    required_facts_satisfied: vec![
                        "file_line_provenance".into(),
                        "enclosing_symbol".into(),
                    ],
                },
                AdequacyForQuery {
                    family: "source-visibility".into(),
                    intent: AdequacyIntent::Proof,
                    tier: AdequacyTier::ProofInadequate,
                    required_facts_satisfied: vec![],
                },
            ],
        },
        methods: scanned.methods,
        calls: scanned.calls,
        score_trace: ScoreTrace {
            adapters: vec!["source-slice-repair".into()],
            family_pack_hits: vec!["source-visibility".into()],
            penalties: vec!["synthetic-repair".into()],
            locality_notes: vec!["scanner repair after parser insufficiency".into()],
        },
    };
    summary.reports.push(report.clone());
    summary
        .merged_observed
        .push("slice repair merged synthetic scanner facts".into());
    summary
        .merged_inferred
        .push("repaired source facts supplement parser-backed analysis".into());
    Ok(Some(report))
}

#[derive(Debug, Clone, Default)]
pub struct ScannedSourceFacts {
    pub methods: Vec<SourceMethodFact>,
    pub calls: Vec<SourceCallFact>,
    pub primary_file: Option<PathBuf>,
}

pub fn scanned_source_facts_from_functions(
    functions: &[source::ParsedFunctionFacts],
) -> ScannedSourceFacts {
    let mut facts = ScannedSourceFacts::default();
    for function in functions {
        if facts.primary_file.is_none() {
            facts.primary_file = Some(function.file.clone());
        }
        facts.methods.push(SourceMethodFact {
            qualified_name: function.name.clone(),
            signature_hash: format!(
                "{}:{}:{}",
                function.name, function.begin_line, function.end_line
            ),
            file: function.file.clone(),
            line: function.begin_line,
            begin_line: function.begin_line,
            end_line: function.end_line,
        });
        for call in &function.calls {
            facts.calls.push(SourceCallFact {
                callee_name: call.name.clone(),
                enclosing_symbol: function.name.clone(),
                file: function.file.clone(),
                line: call.line,
                basis: EvidenceBasis::InferredFromRepairedSlice,
            });
        }
    }
    facts
}
