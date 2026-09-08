use crate::result::{
    ConfidenceSource, FusedSourceEvidence, ParseStatus, SourceAnalysisSummary, SourceBackendKind,
};
use std::collections::BTreeSet;

pub fn fuse_source_analysis(summary: Option<&SourceAnalysisSummary>) -> FusedSourceEvidence {
    let Some(summary) = summary else {
        return FusedSourceEvidence::default();
    };

    let mut methods_seen = BTreeSet::new();
    let mut calls_seen = BTreeSet::new();
    let mut adapters_seen = BTreeSet::new();
    let mut observed_seen = BTreeSet::new();
    let mut inferred_seen = BTreeSet::new();

    let mut fused = FusedSourceEvidence::default();
    let mut reports = summary.reports.iter().collect::<Vec<_>>();
    reports.sort_by_key(|right| std::cmp::Reverse(report_rank(right)));

    for report in reports {
        adapters_seen.insert(format!("{}:{}", report.adapter_id, report.backend.as_str()));
        for method in &report.methods {
            if methods_seen.insert((
                method.signature_hash.clone(),
                method.file.clone(),
                method.begin_line,
                method.end_line,
            )) {
                fused.methods.push(method.clone());
            }
        }
        for call in &report.calls {
            if calls_seen.insert((
                call.callee_name.clone(),
                call.enclosing_symbol.clone(),
                call.file.clone(),
                call.line,
            )) {
                fused.calls.push(call.clone());
            }
        }
        for item in &report.diagnostics.observed {
            observed_seen.insert(item.clone());
        }
        for item in &report.diagnostics.inferred {
            inferred_seen.insert(item.clone());
        }
    }
    fused.adapters = adapters_seen.into_iter().collect();
    fused.observed = observed_seen.into_iter().collect();
    fused.inferred = inferred_seen.into_iter().collect();
    fused
}

fn report_rank(report: &crate::result::SourceEvidenceReport) -> (u8, u8, u8, usize, usize) {
    (
        parse_rank(&report.diagnostics.parse),
        confidence_rank(&report.diagnostics.confidence_source),
        backend_rank(&report.backend),
        report.methods.len(),
        report.calls.len(),
    )
}

fn parse_rank(status: &ParseStatus) -> u8 {
    match status {
        ParseStatus::Parsed => 3,
        ParseStatus::Degraded => 2,
        ParseStatus::Failed => 1,
    }
}

fn confidence_rank(confidence: &ConfidenceSource) -> u8 {
    match confidence {
        ConfidenceSource::Direct => 3,
        ConfidenceSource::Indirect => 2,
        ConfidenceSource::Heuristic => 1,
    }
}

fn backend_rank(kind: &SourceBackendKind) -> u8 {
    match kind {
        SourceBackendKind::LibclangBackend => 3,
        SourceBackendKind::AstDumpJson => 2,
        SourceBackendKind::TextScan => 1,
        SourceBackendKind::SyntheticSliceRepair => 1,
    }
}
