use std::collections::BTreeMap;

use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};

#[derive(Debug, Default)]
pub struct FailureClusteringAnalyzer;

impl Analyzer for FailureClusteringAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "failure-clustering",
            "Failure Clustering",
            AnalyzerClass::CrossRun,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![
            AnalysisTrigger::RunCompleted,
            AnalysisTrigger::RunDegradedCompleted,
            AnalysisTrigger::RunFailed,
        ])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(
            ArtifactKind::DiagnosticSupport,
        )])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for diagnostic in &request.historical_diagnostics {
            let key = format!("{}:{}", diagnostic.class.as_str(), diagnostic.summary);
            *counts.entry(key).or_default() += 1;
        }

        let findings = counts
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(signature, count)| {
                Finding::new(
                    format!(
                        "failure-clustering-{}",
                        fat_core::ids::stable_prefixed_id("cluster", [signature.as_str()])
                    ),
                    format!("Repeated failure signature observed {count} times"),
                    FindingSeverity::Medium,
                    FindingSubject::Project,
                )
                .with_plugin_id("failure-clustering")
            })
            .collect();

        AnalysisResult {
            findings,
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}
