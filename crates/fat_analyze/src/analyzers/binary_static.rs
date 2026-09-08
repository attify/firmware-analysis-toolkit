use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};

#[derive(Debug, Default)]
pub struct BinaryStaticAnalyzer;

impl Analyzer for BinaryStaticAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "binary-static",
            "Binary Static",
            AnalyzerClass::Static,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![
            AnalysisTrigger::ExtractionCompleted,
            AnalysisTrigger::AnalysisRequested,
        ])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(ArtifactKind::Analysis)])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let Some(snapshot) = request.snapshot.as_ref() else {
            return AnalysisResult::default();
        };
        let evidence = request
            .request
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();
        let mut findings = Vec::new();

        for binary in &snapshot.binaries {
            let disabled = [binary.nx, binary.pie, binary.canary]
                .into_iter()
                .filter(|flag| matches!(flag, Some(false)))
                .count();
            if disabled == 0 {
                continue;
            }

            let severity = if disabled >= 2 {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            };

            findings.push(
                Finding::new(
                    format!("binary-static-{}", binary.id),
                    format!("Binary hardening disabled for {}", binary.name),
                    severity,
                    FindingSubject::Binary {
                        binary_id: binary.id.clone(),
                    },
                )
                .with_plugin_id("binary-static")
                .with_evidence_artifact_ids(evidence.clone()),
            );
        }

        AnalysisResult {
            findings,
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}
