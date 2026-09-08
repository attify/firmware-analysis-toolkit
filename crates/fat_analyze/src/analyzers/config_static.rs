use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};

#[derive(Debug, Default)]
pub struct ConfigStaticAnalyzer;

impl Analyzer for ConfigStaticAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "config-static",
            "Config Static",
            AnalyzerClass::Static,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![AnalysisTrigger::AnalysisRequested])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(ArtifactKind::Analysis)])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let evidence = request
            .artifact_documents
            .iter()
            .filter(|artifact| {
                artifact.subkind.contains("config")
                    || artifact
                        .rel_path
                        .as_deref()
                        .map(|path| path.contains("/config") || path.contains("nvram"))
                        .unwrap_or(false)
            })
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();
        if evidence.is_empty() {
            return AnalysisResult::default();
        }

        AnalysisResult {
            findings: vec![Finding::new(
                "config-static-sensitive-surface",
                "Sensitive configuration surface inferred from static artifacts",
                FindingSeverity::Medium,
                FindingSubject::File {
                    rel_path: "etc/config".to_string(),
                },
            )
            .with_plugin_id("config-static")
            .with_evidence_artifact_ids(evidence)],
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}
