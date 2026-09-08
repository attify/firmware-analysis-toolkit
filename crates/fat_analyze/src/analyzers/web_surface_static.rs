use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};

#[derive(Debug, Default)]
pub struct WebSurfaceStaticAnalyzer;

impl Analyzer for WebSurfaceStaticAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "web-surface-static",
            "Web Surface Static",
            AnalyzerClass::Static,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![AnalysisTrigger::AnalysisRequested])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(ArtifactKind::Analysis)])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let snapshot_hit = request
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot.binaries.iter().any(|binary| {
                    matches!(
                        binary.name.as_str(),
                        "httpd" | "uhttpd" | "lighttpd" | "boa" | "mini_httpd"
                    )
                })
            })
            .unwrap_or(false);
        let evidence = request
            .artifact_documents
            .iter()
            .filter(|artifact| {
                let haystack = format!(
                    "{} {} {}",
                    artifact.subkind,
                    artifact.rel_path.clone().unwrap_or_default(),
                    artifact.text_content.clone().unwrap_or_default()
                )
                .to_ascii_lowercase();
                haystack.contains("cgi") || haystack.contains("http") || haystack.contains("web")
            })
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();
        if !snapshot_hit && evidence.is_empty() {
            return AnalysisResult::default();
        }

        AnalysisResult {
            findings: vec![Finding::new(
                "web-surface-static-exposed",
                "HTTP management surface inferred from static analysis",
                FindingSeverity::Medium,
                FindingSubject::Project,
            )
            .with_plugin_id("web-surface-static")
            .with_evidence_artifact_ids(evidence)],
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}
