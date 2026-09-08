use fat_analyze::binary::BinarySecurityAnalyzer;
use fat_analyze::engine::{AnalysisEngine, AnalyzerRegistry};
use fat_analyze::request::NormalizedAnalysisRequest;
use fat_analyze::Analyzer;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_core::inventory::AnalysisSnapshot;
use fat_core::project::Architecture;
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};

#[derive(Debug, Default)]
struct FakeAnalyzer;

impl fat_analyze::engine::Analyzer for FakeAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "fake-runtime",
            "Fake Runtime",
            AnalyzerClass::Runtime,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![AnalysisTrigger::RunCompleted])
        .with_supported_artifacts(vec![ArtifactInputRef::required(ArtifactKind::RuntimeLog)])
    }

    fn analyze(&self, _request: &NormalizedAnalysisRequest) -> AnalysisResult {
        AnalysisResult {
            findings: vec![Finding::new(
                "finding-1",
                "Fake runtime finding",
                FindingSeverity::Medium,
                FindingSubject::Project,
            )
            .with_plugin_id("fake-runtime")
            .with_evidence_artifact_ids(vec!["art-1".to_string()])],
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: vec!["art-produced-1".to_string()],
        }
    }
}

#[test]
fn built_in_analyzers_expose_plugin_descriptors() {
    let descriptor = BinarySecurityAnalyzer.descriptor();

    assert_eq!(descriptor.plugin_id, "binary-static");
    assert_eq!(descriptor.class, AnalyzerClass::Static);
    assert_eq!(descriptor.trust_tier, PluginTrustTier::FirstParty);
    assert!(descriptor
        .supported_triggers
        .contains(&AnalysisTrigger::AnalysisRequested));
}

#[test]
fn engine_consumes_normalized_requests_and_emits_normalized_results() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(FakeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-1")
    .with_run_id("run-1")
    .with_artifact_ids(vec!["art-1".to_string()])
    .with_snapshot(AnalysisSnapshot {
        binaries: vec![fat_core::inventory::BinaryRecord {
            id: "bin-1".to_string(),
            name: "httpd".to_string(),
            rel_path: "bin/httpd".to_string(),
            architecture: Architecture::Armel,
            nx: Some(false),
            pie: Some(false),
            canary: Some(false),
        }],
        findings: Vec::new(),
    });

    let result = engine.analyze_request(&request);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.produced_artifact_ids, vec!["art-produced-1"]);
}

#[test]
fn engine_contract_is_request_based_not_path_scraping_based() {
    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::AnalysisRequested,
        "project-demo",
        "target-demo",
    )
    .with_artifact_ids(vec!["art-1".to_string(), "art-2".to_string()]);

    assert_eq!(request.request.artifacts.len(), 2);
    assert_eq!(request.request.artifacts[0].kind, ArtifactKind::Analysis);
    assert!(request.snapshot.is_none());
}
