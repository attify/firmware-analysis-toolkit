use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisRequest, AnalysisResult, AnalysisTrigger, AnalyzerClass, AnalyzerPlugin,
    ArtifactInputRef, ArtifactRef, ArtifactScope, PluginDescriptor, PluginTrustTier,
};
use fat_plugin_host::PluginRegistry;

#[derive(Debug)]
struct FakePlugin;

impl AnalyzerPlugin for FakePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "service-runtime",
            "Service Runtime",
            AnalyzerClass::Runtime,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![
            AnalysisTrigger::RunCompleted,
            AnalysisTrigger::RunDegradedCompleted,
            AnalysisTrigger::RunFailed,
        ])
        .with_supported_artifacts(vec![
            ArtifactInputRef::required(ArtifactKind::RuntimeLog),
            ArtifactInputRef::optional(ArtifactKind::DiagnosticSupport),
        ])
    }

    fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult {
        let first_artifact = request
            .artifacts
            .first()
            .expect("normalized artifact reference");
        AnalysisResult {
            findings: vec![Finding::new(
                format!("finding-{}", first_artifact.artifact_id),
                format!("saw {}", first_artifact.artifact_id),
                FindingSeverity::Low,
                FindingSubject::Project,
            )
            .with_plugin_id("service-runtime")
            .with_evidence_artifact_ids(vec![first_artifact.artifact_id.clone()])],
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}

#[test]
fn plugin_descriptors_declare_class_triggers_artifacts_and_trust() {
    let descriptor = FakePlugin.descriptor();

    assert_eq!(descriptor.plugin_id, "service-runtime");
    assert_eq!(descriptor.class, AnalyzerClass::Runtime);
    assert_eq!(descriptor.trust_tier, PluginTrustTier::FirstParty);
    assert_eq!(
        descriptor.supported_triggers,
        vec![
            AnalysisTrigger::RunCompleted,
            AnalysisTrigger::RunDegradedCompleted,
            AnalysisTrigger::RunFailed
        ]
    );
    assert_eq!(descriptor.supported_artifacts.len(), 2);
    assert_eq!(
        descriptor.supported_artifacts[0],
        ArtifactInputRef::required(ArtifactKind::RuntimeLog)
    );
}

#[test]
fn plugin_host_registry_registers_and_enumerates_plugins() {
    let mut registry = PluginRegistry::new();
    registry.register(FakePlugin);

    let descriptors = registry.descriptors();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].plugin_id, "service-runtime");
}

#[test]
fn plugin_requests_use_normalized_target_run_and_artifact_inputs() {
    let request =
        AnalysisRequest::new(AnalysisTrigger::RunCompleted, "project-demo", "target-demo")
            .with_session_id("sess-1")
            .with_run_id("run-1")
            .with_artifacts(vec![
                ArtifactRef::new("art-1", ArtifactKind::RuntimeLog, ArtifactScope::Run),
                ArtifactRef::new(
                    "art-2",
                    ArtifactKind::DiagnosticSupport,
                    ArtifactScope::Target,
                ),
            ]);

    assert_eq!(request.project_id, "project-demo");
    assert_eq!(request.target_id, "target-demo");
    assert_eq!(request.session_id.as_deref(), Some("sess-1"));
    assert_eq!(request.run_id.as_deref(), Some("run-1"));
    assert_eq!(request.artifacts.len(), 2);
    assert_eq!(request.artifacts[0].scope, ArtifactScope::Run);
    assert_eq!(request.artifacts[1].scope, ArtifactScope::Target);

    let mut registry = PluginRegistry::new();
    registry.register(FakePlugin);
    let result = registry
        .run("service-runtime", &request)
        .expect("registered plugin");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].id, "finding-art-1");
}
