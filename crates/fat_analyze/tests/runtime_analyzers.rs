use fat_analyze::analyzers::{FailureClusteringAnalyzer, ServiceRuntimeAnalyzer};
use fat_analyze::engine::{AnalysisEngine, AnalyzerRegistry};
use fat_analyze::request::{ArtifactDocument, NormalizedAnalysisRequest};
use fat_core::artifacts::ArtifactKind;
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_plugin_api::{AnalysisTrigger, ArtifactRef, ArtifactScope};

fn diagnostic(run_id: &str, class: DiagnosticClass, summary: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id,
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        class,
        None,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        summary,
        Vec::new(),
        Vec::new(),
        vec!["retry with fallback".to_string()],
    )
}

#[test]
fn runtime_analyzers_consume_run_scoped_artifacts_and_diagnostics() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-1")
    .with_run_id("run-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-service-map",
        ArtifactKind::RuntimeLog,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-service-map",
        ArtifactKind::RuntimeLog,
        ArtifactScope::Run,
        "service-map",
        Some("runtime/service-map.txt".to_string()),
        "text/plain",
        Some("uhttpd 0.0.0.0:80\nsshd 0.0.0.0:22\n".to_string()),
    )])
    .with_diagnostics(vec![diagnostic(
        "run-1",
        DiagnosticClass::GuestUnreachable,
        "temporary guest reachability issue",
    )]);

    let result = engine.analyze_request(&request);
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding.evidence_artifact_ids == vec!["art-service-map".to_string()]
    }));
}

#[test]
fn failure_clustering_groups_repeated_failure_signatures_across_runs() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(FailureClusteringAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunDegradedCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-2")
    .with_run_id("run-2")
    .with_historical_diagnostics(vec![
        diagnostic(
            "run-0",
            DiagnosticClass::LaunchFailed,
            "qemu-direct: launch command exited unsuccessfully",
        ),
        diagnostic(
            "run-1",
            DiagnosticClass::LaunchFailed,
            "qemu-direct: launch command exited unsuccessfully",
        ),
        diagnostic(
            "run-9",
            DiagnosticClass::GuestUnreachable,
            "guest did not reach steady state",
        ),
    ]);

    let result = engine.analyze_request(&request);
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("failure-clustering")
            && finding.title.contains("Repeated failure signature")
    }));
}

#[test]
fn runtime_analyzer_output_remains_normalized_and_queryable() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    registry.register(FailureClusteringAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_run_id("run-3")
    .with_artifacts(vec![ArtifactRef::new(
        "art-service-map",
        ArtifactKind::RuntimeLog,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-service-map",
        ArtifactKind::RuntimeLog,
        ArtifactScope::Run,
        "service-map",
        Some("runtime/service-map.txt".to_string()),
        "text/plain",
        Some("dropbear 0.0.0.0:22\n".to_string()),
    )])
    .with_historical_diagnostics(vec![diagnostic(
        "run-2",
        DiagnosticClass::LaunchFailed,
        "qemu-direct: launch command exited unsuccessfully",
    )]);

    let result = engine.analyze_request(&request);
    assert!(result
        .findings
        .iter()
        .all(|finding| finding.plugin_id.is_some()));
}

#[test]
fn service_runtime_analyzer_consumes_managed_launch_state_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-managed-1")
    .with_run_id("run-managed-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-managed-launch-state",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-managed-launch-state",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "managed-linux-vm-launch-state",
        Some("runtime/managed-linux-vm-launch-state.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "lifecycle_adapter": "legacy-wrapper",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "bundle_version": "dev",
                "workspace_dir": "/tmp/firmae",
                "base_image": "/tmp/base-image.qcow2",
                "guest_agent": "/tmp/guest-agent",
                "mapped_ports": [8080],
                "launch_manifest_present": true,
                "endpoints": [
                    {
                        "kind": "shell",
                        "name": "shell",
                        "host": "127.0.0.1",
                        "port": 2202,
                        "target_port": 22,
                        "uri": "ssh://127.0.0.1:2202"
                    },
                    {
                        "kind": "service",
                        "name": "web-admin",
                        "host": "127.0.0.1",
                        "port": 18080,
                        "target_port": 80,
                        "uri": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let service_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "service-summary")
        .expect("normalized service summary artifact");
    assert!(service_summary
        .text_content
        .contains("\"name\":\"web-admin\""));
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .evidence_artifact_ids
                .contains(&"art-managed-launch-state".to_string())
    }));
}

#[test]
fn service_runtime_analyzer_consumes_managed_stop_state_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunDegradedCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-managed-stop-1")
    .with_run_id("run-managed-stop-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-managed-stop-state",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-managed-stop-state",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "managed-linux-vm-stop-state",
        Some("runtime/managed-linux-vm-stop-state.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "result_contract": "firmae-legacy-wrapper-stop-v1",
                "result_contract_verified": false,
                "stop_mode": "legacy-wrapper-stop",
                "workspace_dir": "/tmp/fake-workspace",
                "workspace_removed": false,
                "exit_code": 0,
                "stdout": "firmware stopped",
                "stderr": "",
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let stop_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "managed-stop-summary")
        .expect("normalized stop summary artifact");
    assert!(stop_summary
        .text_content
        .contains("\"lifecycle_adapter\":\"legacy-wrapper\""));
    assert!(stop_summary
        .text_content
        .contains("\"workspace_dir\":\"/tmp/fake-workspace\""));
    assert!(stop_summary
        .text_content
        .contains("\"workspace_removed\":false"));
    assert!(stop_summary
        .text_content
        .contains("\"stdout\":\"firmware stopped\""));
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .title
                .contains("Managed stop contract was not fully verified")
            && finding
                .evidence_artifact_ids
                .contains(&"art-managed-stop-state".to_string())
    }));
}

#[test]
fn service_runtime_analyzer_consumes_firmae_upstream_observation_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-firmae-observation-1")
    .with_run_id("run-firmae-observation-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-firmae-upstream-observation",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-firmae-upstream-observation",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "firmae-upstream-observation",
        Some("runtime/firmae-upstream-observation.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "observation_source": "bounded-live-inspection",
                "observation_timestamp": "unix-ms:1710000000000",
                "container_name": "firmae-upstream-1",
                "container_running": true,
                "scratch_artifacts_present": true,
                "observed_artifact_paths": [
                    "/tmp/firmae/scratch/1/qemu.initial.serial.log",
                    "/tmp/firmae/scratch/1/qemu.final.serial.log",
                    "/tmp/firmae/scratch/1/makeNetwork.log"
                ],
                "guest_ip": "192.168.0.1",
                "guest_reachable": true,
                "port_80_reachable": false,
                "port_31337_reachable": false,
                "port_31338_reachable": false,
                "runtime_status": {
                    "backend_id": "firmae",
                    "driver_profile": "firmae-managed-legacy-wrapper",
                    "control_contract": "firmae-legacy-wrapper-v1",
                    "lifecycle_adapter": "legacy-wrapper",
                    "phase": "probe-unreachable",
                    "runtime_outcome": "booted-services-unreachable",
                    "workspace_dir": "/tmp/firmae",
                    "services": [
                        {
                            "name": "web-admin",
                            "endpoint": "http://127.0.0.1:18080"
                        }
                    ],
                    "launch_mode": "legacy-wrapper-launch",
                    "stop_mode": "legacy-wrapper-stop",
                    "launch_manifest_present": false,
                    "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                    "probe_result_contract_verified": true,
                    "probe_source": "probe-on-status",
                    "probe_outcome": "unreachable"
                }
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let service_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "service-summary")
        .expect("normalized service summary artifact");
    assert!(service_summary
        .text_content
        .contains("\"name\":\"web-admin\""));
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .evidence_artifact_ids
                .contains(&"art-firmae-upstream-observation".to_string())
    }));
}

#[test]
fn service_runtime_analyzer_consumes_unified_managed_runtime_status_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunDegradedCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-managed-status-1")
    .with_run_id("run-managed-status-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-managed-runtime-status",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-managed-runtime-status",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "managed-runtime-status",
        Some("runtime/managed-runtime-status.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "phase": "stop-failed",
                "bundle_version": "dev",
                "workspace_dir": "/tmp/fake-workspace",
                "base_image": "/tmp/base-image.qcow2",
                "guest_agent": "/tmp/guest-agent",
                "mapped_ports": [8080],
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "launch_manifest_present": true,
                "probe_source": "background-supervisor",
                "probe_outcome": "healthy",
                "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                "probe_result_contract_verified": true,
                "stop_result_contract": "firmae-legacy-wrapper-stop-v1",
                "stop_result_contract_verified": false,
                "stop_exit_code": 0,
                "workspace_removed": false,
                "endpoints": [
                    {
                        "kind": "service",
                        "name": "web-admin",
                        "host": "127.0.0.1",
                        "port": 18080,
                        "target_port": 80,
                        "uri": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let service_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "service-summary")
        .expect("normalized service summary artifact");
    assert!(service_summary
        .text_content
        .contains("\"name\":\"web-admin\""));

    let stop_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "managed-stop-summary")
        .expect("normalized stop summary artifact");
    assert!(stop_summary
        .text_content
        .contains("\"phase\":\"stop-failed\""));
    assert!(stop_summary
        .text_content
        .contains("\"workspace_removed\":false"));
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .title
                .contains("Managed stop contract was not fully verified")
            && finding
                .evidence_artifact_ids
                .contains(&"art-managed-runtime-status".to_string())
    }));
}

#[test]
fn service_runtime_analyzer_prefers_managed_runtime_summary_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunDegradedCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-managed-summary-1")
    .with_run_id("run-managed-summary-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-managed-runtime-summary",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-managed-runtime-summary",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "managed-runtime-summary",
        Some("runtime/managed-runtime-summary.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "runtime_phase": "stop-failed",
                "workspace_dir": "/tmp/fake-workspace",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "launch_manifest_present": true,
                "probe_source": "background-supervisor",
                "probe_outcome": "healthy",
                "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                "probe_result_contract_verified": true,
                "stop_result_contract": "firmae-legacy-wrapper-stop-v1",
                "stop_result_contract_verified": false,
                "workspace_removed": false,
                "services": [
                    {
                        "name": "web-admin",
                        "endpoint": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let service_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "service-summary")
        .expect("normalized service summary artifact");
    assert!(service_summary
        .text_content
        .contains("\"name\":\"web-admin\""));

    let stop_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "managed-stop-summary")
        .expect("normalized stop summary artifact");
    assert!(stop_summary
        .text_content
        .contains("\"phase\":\"stop-failed\""));
    assert!(stop_summary
        .text_content
        .contains("\"workspace_removed\":false"));
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .title
                .contains("Managed stop contract was not fully verified")
            && finding
                .evidence_artifact_ids
                .contains(&"art-managed-runtime-summary".to_string())
    }));
}

#[test]
fn service_runtime_analyzer_accepts_verified_upstream_stop_summary() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-upstream-stop-1")
    .with_run_id("run-upstream-stop-1")
    .with_artifacts(vec![ArtifactRef::new(
        "art-managed-runtime-summary",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
    )])
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-managed-runtime-summary",
        ArtifactKind::RuntimeState,
        ArtifactScope::Run,
        "managed-runtime-summary",
        Some("runtime/managed-runtime-summary.json".to_string()),
        "application/json",
        Some(
            serde_json::json!({
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "runtime_phase": "stop-complete",
                "workspace_dir": "/tmp/fake-workspace",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "launch_manifest_present": false,
                "stop_result_contract": "firmae-upstream-container-stop-v1",
                "stop_result_contract_verified": true,
                "workspace_removed": true,
                "stop_exit_code": 0,
                "services": []
            })
            .to_string(),
        ),
    )]);

    let result = engine.analyze_request(&request);
    let stop_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "managed-stop-summary")
        .expect("normalized stop summary artifact");
    assert!(stop_summary
        .text_content
        .contains("\"result_contract\":\"firmae-upstream-container-stop-v1\""));
    assert!(!result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .title
                .contains("Managed stop contract was not fully verified")
    }));
}

#[test]
fn service_runtime_analyzer_ignores_raw_logs_when_managed_runtime_summary_is_present() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(ServiceRuntimeAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::RunCompleted,
        "project-demo",
        "target-demo",
    )
    .with_session_id("sess-managed-summary-raw-1")
    .with_run_id("run-managed-summary-raw-1")
    .with_artifacts(vec![
        ArtifactRef::new(
            "art-managed-runtime-summary",
            ArtifactKind::RuntimeState,
            ArtifactScope::Run,
        ),
        ArtifactRef::new(
            "art-runtime-log",
            ArtifactKind::RuntimeLog,
            ArtifactScope::Run,
        ),
    ])
    .with_artifact_documents(vec![
        ArtifactDocument::new(
            "art-managed-runtime-summary",
            ArtifactKind::RuntimeState,
            ArtifactScope::Run,
            "managed-runtime-summary",
            Some("runtime/managed-runtime-summary.json".to_string()),
            "application/json",
            Some(
                serde_json::json!({
                    "backend_id": "firmae",
                    "driver_profile": "firmae-managed-legacy-wrapper",
                    "control_contract": "firmae-legacy-wrapper-v1",
                    "lifecycle_adapter": "legacy-wrapper",
                    "runtime_phase": "launch-complete",
                    "runtime_outcome": "booted-services-unreachable",
                    "workspace_dir": "/tmp/fake-workspace",
                    "launch_mode": "legacy-wrapper-launch",
                    "stop_mode": "legacy-wrapper-stop",
                    "launch_manifest_present": true,
                    "probe_source": "upstream-launch",
                    "probe_outcome": "healthy",
                    "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                    "probe_result_contract_verified": true,
                    "services": [
                        {
                            "name": "web-admin",
                            "endpoint": "http://127.0.0.1:18080"
                        }
                    ]
                })
                .to_string(),
            ),
        ),
        ArtifactDocument::new(
            "art-runtime-log",
            ArtifactKind::RuntimeLog,
            ArtifactScope::Run,
            "runtime/launch.log",
            Some("runtime/launch.log".to_string()),
            "text/plain",
            Some("dropbear 0.0.0.0:22\n".to_string()),
        ),
    ]);

    let result = engine.analyze_request(&request);
    let service_summary = result
        .produced_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "service-summary")
        .expect("normalized service summary artifact");
    assert!(service_summary
        .text_content
        .contains("\"name\":\"web-admin\""));
    assert!(!service_summary.text_content.contains("dropbear"));
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings.iter().any(|finding| {
        finding.plugin_id.as_deref() == Some("service-runtime")
            && finding
                .evidence_artifact_ids
                .contains(&"art-managed-runtime-summary".to_string())
    }));
}
