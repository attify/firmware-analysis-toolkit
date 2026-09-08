use fat_core::benchmark::{
    score_fat_native_run, BenchmarkComparator, BenchmarkEvidenceGrade, BenchmarkOutcomeClass,
    BenchmarkOutcomeRecord, BenchmarkRunMode, BenchmarkRunRecord, BenchmarkStageScore,
    BenchmarkStageStatus, BenchmarkStageVector, BenchmarkTarget, ComparatorKind,
};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_core::ids::stable_prefixed_id;
use fat_core::readiness::{ConfidenceLevel, ConfidenceReport, GoalConfidence, GoalState};
use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::runs::{
    RunOrigin, RunRecord, RunStatus, RuntimeEndpoint, RuntimeEndpointKind, SubstrateKind,
};
use fat_core::services::ManagedRuntimeSummary;
use fat_core::targets::TargetRecord;

#[test]
fn benchmark_stage_vector_round_trips_partial_success() {
    let target = BenchmarkTarget::new(
        "target-demo-camera-v1",
        "Demo Camera v1",
        "mipsel",
        "vendor-firmware-blob",
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let vector = BenchmarkStageVector {
        intake: BenchmarkStageScore::reached(),
        boot: BenchmarkStageScore::reached(),
        reachability: BenchmarkStageScore::partial(),
        operator_access: BenchmarkStageScore::not_reached(),
        research_utility: BenchmarkStageScore::reached(),
        exploit_readiness: BenchmarkStageScore::not_reached(),
    };

    let value = (target, comparator, vector);
    let json = serde_json::to_string(&value).unwrap();
    let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let round_trip: (BenchmarkTarget, BenchmarkComparator, BenchmarkStageVector) =
        serde_json::from_str(&json).unwrap();

    assert_eq!(json_value[0]["target_id"], "target-demo-camera-v1");
    assert_eq!(json_value[0]["display_name"], "Demo Camera v1");
    assert_eq!(json_value[1]["run_mode"], "raw-upstream");
    assert_eq!(json_value[2]["operator_access"]["status"], "not-reached");
    assert_eq!(round_trip, value);
}

#[test]
fn benchmark_enums_serialize_with_kebab_case_contract() {
    assert_eq!(
        serde_json::to_string(&ComparatorKind::External).unwrap(),
        "\"external\""
    );
    assert_eq!(
        serde_json::to_string(&BenchmarkOutcomeClass::Strong).unwrap(),
        "\"strong\""
    );
    assert_eq!(
        serde_json::to_string(&BenchmarkEvidenceGrade::Moderate).unwrap(),
        "\"moderate\""
    );
    assert_eq!(
        serde_json::to_string(&BenchmarkStageStatus::NotReached).unwrap(),
        "\"not-reached\""
    );

    assert_eq!(
        serde_json::from_str::<BenchmarkOutcomeClass>("\"useful\"").unwrap(),
        BenchmarkOutcomeClass::Useful
    );
    assert_eq!(
        serde_json::from_str::<BenchmarkEvidenceGrade>("\"rich\"").unwrap(),
        BenchmarkEvidenceGrade::Rich
    );
    assert_eq!(
        serde_json::from_str::<ComparatorKind>("\"external\"").unwrap(),
        ComparatorKind::External
    );
    assert_eq!(
        serde_json::from_str::<BenchmarkStageStatus>("\"partial\"").unwrap(),
        BenchmarkStageStatus::Partial
    );
}

#[test]
fn benchmark_run_and_outcome_records_round_trip() {
    let target = BenchmarkTarget::new(
        "target-demo-camera-v1",
        "Demo Camera v1",
        "mipsel",
        "vendor-firmware-blob",
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let run = BenchmarkRunRecord::try_new(
        target.target_id.clone(),
        comparator.clone(),
        "apple-silicon-laptop",
        "exec-1",
    )
    .unwrap();
    let other_run = BenchmarkRunRecord::try_new(
        target.target_id.clone(),
        comparator.clone(),
        "apple-silicon-laptop",
        "exec-2",
    )
    .unwrap();
    let outcome = BenchmarkOutcomeRecord::new(
        run.benchmark_run_id.clone(),
        BenchmarkOutcomeClass::Partial,
        BenchmarkEvidenceGrade::Moderate,
        BenchmarkStageVector {
            intake: BenchmarkStageScore::reached(),
            boot: BenchmarkStageScore::reached(),
            reachability: BenchmarkStageScore::partial(),
            operator_access: BenchmarkStageScore::not_reached(),
            research_utility: BenchmarkStageScore::reached(),
            exploit_readiness: BenchmarkStageScore::not_reached(),
        },
    );

    let json = serde_json::to_string(&(run.clone(), other_run.clone(), outcome.clone())).unwrap();
    let round_trip: (
        BenchmarkRunRecord,
        BenchmarkRunRecord,
        BenchmarkOutcomeRecord,
    ) = serde_json::from_str(&json).unwrap();

    assert_eq!(round_trip.0, run);
    assert_eq!(round_trip.1, other_run);
    assert_eq!(round_trip.2, outcome);
    assert_eq!(round_trip.2.outcome_class, BenchmarkOutcomeClass::Partial);
    assert_eq!(
        round_trip.2.stage_vector.reachability.status,
        BenchmarkStageStatus::Partial
    );
    assert_ne!(round_trip.0.benchmark_run_id, round_trip.1.benchmark_run_id);
}

#[test]
fn benchmark_run_ids_vary_with_execution_identity() {
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let first = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator.clone(),
        "apple-silicon-laptop",
        "exec-1",
    )
    .unwrap();
    let second = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        "exec-2",
    )
    .unwrap();

    assert_ne!(first.benchmark_run_id, second.benchmark_run_id);
    assert_ne!(first.execution_id, second.execution_id);
}

#[test]
fn legacy_benchmark_run_json_without_execution_id_still_deserializes() {
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let migrated_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
            legacy_benchmark_run_id.as_str(),
        ],
    );
    let json = format!(
        r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
    );

    let run: BenchmarkRunRecord = serde_json::from_str(&json).unwrap();

    assert_eq!(run.benchmark_run_id, migrated_benchmark_run_id);
    assert_eq!(run.execution_id, legacy_benchmark_run_id);
}

#[test]
fn benchmark_run_constructor_rejects_empty_execution_id() {
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );

    let result = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        "   ",
    );

    assert!(result.is_err());
}

#[test]
fn benchmark_run_json_with_explicit_empty_execution_id_is_rejected() {
    let json = r#"{
  "benchmark_run_id": "brun-target-demo-camera-v1-firmae-external-raw-upstream-apple-silicon-laptop-0000000000000000",
  "target_id": "target-demo-camera-v1",
  "comparator": {
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  },
  "host_profile": "apple-silicon-laptop",
  "execution_id": "   "
}"#;

    let err = serde_json::from_str::<BenchmarkRunRecord>(json).unwrap_err();

    assert!(err
        .to_string()
        .contains("benchmark execution_id must not be empty"));
}

#[test]
fn benchmark_run_json_with_explicit_null_execution_id_is_rejected() {
    let json = r#"{
  "benchmark_run_id": "brun-target-demo-camera-v1-firmae-external-raw-upstream-apple-silicon-laptop-0000000000000000",
  "target_id": "target-demo-camera-v1",
  "comparator": {
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  },
  "host_profile": "apple-silicon-laptop",
  "execution_id": null
}"#;

    let err = serde_json::from_str::<BenchmarkRunRecord>(json).unwrap_err();

    assert!(err
        .to_string()
        .contains("benchmark execution_id must not be null"));
}

#[test]
fn benchmark_run_json_with_mismatched_benchmark_run_id_is_rejected() {
    let json = r#"{
  "benchmark_run_id": "brun-stale-id",
  "target_id": "target-demo-camera-v1",
  "comparator": {
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  },
  "host_profile": "apple-silicon-laptop",
  "execution_id": "exec-1"
}"#;

    let err = serde_json::from_str::<BenchmarkRunRecord>(json).unwrap_err();

    assert!(err
        .to_string()
        .contains("benchmark_run_id does not match canonical benchmark run identity"));
}

#[test]
fn fat_native_benchmark_scoring_marks_booted_but_unreachable_runs_as_partial() {
    let target = TargetRecord::new(
        "project-1",
        "target-demo-camera-v1",
        "Demo Camera v1",
        "2026-03-29T00:00:00Z",
    );
    let run = RunRecord::new(
        "session-1",
        "recipe-1",
        "managed-linux-vm",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Booting);
    let runtime_summary = ManagedRuntimeSummary {
        backend_id: "firmae".to_string(),
        control_contract: "firmae-legacy-wrapper-v1".to_string(),
        driver_profile: "firmae-managed-legacy-wrapper".to_string(),
        lifecycle_adapter: "legacy-wrapper".to_string(),
        runtime_phase: "probe-healthy".to_string(),
        runtime_outcome: Some("booted-services-unreachable".to_string()),
        workspace_dir: "/tmp/firmae".to_string(),
        services: Vec::new(),
        launch_mode: Some("legacy-wrapper-launch".to_string()),
        stop_mode: Some("legacy-wrapper-stop".to_string()),
        launch_manifest_present: Some(false),
        probe_result_contract: Some("firmae-legacy-wrapper-probe-v1".to_string()),
        probe_result_contract_verified: Some(true),
        probe_source: Some("background-supervisor".to_string()),
        probe_outcome: Some("healthy".to_string()),
        stop_result_contract: None,
        stop_result_contract_verified: None,
        stop_exit_code: None,
        workspace_removed: None,
    };
    let diagnostics = vec![DiagnosticRecord::new(
        run.run_id.clone(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::Observer,
        DiagnosticClass::GuestUnreachable,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "guest booted but no services exposed",
        vec!["art-runtime-summary".to_string()],
        vec![],
        vec!["collect more runtime evidence".to_string()],
    )];
    let findings = vec![Finding::new(
        "finding-runtime-1",
        "managed runtime is reachable only through boot evidence",
        FindingSeverity::Info,
        FindingSubject::Project,
    )];

    let outcome = score_fat_native_run(
        &target,
        &run,
        Some(&runtime_summary),
        None,
        None,
        &findings,
        &diagnostics,
    );

    assert_eq!(outcome.outcome_class, BenchmarkOutcomeClass::Partial);
    assert_eq!(outcome.evidence_grade, BenchmarkEvidenceGrade::Moderate);
    assert_eq!(
        outcome.stage_vector.intake.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.boot.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.reachability.status,
        BenchmarkStageStatus::Partial
    );
    assert_eq!(
        outcome.stage_vector.operator_access.status,
        BenchmarkStageStatus::NotReached
    );
    assert_eq!(
        outcome.stage_vector.research_utility.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.exploit_readiness.status,
        BenchmarkStageStatus::NotReached
    );
}

#[test]
fn fat_native_benchmark_scoring_can_score_a_clean_run_as_strong() {
    let target = TargetRecord::new(
        "project-1",
        "target-demo-camera-v1",
        "Demo Camera v1",
        "2026-03-29T00:00:00Z",
    );
    let run = RunRecord::new(
        "session-1",
        "recipe-1",
        "managed-linux-vm",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running)
    .with_active_endpoints(vec![
        RuntimeEndpoint::new(RuntimeEndpointKind::Shell, "shell", "127.0.0.1", 12022)
            .with_uri("ssh://127.0.0.1:12022"),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Debugger,
            "debugger",
            "127.0.0.1",
            12023,
        )
        .with_uri("tcp://127.0.0.1:12023"),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Service,
            "web-admin",
            "127.0.0.1",
            18080,
        )
        .with_uri("http://127.0.0.1:18080"),
    ]);
    let runtime_summary = ManagedRuntimeSummary {
        backend_id: "firmae".to_string(),
        control_contract: "firmae-legacy-wrapper-v1".to_string(),
        driver_profile: "firmae-managed-legacy-wrapper".to_string(),
        lifecycle_adapter: "legacy-wrapper".to_string(),
        runtime_phase: "probe-healthy".to_string(),
        runtime_outcome: None,
        workspace_dir: "/tmp/firmae".to_string(),
        services: vec![fat_core::services::ObservedService::new("web-admin")
            .with_endpoint("http://127.0.0.1:18080")],
        launch_mode: Some("legacy-wrapper-launch".to_string()),
        stop_mode: Some("legacy-wrapper-stop".to_string()),
        launch_manifest_present: Some(false),
        probe_result_contract: Some("firmae-legacy-wrapper-probe-v1".to_string()),
        probe_result_contract_verified: Some(true),
        probe_source: Some("background-supervisor".to_string()),
        probe_outcome: Some("healthy".to_string()),
        stop_result_contract: None,
        stop_result_contract_verified: None,
        stop_exit_code: None,
        workspace_removed: None,
    };

    let outcome = score_fat_native_run(&target, &run, Some(&runtime_summary), None, None, &[], &[]);

    assert_eq!(outcome.outcome_class, BenchmarkOutcomeClass::Strong);
    assert_eq!(outcome.evidence_grade, BenchmarkEvidenceGrade::Rich);
    assert_eq!(
        outcome.stage_vector.intake.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.boot.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.reachability.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.operator_access.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.research_utility.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.exploit_readiness.status,
        BenchmarkStageStatus::Reached
    );
}

#[test]
fn fat_native_benchmark_scoring_does_not_credit_boot_for_unknown_runtime_phases() {
    let target = TargetRecord::new(
        "project-1",
        "target-demo-camera-v1",
        "Demo Camera v1",
        "2026-03-29T00:00:00Z",
    );
    let run = RunRecord::new(
        "session-1",
        "recipe-1",
        "managed-linux-vm",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Booting);
    let runtime_summary = ManagedRuntimeSummary {
        backend_id: "firmae".to_string(),
        control_contract: "firmae-legacy-wrapper-v1".to_string(),
        driver_profile: "firmae-managed-legacy-wrapper".to_string(),
        lifecycle_adapter: "legacy-wrapper".to_string(),
        runtime_phase: "starting-up".to_string(),
        runtime_outcome: None,
        workspace_dir: "/tmp/firmae".to_string(),
        services: Vec::new(),
        launch_mode: Some("legacy-wrapper-launch".to_string()),
        stop_mode: Some("legacy-wrapper-stop".to_string()),
        launch_manifest_present: Some(false),
        probe_result_contract: None,
        probe_result_contract_verified: None,
        probe_source: None,
        probe_outcome: None,
        stop_result_contract: None,
        stop_result_contract_verified: None,
        stop_exit_code: None,
        workspace_removed: None,
    };

    let outcome = score_fat_native_run(&target, &run, Some(&runtime_summary), None, None, &[], &[]);

    assert_eq!(outcome.outcome_class, BenchmarkOutcomeClass::Failed);
    assert_eq!(outcome.evidence_grade, BenchmarkEvidenceGrade::Minimal);
    assert_eq!(
        outcome.stage_vector.intake.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.boot.status,
        BenchmarkStageStatus::NotReached
    );
    assert_eq!(
        outcome.stage_vector.reachability.status,
        BenchmarkStageStatus::NotReached
    );
}

#[test]
fn fat_native_benchmark_scoring_can_use_readiness_and_confidence_without_legacy_summary() {
    let target = TargetRecord::new(
        "project-1",
        "target-demo",
        "Demo Target",
        "2026-04-09T00:00:00Z",
    );
    let run = RunRecord::new(
        "session-1",
        "recipe-1",
        "qemu-direct",
        SubstrateKind::NativeHost,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);
    let readiness = ReadinessReport::new(
        "project-1",
        "target-demo",
        "session-1",
        run.run_id.clone(),
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
        ],
        vec![
            RuntimeSurfaceRecord::new(
                "project-1",
                "target-demo",
                "session-1",
                run.run_id.clone(),
                "shell",
                "shell",
                "ssh://127.0.0.1:10022",
                SurfaceReadiness::Validated,
            )
            .with_uri("ssh://127.0.0.1:10022")
            .with_port(10022),
            RuntimeSurfaceRecord::new(
                "project-1",
                "target-demo",
                "session-1",
                run.run_id.clone(),
                "service",
                "service",
                "http://127.0.0.1:8080",
                SurfaceReadiness::Validated,
            )
            .with_uri("http://127.0.0.1:8080")
            .with_port(8080),
        ],
    )
    .with_validated_goals(vec![
        "shell-access".to_string(),
        "listener-bind".to_string(),
        "http-validation".to_string(),
        "process-chain".to_string(),
    ]);
    let confidence = ConfidenceReport::new(
        "project-1",
        "target-demo",
        "session-1",
        run.run_id.clone(),
        None,
        ConfidenceLevel::High,
        85,
    )
    .with_goals(vec![
        GoalConfidence::new("shell-access", GoalState::Validated),
        GoalConfidence::new("listener-bind", GoalState::Validated),
        GoalConfidence::new("http-validation", GoalState::Validated),
        GoalConfidence::new("process-chain", GoalState::Validated),
    ]);

    let outcome = score_fat_native_run(
        &target,
        &run,
        None,
        Some(&readiness),
        Some(&confidence),
        &[],
        &[],
    );

    assert_eq!(outcome.outcome_class, BenchmarkOutcomeClass::Strong);
    assert_eq!(outcome.evidence_grade, BenchmarkEvidenceGrade::Rich);
    assert_eq!(
        outcome.stage_vector.boot.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.reachability.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.operator_access.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcome.stage_vector.exploit_readiness.status,
        BenchmarkStageStatus::Reached
    );
}
