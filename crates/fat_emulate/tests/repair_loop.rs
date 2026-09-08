use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::rehosting::{
    AttemptRecord, FailureClass, RehostingMode, RepairActionKind, RepairRecord,
};
use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runtime_store::RuntimeStore;
use fat_emulate::repair::{apply_repair_for_retry, decide_repair};

fn diagnostic(
    run_id: &str,
    phase: DiagnosticPhase,
    class: DiagnosticClass,
    summary: &str,
    suggested_next_actions: Vec<&str>,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id,
        phase,
        DiagnosticOwner::BackendTool,
        class,
        None,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresBackendFix,
        summary,
        Vec::new(),
        Vec::new(),
        suggested_next_actions
            .into_iter()
            .map(str::to_string)
            .collect(),
    )
}

#[test]
fn decide_repair_maps_missing_device_path_to_create_node_retry() {
    let diagnostic = diagnostic(
        "run-1",
        DiagnosticPhase::Launch,
        DiagnosticClass::DeviceOrPathMissing,
        "missing /dev/ttyS0 while bootstrapping the guest",
        vec!["create the missing device node"],
    );

    assert!(!diagnostic.suggested_next_actions.is_empty());
    let decision = decide_repair(&diagnostic).expect("repair decision");
    assert_eq!(decision.failure_class, FailureClass::SystemResource);
    assert_eq!(decision.action, RepairActionKind::CreateNode);
    assert!(decision.retry_allowed);
}

#[test]
fn decide_repair_maps_missing_config_materialization_to_patch_config_retry() {
    let diagnostic = diagnostic(
        "run-2",
        DiagnosticPhase::Preparation,
        DiagnosticClass::PreparationFailed,
        "config materialization failed for generated init files",
        vec!["patch the generated config and retry"],
    );

    let decision = decide_repair(&diagnostic).expect("repair decision");
    assert_eq!(decision.failure_class, FailureClass::InitDependency);
    assert_eq!(decision.action, RepairActionKind::PatchConfig);
    assert!(decision.retry_allowed);
}

#[test]
fn decide_repair_maps_missing_peer_service_bootstrap_to_start_peer_service_retry() {
    let diagnostic = diagnostic(
        "run-3",
        DiagnosticPhase::UserspaceStartup,
        DiagnosticClass::IpcOrServiceMissing,
        "peer service bootstrap missing for ubus and uhttpd",
        vec!["start the peer service before reattaching"],
    );

    let decision = decide_repair(&diagnostic).expect("repair decision");
    assert_eq!(decision.failure_class, FailureClass::IpcDependency);
    assert_eq!(decision.action, RepairActionKind::StartPeerService);
    assert!(decision.retry_allowed);
}

#[test]
fn decide_repair_falls_back_without_retry_for_generic_launch_failure() {
    let diagnostic = diagnostic(
        "run-4",
        DiagnosticPhase::Launch,
        DiagnosticClass::LaunchFailed,
        "launch failed without a bounded repair hint",
        vec!["inspect the launch logs"],
    );

    let decision = decide_repair(&diagnostic).expect("repair decision");
    assert_eq!(decision.failure_class, FailureClass::TargetLaunch);
    assert_eq!(decision.action, RepairActionKind::RetryPlan);
    assert!(!decision.retry_allowed);
}

#[test]
fn bounded_repair_records_can_persist_a_retry_attempt_and_repair_record() {
    let project_dir = std::env::temp_dir().join(format!("fat-repair-loop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&project_dir);
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let initial_attempt = AttemptRecord::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        1,
        RehostingMode::System,
    )
    .with_summary("initial launch attempt");
    store
        .write_attempt_record(&initial_attempt)
        .expect("write initial attempt");

    let diagnostic = diagnostic(
        "run-1",
        DiagnosticPhase::Launch,
        DiagnosticClass::DeviceOrPathMissing,
        "missing /dev/ttyS0 while bootstrapping the guest",
        vec!["create the missing device node"],
    );
    let decision = decide_repair(&diagnostic).expect("repair decision");
    assert!(decision.retry_allowed);

    let retry_attempt = AttemptRecord::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        initial_attempt.sequence + 1,
        initial_attempt.mode,
    )
    .with_summary(format!(
        "bounded repair retry: {}",
        decision.action.as_str()
    ));
    store
        .write_attempt_record(&retry_attempt)
        .expect("write retry attempt");

    let repair_record = RepairRecord::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        retry_attempt.attempt_id.clone(),
        decision.failure_class,
        decision.action,
    )
    .with_detail(diagnostic.summary.clone());
    store
        .write_repair_record(&repair_record)
        .expect("write repair record");

    let persisted_retry = store
        .read_attempt_record("session-1", "run-1", &retry_attempt.attempt_id)
        .expect("read retry attempt");
    let persisted_repair = store
        .read_repair_record("session-1", "run-1", &repair_record.repair_id)
        .expect("read repair record");
    assert_eq!(persisted_retry.sequence, 2);
    assert_eq!(persisted_retry.mode, RehostingMode::System);
    assert_eq!(persisted_repair.attempt_id, retry_attempt.attempt_id);
    assert_eq!(persisted_repair.failure_class, FailureClass::SystemResource);
    assert_eq!(persisted_repair.action, RepairActionKind::CreateNode);
    let _ = std::fs::remove_dir_all(&project_dir);
}

#[test]
fn apply_repair_for_retry_materializes_missing_device_nodes_into_the_next_recipe_attempt() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_retry_budget(3);
    let diagnostic = diagnostic(
        "run-1",
        DiagnosticPhase::Launch,
        DiagnosticClass::DeviceOrPathMissing,
        "missing /dev/ttyS0 while bootstrapping the guest",
        vec!["create the missing device node and retry"],
    );

    let (decision, mutated) =
        apply_repair_for_retry(&recipe, &diagnostic).expect("mutated retry recipe");

    assert_eq!(decision.action, RepairActionKind::CreateNode);
    assert!(mutated
        .device_nodes
        .iter()
        .any(|node| node.path == "/dev/ttyS0"));
    assert!(mutated
        .instrumentation_flags
        .iter()
        .any(|flag| flag == "repair:create-node:/dev/ttyS0"));
}

#[test]
fn apply_repair_for_retry_rotates_init_candidates_when_the_original_boot_path_is_wrong() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_retry_budget(3);
    let diagnostic = diagnostic(
        "run-1",
        DiagnosticPhase::Launch,
        DiagnosticClass::PreparationFailed,
        "wrong init path /sbin/init; retry with /etc/init.d/rcS",
        vec!["rotate init candidate to /etc/init.d/rcS"],
    );

    let (_, mutated) = apply_repair_for_retry(&recipe, &diagnostic).expect("mutated retry recipe");

    let launch_plan = mutated.launch_plan.expect("launch plan");
    assert_eq!(launch_plan.executable, "/etc/init.d/rcS");
    assert!(mutated
        .instrumentation_flags
        .iter()
        .any(|flag| flag == "repair:rotate-init:/etc/init.d/rcS"));
    assert!(mutated.filesystem_transforms.iter().any(|transform| {
        transform.transform_kind == "patch-config"
            && transform.source == "synth:repair-init"
            && transform.destination == "/etc/fat/repair-init.sh"
    }));
}
