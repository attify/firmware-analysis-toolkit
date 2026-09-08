use fat_core::readiness::{BlockerRecord, ConfidenceLevel, ConfidenceReport};
use fat_core::rehosting::{
    AttemptRecord, FailureClass, ReadinessReport, RehostingMode, RepairActionKind,
    RepairMaterializationRecord, RepairRecord, RuntimeSurfaceRecord, SurfaceReadiness,
    TargetExecutionProfile,
};
use fat_core::rehosting_policy::{SelectionTrace, SubstrateKind, SubstratePreference};
use fat_core::rehosting_recipe::{RecipeDeviceNodePlan, RehostingRecipe};
use fat_core::runtime_store::RuntimeStore;
use fat_core::staging::{StagingManifest, StagingMutation, StagingStrategy};
use fat_core::target_model::TargetModel;

#[test]
fn rehosting_records_round_trip_through_runtime_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuntimeStore::open(dir.path()).expect("runtime store");

    let profile = TargetExecutionProfile::new(
        "demo",
        "target-demo",
        Some("armel"),
        Some("linux-router-arm"),
        vec!["arch:armel".to_string(), "web:cgi".to_string()],
    )
    .with_candidate_modes(vec![RehostingMode::Service, RehostingMode::System]);
    let surface = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "shell",
        "shell",
        "ssh://127.0.0.1:10022",
        SurfaceReadiness::Validated,
    )
    .with_uri("ssh://127.0.0.1:10022");
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        vec!["shell-access".to_string(), "http-validation".to_string()],
        vec![surface],
    )
    .with_validated_goals(vec!["shell-access".to_string()]);
    let attempt = AttemptRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        1,
        RehostingMode::System,
    );
    let repair = RepairRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        &attempt.attempt_id,
        FailureClass::InitDependency,
        RepairActionKind::PatchConfig,
    );
    let repair_materialization = RepairMaterializationRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        &attempt.attempt_id,
        &repair.repair_id,
        RepairActionKind::PatchConfig,
        vec![RecipeDeviceNodePlan::new("/dev/ttyS0", "char")],
        Vec::new(),
        None,
    );

    store.write_target_profile(&profile).expect("write profile");
    let target_model = TargetModel::new(
        "demo",
        "target-demo",
        Some("armel"),
        Some("linux-router-arm"),
        vec!["arch:armel".to_string(), "web:cgi".to_string()],
    );
    store
        .write_target_model(&target_model)
        .expect("write target model");
    store
        .write_readiness_report(&readiness)
        .expect("write readiness");
    store.write_attempt_record(&attempt).expect("write attempt");
    store.write_repair_record(&repair).expect("write repair");
    store
        .write_repair_materialization_record(&repair_materialization)
        .expect("write repair materialization");
    let rehosting_recipe = RehostingRecipe::new(
        "target-demo",
        &target_model.model_id,
        "run-demo",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::Service,
    );
    store
        .write_rehosting_recipe("sess-demo", "run-demo", &rehosting_recipe)
        .expect("write rehosting recipe");
    let selection_trace = SelectionTrace::new("demo", "target-demo", "sess-demo", "run-demo")
        .with_preference(SubstratePreference::Auto);
    store
        .write_selection_trace(&selection_trace)
        .expect("write selection trace");
    let staging = StagingManifest::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        SubstrateKind::Service.as_str(),
        StagingStrategy::MutableOverlay,
        "/inputs/rootfs",
        "/work/staging/run-demo",
    )
    .with_mutations(vec![StagingMutation::new(
        "copy",
        Some("/inputs/rootfs"),
        "/work/staging/run-demo",
    )]);
    store
        .write_staging_manifest(&staging)
        .expect("write staging manifest");
    let blocker = BlockerRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        SubstrateKind::Service,
        "validator-failure",
        "validator did not observe a semantic reply",
        ConfidenceLevel::Low,
    );
    store.write_blocker_record(&blocker).expect("write blocker");
    let confidence = ConfidenceReport::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        Some(SubstrateKind::Service),
        ConfidenceLevel::Low,
        21,
    )
    .with_blockers(vec![blocker.blocker_id.clone()]);
    store
        .write_confidence_report(&confidence)
        .expect("write confidence");

    assert_eq!(
        store
            .read_target_profile(&profile.target_id, &profile.profile_id)
            .expect("read profile"),
        profile
    );
    assert_eq!(
        store
            .read_readiness_report(
                &readiness.session_id,
                &readiness.run_id,
                &readiness.readiness_id
            )
            .expect("read readiness"),
        readiness
    );
    assert_eq!(
        store
            .read_attempt_record(&attempt.session_id, &attempt.run_id, &attempt.attempt_id)
            .expect("read attempt"),
        attempt
    );
    assert_eq!(
        store
            .read_repair_record(&repair.session_id, &repair.run_id, &repair.repair_id)
            .expect("read repair"),
        repair
    );
    assert_eq!(
        store
            .read_repair_materialization_record(
                &repair_materialization.session_id,
                &repair_materialization.run_id,
                &repair_materialization.repair_materialization_id,
            )
            .expect("read repair materialization"),
        repair_materialization
    );
    assert_eq!(
        store
            .read_target_model(&target_model.target_id, &target_model.model_id)
            .expect("read target model"),
        target_model
    );
    assert_eq!(
        store
            .read_rehosting_recipe(
                "sess-demo",
                "run-demo",
                &rehosting_recipe.rehosting_recipe_id
            )
            .expect("read rehosting recipe"),
        rehosting_recipe
    );
    assert_eq!(
        store
            .read_selection_trace(
                &selection_trace.session_id,
                &selection_trace.run_id,
                &selection_trace.selection_trace_id
            )
            .expect("read selection trace"),
        selection_trace
    );
    assert_eq!(
        store
            .read_staging_manifest("sess-demo", "run-demo", &staging.staging_manifest_id)
            .expect("read staging"),
        staging
    );
    assert_eq!(
        store
            .read_blocker_record("sess-demo", "run-demo", &blocker.blocker_id)
            .expect("read blocker"),
        blocker
    );
    assert_eq!(
        store
            .read_confidence_report("sess-demo", "run-demo", &confidence.confidence_report_id,)
            .expect("read confidence"),
        confidence
    );
}

#[test]
fn rehosting_runtime_store_paths_live_under_targets_and_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuntimeStore::open(dir.path()).expect("runtime store");

    let profile_path = store.target_profile_path("target-demo", "profile-demo");
    let readiness_path = store.readiness_report_path("sess-demo", "run-demo", "ready-demo");
    let attempt_path = store.attempt_record_path("sess-demo", "run-demo", "attempt-demo");
    let repair_path = store.repair_record_path("sess-demo", "run-demo", "repair-demo");
    let repair_materialization_path =
        store.repair_materialization_path("sess-demo", "run-demo", "repair-materialization-demo");
    let target_model_path = store.target_model_path("target-demo", "model-demo");
    let rehosting_recipe_path =
        store.rehosting_recipe_path("sess-demo", "run-demo", "rh-recipe-demo");
    let selection_trace_path = store.selection_trace_path("sess-demo", "run-demo", "trace-demo");
    let staging_path = store.staging_manifest_path("sess-demo", "run-demo", "staging-demo");
    let confidence_path = store.confidence_report_path("sess-demo", "run-demo", "confidence-demo");
    let blocker_path = store.blocker_record_path("sess-demo", "run-demo", "blocker-demo");

    assert!(profile_path.starts_with(
        dir.path()
            .join("targets")
            .join("target-demo")
            .join("rehosting")
            .join("profiles")
    ));
    assert!(readiness_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("readiness")
    ));
    assert!(attempt_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("attempts")
    ));
    assert!(repair_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("repairs")
    ));
    assert!(repair_materialization_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("repairs")
            .join("materializations")
    ));
    assert!(target_model_path.starts_with(
        dir.path()
            .join("targets")
            .join("target-demo")
            .join("rehosting")
            .join("models")
    ));
    assert!(rehosting_recipe_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("recipes")
    ));
    assert!(selection_trace_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("selection")
    ));
    assert!(staging_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("staging")
    ));
    assert!(confidence_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("confidence")
    ));
    assert!(blocker_path.starts_with(
        dir.path()
            .join("sessions")
            .join("sess-demo")
            .join("runs")
            .join("run-demo")
            .join("rehosting")
            .join("blockers")
    ));
}
