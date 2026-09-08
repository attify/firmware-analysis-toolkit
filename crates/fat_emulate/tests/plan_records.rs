use fat_core::rehosting::RehostingMode;
use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_core::runs::RunStatus;
use fat_core::sessions::SessionStatus;
use fat_emulate::{create_emulation_bundle, EmulationPlan, EmulationRun};

#[test]
fn planning_emulation_request_produces_recipe_session_and_run_records() {
    let plan =
        create_emulation_bundle("smoke-1", "firmae", vec![443, 502]).expect("supported backend");

    assert_eq!(plan.requested_session_id, "smoke-1");
    assert_eq!(plan.session.project_id, "emulation-project");
    assert_eq!(plan.session.target_id, "emulation-target");
    assert!(plan.session.created_at.starts_with("unix-ms:"));
    assert_eq!(plan.recipe.selected_backend, "firmae");
    assert_eq!(plan.recipe.target_id, "emulation-target");
    assert_eq!(
        plan.recipe.launch_parameters,
        vec![
            "backend=firmae".to_string(),
            "port=443".to_string(),
            "port=502".to_string(),
        ]
    );
    assert_eq!(plan.session.status, SessionStatus::Planned);
    assert_eq!(plan.session.run_ids, vec![plan.run.record.run_id.clone()]);
    assert_eq!(plan.run.record.backend_driver, "firmae");
    assert_eq!(plan.run.record.session_id, plan.session.session_id);
    assert_eq!(plan.profile.project_id, "emulation-project");
    assert_eq!(plan.profile.target_id, "emulation-target");
    assert!(plan.profile.candidate_modes.is_empty());
    assert_eq!(plan.target_model.project_id, "emulation-project");
    assert_eq!(plan.target_model.target_id, "emulation-target");
    assert_eq!(plan.target_model.to_execution_profile(), plan.profile);
    assert_eq!(plan.rehosting_recipe.target_id, "emulation-target");
    assert_eq!(plan.selection_trace.project_id, "emulation-project");
    assert_eq!(plan.selection_trace.target_id, "emulation-target");
    assert_eq!(plan.selection_trace.session_id, plan.session.session_id);
    assert_eq!(plan.selection_trace.run_id, plan.run.record.run_id);
    assert_eq!(plan.selection_trace.attempts.len(), 3);
    assert_eq!(
        plan.rehosting_recipe.substrate_preference,
        SubstratePreference::Auto
    );
    assert_eq!(
        plan.rehosting_recipe.selected_substrate,
        SubstrateKind::System
    );
    assert!(plan.readiness_goals.contains(&"shell-access".to_string()));
    assert!(plan
        .recipe
        .debug_features
        .contains(&"goal=shell-access".to_string()));
    assert_eq!(
        plan.run
            .record
            .active_endpoints
            .iter()
            .map(|endpoint| endpoint.port)
            .collect::<Vec<_>>(),
        vec![443, 502]
    );
}

#[test]
fn launching_a_plan_returns_session_and_run_views_backed_by_core_records() {
    let session = EmulationPlan::new("smoke-2", "qemu-direct", vec![8080])
        .expect("supported backend")
        .launch();

    assert_eq!(session.requested_session_id(), "smoke-2");
    assert_ne!(session.session_id(), session.requested_session_id());
    assert_eq!(session.backend_id(), "qemu-direct");
    assert_eq!(session.mapped_ports(), vec![8080]);
    assert_eq!(session.session.status, SessionStatus::Active);
    assert_eq!(session.run_record().status, RunStatus::Queued);
    assert_eq!(
        session.session.run_ids,
        vec![session.run_record().run_id.clone()]
    );
}

#[test]
fn run_state_transitions_cover_the_slice() {
    let run = EmulationRun::default();

    assert_eq!(run.record.status, RunStatus::Created);
    assert_eq!(run.clone().queued().record.status, RunStatus::Queued);
    assert_eq!(run.clone().preparing().record.status, RunStatus::Preparing);
    assert_eq!(run.clone().completed().record.status, RunStatus::Completed);
    assert_eq!(run.failed().record.status, RunStatus::Failed);
}

#[test]
fn planning_persists_backend_and_ports_in_the_recipe_record() {
    let plan =
        create_emulation_bundle("smoke-3", "firmadyne", vec![80, 8080]).expect("supported backend");

    assert_eq!(plan.requested_session_id, "smoke-3");
    assert_eq!(plan.recipe.selected_backend, "firmadyne");
    assert_eq!(plan.recipe.selected_substrate, "managed-linux-vm");
    assert_eq!(plan.session.project_id, "emulation-project");
    assert_eq!(plan.session.target_id, "emulation-target");
    assert_eq!(plan.session.strategy_family, "fat-emulate");
    assert!(plan
        .recipe
        .resolved_profile_chain
        .iter()
        .all(|entry| entry != "mode=system"));
    assert!(plan
        .recipe
        .debug_features
        .iter()
        .any(|entry| entry == "goal=shell-access"));
    assert_eq!(
        plan.recipe.launch_parameters,
        vec![
            "backend=firmadyne".to_string(),
            "port=80".to_string(),
            "port=8080".to_string(),
        ]
    );
    // The recipe id carries a bounded, readable slug prefix plus a stable hash
    // suffix; the backend/strategy specifics are asserted above.
    assert!(plan
        .recipe
        .recipe_id
        .starts_with("recipe-emulation-target-fat-emulate-slice-1"));
    assert_eq!(plan.recipe.target_id, "emulation-target");
    assert_eq!(plan.recipe.strategy_version, "fat-emulate-slice-1");
    assert_eq!(plan.recipe.goal, "emulate firmware");
}

#[test]
fn distinct_requested_session_ids_produce_distinct_core_ids() {
    let alpha = create_emulation_bundle("smoke-alpha", "firmae", vec![443, 502])
        .expect("supported backend");
    let beta =
        create_emulation_bundle("smoke-beta", "firmae", vec![443, 502]).expect("supported backend");

    assert_eq!(alpha.requested_session_id, "smoke-alpha");
    assert_eq!(beta.requested_session_id, "smoke-beta");
    assert_ne!(alpha.session.session_id, beta.session.session_id);
    assert_ne!(alpha.recipe.recipe_id, beta.recipe.recipe_id);
    assert_eq!(alpha.session.project_id, beta.session.project_id);
    assert_eq!(alpha.session.target_id, beta.session.target_id);
    assert_eq!(alpha.recipe.target_id, beta.recipe.target_id);
}

#[test]
fn distinct_evidence_changes_recipe_and_profile_identity_for_same_session_context() {
    let alpha = fat_emulate::plan::create_emulation_bundle_from_request(
        fat_emulate::plan::EmulationBundleRequest::new("smoke-identity", vec![443, 502])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:/etc/init.d/rcS".to_string(),
                "web:cgi".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(fat_emulate::strategy::EmulationAutomationMode::AutoSafe),
    )
    .expect("supported backend");
    let beta = fat_emulate::plan::create_emulation_bundle_from_request(
        fat_emulate::plan::EmulationBundleRequest::new("smoke-identity", vec![443, 502])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:/etc/init.d/rcS".to_string(),
                "web:uhttpd".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(fat_emulate::strategy::EmulationAutomationMode::AutoSafe),
    )
    .expect("supported backend");

    assert_ne!(alpha.profile.profile_id, beta.profile.profile_id);
    assert_ne!(alpha.target_model.model_id, beta.target_model.model_id);
    assert_ne!(alpha.recipe.recipe_id, beta.recipe.recipe_id);
    assert_ne!(
        alpha.rehosting_recipe.rehosting_recipe_id,
        beta.rehosting_recipe.rehosting_recipe_id
    );
    assert_ne!(
        alpha.selection_trace.selection_trace_id,
        beta.selection_trace.selection_trace_id
    );
}

#[test]
fn unsupported_backend_ids_return_a_recoverable_error() {
    let err = create_emulation_bundle("smoke-unsupported", "mystery-backend", vec![1, 2])
        .expect_err("unsupported backend should not panic");

    assert_eq!(
        err,
        fat_emulate::plan::EmulationPlanError::UnsupportedBackend {
            backend_id: "mystery-backend".to_string()
        }
    );
}

#[test]
fn planning_with_profile_evidence_keeps_family_and_readiness_context_additive() {
    let plan = fat_emulate::plan::create_emulation_bundle_from_request(
        fat_emulate::plan::EmulationBundleRequest::new("smoke-profile", vec![80])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:/etc/init.d/rcS".to_string(),
                "web:uhttpd".to_string(),
                "generated:reference-rootfs".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(fat_emulate::strategy::EmulationAutomationMode::AutoSafe),
    )
    .expect("supported backend");

    assert_eq!(plan.profile.family_id.as_deref(), Some("linux-router-arm"));
    assert_eq!(
        plan.target_model.family_id.as_deref(),
        Some("linux-router-arm")
    );
    assert_eq!(
        plan.profile.candidate_modes,
        vec![
            RehostingMode::Service,
            RehostingMode::System,
            RehostingMode::Reference,
        ]
    );
    assert_eq!(
        plan.readiness_goals,
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
            "init-complete".to_string(),
            "reference-bootstrap".to_string(),
        ]
    );
    assert!(plan
        .recipe
        .resolved_profile_chain
        .iter()
        .any(|entry| entry == "family=linux-router-arm"));
    assert!(plan
        .recipe
        .resolved_profile_chain
        .iter()
        .any(|entry| entry == "mode=service"));
    assert!(plan
        .recipe
        .debug_features
        .iter()
        .any(|entry| entry == "goal=http-validation"));
    assert!(plan
        .recipe
        .debug_features
        .iter()
        .any(|entry| entry == "goal=reference-bootstrap"));
    assert_eq!(
        plan.rehosting_recipe.target_model_id,
        plan.target_model.model_id
    );
    assert_eq!(
        plan.rehosting_recipe.selected_substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        plan.selection_trace.attempts[0].substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        plan.selection_trace.attempts[0].state,
        fat_core::rehosting_policy::SubstrateAttemptState::Selected
    );
    assert_eq!(
        plan.selection_trace.attempts[1].substrate,
        SubstrateKind::System
    );
    assert_eq!(
        plan.selection_trace.attempts[2].substrate,
        SubstrateKind::Reference
    );
}

#[test]
fn plan_and_synthesis_keep_profile_context_aligned_for_the_same_evidence() {
    let evidence = vec![
        "arch:armel".to_string(),
        "fs:squashfs".to_string(),
        "init:/etc/init.d/rcS".to_string(),
        "web:uhttpd".to_string(),
        "generated:reference-rootfs".to_string(),
    ];
    let plan = fat_emulate::plan::create_emulation_bundle_from_request(
        fat_emulate::plan::EmulationBundleRequest::new("smoke-align", vec![80])
            .with_target_evidence(evidence.clone())
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(fat_emulate::strategy::EmulationAutomationMode::AutoSafe),
    )
    .expect("supported backend");
    let strategy = fat_emulate::strategy::StrategyEngine::new(
        fat_backend::BackendRegistry::with_test_backends(),
    )
    .evaluate(
        &fat_emulate::strategy::StrategyRequest::new(
            "emulate firmware",
            evidence,
            vec!["native-host".to_string()],
            Vec::new(),
        )
        .with_automation_mode(fat_emulate::strategy::EmulationAutomationMode::AutoSafe),
    )
    .expect("strategy");
    let synthesis = fat_emulate::synthesizer::SynthesisEngine::new()
        .synthesize(fat_emulate::synthesizer::SynthesisRequest::from_strategy(
            strategy,
        ))
        .expect("synthesis");

    assert_eq!(plan.target_model.model_id, synthesis.target_model.model_id);
    assert_eq!(plan.profile.profile_id, synthesis.profile.profile_id);
    assert_eq!(
        plan.recipe.resolved_profile_chain,
        synthesis.recipe.resolved_profile_chain
    );
    assert_eq!(plan.readiness_goals, synthesis.readiness_goals);
}
