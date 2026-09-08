use fat_backend::BackendRegistry;
use fat_core::rehosting_policy::{SubstrateKind as LogicalSubstrateKind, SubstratePreference};
use fat_core::runs::SubstrateKind;
use fat_emulate::plan::{create_emulation_bundle_from_request, EmulationBundleRequest};
use fat_emulate::strategy::{
    EmulationAutomationMode, PriorRunSummary, StrategyEngine, StrategyError, StrategyRequest,
};

#[test]
fn strategy_request_carries_goal_evidence_host_capabilities_and_prior_runs() {
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ],
        vec!["native-host".to_string(), "docker-engine".to_string()],
        vec![PriorRunSummary::new(
            "run-1",
            "qemu-direct",
            "native-host",
            "degraded-completed",
        )],
    )
    .with_automation_mode(EmulationAutomationMode::AutoSafe);

    assert_eq!(request.goal, "emulate firmware");
    assert_eq!(
        request.target_evidence,
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ]
    );
    assert_eq!(
        request.host_capabilities,
        vec!["native-host".to_string(), "docker-engine".to_string()]
    );
    assert_eq!(request.prior_runs.len(), 1);
    assert_eq!(request.automation_mode, EmulationAutomationMode::AutoSafe);
    assert_eq!(request.substrate_preference, SubstratePreference::Auto);
}

#[test]
fn strategy_filters_candidates_by_hard_constraints_before_ranking() {
    let engine = StrategyEngine::new(BackendRegistry::with_test_backends());
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
            "nvram:present".to_string(),
        ],
        vec!["native-host".to_string()],
        Vec::new(),
    );

    let evaluation = engine.evaluate(&request).expect("evaluation");

    assert!(evaluation
        .filtered_out
        .iter()
        .any(|candidate| candidate.backend_id == "docker-native"));
    assert!(!evaluation
        .candidates
        .iter()
        .any(|candidate| candidate.backend_id == "docker-native"));
    assert_eq!(evaluation.selected.backend_id, "qemu-direct");
    assert!(evaluation
        .selected
        .hard_constraint_reasons
        .iter()
        .any(|reason| reason.contains("native-host")));
    assert_eq!(
        evaluation.selected.logical_substrate,
        LogicalSubstrateKind::Service
    );
}

#[test]
fn managed_linux_vm_host_capability_allows_firmae_selection() {
    let engine = StrategyEngine::new(BackendRegistry::with_test_backends());
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
        ],
        vec!["managed-linux-vm".to_string()],
        Vec::new(),
    );

    let evaluation = engine.evaluate(&request).expect("evaluation");

    assert_eq!(evaluation.selected.backend_id, "firmae");
    assert_eq!(evaluation.selected.substrate, SubstrateKind::ManagedLinuxVm);
    assert_eq!(
        evaluation.selected.logical_substrate,
        LogicalSubstrateKind::System
    );
}

#[test]
fn strategy_selection_preserves_backend_substrate_and_reasoning_for_requested_backend() {
    let plan = fat_emulate::EmulationPlan::new("smoke-1", "qemu-direct", vec![8080])
        .expect("supported backend");

    assert_eq!(plan.recipe.selected_backend, "qemu-direct");
    assert_eq!(plan.recipe.selected_substrate, "native-host");
    assert_eq!(plan.strategy.selected.backend_id, "qemu-direct");
    assert_eq!(plan.strategy.selected.substrate, SubstrateKind::NativeHost);
    assert_eq!(
        plan.strategy.selected.logical_substrate,
        LogicalSubstrateKind::System
    );
    assert!(plan
        .strategy
        .reasoning
        .iter()
        .any(|reason| reason.contains("explicit backend request")));
}

#[test]
fn auto_prefers_service_before_system_and_reference_when_viable() {
    let engine = StrategyEngine::new(BackendRegistry::with_test_backends());
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "web:uhttpd".to_string(),
            "generated:reference-rootfs".to_string(),
        ],
        vec!["native-host".to_string(), "docker-engine".to_string()],
        Vec::new(),
    )
    .with_automation_mode(EmulationAutomationMode::AutoSafe);

    let evaluation = engine.evaluate(&request).expect("evaluation");

    assert_eq!(
        evaluation.request.substrate_preference,
        SubstratePreference::Auto
    );
    assert_eq!(
        evaluation.selected.logical_substrate,
        LogicalSubstrateKind::Service
    );
}

#[test]
fn reference_only_preference_selects_reference_candidates() {
    let engine = StrategyEngine::new(BackendRegistry::with_test_backends());
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "generated:reference-rootfs".to_string(),
        ],
        vec!["docker-engine".to_string()],
        Vec::new(),
    )
    .with_substrate_preference(SubstratePreference::ReferenceOnly)
    .with_automation_mode(EmulationAutomationMode::AutoSafe);

    let evaluation = engine.evaluate(&request).expect("evaluation");

    assert_eq!(evaluation.selected.backend_id, "emux");
    assert_eq!(
        evaluation.selected.logical_substrate,
        LogicalSubstrateKind::Reference
    );
}

#[test]
fn explicit_backend_and_substrate_mismatch_is_rejected() {
    let engine = StrategyEngine::new(BackendRegistry::with_test_backends());
    let request = StrategyRequest::new(
        "emulate firmware",
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ],
        vec!["native-host".to_string(), "docker-engine".to_string()],
        Vec::new(),
    )
    .with_requested_backend("docker-native")
    .with_requested_substrate("native-host")
    .with_automation_mode(EmulationAutomationMode::AutoSafe);

    let err = engine
        .evaluate(&request)
        .expect_err("mismatch should be rejected");
    assert!(matches!(
        err,
        StrategyError::NoViableCandidates { ref goal, ref family_id }
        if goal == "emulate firmware" && family_id == "linux-router-arm"
    ));
}

#[test]
fn rich_request_path_preserves_evidence_and_prior_runs_in_strategy_reasoning() {
    let request = EmulationBundleRequest::new("smoke-rich", vec![8080])
        .with_target_evidence(vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
            "nvram:present".to_string(),
        ])
        .with_host_capabilities(vec!["native-host".to_string()])
        .with_prior_runs(vec![PriorRunSummary::new(
            "run-2",
            "firmae",
            "docker-engine",
            "degraded-completed",
        )])
        .with_requested_backend("qemu-direct")
        .with_requested_substrate("native-host")
        .with_automation_mode(EmulationAutomationMode::AutoSafe);

    let plan = create_emulation_bundle_from_request(request).expect("rich request should work");

    assert_eq!(
        plan.strategy.request.target_evidence,
        vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
            "nvram:present".to_string(),
        ]
    );
    assert_eq!(plan.strategy.request.prior_runs.len(), 1);
    assert!(plan.strategy.reasoning.iter().any(|reason| reason.contains(
        "target evidence: arch:armel, fs:squashfs, init:busybox, web:cgi, nvram:present"
    )));
    assert!(plan
        .strategy
        .reasoning
        .iter()
        .any(|reason| reason.contains("prior runs considered: 1")));
    assert_eq!(plan.recipe.selected_backend, "qemu-direct");
    assert_eq!(plan.recipe.selected_substrate, "native-host");
}
