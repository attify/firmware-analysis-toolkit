use fat_backend::BackendRegistry;
use fat_core::artifacts::{ArtifactKind, ArtifactRetentionPolicy};
use fat_core::rehosting::RehostingMode;
use fat_core::runs::SubstrateKind;
use fat_emulate::strategy::{
    EmulationAutomationMode, PriorRunSummary, StrategyEngine, StrategyRequest,
};
use fat_emulate::synthesizer::{
    MaterializationAdapter, MaterializationTarget, SynthesisCategory, SynthesisContext,
    SynthesisEngine, SynthesisError, SynthesisRequest,
};
use fat_family::runtime_hints::{runtime_hints_for_family, RuntimeHintActionKind};

#[test]
fn family_runtime_hints_contribute_required_and_recommended_actions() {
    let hints = runtime_hints_for_family("linux-router-arm");

    assert!(hints
        .required_actions
        .iter()
        .any(|action| action.kind == RuntimeHintActionKind::Mount));
    assert!(hints
        .required_actions
        .iter()
        .any(|action| action.kind == RuntimeHintActionKind::ConfigMaterialization));
    assert!(hints
        .recommended_actions
        .iter()
        .any(|action| action.kind == RuntimeHintActionKind::Overlay));
}

#[test]
fn synthesis_plan_covers_mounts_overlays_config_and_device_nodes() {
    let strategy = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                    "web:cgi".to_string(),
                    "nvram:present".to_string(),
                ],
                vec!["native-host".to_string()],
                vec![PriorRunSummary::new(
                    "run-1",
                    "firmae",
                    "native-host",
                    "degraded-completed",
                )],
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");

    let synthesis = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(strategy))
        .expect("synthesis");

    assert!(synthesis
        .plan
        .steps
        .iter()
        .any(|step| step.category == SynthesisCategory::Mount));
    assert!(synthesis
        .plan
        .steps
        .iter()
        .any(|step| step.category == SynthesisCategory::Overlay));
    assert!(synthesis
        .plan
        .steps
        .iter()
        .any(|step| step.category == SynthesisCategory::ConfigMaterialization));
    assert!(synthesis
        .plan
        .steps
        .iter()
        .any(|step| step.category == SynthesisCategory::DeviceNode));
    assert!(synthesis.plan.steps.iter().any(|step| !step.required));
    assert!(synthesis
        .recipe
        .synthesis_steps
        .iter()
        .any(|step| step.contains("mount")));
    assert_eq!(
        synthesis.profile.family_id.as_deref(),
        Some("linux-router-arm")
    );
    assert!(synthesis
        .profile
        .candidate_modes
        .contains(&RehostingMode::Service));
    assert_eq!(
        synthesis.readiness_goals,
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
            "init-complete".to_string(),
        ]
    );
    assert!(synthesis
        .recipe
        .resolved_profile_chain
        .iter()
        .any(|entry| entry == "family=linux-router-arm"));
    assert!(synthesis
        .recipe
        .resolved_profile_chain
        .iter()
        .any(|entry| entry == "mode=service"));
    assert!(synthesis
        .recipe
        .debug_features
        .iter()
        .any(|entry| entry == "goal=http-validation"));
}

#[test]
fn synthesis_results_attach_to_recipe_and_emit_runtime_input_artifacts() {
    let strategy = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                ],
                vec!["managed-linux-vm".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");

    let synthesis = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(strategy))
        .expect("synthesis");

    assert_eq!(synthesis.recipe.selected_backend, "firmae");
    assert!(!synthesis.recipe.synthesis_steps.is_empty());
    assert!(synthesis
        .recipe
        .debug_features
        .iter()
        .any(|feature| feature == "goal=shell-access"));
    assert!(synthesis
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ArtifactKind::Strategy));
    assert!(synthesis
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ArtifactKind::RuntimeInput));
    assert!(synthesis
        .artifacts
        .iter()
        .all(|artifact| artifact.retention_policy == ArtifactRetentionPolicy::Session));
    assert!(matches!(
        synthesis.materialization.adapter,
        MaterializationAdapter::NativeHost
    ));
    assert!(synthesis
        .materialization
        .supported_steps
        .iter()
        .any(|step| step.category == SynthesisCategory::Mount));
}

#[test]
fn synthesis_materialization_supports_native_host_and_docker_engine() {
    let strategy = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                ],
                vec!["native-host".to_string(), "docker-engine".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");

    let synthesis = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(strategy))
        .expect("synthesis");

    assert!(matches!(
        synthesis.materialization_target,
        MaterializationTarget::NativeHost | MaterializationTarget::DockerEngine
    ));
    assert!(synthesis
        .plan
        .materialization_targets
        .contains(&MaterializationTarget::NativeHost));
    assert!(synthesis
        .plan
        .materialization_targets
        .contains(&MaterializationTarget::DockerEngine));
    assert!(synthesis
        .artifacts
        .iter()
        .all(
            |artifact| artifact.substrate_kind == Some(SubstrateKind::NativeHost)
                || artifact.substrate_kind == Some(SubstrateKind::DockerEngine)
        ));
    assert!(!synthesis.materialization.deferred_steps.is_empty());
}

#[test]
fn repeated_synthesis_with_distinct_contexts_does_not_collide() {
    let strategy = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                ],
                vec!["native-host".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");

    let first = SynthesisEngine::new()
        .synthesize(
            SynthesisRequest::from_strategy(strategy.clone()).with_context(SynthesisContext::new(
                "request-a",
                "project-a",
                "target-a",
                "session-a",
                "run-a",
            )),
        )
        .expect("first synthesis");
    let second =
        SynthesisEngine::new()
            .synthesize(SynthesisRequest::from_strategy(strategy).with_context(
                SynthesisContext::new("request-b", "project-b", "target-b", "session-b", "run-b"),
            ))
            .expect("second synthesis");

    assert_ne!(first.recipe.recipe_id, second.recipe.recipe_id);
    assert_ne!(
        first.artifacts[0].artifact_id,
        second.artifacts[0].artifact_id
    );
    assert_ne!(
        first.artifacts[1].artifact_id,
        second.artifacts[1].artifact_id
    );
}

#[test]
fn synthesis_rejects_unavailable_selected_materialization_target() {
    let mut strategy = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                ],
                vec!["native-host".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");
    strategy.selected.substrate = SubstrateKind::DockerEngine;

    let err = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(strategy))
        .expect_err("unavailable selected substrate should be rejected");

    assert!(matches!(
        err,
        SynthesisError::SelectedMaterializationTargetUnavailable { .. }
    ));
}

#[test]
fn synthesis_is_stable_for_permuted_evidence_order() {
    let alpha = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:/etc/init.d/rcS".to_string(),
                    "web:uhttpd".to_string(),
                    "generated:reference-rootfs".to_string(),
                ],
                vec!["native-host".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");
    let beta = StrategyEngine::new(BackendRegistry::with_test_backends())
        .evaluate(
            &StrategyRequest::new(
                "emulate firmware",
                vec![
                    "generated:reference-rootfs".to_string(),
                    "web:uhttpd".to_string(),
                    "init:/etc/init.d/rcS".to_string(),
                    "fs:squashfs".to_string(),
                    "arch:armel".to_string(),
                ],
                vec!["native-host".to_string()],
                Vec::new(),
            )
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("strategy");

    let alpha = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(alpha))
        .expect("alpha synthesis");
    let beta = SynthesisEngine::new()
        .synthesize(SynthesisRequest::from_strategy(beta))
        .expect("beta synthesis");

    assert_eq!(alpha.profile.profile_id, beta.profile.profile_id);
    assert_eq!(
        alpha.recipe.resolved_profile_chain,
        beta.recipe.resolved_profile_chain
    );
    assert_eq!(alpha.recipe.debug_features, beta.recipe.debug_features);
    assert_eq!(alpha.readiness_goals, beta.readiness_goals);
}
