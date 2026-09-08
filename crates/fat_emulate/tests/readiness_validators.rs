use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_core::rehosting_recipe::{RecipeValidator, RehostingRecipe};
use fat_emulate::validators::{
    apply_runtime_validation, goal_confidence_from_readiness, RuntimeValidationSnapshot,
};

fn recipe_with_goals(goals: &[&str]) -> RehostingRecipe {
    RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_validators(
        goals
            .iter()
            .map(|goal| RecipeValidator::new((*goal).to_string(), "goal"))
            .collect(),
    )
}

#[test]
fn runtime_validation_distinguishes_listener_bind_from_http_reply_and_process_chain() {
    let recipe = recipe_with_goals(&[
        "shell-access",
        "listener-bind",
        "http-validation",
        "process-chain",
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
        ],
        vec![
            RuntimeSurfaceRecord::new(
                "demo",
                "target-demo",
                "session-1",
                "run-1",
                "shell",
                "shell",
                "ssh://127.0.0.1:10022",
                SurfaceReadiness::Ready,
            )
            .with_uri("ssh://127.0.0.1:10022")
            .with_port(10022),
            RuntimeSurfaceRecord::new(
                "demo",
                "target-demo",
                "session-1",
                "run-1",
                "web",
                "service",
                "http://127.0.0.1:8080",
                SurfaceReadiness::Ready,
            )
            .with_uri("http://127.0.0.1:8080")
            .with_port(8080),
        ],
    )
    .with_summary("service listener is bound but no reply yet");
    let snapshot = RuntimeValidationSnapshot {
        shell_surface_ready: true,
        service_surface_ready: true,
        process_snapshot_present: true,
        process_chain_observed: true,
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert!(updated
        .validated_goals
        .contains(&"shell-access".to_string()));
    assert!(updated
        .validated_goals
        .contains(&"listener-bind".to_string()));
    assert!(updated
        .validated_goals
        .contains(&"process-chain".to_string()));
    assert!(!updated
        .validated_goals
        .contains(&"http-validation".to_string()));
    let service_surface = updated
        .surfaces
        .iter()
        .find(|surface| surface.kind == "service")
        .expect("service surface");
    assert_eq!(service_surface.readiness, SurfaceReadiness::Validated);
    assert_eq!(
        service_surface.validation_note.as_deref(),
        Some("listener bind observed")
    );
}

#[test]
fn runtime_validation_requires_explicit_http_reply_evidence() {
    let recipe = recipe_with_goals(&["listener-bind", "http-validation", "process-chain"]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec![
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
        ],
        vec![RuntimeSurfaceRecord::new(
            "demo",
            "target-demo",
            "session-1",
            "run-1",
            "web",
            "service",
            "http://127.0.0.1:8080",
            SurfaceReadiness::Ready,
        )
        .with_uri("http://127.0.0.1:8080")
        .with_port(8080)],
    )
    .with_summary("listener and service observations exist but no HTTP reply was recorded");
    let snapshot = RuntimeValidationSnapshot {
        service_surface_ready: true,
        service_listener_bound: true,
        process_snapshot_present: true,
        service_snapshot_present: true,
        process_chain_observed: true,
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert!(updated
        .validated_goals
        .contains(&"listener-bind".to_string()));
    assert!(updated
        .validated_goals
        .contains(&"process-chain".to_string()));
    assert!(!updated
        .validated_goals
        .contains(&"http-validation".to_string()));
}

#[test]
fn runtime_validation_requires_explicit_process_chain_evidence() {
    let recipe = recipe_with_goals(&["listener-bind", "process-chain"]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec!["listener-bind".to_string(), "process-chain".to_string()],
        vec![RuntimeSurfaceRecord::new(
            "demo",
            "target-demo",
            "session-1",
            "run-1",
            "web",
            "service",
            "http://127.0.0.1:8080",
            SurfaceReadiness::Ready,
        )
        .with_uri("http://127.0.0.1:8080")
        .with_port(8080)],
    )
    .with_summary(
        "generic runtime observations exist but no explicit process-chain match was recorded",
    );
    let snapshot = RuntimeValidationSnapshot {
        service_surface_ready: true,
        service_listener_bound: true,
        process_snapshot_present: true,
        service_snapshot_present: true,
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert!(updated
        .validated_goals
        .contains(&"listener-bind".to_string()));
    assert!(!updated
        .validated_goals
        .contains(&"process-chain".to_string()));
}

#[test]
fn typed_pack_validators_use_their_pattern_name_path_and_port() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_validators(vec![
        RecipeValidator::new("init-handoff", "serial-log-pattern").with_pattern("app_init.sh"),
        RecipeValidator::new("boa-process", "process").with_name("boa"),
        RecipeValidator::new("config-present", "file-exists").with_path("/configs/device.conf"),
        RecipeValidator::new("http-reply", "http").with_port(80),
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec![
            "init-handoff".into(),
            "boa-process".into(),
            "config-present".into(),
            "http-reply".into(),
        ],
        vec![],
    );
    let snapshot = RuntimeValidationSnapshot {
        serial_log: "boot: app_init.sh started".into(),
        process_names: vec!["boa".into()],
        existing_paths: vec!["/configs/device.conf".into()],
        http_reply_ports: vec![80],
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    for goal in [
        "init-handoff",
        "boa-process",
        "config-present",
        "http-reply",
    ] {
        assert!(
            updated.validated_goals.contains(&goal.to_string()),
            "{goal}"
        );
    }
}

#[test]
fn typed_http_validator_is_not_bypassed_by_generic_reply_evidence() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_validators(vec![
        RecipeValidator::new("http-validation", "http").with_port(80)
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec!["http-validation".into()],
        vec![],
    );
    let snapshot = RuntimeValidationSnapshot {
        http_reply_received: true,
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert!(updated.validated_goals.is_empty());
}

#[test]
fn typed_process_validator_requires_the_declared_process_name() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_validators(vec![
        RecipeValidator::new("shell-access", "process").with_name("boa")
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec!["shell-access".into()],
        vec![],
    );
    let snapshot = RuntimeValidationSnapshot {
        process_snapshot_present: true,
        process_names: vec!["init".into()],
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert!(updated.validated_goals.is_empty());
}

#[test]
fn boot_progress_does_not_satisfy_unobserved_typed_process_or_http_validators() {
    let recipe = RehostingRecipe::new(
        "target-demo",
        "tmodel-demo",
        "run-1",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    )
    .with_validators(vec![
        RecipeValidator::new("init-complete", "serial-log-pattern")
            .with_pattern("FAT_INIT_COMPLETE"),
        RecipeValidator::new("boa-process", "process").with_name("boa"),
        RecipeValidator::new("http-validation", "http").with_port(80),
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec![
            "init-complete".into(),
            "boa-process".into(),
            "http-validation".into(),
        ],
        vec![],
    );
    let snapshot = RuntimeValidationSnapshot {
        serial_log: "FAT_INIT_COMPLETE".into(),
        init_stage_complete: true,
        ..RuntimeValidationSnapshot::default()
    };

    let updated = apply_runtime_validation(&recipe, &readiness, &snapshot);

    assert_eq!(updated.validated_goals, vec!["init-complete"]);
}

#[test]
fn goal_confidence_tracks_validated_ready_and_blocked_states_across_all_runtime_goals() {
    let recipe = recipe_with_goals(&[
        "shell-access",
        "listener-bind",
        "http-validation",
        "process-chain",
        "init-complete",
        "reference-bootstrap",
    ]);
    let readiness = ReadinessReport::new(
        "demo",
        "target-demo",
        "session-1",
        "run-1",
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
            "init-complete".to_string(),
            "reference-bootstrap".to_string(),
        ],
        vec![RuntimeSurfaceRecord::new(
            "demo",
            "target-demo",
            "session-1",
            "run-1",
            "shell",
            "shell",
            "ssh://127.0.0.1:10022",
            SurfaceReadiness::Ready,
        )],
    )
    .with_validated_goals(vec![
        "shell-access".to_string(),
        "listener-bind".to_string(),
        "process-chain".to_string(),
    ]);

    let goals = goal_confidence_from_readiness(&recipe, &readiness);

    assert!(goals.iter().any(|goal| goal.goal == "shell-access"
        && goal.state == fat_core::readiness::GoalState::Validated));
    assert!(goals.iter().any(|goal| goal.goal == "listener-bind"
        && goal.state == fat_core::readiness::GoalState::Validated));
    assert!(goals.iter().any(|goal| goal.goal == "process-chain"
        && goal.state == fat_core::readiness::GoalState::Validated));
    assert!(goals.iter().any(|goal| goal.goal == "http-validation"
        && goal.state == fat_core::readiness::GoalState::Ready));
    assert!(goals
        .iter()
        .any(|goal| goal.goal == "init-complete"
            && goal.state == fat_core::readiness::GoalState::Ready));
    assert!(goals.iter().any(|goal| goal.goal == "reference-bootstrap"
        && goal.state == fat_core::readiness::GoalState::Ready));
}
