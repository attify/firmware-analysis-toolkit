use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::debug::{DebugCapability, DebugSurfaceKind};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::ids::stable_prefixed_id;
use fat_core::recipes::{FallbackPolicy, RecipeRecord};
use fat_core::runs::{RunOrigin, RunRecord, RunStatus, RuntimeEndpointKind, SubstrateKind};
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};

#[test]
fn constructors_use_stable_prefixed_ids() {
    let session_a = SessionRecord::new(
        "project-1",
        "target-1",
        "reach shell",
        "qemu-direct",
        SessionOrigin::Manual,
        "2026-03-27T00:00:00Z",
    );
    let session_b = SessionRecord::new(
        "project-1",
        "target-1",
        "reach shell",
        "qemu-direct",
        SessionOrigin::Manual,
        "2026-03-27T00:00:00Z",
    );
    assert_eq!(session_a.session_id, session_b.session_id);
    assert!(session_a.session_id.starts_with("sess-"));

    let run = RunRecord::new(
        &session_a.session_id,
        "recipe-1",
        "qemu-direct",
        SubstrateKind::NativeHost,
        1,
        RunOrigin::Manual,
    );
    assert!(run.run_id.starts_with("run-"));

    let artifact = ArtifactRecord::new(
        "project-1",
        "target-1",
        &session_a.session_id,
        &run.run_id,
        ArtifactKind::RuntimeLog,
        "console",
        "backend-driver",
        "driver-1",
        "2026-03-27T00:01:00Z",
        "logs/console.txt",
        "text/plain",
        120,
        None,
        "run-scoped evidence",
        ArtifactRetentionPolicy::Session,
    );
    assert!(artifact.artifact_id.starts_with("art-"));

    let diagnostic = DiagnosticRecord::new(
        &run.run_id,
        DiagnosticPhase::Boot,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some("qemu-exit".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        "boot exited before userspace",
        vec![artifact.artifact_id.clone()],
        vec![],
        vec!["retry with alternate substrate".to_string()],
    );
    assert!(diagnostic.diagnostic_id.starts_with("diag-"));

    let recipe = RecipeRecord::new(
        "target-1",
        "1.0.0",
        "reach shell",
        "qemu-direct",
        "native-host",
    )
    .with_fallback_policy(FallbackPolicy::RetryWithFallback);
    assert!(recipe.recipe_id.starts_with("recipe-"));
    assert_eq!(recipe.fallback_policy, FallbackPolicy::RetryWithFallback);
}

#[test]
fn stable_prefixed_ids_distinguish_slug_collisions_and_remain_stable() {
    let colliding_a = stable_prefixed_id("sess", ["Project One"]);
    let colliding_b = stable_prefixed_id("sess", ["Project/One"]);
    let repeated = stable_prefixed_id("sess", ["Project One"]);

    assert_eq!(colliding_a, repeated);
    assert_ne!(colliding_a, colliding_b);
    assert!(colliding_a.starts_with("sess-project-one-"));
    assert!(colliding_b.starts_with("sess-project-one-"));

    let session_a = SessionRecord::new(
        "project-3",
        "target-3",
        "reach shell",
        "qemu-direct",
        SessionOrigin::Manual,
        "2026-03-27T02:00:00Z",
    );
    let session_b = SessionRecord::new(
        "project-3",
        "target-3",
        "reach shell",
        "qemu-direct",
        SessionOrigin::Manual,
        "2026-03-27T02:00:00Z",
    );

    assert_eq!(session_a.session_id, session_b.session_id);
}

#[test]
fn core_enums_round_trip_through_json() {
    let values = [
        serde_json::to_value(SessionStatus::Draft).unwrap(),
        serde_json::to_value(GoalProgress::Substantial).unwrap(),
        serde_json::to_value(RunStatus::DegradedCompleted).unwrap(),
        serde_json::to_value(SubstrateKind::ManagedLinuxVm).unwrap(),
        serde_json::to_value(RuntimeEndpointKind::Debugger).unwrap(),
        serde_json::to_value(DebugSurfaceKind::Monitor).unwrap(),
        serde_json::to_value(DebugCapability::DiagnosticsSupported).unwrap(),
    ];

    assert_eq!(
        serde_json::from_value::<SessionStatus>(values[0].clone()).unwrap(),
        SessionStatus::Draft
    );
    assert_eq!(
        serde_json::from_value::<GoalProgress>(values[1].clone()).unwrap(),
        GoalProgress::Substantial
    );
    assert_eq!(
        serde_json::from_value::<RunStatus>(values[2].clone()).unwrap(),
        RunStatus::DegradedCompleted
    );
    assert_eq!(
        serde_json::from_value::<SubstrateKind>(values[3].clone()).unwrap(),
        SubstrateKind::ManagedLinuxVm
    );
    assert_eq!(
        serde_json::from_value::<RuntimeEndpointKind>(values[4].clone()).unwrap(),
        RuntimeEndpointKind::Debugger
    );
    assert_eq!(
        serde_json::from_value::<DebugSurfaceKind>(values[5].clone()).unwrap(),
        DebugSurfaceKind::Monitor
    );
    assert_eq!(
        serde_json::from_value::<DebugCapability>(values[6].clone()).unwrap(),
        DebugCapability::DiagnosticsSupported
    );
}

#[test]
fn stable_prefixed_id_helper_uses_component_slugs() {
    let id = stable_prefixed_id("sess", ["Project One", "Target/Two", ""]);
    assert!(id.starts_with("sess-project-one-target-two-"));
    assert_eq!(
        id,
        stable_prefixed_id("sess", ["Project One", "Target/Two", ""])
    );
}
