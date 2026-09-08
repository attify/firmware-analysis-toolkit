use fat_core::rehosting::{
    FailureClass, RehostingMode, RepairActionKind, RuntimeSurfaceRecord, SurfaceReadiness,
    TargetExecutionProfile,
};

#[test]
fn rehosting_enums_expose_stable_string_labels() {
    assert_eq!(RehostingMode::Service.as_str(), "service");
    assert_eq!(RehostingMode::System.as_str(), "system");
    assert_eq!(RehostingMode::Reference.as_str(), "reference");

    assert_eq!(SurfaceReadiness::Registered.as_str(), "registered");
    assert_eq!(SurfaceReadiness::Ready.as_str(), "ready");
    assert_eq!(SurfaceReadiness::Validated.as_str(), "validated");

    assert_eq!(FailureClass::SystemResource.as_str(), "system-resource");
    assert_eq!(FailureClass::InitDependency.as_str(), "init-dependency");
    assert_eq!(FailureClass::IpcDependency.as_str(), "ipc-dependency");
    assert_eq!(FailureClass::TargetLaunch.as_str(), "target-launch");
    assert_eq!(FailureClass::Validation.as_str(), "validation");

    assert_eq!(RepairActionKind::CreateNode.as_str(), "create-node");
    assert_eq!(RepairActionKind::PatchConfig.as_str(), "patch-config");
    assert_eq!(RepairActionKind::InjectEnv.as_str(), "inject-env");
    assert_eq!(
        RepairActionKind::StartPeerService.as_str(),
        "start-peer-service"
    );
    assert_eq!(RepairActionKind::RetryPlan.as_str(), "retry-plan");
}

#[test]
fn target_profiles_with_distinct_evidence_do_not_collide() {
    let alpha = TargetExecutionProfile::new(
        "demo",
        "target-demo",
        Some("armel"),
        Some("linux-router-arm"),
        vec!["arch:armel".to_string(), "init:busybox".to_string()],
    );
    let beta = TargetExecutionProfile::new(
        "demo",
        "target-demo",
        Some("armel"),
        Some("linux-router-arm"),
        vec!["arch:armel".to_string(), "web:cgi".to_string()],
    );

    assert_ne!(alpha.profile_id, beta.profile_id);
}

#[test]
fn runtime_surface_identity_is_stable_across_readiness_changes() {
    let registered = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "shell",
        "shell",
        "ssh://127.0.0.1:10022",
        SurfaceReadiness::Registered,
    );
    let ready = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "shell",
        "shell",
        "ssh://127.0.0.1:10022",
        SurfaceReadiness::Ready,
    );
    let validated = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "shell",
        "shell",
        "ssh://127.0.0.1:10022",
        SurfaceReadiness::Validated,
    );

    assert_eq!(registered.surface_id, ready.surface_id);
    assert_eq!(ready.surface_id, validated.surface_id);
}

#[test]
fn runtime_surface_identity_distinguishes_same_name_surfaces_with_different_locators() {
    let alpha = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "httpd",
        "service",
        "127.0.0.1:8080",
        SurfaceReadiness::Registered,
    );
    let beta = RuntimeSurfaceRecord::new(
        "demo",
        "target-demo",
        "sess-demo",
        "run-demo",
        "httpd",
        "service",
        "127.0.0.1:8443",
        SurfaceReadiness::Registered,
    );

    assert_ne!(alpha.surface_id, beta.surface_id);
}
