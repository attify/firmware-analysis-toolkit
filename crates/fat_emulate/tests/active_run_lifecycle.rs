use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::runs::{RunStatus, RuntimeEndpoint, RuntimeEndpointKind};
use fat_core::sessions::{GoalProgress, SessionStatus};
use fat_emulate::{ActiveRun, EmulationPlan};

fn diagnostic(run_id: &str, phase: DiagnosticPhase, class: DiagnosticClass) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id,
        phase,
        DiagnosticOwner::Observer,
        class,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        "runtime observation indicated a degraded state",
        Vec::new(),
        Vec::new(),
        vec!["reattach or fall back to a different backend".to_string()],
    )
}

#[test]
fn launched_session_surfaces_reattachable_endpoints_after_launch() {
    let launched = EmulationPlan::new("active-1", "qemu-direct", vec![8443, 8080])
        .expect("supported backend")
        .launch();

    let active = ActiveRun::from_session(launched);

    assert_eq!(
        active
            .active_endpoints()
            .iter()
            .map(|endpoint| endpoint.port)
            .collect::<Vec<_>>(),
        vec![8443, 8080]
    );
    assert_eq!(active.run_record().status, RunStatus::Queued);
    assert_eq!(active.session_record().status, SessionStatus::Active);

    let active = active
        .reattach_endpoint(
            RuntimeEndpoint::new(RuntimeEndpointKind::Shell, "shell", "127.0.0.1", 2222)
                .with_uri("ssh://127.0.0.1:2222"),
        )
        .reattach_endpoint(
            RuntimeEndpoint::new(RuntimeEndpointKind::Debugger, "gdb", "127.0.0.1", 3333)
                .with_uri("tcp://127.0.0.1:3333"),
        );

    assert!(active
        .active_endpoints()
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Shell && endpoint.port == 2222));
    assert!(active
        .active_endpoints()
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Debugger && endpoint.port == 3333));
    assert_eq!(active.active_endpoints().len(), 4);
}

#[test]
fn lifecycle_transition_helpers_update_status_progress_and_timestamps_together() {
    let launched = EmulationPlan::new("active-2", "qemu-direct", vec![8080])
        .expect("supported backend")
        .launch();
    let active = ActiveRun::from_session(launched);

    let preparing = active.preparing_at("unix-ms:10");
    assert_eq!(preparing.session_record().status, SessionStatus::Active);
    assert_eq!(preparing.session_record().progress, GoalProgress::Partial);
    assert_eq!(preparing.session_record().updated_at, "unix-ms:10");
    assert_eq!(preparing.run_record().status, RunStatus::Preparing);
    assert_eq!(preparing.run_record().started_at, None);
    assert_eq!(preparing.run_record().finished_at, None);

    let launching = preparing.launching_at("unix-ms:11");
    assert_eq!(
        launching.session_record().progress,
        GoalProgress::Substantial
    );
    assert_eq!(launching.session_record().updated_at, "unix-ms:11");
    assert_eq!(launching.run_record().status, RunStatus::Launching);
    assert_eq!(launching.run_record().started_at, None);
    assert_eq!(launching.run_record().finished_at, None);

    let running = launching.running_at("unix-ms:12");
    assert_eq!(running.session_record().progress, GoalProgress::Substantial);
    assert_eq!(running.session_record().updated_at, "unix-ms:12");
    assert_eq!(running.run_record().status, RunStatus::Running);
    assert_eq!(
        running.run_record().started_at.as_deref(),
        Some("unix-ms:12")
    );
    assert_eq!(running.run_record().finished_at, None);
}

#[test]
fn degraded_running_and_degraded_completed_carry_diagnostics() {
    let launched = EmulationPlan::new("active-3", "qemu-direct", vec![8080])
        .expect("supported backend")
        .launch();
    let active = ActiveRun::from_session(launched).running_at("unix-ms:12");
    let run_id = active.run_record().run_id.clone();

    let degraded_running = active.degraded_running_at(
        "unix-ms:13",
        diagnostic(
            &run_id,
            DiagnosticPhase::Observation,
            DiagnosticClass::GuestUnreachable,
        ),
    );

    assert_eq!(
        degraded_running.session_record().status,
        SessionStatus::Degraded
    );
    assert_eq!(
        degraded_running.run_record().status,
        RunStatus::DegradedRunning
    );
    assert_eq!(degraded_running.diagnostics().len(), 1);
    assert_eq!(
        degraded_running.diagnostics()[0].actionability,
        DiagnosticActionability::FallbackRecommended
    );

    let degraded_completed = degraded_running.degraded_completed_at(
        "unix-ms:14",
        diagnostic(
            &run_id,
            DiagnosticPhase::Cleanup,
            DiagnosticClass::CleanupFailed,
        ),
    );

    assert_eq!(
        degraded_completed.session_record().status,
        SessionStatus::Completed
    );
    assert_eq!(
        degraded_completed.run_record().status,
        RunStatus::DegradedCompleted
    );
    assert_eq!(
        degraded_completed.run_record().finished_at.as_deref(),
        Some("unix-ms:14")
    );
    assert_eq!(
        degraded_completed.session_record().progress,
        GoalProgress::Achieved
    );
    assert_eq!(degraded_completed.diagnostics().len(), 2);
}

#[test]
fn failed_launch_remains_failed_without_becoming_degraded_completed() {
    let launched = EmulationPlan::new("active-4", "qemu-direct", vec![8080])
        .expect("supported backend")
        .launch();
    let active = ActiveRun::from_session(launched);
    let run_id = active.run_record().run_id.clone();

    let failed = active.failed_at(
        "unix-ms:20",
        diagnostic(
            &run_id,
            DiagnosticPhase::Launch,
            DiagnosticClass::LaunchFailed,
        ),
    );

    assert_eq!(failed.session_record().status, SessionStatus::Degraded);
    assert_eq!(failed.session_record().progress, GoalProgress::Blocked);
    assert_eq!(failed.run_record().status, RunStatus::Failed);
    assert_eq!(
        failed.run_record().finished_at.as_deref(),
        Some("unix-ms:20")
    );
    assert_eq!(failed.diagnostics().len(), 1);
}
