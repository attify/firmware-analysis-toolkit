use fat_core::discovery::{DiscoveryLifecycleStatus, DiscoveryOutcomeClass, HarnessAttemptRecord};
use fat_core::runtime_store::RuntimeStore;
use fat_query::discovery_triage::{normalize_triage, TriageInput};

fn sample_attempt() -> HarnessAttemptRecord {
    HarnessAttemptRecord {
        harness_attempt_id: "hat-triage-1".into(),
        expansion_id: "hexp-1".into(),
        lifecycle: DiscoveryLifecycleStatus::Completed,
        outcome: None,
        attempt_plan_hash: "plan-hash-triage-1".into(),
        artifact_root: "/tmp/discovery-triage".into(),
        retry_count: 0,
        launcher_command: "./browser_tests --gtest_filter=Demo.*".into(),
        generated_binding_id: Some("hexp-1::g0".into()),
        generated_input_bindings: std::collections::BTreeMap::from([(
            "callback_count".into(),
            "1".into(),
        )]),
        resolved_argv: vec!["./browser_tests".into(), "--gtest_filter=Demo.*".into()],
        resolved_env: std::collections::BTreeMap::new(),
        resolved_cwd: "/tmp".into(),
        timeout_ms: 1000,
        state_hypothesis_id: Some("hat-triage-1::h0".into()),
        forbidden_transition_id: Some("destroy-owner-during-callback".into()),
        attempted_transition_summary: Some(
            "destroy-owner-during-callback: stale callback reaches destroyed owner".into(),
        ),
    }
}

#[test]
fn discovery_triage_normalizes_supported_outcomes() {
    let attempt = sample_attempt();

    let use_after_free = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "ERROR: AddressSanitizer: heap-use-after-free on address".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(
        use_after_free.outcome,
        Some(DiscoveryOutcomeClass::AsanUseAfterFree)
    );
    assert_eq!(
        use_after_free.lifecycle,
        DiscoveryLifecycleStatus::NeedsReview
    );
    assert_eq!(
        use_after_free.state_hypothesis_id.as_deref(),
        Some("hat-triage-1::h0")
    );
    assert_eq!(
        use_after_free.forbidden_transition_id.as_deref(),
        Some("destroy-owner-during-callback")
    );

    let heap_overflow = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "ERROR: AddressSanitizer: heap-buffer-overflow".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(
        heap_overflow.outcome,
        Some(DiscoveryOutcomeClass::AsanHeapBufferOverflow)
    );
    assert_eq!(
        heap_overflow.lifecycle,
        DiscoveryLifecycleStatus::NeedsReview
    );

    let integer_overflow = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "runtime error: signed integer overflow: 2147483647 + 1".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(
        integer_overflow.outcome,
        Some(DiscoveryOutcomeClass::UbsanIntegerOverflow)
    );

    let guard_trip = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "Check failed: size <= capacity".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(guard_trip.outcome, Some(DiscoveryOutcomeClass::GuardTrip));

    let ktap_guard_trip = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "KTAP version 1\nnot ok 1 binder_alloc_kunit".into(),
            stderr: "".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(
        ktap_guard_trip.outcome,
        Some(DiscoveryOutcomeClass::GuardTrip)
    );

    let bad_message = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "Received bad user message: malformed mojo payload".into(),
            exit_code: Some(1),
        },
    );
    assert_eq!(bad_message.outcome, Some(DiscoveryOutcomeClass::BadMessage));

    let blocked = normalize_triage(
        &attempt,
        TriageInput::BlockedByLocality {
            reason: "upstream-hidden locality blocked vendored widening".into(),
        },
    );
    assert_eq!(
        blocked.outcome,
        Some(DiscoveryOutcomeClass::BlockedByLocality)
    );
    assert_eq!(blocked.lifecycle, DiscoveryLifecycleStatus::Completed);

    let no_signal = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "pass".into(),
            stderr: "".into(),
            exit_code: Some(0),
        },
    );
    assert_eq!(no_signal.outcome, Some(DiscoveryOutcomeClass::NoSignal));
    assert_eq!(no_signal.lifecycle, DiscoveryLifecycleStatus::Completed);

    let no_signal_with_lifetime_sequence = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "pass".into(),
            stderr: "lifetime markers: callback_fired,owner_destroyed\nlifetime sequence observed without native proof".into(),
            exit_code: Some(0),
        },
    );
    assert_eq!(
        no_signal_with_lifetime_sequence.outcome,
        Some(DiscoveryOutcomeClass::NoSignal)
    );
    assert!(
        no_signal_with_lifetime_sequence
            .summary
            .contains("lifetime-sequence-observed"),
        "{}",
        no_signal_with_lifetime_sequence.summary
    );
    assert!(
        no_signal_with_lifetime_sequence
            .summary
            .contains("markers=callback_fired,owner_destroyed"),
        "{}",
        no_signal_with_lifetime_sequence.summary
    );

    let no_signal_with_stale_access = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "pass".into(),
            stderr: "lifetime markers: callback_fired,owner_destroyed,stale_access_tripped\nlifetime stale access observed without native proof".into(),
            exit_code: Some(0),
        },
    );
    assert_eq!(
        no_signal_with_stale_access.outcome,
        Some(DiscoveryOutcomeClass::NoSignal)
    );
    assert!(
        no_signal_with_stale_access
            .summary
            .contains("lifetime-stale-access-observed"),
        "{}",
        no_signal_with_stale_access.summary
    );
    assert!(
        no_signal_with_stale_access
            .summary
            .contains("markers=callback_fired,owner_destroyed,stale_access_tripped"),
        "{}",
        no_signal_with_stale_access.summary
    );
}

#[test]
fn discovery_triage_records_round_trip_through_runtime_store() {
    let attempt = sample_attempt();
    let triage = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout: "".into(),
            stderr: "ERROR: AddressSanitizer: heap-use-after-free on address".into(),
            exit_code: Some(1),
        },
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let store = RuntimeStore::open(dir.path()).expect("runtime store");
    store.write_triage(&triage).expect("write triage");
    assert_eq!(
        store.read_triage(&triage.triage_id).expect("read triage"),
        triage
    );
}
