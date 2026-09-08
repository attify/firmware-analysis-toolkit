use fat_core::discovery::{
    DiscoveryLifecycleStatus, DiscoveryOutcomeClass, HarnessAttemptRecord, TriageRecord,
};

fn sample_harness_attempt_pre_result() -> HarnessAttemptRecord {
    HarnessAttemptRecord {
        harness_attempt_id: "hat-1".to_string(),
        expansion_id: "hexp-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Queued,
        outcome: None,
        attempt_plan_hash: "plan-hash-1".to_string(),
        artifact_root: "/tmp/artifacts/attempt-1".to_string(),
        retry_count: 2,
        launcher_command: "fat discover run".to_string(),
        generated_binding_id: Some("hexp-1::g0".to_string()),
        generated_input_bindings: std::collections::BTreeMap::from([
            ("arg_size".to_string(), "32".to_string()),
            (
                "vk_icd_filenames".to_string(),
                "/tmp/swiftshader_icd.json".to_string(),
            ),
        ]),
        resolved_argv: vec!["fat".to_string(), "discover".to_string(), "run".to_string()],
        resolved_env: std::collections::BTreeMap::from([(
            "ASAN_OPTIONS".to_string(),
            "symbolize=1".to_string(),
        )]),
        resolved_cwd: "/tmp/runtime/cwd".to_string(),
        timeout_ms: 1000,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("copy-size-exceeds-allocation".to_string()),
        attempted_transition_summary: Some(
            "copy-size-exceeds-allocation: copy exceeds backing allocation".to_string(),
        ),
    }
}

fn sample_harness_attempt_terminal() -> HarnessAttemptRecord {
    HarnessAttemptRecord {
        harness_attempt_id: "hat-2".to_string(),
        expansion_id: "hexp-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Completed,
        outcome: Some(DiscoveryOutcomeClass::AsanHeapBufferOverflow),
        attempt_plan_hash: "plan-hash-2".to_string(),
        artifact_root: "/tmp/artifacts/attempt-2".to_string(),
        retry_count: 0,
        launcher_command: "fat discover run".to_string(),
        generated_binding_id: Some("hexp-1::g1".to_string()),
        generated_input_bindings: std::collections::BTreeMap::from([
            ("arg_size".to_string(), "16".to_string()),
            (
                "vk_icd_filenames".to_string(),
                "/tmp/swiftshader_icd.json".to_string(),
            ),
        ]),
        resolved_argv: vec!["fat".to_string(), "discover".to_string(), "run".to_string()],
        resolved_env: std::collections::BTreeMap::from([(
            "ASAN_OPTIONS".to_string(),
            "symbolize=1".to_string(),
        )]),
        resolved_cwd: "/tmp/runtime/cwd".to_string(),
        timeout_ms: 1000,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("copy-size-exceeds-allocation".to_string()),
        attempted_transition_summary: Some(
            "copy-size-exceeds-allocation: copy exceeds backing allocation".to_string(),
        ),
    }
}

fn sample_triage_pre_result() -> TriageRecord {
    TriageRecord {
        triage_id: "tri-1".to_string(),
        harness_attempt_id: "hat-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Ready,
        outcome: None,
        attempt_plan_hash: "plan-hash-1".to_string(),
        artifact_root: "/tmp/artifacts/triage-1".to_string(),
        retry_count: 3,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("copy-size-exceeds-allocation".to_string()),
        attempted_transition_summary: Some(
            "copy-size-exceeds-allocation: copy exceeds backing allocation".to_string(),
        ),
        summary: "triage complete".to_string(),
    }
}

fn sample_triage_terminal() -> TriageRecord {
    TriageRecord {
        triage_id: "tri-2".to_string(),
        harness_attempt_id: "hat-2".to_string(),
        lifecycle: DiscoveryLifecycleStatus::NeedsReview,
        outcome: Some(DiscoveryOutcomeClass::GuardTrip),
        attempt_plan_hash: "plan-hash-2".to_string(),
        artifact_root: "/tmp/artifacts/triage-2".to_string(),
        retry_count: 1,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("copy-size-exceeds-allocation".to_string()),
        attempted_transition_summary: Some(
            "copy-size-exceeds-allocation: copy exceeds backing allocation".to_string(),
        ),
        summary: "triage complete".to_string(),
    }
}

#[test]
fn discovery_lifecycle_and_record_level_outcome_serialize_independently() {
    let lifecycle = serde_json::to_value(DiscoveryLifecycleStatus::FailedInfra).unwrap();
    let pre_result_attempt = serde_json::to_value(sample_harness_attempt_pre_result()).unwrap();
    let terminal_attempt = serde_json::to_value(sample_harness_attempt_terminal()).unwrap();
    let pre_result_triage = serde_json::to_value(sample_triage_pre_result()).unwrap();
    let terminal_triage = serde_json::to_value(sample_triage_terminal()).unwrap();

    assert_eq!(
        serde_json::from_value::<DiscoveryLifecycleStatus>(lifecycle).unwrap(),
        DiscoveryLifecycleStatus::FailedInfra
    );
    assert_eq!(
        serde_json::from_value::<HarnessAttemptRecord>(pre_result_attempt)
            .unwrap()
            .outcome,
        None
    );
    assert_eq!(
        serde_json::from_value::<HarnessAttemptRecord>(terminal_attempt)
            .unwrap()
            .outcome,
        Some(DiscoveryOutcomeClass::AsanHeapBufferOverflow)
    );
    assert_eq!(
        serde_json::from_value::<TriageRecord>(pre_result_triage)
            .unwrap()
            .outcome,
        None
    );
    assert_eq!(
        serde_json::from_value::<TriageRecord>(terminal_triage)
            .unwrap()
            .outcome,
        Some(DiscoveryOutcomeClass::GuardTrip)
    );

    let pre_result_attempt_json =
        serde_json::to_value(sample_harness_attempt_pre_result()).unwrap();
    let terminal_attempt_json = serde_json::to_value(sample_harness_attempt_terminal()).unwrap();
    let pre_result_triage_json = serde_json::to_value(sample_triage_pre_result()).unwrap();
    let terminal_triage_json = serde_json::to_value(sample_triage_terminal()).unwrap();

    assert!(pre_result_attempt_json.get("outcome").is_none());
    assert_eq!(
        pre_result_attempt_json
            .get("state_hypothesis_id")
            .and_then(|value| value.as_str()),
        Some("lead-1::h0")
    );
    assert_eq!(
        terminal_attempt_json
            .get("outcome")
            .and_then(|value| value.as_str()),
        Some("asan-heap-buffer-overflow")
    );
    assert_eq!(
        terminal_attempt_json
            .get("generated_binding_id")
            .and_then(|value| value.as_str()),
        Some("hexp-1::g1")
    );
    assert_eq!(
        terminal_attempt_json
            .get("generated_input_bindings")
            .and_then(|value| value.get("arg_size"))
            .and_then(|value| value.as_str()),
        Some("16")
    );
    assert_eq!(
        terminal_attempt_json
            .get("resolved_argv")
            .and_then(|value| value.as_array())
            .map(|value| value.len()),
        Some(3)
    );
    assert_eq!(
        terminal_attempt_json
            .get("forbidden_transition_id")
            .and_then(|value| value.as_str()),
        Some("copy-size-exceeds-allocation")
    );
    assert!(pre_result_triage_json.get("outcome").is_none());
    assert_eq!(
        terminal_triage_json
            .get("outcome")
            .and_then(|value| value.as_str()),
        Some("guard-trip")
    );
}
