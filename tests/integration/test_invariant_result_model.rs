#[test]
fn invariant_result_tracks_satisfying_violating_and_unknown_sites() {
    let result =
        fat_query::result::InvariantResult::new("Every override must call enforcePermission()");
    assert!(result.satisfying.is_empty());
    assert!(result.violating.is_empty());
    assert!(result.unknown.is_empty());
    assert!(result.discovery_leads.is_none());
}

#[test]
fn invariant_result_serializes_discovery_leads_when_present() {
    let mut result = fat_query::result::InvariantResult::new("discovery-smoke");
    result.discovery_leads = Some(vec![fat_query::discovery::DiscoveryLead {
        lead_id: "lead-1".into(),
        symbol: "Demo::candidate".into(),
        family: fat_query::discovery::BugFamily::LifetimeReentrancy,
        family_confidence: 0.91,
        family_pack_version: "v1".into(),
        analysis_scope: fat_query::discovery::AnalysisScope::OriginalSlice,
        candidate_status: fat_query::discovery::CandidateStatus::Primary,
        matched_roles: vec![fat_query::discovery::RoleMatch {
            role: "callback-teardown".into(),
            detail: "callback + destroy observed".into(),
        }],
        why_matched: vec!["callback and teardown signals overlap".into()],
        evidence_basis: vec![fat_query::result::EvidenceBasis::ObservedFromAstFacts],
        locality: fat_query::result::LocalityStatus::RepoLocal,
        sibling_candidates: Vec::new(),
        suggested_trigger_recipe: vec![fat_query::discovery::TriggerRecipeStep {
            kind: "destroy-owner-during-callback".into(),
            detail: "destroy the owner before callback completion".into(),
        }],
        required_environment: fat_query::discovery::RequiredEnvironment {
            execution_mode: "in-process".into(),
            platform_constraints: vec!["none".into()],
        },
        expected_proof_signal: vec![fat_query::discovery::ProofSignal {
            kind: "asan-use-after-free".into(),
            detail: "stale callback dereferences freed owner".into(),
        }],
        state_hypotheses: vec![fat_query::discovery::StateHypothesis {
            hypothesis_id: "lead-1::h0".into(),
            machine_id: "lifetime-reentrancy".into(),
            actors: vec!["Owner".into(), "Callback".into()],
            active_regions: vec!["default".into()],
            key_states: vec!["CallbackPending".into(), "OwnerDestroyed".into()],
            ghost_states: vec!["OwnerAlive".into()],
            invalidating_events: vec!["destroy-owner-while-callback-pending".into()],
            required_guards: vec!["weak-ptr-invalidation".into()],
            forbidden_transitions: vec![fat_query::discovery::ForbiddenTransitionRef {
                transition_id: "destroy-owner-while-callback-pending".into(),
                expected_proof_class: "asan-use-after-free".into(),
                rationale: vec!["stale callback reaches destroyed owner".into()],
            }],
            confidence: 0.91,
        }],
        score_trace: fat_query::result::ScoreTrace {
            adapters: vec!["SyntheticSliceRepair".into()],
            family_pack_hits: vec!["callback_or_teardown_call_present".into()],
            penalties: Vec::new(),
            locality_notes: vec!["repo-local".into()],
        },
    }]);

    let value = serde_json::to_value(&result).expect("serialize invariant result");
    let leads = value
        .get("discovery_leads")
        .and_then(|value| value.as_array())
        .expect("discovery leads array");
    assert_eq!(leads.len(), 1);
    assert_eq!(
        leads[0].get("lead_id").and_then(|v| v.as_str()),
        Some("lead-1")
    );
    assert_eq!(
        leads[0]
            .get("state_hypotheses")
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(1)
    );
}
