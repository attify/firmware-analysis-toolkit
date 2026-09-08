use fat_query::derived::derive_from_fused_source;
use fat_query::discovery::{
    build_discovery_leads, AnalysisScope, BugFamily, CandidateStatus, DiscoveryLead,
    ForbiddenTransitionRef, ProofSignal, RequiredEnvironment, StateHypothesis, TriggerRecipeStep,
};
use fat_query::result::{
    EvidenceBasis, LocalityStatus, RollResolution, ScoreTrace, SourceCallFact, SourceMethodFact,
};
use fat_query::state_machines::{build_machines_for_lead, registered_machine_ids, StateRegionMode};
use fat_query::state_queries::{
    find_counterfactual_transition_matches, find_ghost_state_matches,
    find_lifetime_coexistence_candidates, find_lifetime_event_path_matches,
    find_lifetime_invalidation_candidates, find_lifetime_invalidation_paths,
    find_locality_policy_candidates, find_protocol_event_path_matches,
    find_protocol_invalidation_paths, find_protocol_order_candidates, find_size_event_path_matches,
    find_size_invalidation_paths, find_size_mismatch_candidates, find_state_condition_matches,
    find_validation_event_path_matches, find_validation_gap_candidates,
    find_validation_invalidation_paths,
};
use fat_query::store::{load_snapshot_meta, materialize_state_leads_snapshot, GraphReader};
use std::path::PathBuf;

fn hypothesis(
    lead_id: &str,
    machine_id: &str,
    transition_id: &str,
    expected_proof_class: &str,
    actors: &[&str],
    ghost_states: &[&str],
    required_guards: &[&str],
) -> StateHypothesis {
    StateHypothesis {
        hypothesis_id: format!("{lead_id}::h0"),
        machine_id: machine_id.into(),
        actors: actors.iter().map(|value| value.to_string()).collect(),
        active_regions: vec!["default".into()],
        key_states: vec!["Pending".into(), "Invalidated".into()],
        ghost_states: ghost_states.iter().map(|value| value.to_string()).collect(),
        invalidating_events: vec![transition_id.into()],
        required_guards: required_guards
            .iter()
            .map(|value| value.to_string())
            .collect(),
        forbidden_transitions: vec![ForbiddenTransitionRef {
            transition_id: transition_id.into(),
            expected_proof_class: expected_proof_class.into(),
            rationale: vec!["state query regression fixture".into()],
        }],
        confidence: 0.9,
    }
}

fn lead(
    lead_id: &str,
    symbol: &str,
    family: BugFamily,
    locality: LocalityStatus,
    transition_id: &str,
    expected_proof_class: &str,
    actors: &[&str],
    ghost_states: &[&str],
    required_guards: &[&str],
) -> DiscoveryLead {
    DiscoveryLead {
        lead_id: lead_id.into(),
        symbol: symbol.into(),
        family: family.clone(),
        family_confidence: 0.92,
        family_pack_version: "state-query-pack-v1".into(),
        analysis_scope: AnalysisScope::WholeTu,
        candidate_status: CandidateStatus::Primary,
        matched_roles: Vec::new(),
        why_matched: vec!["state query fixture".into()],
        evidence_basis: vec![EvidenceBasis::ObservedFromAstFacts],
        locality: locality.clone(),
        sibling_candidates: Vec::new(),
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: transition_id.into(),
            detail: "state query fixture trigger".into(),
        }],
        required_environment: RequiredEnvironment {
            execution_mode: "test".into(),
            platform_constraints: vec!["asan".into()],
        },
        expected_proof_signal: vec![ProofSignal {
            kind: expected_proof_class.into(),
            detail: "state query fixture proof".into(),
        }],
        state_hypotheses: vec![hypothesis(
            lead_id,
            family.as_str(),
            transition_id,
            expected_proof_class,
            actors,
            ghost_states,
            required_guards,
        )],
        score_trace: ScoreTrace {
            adapters: vec!["SyntheticSliceRepair".into()],
            family_pack_hits: vec!["fixture".into()],
            penalties: Vec::new(),
            locality_notes: vec![format!("{:?}", locality)],
        },
    }
}

fn sample_leads() -> Vec<DiscoveryLead> {
    vec![
        lead(
            "lead-lifetime",
            "AsyncCallbackDestroy",
            BugFamily::LifetimeReentrancy,
            LocalityStatus::RepoLocal,
            "destroy-owner-during-callback",
            "asan-use-after-free",
            &["Owner", "Callback"],
            &["OwnerAlive", "CallbackMayFire"],
            &["safe_invalidation_guard"],
        ),
        lead(
            "lead-size",
            "UploadSubImage",
            BugFamily::SizeStrideArithmetic,
            LocalityStatus::RepoLocal,
            "copy-size-exceeds-allocation",
            "asan-heap-buffer-overflow",
            &["Buffer", "Copy"],
            &["AllocSizeKnown", "GuardDominatesCopy"],
            &["dominating-size-guard"],
        ),
        lead(
            "lead-protocol",
            "MapDestroySequence",
            BugFamily::GpuProtocolOrderLifecycle,
            LocalityStatus::RepoLocal,
            "destroy-device-before-completion",
            "guard-trip",
            &["Device", "Callback"],
            &["MappedBufferStillValid"],
            &["explicit_state_guard"],
        ),
        lead(
            "lead-validation",
            "ValidateRemoteAction",
            BugFamily::ValidationTrustBoundary,
            LocalityStatus::UpstreamHidden,
            "use-before-validation",
            "bad-message",
            &["Input", "Validator"],
            &["ValidationDominatesUse", "PermissionFresh"],
            &["dominating_validation_guard"],
        ),
    ]
}

#[test]
fn state_queries_find_family_specific_transition_matches() {
    let leads = sample_leads();

    let lifetime = find_lifetime_invalidation_candidates(&leads);
    assert_eq!(lifetime.len(), 1, "{lifetime:#?}");
    assert_eq!(lifetime[0].lead_id, "lead-lifetime");
    assert_eq!(
        lifetime[0].forbidden_transition_id,
        "destroy-owner-during-callback"
    );

    let size = find_size_mismatch_candidates(&leads);
    assert_eq!(size.len(), 1, "{size:#?}");
    assert_eq!(size[0].lead_id, "lead-size");
    assert_eq!(size[0].expected_proof_class, "asan-heap-buffer-overflow");

    let protocol = find_protocol_order_candidates(&leads);
    assert_eq!(protocol.len(), 1, "{protocol:#?}");
    assert_eq!(protocol[0].lead_id, "lead-protocol");

    let validation = find_validation_gap_candidates(&leads);
    assert_eq!(validation.len(), 1, "{validation:#?}");
    assert_eq!(validation[0].lead_id, "lead-validation");
}

#[test]
fn state_queries_can_treat_locality_as_state_conditioned_policy() {
    let leads = sample_leads();

    let locality = find_locality_policy_candidates(&leads);
    assert_eq!(locality.len(), 1, "{locality:#?}");
    assert_eq!(locality[0].lead_id, "lead-validation");
    assert_eq!(locality[0].locality, "UpstreamHidden");
    assert!(locality[0].blocked_widening);
}

#[test]
fn state_queries_emit_lifetime_machine_path_matches() {
    let leads = sample_leads();

    let coexistence = find_lifetime_coexistence_candidates(&leads);
    assert_eq!(coexistence.len(), 1, "{coexistence:#?}");
    assert_eq!(coexistence[0].lead_id, "lead-lifetime");
    assert_eq!(
        coexistence[0].transition_id,
        "destroy-owner-during-callback"
    );
    assert_eq!(
        coexistence[0].conflict_states,
        vec!["CallbackPending".to_string(), "CallbackRunning".to_string()]
    );
    assert_eq!(coexistence[0].event_id, "DestroyOwner");

    let invalidation_paths = find_lifetime_invalidation_paths(&leads);
    assert_eq!(invalidation_paths.len(), 1, "{invalidation_paths:#?}");
    assert_eq!(invalidation_paths[0].lead_id, "lead-lifetime");
    assert_eq!(invalidation_paths[0].source_actor, "Owner");
    assert_eq!(invalidation_paths[0].target_actor, "Callback");
    assert_eq!(invalidation_paths[0].invalidated_state, "CallbackPending");

    let event_paths = find_lifetime_event_path_matches(&leads, "DestroyOwner");
    assert_eq!(event_paths.len(), 1, "{event_paths:#?}");
    assert_eq!(event_paths[0].lead_id, "lead-lifetime");
    assert_eq!(
        event_paths[0].transition_id,
        "destroy-owner-during-callback"
    );
    assert_eq!(
        event_paths[0].expected_proof_class,
        Some("asan-use-after-free".to_string())
    );

    let unmatched = find_lifetime_event_path_matches(&leads, "ObserverMutation");
    assert!(unmatched.is_empty(), "{unmatched:#?}");
}

#[test]
fn state_queries_emit_protocol_machine_path_matches() {
    let leads = sample_leads();

    let invalidation_paths = find_protocol_invalidation_paths(&leads);
    assert_eq!(invalidation_paths.len(), 1, "{invalidation_paths:#?}");
    assert_eq!(invalidation_paths[0].lead_id, "lead-protocol");
    assert_eq!(invalidation_paths[0].source_actor, "Device");
    assert_eq!(invalidation_paths[0].target_actor, "Mapping");
    assert_eq!(invalidation_paths[0].invalidated_state, "MapPending");

    let event_paths = find_protocol_event_path_matches(&leads, "DestroyDevice");
    assert_eq!(event_paths.len(), 1, "{event_paths:#?}");
    assert_eq!(event_paths[0].lead_id, "lead-protocol");
    assert_eq!(
        event_paths[0].transition_id,
        "destroy-device-before-completion"
    );
    assert_eq!(event_paths[0].source_state, "MapPending");
    assert_eq!(event_paths[0].target_state, "DeviceLost");
    assert_eq!(
        event_paths[0].expected_proof_class,
        Some("guard-trip".to_string())
    );

    let unmatched = find_protocol_event_path_matches(&leads, "SubmitMapAsync");
    assert!(unmatched.is_empty(), "{unmatched:#?}");
}

#[test]
fn state_queries_emit_size_and_validation_machine_path_matches() {
    let leads = sample_leads();

    let size_invalidation = find_size_invalidation_paths(&leads);
    assert_eq!(size_invalidation.len(), 1, "{size_invalidation:#?}");
    assert_eq!(size_invalidation[0].lead_id, "lead-size");
    assert_eq!(size_invalidation[0].source_actor, "Shape");
    assert_eq!(size_invalidation[0].target_actor, "Buffer");

    let size_events = find_size_event_path_matches(&leads, "CopyWithMismatchedPitch");
    assert_eq!(size_events.len(), 1, "{size_events:#?}");
    assert_eq!(size_events[0].lead_id, "lead-size");
    assert_eq!(size_events[0].transition_id, "copy-size-exceeds-allocation");

    let validation_invalidation = find_validation_invalidation_paths(&leads);
    assert_eq!(
        validation_invalidation.len(),
        1,
        "{validation_invalidation:#?}"
    );
    assert_eq!(validation_invalidation[0].lead_id, "lead-validation");
    assert_eq!(validation_invalidation[0].source_actor, "Validator");
    assert_eq!(validation_invalidation[0].target_actor, "Action");

    let validation_events = find_validation_event_path_matches(&leads, "UseBeforeValidation");
    assert_eq!(validation_events.len(), 1, "{validation_events:#?}");
    assert_eq!(validation_events[0].lead_id, "lead-validation");
    assert_eq!(validation_events[0].transition_id, "use-before-validation");
}

#[test]
fn state_machine_core_exposes_explicit_events_and_region_modes() {
    let leads = sample_leads();
    let machines = build_machines_for_lead(&leads[0]);
    assert_eq!(machines.len(), 1, "{machines:#?}");

    let machine = &machines[0];
    assert!(machine
        .events
        .iter()
        .any(|event| event.event_id == "DestroyOwner" && event.actor == Some("Owner".to_string())));
    assert!(machine
        .events
        .iter()
        .any(|event| event.event_id == "ObserverMutation"
            && event.actor == Some("Callback".to_string())));
    assert!(machine.regions.iter().any(|region| {
        region.region_id == "owner-lifecycle" && region.mode == StateRegionMode::Exclusive
    }));
    assert!(machine.regions.iter().any(|region| {
        region.region_id == "callback-status" && region.mode == StateRegionMode::Parallel
    }));
    assert!(machine
        .regions
        .iter()
        .any(|region| region.region_id == "ghost-states"));
    assert!(machine
        .nodes
        .iter()
        .any(|node| node.state_id == "CallbackMayFire"));
}

#[test]
fn state_machine_registry_exposes_lifetime_family() {
    let ids = registered_machine_ids();
    assert!(ids.contains(&"lifetime-reentrancy"), "{ids:#?}");
    assert!(ids.contains(&"size-stride-arithmetic"), "{ids:#?}");
    assert!(ids.contains(&"validation-trust-boundary"), "{ids:#?}");
}

#[test]
fn state_machine_registry_builds_size_and_validation_families() {
    let leads = sample_leads();

    let size_machines = build_machines_for_lead(&leads[1]);
    assert_eq!(size_machines.len(), 1, "{size_machines:#?}");
    assert_eq!(size_machines[0].machine_id, "size-stride-arithmetic");
    assert!(size_machines[0]
        .events
        .iter()
        .any(|event| event.event_id == "CopyWithMismatchedPitch"));

    let validation_machines = build_machines_for_lead(&leads[3]);
    assert_eq!(validation_machines.len(), 1, "{validation_machines:#?}");
    assert_eq!(
        validation_machines[0].machine_id,
        "validation-trust-boundary"
    );
    assert!(validation_machines[0]
        .events
        .iter()
        .any(|event| event.event_id == "UseBeforeValidation"));
    assert!(validation_machines[0]
        .nodes
        .iter()
        .any(|node| node.state_id == "ValidationDominatesUse"));
}

#[test]
fn state_queries_emit_ghost_state_matches() {
    let leads = sample_leads();

    let size_ghosts = find_ghost_state_matches(&leads, "size-stride-arithmetic");
    assert_eq!(size_ghosts.len(), 2, "{size_ghosts:#?}");
    assert!(size_ghosts
        .iter()
        .any(|item| item.state_id == "AllocSizeKnown"));
    assert!(size_ghosts
        .iter()
        .any(|item| item.path == "ghost-states/GuardDominatesCopy"));

    let validation_ghosts = find_ghost_state_matches(&leads, "validation-trust-boundary");
    assert_eq!(validation_ghosts.len(), 2, "{validation_ghosts:#?}");
    assert!(validation_ghosts
        .iter()
        .any(|item| item.state_id == "ValidationDominatesUse"));
}

#[test]
fn state_queries_emit_state_condition_and_counterfactual_matches() {
    let leads = sample_leads();

    let conditioned =
        find_state_condition_matches(&leads, "size-stride-arithmetic", "AllocationCommitted");
    assert_eq!(conditioned.len(), 1, "{conditioned:#?}");
    assert_eq!(conditioned[0].transition_id, "copy-size-exceeds-allocation");

    let counterfactual = find_counterfactual_transition_matches(
        &leads,
        "validation-trust-boundary",
        Some("dominating_validation_guard"),
    );
    assert_eq!(counterfactual.len(), 1, "{counterfactual:#?}");
    assert_eq!(counterfactual[0].transition_id, "use-before-validation");
    assert_eq!(
        counterfactual[0].absent_guard,
        "dominating_validation_guard"
    );
}

#[test]
fn state_query_snapshot_materializes_leads_hypotheses_and_transitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot_path = dir.path().join("state-query-snapshot.sqlite");
    let leads = sample_leads();

    materialize_state_leads_snapshot(&snapshot_path, "state-query-fixture", &leads)
        .expect("materialize snapshot");

    let meta = load_snapshot_meta(&snapshot_path).expect("load meta");
    assert_eq!(meta.project_id, "state-query-fixture");
    assert_eq!(meta.target_kind, "ssdb-state-leads");

    let reader = GraphReader::open(&snapshot_path).expect("open graph");
    let nodes = reader.nodes().expect("nodes");
    let edges = reader.edges().expect("edges");

    assert!(nodes.iter().any(|node| {
        node.label == "lead:AsyncCallbackDestroy" && node.attr("kind") == Some("discovery-lead")
    }));
    assert!(nodes.iter().any(|node| {
        node.label == "hypothesis:lead-lifetime::h0"
            && node.attr("kind") == Some("state-hypothesis")
    }));
    assert!(nodes.iter().any(|node| {
        node.label == "transition:destroy-owner-during-callback"
            && node.attr("kind") == Some("forbidden-transition")
    }));

    assert!(edges.iter().any(|edge| {
        edge.kind_name() == "ReadsChannel"
            && edge.attrs.get("relation") == Some(&"has-hypothesis".into())
    }));
    assert!(edges.iter().any(|edge| {
        edge.kind_name() == "ViolatesInvariant"
            && edge.attrs.get("relation") == Some(&"targets-transition".into())
    }));
}

#[test]
fn previously_unmatched_transition_ids_produce_real_transitions() {
    // observer-mutation-during-iteration
    let lifetime_lead = lead(
        "lead-lifetime-observer",
        "ObserverListIteration",
        BugFamily::LifetimeReentrancy,
        LocalityStatus::RepoLocal,
        "observer-mutation-during-iteration",
        "asan-use-after-free",
        &["Owner", "Callback"],
        &["OwnerAlive"],
        &["safe_invalidation_guard"],
    );
    let machines = build_machines_for_lead(&lifetime_lead);
    assert_eq!(machines.len(), 1);
    let t = &machines[0].transitions[0];
    assert_ne!(
        t.event_id, "GenericEvent",
        "observer-mutation-during-iteration should not fall through to GenericEvent"
    );
    assert_eq!(t.event_id, "ObserverMutation");
    assert_eq!(t.source_state, "CallbackPending");
    assert!(!t.required_guards.is_empty(), "should have guards");

    // map-then-destroy-before-completion
    let protocol_lead_map = lead(
        "lead-proto-map",
        "MapThenDestroy",
        BugFamily::GpuProtocolOrderLifecycle,
        LocalityStatus::RepoLocal,
        "map-then-destroy-before-completion",
        "guard-trip",
        &["Device", "Mapping"],
        &["MappedBufferStillValid"],
        &["explicit_state_guard"],
    );
    let machines = build_machines_for_lead(&protocol_lead_map);
    assert_eq!(machines.len(), 1);
    let t = &machines[0].transitions[0];
    assert_ne!(
        t.event_id, "GenericEvent",
        "map-then-destroy-before-completion should not fall through"
    );
    assert_eq!(t.event_id, "DestroyDevice");
    assert!(!t.required_guards.is_empty());

    // device-loss-during-submit
    let protocol_lead_loss = lead(
        "lead-proto-loss",
        "DeviceLossDuringSubmit",
        BugFamily::GpuProtocolOrderLifecycle,
        LocalityStatus::RepoLocal,
        "device-loss-during-submit",
        "guard-trip",
        &["Device", "Mapping"],
        &["DeviceAlive"],
        &["device_loss_handler"],
    );
    let machines = build_machines_for_lead(&protocol_lead_loss);
    assert_eq!(machines.len(), 1);
    let t = &machines[0].transitions[0];
    assert_ne!(
        t.event_id, "GenericEvent",
        "device-loss-during-submit should not fall through"
    );
    assert_eq!(t.event_id, "DeviceLost");
    assert!(!t.required_guards.is_empty());
}

#[test]
fn gpu_protocol_counterfactual_returns_results() {
    let leads = vec![lead(
        "lead-proto-cf",
        "MapDestroyCounterfactual",
        BugFamily::GpuProtocolOrderLifecycle,
        LocalityStatus::RepoLocal,
        "device-loss-during-submit",
        "guard-trip",
        &["Device", "Mapping"],
        &["DeviceAlive"],
        &["device_loss_handler"],
    )];
    let cf = find_counterfactual_transition_matches(&leads, "gpu-protocol-order-lifecycle", None);
    assert!(!cf.is_empty(), "gpu-protocol counterfactual should return results after device-loss-during-submit gets proper guards");
    assert_eq!(cf[0].transition_id, "device-loss-during-submit");
}

#[test]
fn machines_with_different_roles_have_different_ghost_states() {
    // Two methods that both match SizeStrideArithmetic family, but one has an
    // extra booster role (stride_pitch_depth_role). After the fix,
    // build_state_hypotheses should incorporate matched_roles into ghost_states,
    // so leads with different role sets get distinct ghost state regions.

    // Method A: has allocation + copy calls (allocation-size + copy-size roles)
    // Method B: has allocation + copy + stride calls (allocation-size + copy-size + pitch-stride-depth)
    let mut fused = fat_query::result::FusedSourceEvidence::default();

    // Method A: buffer_upload -- simple alloc + copy
    fused.methods.push(SourceMethodFact {
        qualified_name: "buffer_upload".into(),
        signature_hash: String::new(),
        file: PathBuf::from("test_a.c"),
        line: 1,
        begin_line: 1,
        end_line: 10,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "malloc".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("test_a.c"),
        line: 2,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "memcpy".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("test_a.c"),
        line: 3,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });

    // Method B: subimage_upload -- alloc + copy + stride
    fused.methods.push(SourceMethodFact {
        qualified_name: "subimage_upload".into(),
        signature_hash: String::new(),
        file: PathBuf::from("test_b.c"),
        line: 1,
        begin_line: 1,
        end_line: 20,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "alloc_buffer".into(),
        enclosing_symbol: "subimage_upload".into(),
        file: PathBuf::from("test_b.c"),
        line: 2,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "copy_region".into(),
        enclosing_symbol: "subimage_upload".into(),
        file: PathBuf::from("test_b.c"),
        line: 3,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "compute_pitch_stride".into(),
        enclosing_symbol: "subimage_upload".into(),
        file: PathBuf::from("test_b.c"),
        line: 4,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });

    let derived = derive_from_fused_source(&fused);
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let leads = build_discovery_leads(&fused, &derived, &locality);

    // Both methods should produce SizeStrideArithmetic leads
    let size_leads: Vec<_> = leads
        .iter()
        .filter(|l| l.family == BugFamily::SizeStrideArithmetic)
        .collect();
    assert!(
        size_leads.len() >= 2,
        "expected at least 2 SizeStrideArithmetic leads, got {}. all leads: {:?}",
        size_leads.len(),
        leads
            .iter()
            .map(|l| (&l.symbol, &l.family))
            .collect::<Vec<_>>()
    );

    // Find the two leads
    let lead_a = size_leads.iter().find(|l| l.symbol == "buffer_upload");
    let lead_b = size_leads.iter().find(|l| l.symbol == "subimage_upload");
    assert!(lead_a.is_some(), "should have a lead for buffer_upload");
    assert!(lead_b.is_some(), "should have a lead for subimage_upload");
    let lead_a = lead_a.unwrap();
    let lead_b = lead_b.unwrap();

    // Lead B should have more matched roles than lead A (extra pitch-stride-depth)
    assert!(
        lead_b.matched_roles.len() > lead_a.matched_roles.len(),
        "subimage_upload should have more roles than buffer_upload. \
         a_roles={:?} b_roles={:?}",
        lead_a.matched_roles,
        lead_b.matched_roles
    );

    // After the fix: state hypotheses should differ because ghost_states
    // now include role-derived ghost states (RolePresent:*)
    let hypo_a = &lead_a.state_hypotheses[0];
    let hypo_b = &lead_b.state_hypotheses[0];

    assert_ne!(
        hypo_a.ghost_states, hypo_b.ghost_states,
        "leads with different matched_roles should have different ghost_states in their hypotheses. \
         a_ghosts={:?} b_ghosts={:?}",
        hypo_a.ghost_states, hypo_b.ghost_states
    );

    // Verify the role-derived ghost states are present
    assert!(
        hypo_b
            .ghost_states
            .iter()
            .any(|g| g.starts_with("RolePresent:")),
        "hypothesis for subimage_upload should have RolePresent:* ghost states. got: {:?}",
        hypo_b.ghost_states
    );

    // Build machines and verify the ghost-state region nodes differ
    let machines_a = build_machines_for_lead(lead_a);
    let machines_b = build_machines_for_lead(lead_b);
    assert_eq!(machines_a.len(), 1, "lead_a should produce 1 machine");
    assert_eq!(machines_b.len(), 1, "lead_b should produce 1 machine");

    let ghost_a: Vec<_> = machines_a[0]
        .nodes
        .iter()
        .filter(|n| n.region_id == "ghost-states")
        .map(|n| n.state_id.clone())
        .collect();
    let ghost_b: Vec<_> = machines_b[0]
        .nodes
        .iter()
        .filter(|n| n.region_id == "ghost-states")
        .map(|n| n.state_id.clone())
        .collect();

    assert_ne!(
        ghost_a.len(),
        ghost_b.len(),
        "machines for leads with different matched_roles should have different ghost state counts. \
         a={ghost_a:?} b={ghost_b:?}"
    );
}

#[test]
fn discovery_lead_dedup_removes_duplicates() {
    use fat_query::discovery::dedup_discovery_leads;
    let mut leads = sample_leads();
    let original_len = leads.len();
    // double them
    leads.extend(sample_leads());
    assert_eq!(leads.len(), original_len * 2);
    let deduped = dedup_discovery_leads(leads);
    assert_eq!(
        deduped.len(),
        original_len,
        "dedup should remove exact duplicates"
    );
}

#[test]
fn same_named_functions_in_different_files_produce_distinct_leads() {
    // Two functions both named "buffer_upload" but in different files should
    // produce two separate leads, not get collapsed by dedup.
    let mut fused = fat_query::result::FusedSourceEvidence::default();

    // buffer_upload in file_a.c
    fused.methods.push(SourceMethodFact {
        qualified_name: "buffer_upload".into(),
        signature_hash: String::new(),
        file: PathBuf::from("file_a.c"),
        line: 1,
        begin_line: 1,
        end_line: 10,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "malloc".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("file_a.c"),
        line: 2,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "memcpy".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("file_a.c"),
        line: 3,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });

    // buffer_upload in file_b.c (same name, different file)
    fused.methods.push(SourceMethodFact {
        qualified_name: "buffer_upload".into(),
        signature_hash: String::new(),
        file: PathBuf::from("file_b.c"),
        line: 1,
        begin_line: 1,
        end_line: 10,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "malloc".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("file_b.c"),
        line: 2,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });
    fused.calls.push(SourceCallFact {
        callee_name: "memcpy".into(),
        enclosing_symbol: "buffer_upload".into(),
        file: PathBuf::from("file_b.c"),
        line: 3,
        basis: EvidenceBasis::ObservedFromAstFacts,
    });

    let derived = derive_from_fused_source(&fused);
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let leads = build_discovery_leads(&fused, &derived, &locality);
    let size_leads: Vec<_> = leads
        .iter()
        .filter(|l| l.family == BugFamily::SizeStrideArithmetic && l.symbol == "buffer_upload")
        .collect();

    assert_eq!(
        size_leads.len(),
        2,
        "two buffer_upload functions in different files should produce 2 distinct leads, \
         not be collapsed by dedup. Got {} leads with ids: {:?}",
        size_leads.len(),
        size_leads.iter().map(|l| &l.lead_id).collect::<Vec<_>>()
    );

    // Their lead_ids should differ
    assert_ne!(
        size_leads[0].lead_id, size_leads[1].lead_id,
        "same-named functions in different files must have different lead_ids"
    );
}
