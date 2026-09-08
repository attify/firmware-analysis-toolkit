use fat_query::discovery::{
    build_discovery_leads, AnalysisScope, BugFamily, CandidateStatus, DiscoveryLead,
    ForbiddenTransitionRef, ProofSignal, RequiredEnvironment, RoleMatch, SiblingCandidate,
    StateHypothesis, TriggerRecipeStep,
};
use fat_query::result::{
    DerivedAnalysis, DerivedFact, EvidenceBasis, FamilyPack, FusedSourceEvidence, LocalityStatus,
    ReplayAnalysis, ReplayCandidate, ReplayRole, RollResolution, ScoreTrace, SourceMethodFact,
};
use fat_query::variant_hunter::hunt_variants;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn discovery_lead_carries_operational_fields_and_serializes_cleanly() {
    let lead = DiscoveryLead {
        lead_id: "lead-demo-1".into(),
        symbol: "Demo::candidate".into(),
        family: BugFamily::SizeStrideArithmetic,
        family_confidence: 0.84,
        family_pack_version: "size-pack-v1".into(),
        analysis_scope: AnalysisScope::RepairedSlice,
        candidate_status: CandidateStatus::Sibling,
        matched_roles: vec![
            RoleMatch {
                role: "allocation-size".into(),
                detail: "allocation-like site observed".into(),
            },
            RoleMatch {
                role: "copy-size".into(),
                detail: "copy-like site observed".into(),
            },
        ],
        why_matched: vec![
            "allocation and copy roles diverge".into(),
            "stride/pitch signal boosts the family".into(),
        ],
        evidence_basis: vec![
            EvidenceBasis::ObservedFromAstFacts,
            EvidenceBasis::InferredFromRepairedSlice,
        ],
        locality: LocalityStatus::VendoredLocal,
        sibling_candidates: vec![SiblingCandidate {
            symbol: "Demo::neighbor".into(),
            fingerprint: "sibling-fp".into(),
            score: 17,
            candidate_status: CandidateStatus::VendoredSibling,
        }],
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: "pitch-depth-mismatch".into(),
            detail: "make payload smaller than metadata-implied copy size".into(),
        }],
        required_environment: RequiredEnvironment {
            execution_mode: "gpu-upload".into(),
            platform_constraints: vec!["asan".into(), "vulkan".into()],
        },
        expected_proof_signal: vec![ProofSignal {
            kind: "asan-heap-buffer-overflow".into(),
            detail: "copy size exceeds allocation".into(),
        }],
        state_hypotheses: vec![StateHypothesis {
            hypothesis_id: "lead-demo-1::size-h0".into(),
            machine_id: "size-stride-arithmetic".into(),
            actors: vec!["Buffer".into(), "Copy".into()],
            active_regions: vec!["allocation-vs-copy".into()],
            key_states: vec!["Allocated".into(), "CopyPending".into()],
            ghost_states: vec!["GuardDominatesCopy".into(), "AllocSizeKnown".into()],
            invalidating_events: vec!["copy-size-exceeds-allocation".into()],
            required_guards: vec!["dominating-size-guard".into()],
            forbidden_transitions: vec![ForbiddenTransitionRef {
                transition_id: "copy-size-exceeds-allocation".into(),
                expected_proof_class: "asan-heap-buffer-overflow".into(),
                rationale: vec!["copy exceeds backing allocation".into()],
            }],
            confidence: 0.84,
        }],
        score_trace: ScoreTrace {
            adapters: vec!["AstDumpJson".into(), "SyntheticSliceRepair".into()],
            family_pack_hits: vec!["allocation_call_present".into(), "copy_call_present".into()],
            penalties: vec!["repaired-slice-evidence".into()],
            locality_notes: vec!["vendored-local".into()],
        },
    };

    let value = serde_json::to_value(&lead).expect("serialize discovery lead");
    assert_eq!(
        value.get("lead_id").and_then(|v| v.as_str()),
        Some("lead-demo-1")
    );
    assert_eq!(
        value.get("family_pack_version").and_then(|v| v.as_str()),
        Some("size-pack-v1")
    );
    let confidence = value
        .get("family_confidence")
        .and_then(|v| v.as_f64())
        .expect("family confidence");
    assert!((confidence - 0.84).abs() < 0.000_001);
    assert_eq!(
        value.get("analysis_scope").and_then(|v| v.as_str()),
        Some("RepairedSlice")
    );
    assert_eq!(
        value.get("candidate_status").and_then(|v| v.as_str()),
        Some("Sibling")
    );
    assert_eq!(
        value.get("locality").and_then(|v| v.as_str()),
        Some("VendoredLocal")
    );
    assert_eq!(
        value
            .get("matched_roles")
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(2)
    );
    assert_eq!(
        value
            .get("state_hypotheses")
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(1)
    );
    assert_eq!(
        value
            .get("state_hypotheses")
            .and_then(|v| v.get(0))
            .and_then(|v| v.get("hypothesis_id"))
            .and_then(|v| v.as_str()),
        Some("lead-demo-1::size-h0")
    );
    assert_eq!(
        value
            .get("state_hypotheses")
            .and_then(|v| v.get(0))
            .and_then(|v| v.get("forbidden_transitions"))
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(1)
    );
}

#[test]
fn build_discovery_leads_emits_lifetime_lead_and_suppresses_guarded_negative() {
    let file = PathBuf::from("/tmp/lifetime.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "AsyncCallbackDestroy".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 10,
            },
            SourceMethodFact {
                qualified_name: "GuardedAsyncCallback".into(),
                signature_hash: "b".into(),
                file,
                line: 12,
                begin_line: 12,
                end_line: 20,
            },
        ],
        calls: Vec::new(),
        adapters: Vec::new(),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "callback-like call ReleaseSoon".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "GuardedAsyncCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "GuardedAsyncCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "callback-like call DestroyLater".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "safe_invalidation_guard".into(),
                subject: "GuardedAsyncCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "weak pointer invalidation dominates callback completion".into(),
            },
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 5usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let leads = build_discovery_leads(&fused, &derived, &repo_locality());

    assert_eq!(leads.len(), 1);
    assert_eq!(leads[0].symbol, "AsyncCallbackDestroy");
    assert_eq!(leads[0].family, BugFamily::LifetimeReentrancy);
    assert!(!leads[0].suggested_trigger_recipe.is_empty());
    assert!(!leads[0].expected_proof_signal.is_empty());
    assert!(!leads[0].state_hypotheses.is_empty());
    assert!(!leads[0].state_hypotheses[0]
        .forbidden_transitions
        .is_empty());
    assert_eq!(leads[0].candidate_status, CandidateStatus::Primary);
}

#[test]
fn build_discovery_leads_emits_post_handoff_lifetime_lead() {
    let file = PathBuf::from("/tmp/post_handoff.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![SourceMethodFact {
            qualified_name: "Txn::PendingFrozenReport".into(),
            signature_hash: "a".into(),
            file,
            line: 1,
            begin_line: 1,
            end_line: 10,
        }],
        calls: Vec::new(),
        adapters: Vec::new(),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "ownership_transfer_call_present".into(),
                subject: "Txn::PendingFrozenReport".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "handoff-like call QueueTransaction".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "post_handoff_observer_present".into(),
                subject: "Txn::PendingFrozenReport".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "report-like call ReportTransaction".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "deferred_or_pending_state_present".into(),
                subject: "Txn::PendingFrozenReport".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "pending-like call MarkPendingFrozen".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "stale_subject_reuse_risk".into(),
                subject: "Txn::PendingFrozenReport".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "handoff then observe on the same subject".into(),
            },
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 4usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let leads = build_discovery_leads(&fused, &derived, &repo_locality());

    assert_eq!(leads.len(), 1);
    assert_eq!(leads[0].symbol, "Txn::PendingFrozenReport");
    assert_eq!(leads[0].family, BugFamily::LifetimeReentrancy);
    assert!(leads[0]
        .matched_roles
        .iter()
        .any(|role| role.role == "ownership-transfer"));
    assert!(leads[0]
        .matched_roles
        .iter()
        .any(|role| role.role == "post-handoff-observer"));
}

#[test]
fn build_discovery_leads_emits_size_lead_and_suppresses_guarded_negative() {
    let file = PathBuf::from("/tmp/size.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "UploadSubImage".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 10,
            },
            SourceMethodFact {
                qualified_name: "GuardedUploadSubImage".into(),
                signature_hash: "b".into(),
                file,
                line: 12,
                begin_line: 12,
                end_line: 20,
            },
        ],
        calls: Vec::new(),
        adapters: Vec::new(),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "allocation_call_present".into(),
                subject: "UploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "allocation-like call MakeBuffer".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "copy_call_present".into(),
                subject: "UploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "copy-like call CopyBufferToOriginalTextureIfDstIsAView".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "stride_pitch_depth_role".into(),
                subject: "UploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "size-role call SaturateDepth".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "allocation_call_present".into(),
                subject: "GuardedUploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "allocation-like call MakeBuffer".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "copy_call_present".into(),
                subject: "GuardedUploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "copy-like call memcpy".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "dominating_size_guard".into(),
                subject: "GuardedUploadSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "validated payload size dominates allocation and copy".into(),
            },
        ],
        family_scores: BTreeMap::from([("bounds-size-arithmetic".into(), 6usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let leads = build_discovery_leads(&fused, &derived, &repo_locality());

    assert_eq!(leads.len(), 1);
    assert_eq!(leads[0].symbol, "UploadSubImage");
    assert_eq!(leads[0].family, BugFamily::SizeStrideArithmetic);
    assert!(leads[0]
        .matched_roles
        .iter()
        .any(|role| role.role == "allocation-size"));
    assert!(leads[0]
        .matched_roles
        .iter()
        .any(|role| role.role == "copy-size"));
    assert!(!leads[0].suggested_trigger_recipe.is_empty());
    assert!(!leads[0].expected_proof_signal.is_empty());
    assert!(!leads[0].state_hypotheses.is_empty());
    assert_eq!(
        leads[0].state_hypotheses[0].forbidden_transitions[0].expected_proof_class,
        "asan-heap-buffer-overflow"
    );
}

#[test]
fn discovery_leads_attach_locality_aware_siblings_and_blocked_vendored_status() {
    let file = PathBuf::from("/tmp/lifetime.cpp");
    let vendored = PathBuf::from("/tmp/third_party/upstream/bug.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "AsyncCallbackDestroy".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 10,
            },
            SourceMethodFact {
                qualified_name: "AsyncCallbackDestroySibling".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 12,
                begin_line: 12,
                end_line: 20,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "callback-like call ReleaseSoon".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "AsyncCallbackDestroySibling".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "AsyncCallbackDestroySibling".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "callback-like call DestroyLater".into(),
            },
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 4usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["HistoricalLifetimeBug".into()],
        required_roles: vec![ReplayRole::CallbackTeardown],
        candidates: vec![ReplayCandidate {
            symbol: "AsyncCallbackDestroy".into(),
            file: Some(file.clone()),
            score: 40,
            matched_roles: vec![ReplayRole::CallbackTeardown],
            missing_roles: vec![],
            family_pack_hits: vec!["lifetime-ownership".into()],
            score_trace: ScoreTrace {
                adapters: vec!["SyntheticSliceRepair".into()],
                family_pack_hits: vec!["callback_or_teardown_call_present".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let locality = RollResolution {
        locality: LocalityStatus::VendoredLocal,
        likely_upstream_repo: Some("angle/angle".into()),
        vendored_nearby_path: Some(vendored.clone()),
        local_patch_touching_vendored_code: true,
        no_local_vulnerable_source_likely: true,
        allow_vendored_scan: true,
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let variant_leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 1);
    let mut leads = build_discovery_leads(&fused, &derived, &locality);
    fat_query::discovery::attach_siblings(&mut leads, &variant_leads, &locality, 3);

    let lead = leads
        .iter()
        .find(|lead| lead.symbol == "AsyncCallbackDestroy")
        .expect("primary discovery lead");
    assert_eq!(lead.locality, LocalityStatus::VendoredLocal);
    assert!(!lead.sibling_candidates.is_empty());
    assert_eq!(
        lead.sibling_candidates[0].symbol,
        "vendored-neighborhood:/tmp/third_party/upstream/bug.cpp"
    );
    assert_eq!(
        lead.sibling_candidates[0].candidate_status,
        CandidateStatus::VendoredSibling
    );
    assert!(lead
        .score_trace
        .locality_notes
        .iter()
        .any(|note| note.contains("vendored-sibling-attached")));
}

#[test]
fn discovery_leads_record_blocked_vendored_status_when_locality_disallows_expansion() {
    let file = PathBuf::from("/tmp/lifetime.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![SourceMethodFact {
            qualified_name: "AsyncCallbackDestroy".into(),
            signature_hash: "a".into(),
            file: file.clone(),
            line: 1,
            begin_line: 1,
            end_line: 10,
        }],
        calls: Vec::new(),
        adapters: Vec::new(),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "AsyncCallbackDestroy".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "callback-like call ReleaseSoon".into(),
            },
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 2usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let locality = RollResolution {
        locality: LocalityStatus::UpstreamHidden,
        likely_upstream_repo: Some("angle/angle".into()),
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: true,
        allow_vendored_scan: false,
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let mut leads = build_discovery_leads(&fused, &derived, &locality);
    fat_query::discovery::attach_siblings(&mut leads, &[], &locality, 3);

    assert_eq!(leads.len(), 1);
    assert_eq!(
        leads[0].candidate_status,
        CandidateStatus::BlockedByLocality
    );
    assert!(leads[0].sibling_candidates.is_empty());
    assert!(leads[0]
        .score_trace
        .penalties
        .iter()
        .any(|penalty| penalty == "vendored-expansion-blocked"));
}

fn repo_locality() -> RollResolution {
    RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: Vec::new(),
        inferred: Vec::new(),
    }
}
