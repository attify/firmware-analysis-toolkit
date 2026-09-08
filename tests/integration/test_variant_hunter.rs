use fat_query::result::{
    DerivedAnalysis, DerivedFact, EvidenceBasis, FamilyPack, FusedSourceEvidence, LocalityStatus,
    ReplayAnalysis, ReplayCandidate, ReplayRole, RollResolution, SourceCallFact, SourceMethodFact,
};
use fat_query::variant_hunter::hunt_variants;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn variant_hunter_ranks_local_neighbors_and_dedups() {
    let file = PathBuf::from("/tmp/service.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "GoodOverride".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 3,
            },
            SourceMethodFact {
                qualified_name: "BadOverride".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 5,
                begin_line: 5,
                end_line: 7,
            },
        ],
        calls: vec![SourceCallFact {
            callee_name: "doThing".into(),
            enclosing_symbol: "BadOverride".into(),
            file: file.clone(),
            line: 6,
            basis: EvidenceBasis::ObservedFromAstFacts,
        }],
        adapters: vec!["source-clang-facts:AstDumpJson".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![DerivedFact {
            family_pack: FamilyPack::ValidationPolicy,
            kind: "override_permission_site".into(),
            subject: "BadOverride".into(),
            source_file: None,
            evidence_basis: EvidenceBasis::ObservedFromAstFacts,
            detail: "candidate".into(),
        }],
        family_scores: BTreeMap::from([("validation-policy".into(), 1usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["GoodOverride".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "GoodOverride".into(),
            file: Some(file.clone()),
            score: 30,
            matched_roles: vec![ReplayRole::GuardValidation],
            missing_roles: vec![],
            family_pack_hits: vec!["validation-policy".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:AstDumpJson".into()],
                family_pack_hits: vec!["override_permission_site".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 5);

    assert_eq!(
        leads.first().map(|lead| lead.symbol.as_str()),
        Some("BadOverride")
    );
    assert_eq!(leads.len(), 1);
}

#[test]
fn variant_hunter_prefers_same_file_family_overlap_over_override_shaped_noise() {
    let replay_file = PathBuf::from("/tmp/secure.cpp");
    let noise_file = PathBuf::from("/tmp/noise.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "PermissionReplay".into(),
                signature_hash: "a".into(),
                file: replay_file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 5,
            },
            SourceMethodFact {
                qualified_name: "PermissionShadow".into(),
                signature_hash: "b".into(),
                file: replay_file.clone(),
                line: 7,
                begin_line: 7,
                end_line: 11,
            },
            SourceMethodFact {
                qualified_name: "DangerousOverrideNoise".into(),
                signature_hash: "c".into(),
                file: noise_file.clone(),
                line: 3,
                begin_line: 3,
                end_line: 7,
            },
        ],
        calls: vec![],
        adapters: vec!["source-clang-facts:LibclangBackend".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "override_permission_site".into(),
                subject: "PermissionShadow".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "same-family same-file neighbor".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "override_permission_site".into(),
                subject: "DangerousOverrideNoise".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "same-family but noisier neighbor".into(),
            },
        ],
        family_scores: BTreeMap::from([("validation-policy".into(), 2usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["PermissionReference".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "PermissionReplay".into(),
            file: Some(replay_file.clone()),
            score: 40,
            matched_roles: vec![ReplayRole::GuardValidation],
            missing_roles: vec![],
            family_pack_hits: vec!["validation-policy".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:LibclangBackend".into()],
                family_pack_hits: vec!["override_permission_site".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 1);

    assert_eq!(
        leads.first().map(|lead| lead.symbol.as_str()),
        Some("PermissionShadow")
    );
    assert!(leads.len() >= 2);
    assert!(leads[0].score > leads[1].score);
}

#[test]
fn variant_hunter_emits_vendored_neighbor_only_when_locality_allows_it() {
    let replay_file = PathBuf::from("/tmp/secure.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "rollSurface".into(),
                signature_hash: "a".into(),
                file: replay_file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 5,
            },
            SourceMethodFact {
                qualified_name: "rollSurfaceVariant".into(),
                signature_hash: "b".into(),
                file: replay_file.clone(),
                line: 7,
                begin_line: 7,
                end_line: 11,
            },
        ],
        calls: vec![
            SourceCallFact {
                callee_name: "hasPermission".into(),
                enclosing_symbol: "rollSurface".into(),
                file: replay_file.clone(),
                line: 2,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "enforcePermission".into(),
                enclosing_symbol: "rollSurface".into(),
                file: replay_file.clone(),
                line: 4,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "hasPermission".into(),
                enclosing_symbol: "rollSurfaceVariant".into(),
                file: replay_file.clone(),
                line: 8,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "enforcePermission".into(),
                enclosing_symbol: "rollSurfaceVariant".into(),
                file: replay_file.clone(),
                line: 10,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
        ],
        adapters: vec!["source-clang-facts:LibclangBackend".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "override_permission_site".into(),
                subject: "rollSurface".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "reference".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "permission_gate_present".into(),
                subject: "rollSurface".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "reference gate".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "override_permission_site".into(),
                subject: "rollSurfaceVariant".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "candidate".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "permission_gate_present".into(),
                subject: "rollSurfaceVariant".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "candidate gate".into(),
            },
        ],
        family_scores: BTreeMap::from([("validation-policy".into(), 4usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["rollSurface".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "rollSurfaceVariant".into(),
            file: Some(replay_file.clone()),
            score: 40,
            matched_roles: vec![ReplayRole::GuardValidation],
            missing_roles: vec![],
            family_pack_hits: vec!["validation-policy".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:LibclangBackend".into()],
                family_pack_hits: vec!["override_permission_site".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };
    let vendored_locality = RollResolution {
        locality: LocalityStatus::VendoredLocal,
        likely_upstream_repo: Some("https://example.invalid/upstream.git".into()),
        vendored_nearby_path: Some(PathBuf::from("third_party/libdemo")),
        local_patch_touching_vendored_code: true,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: true,
        observed: vec![],
        inferred: vec![],
    };
    let upstream_locality = RollResolution {
        locality: LocalityStatus::UpstreamReferenced,
        likely_upstream_repo: Some("https://example.invalid/upstream.git".into()),
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };

    let vendored_leads = hunt_variants(&replay, &fused, &derived, &vendored_locality, &[], 1);
    let upstream_leads = hunt_variants(&replay, &fused, &derived, &upstream_locality, &[], 1);

    assert!(vendored_leads
        .iter()
        .any(|lead| lead.symbol == "vendored-neighborhood:third_party/libdemo"));
    assert!(!upstream_leads
        .iter()
        .any(|lead| lead.symbol.starts_with("vendored-neighborhood:")));
}

#[test]
fn variant_hunter_demotes_cleanup_only_lifetime_neighbors_below_top_three() {
    let file = PathBuf::from("/tmp/lifetime.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "destroyObserverCallback".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 4,
            },
            SourceMethodFact {
                qualified_name: "DestroyEndpoint".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 6,
                begin_line: 6,
                end_line: 6,
            },
            SourceMethodFact {
                qualified_name: "ReleaseObserver".into(),
                signature_hash: "c".into(),
                file: file.clone(),
                line: 7,
                begin_line: 7,
                end_line: 7,
            },
            SourceMethodFact {
                qualified_name: "cleanupShadow".into(),
                signature_hash: "d".into(),
                file: file.clone(),
                line: 9,
                begin_line: 9,
                end_line: 12,
            },
            SourceMethodFact {
                qualified_name: "copyOnlyNoise".into(),
                signature_hash: "e".into(),
                file,
                line: 14,
                begin_line: 14,
                end_line: 16,
            },
        ],
        calls: vec![],
        adapters: vec!["source-clang-facts:AstDumpJson".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "destroyObserverCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "destroyObserverCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "lifetime-like call ReleaseObserver".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "destroyObserverCallback".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "lifetime-like call DestroyEndpoint".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "lifetime_sensitive_method".into(),
                subject: "cleanupShadow".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests teardown/callback lifetime pattern".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "callback_or_teardown_call_present".into(),
                subject: "cleanupShadow".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "lifetime-like call ReleaseObserver".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::LifetimeOwnership,
                kind: "cleanup_only_teardown".into(),
                subject: "cleanupShadow".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "cleanup-only path".into(),
            },
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 5usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["HistoricalLifetimeBug".into()],
        required_roles: vec![ReplayRole::CallbackTeardown],
        candidates: vec![ReplayCandidate {
            symbol: "destroyObserverCallback".into(),
            file: Some(PathBuf::from("/tmp/lifetime.cpp")),
            score: 40,
            matched_roles: vec![ReplayRole::CallbackTeardown],
            missing_roles: vec![],
            family_pack_hits: vec!["lifetime-ownership".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:AstDumpJson".into()],
                family_pack_hits: vec!["callback_or_teardown_call_present".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 1);

    let cleanup_rank = leads
        .iter()
        .position(|lead| lead.symbol == "cleanupShadow")
        .map(|index| index + 1)
        .unwrap_or(usize::MAX);
    assert!(
        cleanup_rank > 3,
        "cleanup-only candidate leaked into top-3: {cleanup_rank}"
    );
}

#[test]
fn variant_hunter_demotes_guard_dominated_size_neighbors_below_top_three() {
    let file = PathBuf::from("/tmp/size.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "setPerSliceSubImage".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 5,
            },
            SourceMethodFact {
                qualified_name: "GuardedUploadSubImage".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 7,
                begin_line: 7,
                end_line: 11,
            },
            SourceMethodFact {
                qualified_name: "copyOnlyProbe".into(),
                signature_hash: "c".into(),
                file,
                line: 13,
                begin_line: 13,
                end_line: 15,
            },
        ],
        calls: vec![],
        adapters: vec!["source-clang-facts:AstDumpJson".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "buffer_or_subimage_method".into(),
                subject: "setPerSliceSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "method name suggests copy/allocation size handling".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "allocation_call_present".into(),
                subject: "setPerSliceSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "allocation-like call MakeBuffer".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::BoundsSizeArithmetic,
                kind: "copy_call_present".into(),
                subject: "setPerSliceSubImage".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "copy-like call CopyBufferToOriginalTextureIfDstIsAView".into(),
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
        family_scores: BTreeMap::from([("bounds-size-arithmetic".into(), 4usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["HistoricalSizeBug".into()],
        required_roles: vec![
            ReplayRole::AllocationSize,
            ReplayRole::CopySize,
            ReplayRole::PitchStrideDepth,
        ],
        candidates: vec![ReplayCandidate {
            symbol: "setPerSliceSubImage".into(),
            file: Some(PathBuf::from("/tmp/size.cpp")),
            score: 50,
            matched_roles: vec![
                ReplayRole::AllocationSize,
                ReplayRole::CopySize,
                ReplayRole::PitchStrideDepth,
            ],
            missing_roles: vec![],
            family_pack_hits: vec!["bounds-size-arithmetic".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:AstDumpJson".into()],
                family_pack_hits: vec![
                    "allocation_call_present".into(),
                    "copy_call_present".into(),
                ],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 1);

    let guarded_rank = leads
        .iter()
        .position(|lead| lead.symbol == "GuardedUploadSubImage")
        .map(|index| index + 1)
        .unwrap_or(usize::MAX);
    assert!(
        guarded_rank > 3,
        "guard-dominated candidate leaked into top-3: {guarded_rank}"
    );
}

#[test]
fn variant_hunter_drops_same_file_noise_without_family_facts() {
    let replay_file = PathBuf::from("/tmp/secure.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "PermissionReplay".into(),
                signature_hash: "a".into(),
                file: replay_file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 5,
            },
            SourceMethodFact {
                qualified_name: "SameFileNoise".into(),
                signature_hash: "b".into(),
                file: replay_file,
                line: 7,
                begin_line: 7,
                end_line: 11,
            },
        ],
        calls: vec![],
        adapters: vec!["source-clang-facts:LibclangBackend".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![DerivedFact {
            family_pack: FamilyPack::ValidationPolicy,
            kind: "override_permission_site".into(),
            subject: "PermissionReplay".into(),
            source_file: None,
            evidence_basis: EvidenceBasis::ObservedFromAstFacts,
            detail: "replay reference".into(),
        }],
        family_scores: BTreeMap::from([("validation-policy".into(), 1usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let locality = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["PermissionReplay".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "PermissionReplay".into(),
            file: Some(PathBuf::from("/tmp/secure.cpp")),
            score: 40,
            matched_roles: vec![ReplayRole::GuardValidation],
            missing_roles: vec![],
            family_pack_hits: vec!["validation-policy".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:LibclangBackend".into()],
                family_pack_hits: vec!["override_permission_site".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 1);

    assert!(leads.is_empty());
}

#[test]
fn variant_hunter_emits_vendored_neighbors_only_when_locality_allows() {
    let file = PathBuf::from("/tmp/roll.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "rollSurface".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 6,
            },
            SourceMethodFact {
                qualified_name: "rollDecoy".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 8,
                begin_line: 8,
                end_line: 10,
            },
        ],
        calls: vec![
            SourceCallFact {
                callee_name: "hasPermission".into(),
                enclosing_symbol: "rollSurface".into(),
                file: file.clone(),
                line: 2,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "enforcePermission".into(),
                enclosing_symbol: "rollSurface".into(),
                file: file.clone(),
                line: 3,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "logDenied".into(),
                enclosing_symbol: "rollSurface".into(),
                file: file.clone(),
                line: 4,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
            SourceCallFact {
                callee_name: "vendorCall".into(),
                enclosing_symbol: "rollDecoy".into(),
                file: file.clone(),
                line: 9,
                basis: EvidenceBasis::ObservedFromAstFacts,
            },
        ],
        adapters: vec!["source-clang-facts:LibclangBackend".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "permission_gate_present".into(),
                subject: "rollSurface".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "local permission gate".into(),
            },
            DerivedFact {
                family_pack: FamilyPack::ValidationPolicy,
                kind: "override_permission_site".into(),
                subject: "rollSurface".into(),
                source_file: None,
                evidence_basis: EvidenceBasis::ObservedFromAstFacts,
                detail: "override site".into(),
            },
        ],
        family_scores: BTreeMap::from([("validation-policy".into(), 2usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["rollSurface".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "rollSurface".into(),
            file: Some(file.clone()),
            score: 50,
            matched_roles: vec![ReplayRole::GuardValidation],
            missing_roles: vec![],
            family_pack_hits: vec!["validation-policy".into()],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec!["source-clang-facts:LibclangBackend".into()],
                family_pack_hits: vec!["override_permission_site".into()],
                penalties: vec![],
                locality_notes: vec!["replay".into()],
            },
        }],
        observed: vec![],
        inferred: vec![],
    };
    let repo_local = RollResolution {
        locality: LocalityStatus::RepoLocal,
        likely_upstream_repo: None,
        vendored_nearby_path: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: vec![],
        inferred: vec![],
    };
    let vendored_local = RollResolution {
        locality: LocalityStatus::VendoredLocal,
        likely_upstream_repo: Some("https://example.invalid/upstream.git".into()),
        vendored_nearby_path: Some(PathBuf::from("third_party/libdemo")),
        local_patch_touching_vendored_code: true,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: true,
        observed: vec![],
        inferred: vec![],
    };

    let blocked = hunt_variants(&replay, &fused, &derived, &repo_local, &[], 3);
    assert!(!blocked
        .iter()
        .any(|lead| lead.symbol.starts_with("vendored-neighborhood:")));

    let allowed = hunt_variants(&replay, &fused, &derived, &vendored_local, &[], 3);
    assert_eq!(
        allowed.first().map(|lead| lead.symbol.as_str()),
        Some("vendored-neighborhood:third_party/libdemo")
    );
    assert!(allowed
        .first()
        .expect("vendored lead")
        .score_trace
        .locality_notes
        .iter()
        .any(|note| note.contains("vendored expansion allowed")));
}
