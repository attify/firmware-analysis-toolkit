use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fat_query::discovery::{
    build_discovery_leads, populate_harvested_sibling_candidates, BugFamily, CandidateStatus,
};
use fat_query::harvesters::harvest_family_candidates;
use fat_query::result::{
    DerivedAnalysis, DerivedFact, EvidenceBasis, FamilyPack, FusedSourceEvidence, LocalityStatus,
    RollResolution, SourceMethodFact,
};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/discovery")
        .join(name)
}

fn repo_locality() -> RollResolution {
    RollResolution {
        locality: LocalityStatus::RepoLocal,
        vendored_nearby_path: None,
        likely_upstream_repo: None,
        local_patch_touching_vendored_code: false,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: false,
        observed: Vec::new(),
        inferred: Vec::new(),
    }
}

#[test]
fn lifetime_harvester_emits_real_siblings_and_suppresses_cleanup_negative() {
    let file = fixture_path("lifetime-cleanup-negative.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "AsyncCallbackDestroy".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 1,
            },
            SourceMethodFact {
                qualified_name: "ObserverCallbackDestroy".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 2,
                begin_line: 2,
                end_line: 2,
            },
            SourceMethodFact {
                qualified_name: "CleanupReleaseObserver".into(),
                signature_hash: "c".into(),
                file,
                line: 3,
                begin_line: 3,
                end_line: 3,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "AsyncCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "AsyncCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "ObserverCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "ObserverCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "CleanupReleaseObserver",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "CleanupReleaseObserver",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "cleanup_only_teardown",
                "CleanupReleaseObserver",
            ),
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 7usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let report = harvest_family_candidates(
        BugFamily::LifetimeReentrancy,
        &fused,
        &derived,
        &repo_locality(),
    );

    let emitted: BTreeSet<_> = report.emitted.iter().map(|c| c.symbol.as_str()).collect();
    let suppressed: Vec<_> = report
        .suppressed
        .iter()
        .map(|c| c.symbol.as_str())
        .collect();

    assert_eq!(
        emitted,
        BTreeSet::from(["AsyncCallbackDestroy", "ObserverCallbackDestroy"])
    );
    assert_eq!(suppressed, vec!["CleanupReleaseObserver"]);
    assert!(report.suppressed[0]
        .suppression_reasons
        .contains(&"cleanup_only_teardown".to_string()));
}

#[test]
fn size_harvester_emits_real_siblings_and_suppresses_guarded_negative() {
    let file = fixture_path("size-guarded-negative.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "UploadSubImage".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 1,
            },
            SourceMethodFact {
                qualified_name: "SiblingUploadSubImage".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 2,
                begin_line: 2,
                end_line: 2,
            },
            SourceMethodFact {
                qualified_name: "GuardedUploadSubImage".into(),
                signature_hash: "c".into(),
                file,
                line: 3,
                begin_line: 3,
                end_line: 3,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "allocation_call_present",
                "UploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "copy_call_present",
                "UploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "stride_pitch_depth_role",
                "UploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "allocation_call_present",
                "SiblingUploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "copy_call_present",
                "SiblingUploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "stride_pitch_depth_role",
                "SiblingUploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "allocation_call_present",
                "GuardedUploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "copy_call_present",
                "GuardedUploadSubImage",
            ),
            fact(
                FamilyPack::BoundsSizeArithmetic,
                "dominating_size_guard",
                "GuardedUploadSubImage",
            ),
        ],
        family_scores: BTreeMap::from([("bounds-size-arithmetic".into(), 9usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let report = harvest_family_candidates(
        BugFamily::SizeStrideArithmetic,
        &fused,
        &derived,
        &repo_locality(),
    );

    let emitted: Vec<_> = report.emitted.iter().map(|c| c.symbol.as_str()).collect();
    let suppressed: Vec<_> = report
        .suppressed
        .iter()
        .map(|c| c.symbol.as_str())
        .collect();

    assert_eq!(emitted, vec!["SiblingUploadSubImage", "UploadSubImage"]);
    assert_eq!(suppressed, vec!["GuardedUploadSubImage"]);
    assert!(report.suppressed[0]
        .suppression_reasons
        .contains(&"dominating_size_guard".to_string()));
}

#[test]
fn harvested_siblings_attach_without_reintroducing_suppressed_negative() {
    let file = fixture_path("lifetime-cleanup-negative.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "AsyncCallbackDestroy".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 1,
            },
            SourceMethodFact {
                qualified_name: "ObserverCallbackDestroy".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 2,
                begin_line: 2,
                end_line: 2,
            },
            SourceMethodFact {
                qualified_name: "CleanupReleaseObserver".into(),
                signature_hash: "c".into(),
                file,
                line: 3,
                begin_line: 3,
                end_line: 3,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "AsyncCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "AsyncCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "ObserverCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "ObserverCallbackDestroy",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                "CleanupReleaseObserver",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                "CleanupReleaseObserver",
            ),
            fact(
                FamilyPack::LifetimeOwnership,
                "cleanup_only_teardown",
                "CleanupReleaseObserver",
            ),
        ],
        family_scores: BTreeMap::from([("lifetime-ownership".into(), 7usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let mut leads = build_discovery_leads(&fused, &derived, &repo_locality());
    let lead = leads
        .iter_mut()
        .find(|lead| lead.symbol == "AsyncCallbackDestroy")
        .expect("primary lifetime lead");

    populate_harvested_sibling_candidates(
        std::slice::from_mut(lead),
        &fused,
        &derived,
        &repo_locality(),
        5,
    );

    let sibling_symbols: Vec<_> = lead
        .sibling_candidates
        .iter()
        .map(|candidate| candidate.symbol.as_str())
        .collect();
    assert_eq!(sibling_symbols, vec!["ObserverCallbackDestroy"]);
    assert!(lead
        .sibling_candidates
        .iter()
        .all(|candidate| candidate.candidate_status == CandidateStatus::Sibling));
}

#[test]
fn protocol_harvester_emits_real_siblings_and_suppresses_guarded_negative() {
    let file = fixture_path("protocol-guarded-negative.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "MapDestroySequence".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 1,
            },
            SourceMethodFact {
                qualified_name: "DeviceLostAsyncSequence".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 2,
                begin_line: 2,
                end_line: 2,
            },
            SourceMethodFact {
                qualified_name: "GuardedDeviceLossHandler".into(),
                signature_hash: "c".into(),
                file,
                line: 3,
                begin_line: 3,
                end_line: 3,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_protocol_lifecycle_method",
                "MapDestroySequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_ordering_call_present",
                "MapDestroySequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_async_callback_present",
                "MapDestroySequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_protocol_lifecycle_method",
                "DeviceLostAsyncSequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_ordering_call_present",
                "DeviceLostAsyncSequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_async_callback_present",
                "DeviceLostAsyncSequence",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_protocol_lifecycle_method",
                "GuardedDeviceLossHandler",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "gpu_ordering_call_present",
                "GuardedDeviceLossHandler",
            ),
            fact(
                FamilyPack::GpuProtocolLifecycle,
                "explicit_state_guard",
                "GuardedDeviceLossHandler",
            ),
        ],
        family_scores: BTreeMap::from([("gpu-protocol-order-lifecycle".into(), 8usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let report = harvest_family_candidates(
        BugFamily::GpuProtocolOrderLifecycle,
        &fused,
        &derived,
        &repo_locality(),
    );

    let emitted: BTreeSet<_> = report.emitted.iter().map(|c| c.symbol.as_str()).collect();
    let suppressed: Vec<_> = report
        .suppressed
        .iter()
        .map(|c| c.symbol.as_str())
        .collect();

    assert_eq!(
        emitted,
        BTreeSet::from(["DeviceLostAsyncSequence", "MapDestroySequence"])
    );
    assert_eq!(suppressed, vec!["GuardedDeviceLossHandler"]);
    assert!(report.suppressed[0]
        .suppression_reasons
        .contains(&"explicit_state_guard".to_string()));
}

#[test]
fn validation_harvester_emits_real_siblings_and_suppresses_guarded_negative() {
    let file = fixture_path("validation-guarded-negative.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "ValidateRemoteAction".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 1,
            },
            SourceMethodFact {
                qualified_name: "PermissionCheckedMojoDispatch".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 2,
                begin_line: 2,
                end_line: 2,
            },
            SourceMethodFact {
                qualified_name: "GuardedPermissionDispatch".into(),
                signature_hash: "c".into(),
                file,
                line: 3,
                begin_line: 3,
                end_line: 3,
            },
        ],
        calls: Vec::new(),
        adapters: vec!["SyntheticSliceRepair".into()],
        observed: Vec::new(),
        inferred: Vec::new(),
    };
    let derived = DerivedAnalysis {
        facts: vec![
            fact(
                FamilyPack::ValidationPolicy,
                "validation_or_permission_method",
                "ValidateRemoteAction",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "trust_boundary_action_present",
                "ValidateRemoteAction",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "bad_message_path_present",
                "ValidateRemoteAction",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "validation_or_permission_method",
                "PermissionCheckedMojoDispatch",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "trust_boundary_action_present",
                "PermissionCheckedMojoDispatch",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "validation_or_permission_method",
                "GuardedPermissionDispatch",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "trust_boundary_action_present",
                "GuardedPermissionDispatch",
            ),
            fact(
                FamilyPack::ValidationPolicy,
                "dominating_validation_guard",
                "GuardedPermissionDispatch",
            ),
        ],
        family_scores: BTreeMap::from([("validation-policy".into(), 8usize)]),
        observed: Vec::new(),
        inferred: Vec::new(),
    };

    let report = harvest_family_candidates(
        BugFamily::ValidationTrustBoundary,
        &fused,
        &derived,
        &repo_locality(),
    );

    let emitted: BTreeSet<_> = report.emitted.iter().map(|c| c.symbol.as_str()).collect();
    let suppressed: Vec<_> = report
        .suppressed
        .iter()
        .map(|c| c.symbol.as_str())
        .collect();

    assert_eq!(
        emitted,
        BTreeSet::from(["PermissionCheckedMojoDispatch", "ValidateRemoteAction"])
    );
    assert_eq!(suppressed, vec!["GuardedPermissionDispatch"]);
    assert!(report.suppressed[0]
        .suppression_reasons
        .contains(&"dominating_validation_guard".to_string()));
}

fn fact(family_pack: FamilyPack, kind: &str, subject: &str) -> DerivedFact {
    DerivedFact {
        family_pack,
        kind: kind.into(),
        subject: subject.into(),
        source_file: None,
        evidence_basis: EvidenceBasis::ObservedFromAstFacts,
        detail: kind.into(),
    }
}
