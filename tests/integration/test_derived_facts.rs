use fat_query::derived::derive_from_fused_source;
use fat_query::discovery::{build_discovery_leads, BugFamily};
use fat_query::fusion::fuse_source_analysis;
use fat_query::result::{
    EvidenceBasis, SourceAnalysisSummary, SourceBackendKind, SourceCallFact, SourceEvidenceReport,
    SourceMethodFact,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn derived_facts_classify_validation_and_bounds_signals() {
    let file = PathBuf::from("/tmp/service.cpp");
    let summary = SourceAnalysisSummary {
        reports: vec![SourceEvidenceReport {
            adapter_id: "source-clang-facts".into(),
            backend: SourceBackendKind::AstDumpJson,
            backend_version: "test".into(),
            tu_file: file.clone(),
            tu_spec_hash: "tu".into(),
            toolchain_profile_hash: "tool".into(),
            diagnostics: fat_query::result::AdapterDiagnostics {
                visibility: fat_query::result::VisibilityStatus::Present,
                parse: fat_query::result::ParseStatus::Parsed,
                locality: fat_query::result::LocalityStatus::RepoLocal,
                confidence_source: fat_query::result::ConfidenceSource::Direct,
                observed: vec![],
                inferred: vec![],
                adequacy: vec![],
            },
            methods: vec![SourceMethodFact {
                qualified_name: "GoodOverride".into(),
                signature_hash: "sig".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 4,
            }],
            calls: vec![
                SourceCallFact {
                    callee_name: "enforcePermission".into(),
                    enclosing_symbol: "GoodOverride".into(),
                    file: file.clone(),
                    line: 2,
                    basis: EvidenceBasis::ObservedFromAstFacts,
                },
                SourceCallFact {
                    callee_name: "MakeBuffer".into(),
                    enclosing_symbol: "GoodOverride".into(),
                    file,
                    line: 3,
                    basis: EvidenceBasis::ObservedFromAstFacts,
                },
            ],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec![],
                family_pack_hits: vec![],
                penalties: vec![],
                locality_notes: vec![],
            },
        }],
        merged_observed: vec![],
        merged_inferred: vec![],
        cache: None,
        metadata: BTreeMap::new(),
    };

    let fused = fuse_source_analysis(Some(&summary));
    let derived = derive_from_fused_source(&fused);

    assert!(derived.family_scores.contains_key("validation-policy"));
    assert!(derived.family_scores.contains_key("bounds-size-arithmetic"));
}

#[test]
fn derived_facts_classify_generic_lifetime_callback_patterns() {
    let file = PathBuf::from("/tmp/async_owner.cc");
    let summary = SourceAnalysisSummary {
        reports: vec![SourceEvidenceReport {
            adapter_id: "source-slice-repair".into(),
            backend: SourceBackendKind::SyntheticSliceRepair,
            backend_version: "test".into(),
            tu_file: file.clone(),
            tu_spec_hash: "tu".into(),
            toolchain_profile_hash: "tool".into(),
            diagnostics: fat_query::result::AdapterDiagnostics {
                visibility: fat_query::result::VisibilityStatus::Present,
                parse: fat_query::result::ParseStatus::Degraded,
                locality: fat_query::result::LocalityStatus::RepoLocal,
                confidence_source: fat_query::result::ConfidenceSource::Indirect,
                observed: vec![],
                inferred: vec![],
                adequacy: vec![],
            },
            methods: vec![
                SourceMethodFact {
                    qualified_name: "AsyncOwner::RegisterCallback".into(),
                    signature_hash: "sig-start".into(),
                    file: file.clone(),
                    line: 1,
                    begin_line: 1,
                    end_line: 10,
                },
                SourceMethodFact {
                    qualified_name: "AsyncOwner::DestroyPendingOwner".into(),
                    signature_hash: "sig-remove".into(),
                    file: file.clone(),
                    line: 12,
                    begin_line: 12,
                    end_line: 22,
                },
                SourceMethodFact {
                    qualified_name: "AsyncOwner::CancelPendingRequest".into(),
                    signature_hash: "sig-cancel".into(),
                    file: file.clone(),
                    line: 24,
                    begin_line: 24,
                    end_line: 28,
                },
            ],
            calls: vec![
                SourceCallFact {
                    callee_name: "BindOnce".into(),
                    enclosing_symbol: "AsyncOwner::RegisterCallback".into(),
                    file: file.clone(),
                    line: 4,
                    basis: EvidenceBasis::InferredFromRepairedSlice,
                },
                SourceCallFact {
                    callee_name: "ScheduleCompletion".into(),
                    enclosing_symbol: "AsyncOwner::RegisterCallback".into(),
                    file: file.clone(),
                    line: 8,
                    basis: EvidenceBasis::InferredFromRepairedSlice,
                },
                SourceCallFact {
                    callee_name: "PostTask".into(),
                    enclosing_symbol: "AsyncOwner::DestroyPendingOwner".into(),
                    file: file.clone(),
                    line: 15,
                    basis: EvidenceBasis::InferredFromRepairedSlice,
                },
                SourceCallFact {
                    callee_name: "CancelPendingCompletion".into(),
                    enclosing_symbol: "AsyncOwner::CancelPendingRequest".into(),
                    file,
                    line: 26,
                    basis: EvidenceBasis::InferredFromRepairedSlice,
                },
            ],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec![],
                family_pack_hits: vec![],
                penalties: vec![],
                locality_notes: vec![],
            },
        }],
        merged_observed: vec![],
        merged_inferred: vec![],
        cache: None,
        metadata: BTreeMap::new(),
    };

    let fused = fuse_source_analysis(Some(&summary));
    let derived = derive_from_fused_source(&fused);
    let leads = build_discovery_leads(
        &fused,
        &derived,
        &fat_query::result::RollResolution {
            locality: fat_query::result::LocalityStatus::RepoLocal,
            likely_upstream_repo: None,
            vendored_nearby_path: None,
            local_patch_touching_vendored_code: false,
            no_local_vulnerable_source_likely: false,
            allow_vendored_scan: false,
            observed: vec![],
            inferred: vec![],
        },
    );

    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "AsyncOwner::RegisterCallback" && fact.kind == "lifetime_sensitive_method"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "AsyncOwner::RegisterCallback"
            && fact.kind == "callback_or_teardown_call_present"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "AsyncOwner::DestroyPendingOwner"
            && fact.kind == "callback_or_teardown_call_present"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "AsyncOwner::CancelPendingRequest"
            && fact.kind == "callback_or_teardown_call_present"
    }));
    assert!(leads.iter().any(|lead| {
        lead.family == BugFamily::LifetimeReentrancy
            && lead.symbol == "AsyncOwner::RegisterCallback"
    }));
}

#[test]
fn derived_facts_classify_post_handoff_stale_observation_patterns() {
    let file = PathBuf::from("/tmp/binder_like.cc");
    let summary = SourceAnalysisSummary {
        reports: vec![SourceEvidenceReport {
            adapter_id: "source-clang-facts".into(),
            backend: SourceBackendKind::AstDumpJson,
            backend_version: "test".into(),
            tu_file: file.clone(),
            tu_spec_hash: "tu".into(),
            toolchain_profile_hash: "tool".into(),
            diagnostics: fat_query::result::AdapterDiagnostics {
                visibility: fat_query::result::VisibilityStatus::Present,
                parse: fat_query::result::ParseStatus::Parsed,
                locality: fat_query::result::LocalityStatus::RepoLocal,
                confidence_source: fat_query::result::ConfidenceSource::Direct,
                observed: vec![],
                inferred: vec![],
                adequacy: vec![],
            },
            methods: vec![SourceMethodFact {
                qualified_name: "KernelTxn::SendPendingReport".into(),
                signature_hash: "sig".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 8,
            }],
            calls: vec![
                SourceCallFact {
                    callee_name: "EnqueueTransaction".into(),
                    enclosing_symbol: "KernelTxn::SendPendingReport".into(),
                    file: file.clone(),
                    line: 2,
                    basis: EvidenceBasis::ObservedFromAstFacts,
                },
                SourceCallFact {
                    callee_name: "MarkPendingFrozen".into(),
                    enclosing_symbol: "KernelTxn::SendPendingReport".into(),
                    file: file.clone(),
                    line: 3,
                    basis: EvidenceBasis::ObservedFromAstFacts,
                },
                SourceCallFact {
                    callee_name: "ReportTransaction".into(),
                    enclosing_symbol: "KernelTxn::SendPendingReport".into(),
                    file,
                    line: 4,
                    basis: EvidenceBasis::ObservedFromAstFacts,
                },
            ],
            score_trace: fat_query::result::ScoreTrace {
                adapters: vec![],
                family_pack_hits: vec![],
                penalties: vec![],
                locality_notes: vec![],
            },
        }],
        merged_observed: vec![],
        merged_inferred: vec![],
        cache: None,
        metadata: BTreeMap::new(),
    };

    let fused = fuse_source_analysis(Some(&summary));
    let derived = derive_from_fused_source(&fused);

    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "KernelTxn::SendPendingReport"
            && fact.kind == "ownership_transfer_call_present"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "KernelTxn::SendPendingReport"
            && fact.kind == "deferred_or_pending_state_present"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "KernelTxn::SendPendingReport"
            && fact.kind == "post_handoff_observer_present"
    }));
    assert!(derived.facts.iter().any(|fact| {
        fact.subject == "KernelTxn::SendPendingReport" && fact.kind == "stale_subject_reuse_risk"
    }));
}
