use fat_query::fusion::fuse_source_analysis;
use fat_query::result::{
    AdapterDiagnostics, AdequacyForQuery, AdequacyIntent, AdequacyTier, ConfidenceSource,
    EvidenceBasis, LocalityStatus, ParseStatus, ScoreTrace, SourceAnalysisSummary,
    SourceBackendKind, SourceCallFact, SourceEvidenceReport, SourceMethodFact, VisibilityStatus,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn fusion_prefers_direct_ast_calls_over_repaired_duplicates() {
    let file = PathBuf::from("/tmp/TextureMtl.mm");
    let method = SourceMethodFact {
        qualified_name: "setPerSliceSubImageVariant".into(),
        signature_hash: "sig".into(),
        file: file.clone(),
        line: 10,
        begin_line: 10,
        end_line: 16,
    };
    let repaired_call = SourceCallFact {
        callee_name: "CopyBytes".into(),
        enclosing_symbol: "setPerSliceSubImageVariant".into(),
        file: file.clone(),
        line: 13,
        basis: EvidenceBasis::InferredFromRepairedSlice,
    };
    let direct_call = SourceCallFact {
        basis: EvidenceBasis::ObservedFromAstFacts,
        ..repaired_call.clone()
    };
    let summary = SourceAnalysisSummary {
        reports: vec![
            SourceEvidenceReport {
                adapter_id: "source-clang-facts".into(),
                backend: SourceBackendKind::SyntheticSliceRepair,
                backend_version: "synthetic".into(),
                tu_file: file.clone(),
                tu_spec_hash: "tu".into(),
                toolchain_profile_hash: "toolchain".into(),
                diagnostics: AdapterDiagnostics {
                    visibility: VisibilityStatus::Present,
                    parse: ParseStatus::Degraded,
                    locality: LocalityStatus::RepoLocal,
                    confidence_source: ConfidenceSource::Indirect,
                    observed: vec![],
                    inferred: vec!["repaired".into()],
                    adequacy: vec![AdequacyForQuery {
                        family: "source-visibility".into(),
                        intent: AdequacyIntent::ReplaySiting,
                        tier: AdequacyTier::ReplaySitingAdequate,
                        required_facts_satisfied: vec!["callsites".into()],
                    }],
                },
                methods: vec![method.clone()],
                calls: vec![repaired_call],
                score_trace: ScoreTrace {
                    adapters: vec!["source-clang-facts:SyntheticSliceRepair".into()],
                    family_pack_hits: vec!["source-visibility".into()],
                    penalties: vec!["repaired-slice".into()],
                    locality_notes: vec![],
                },
            },
            SourceEvidenceReport {
                adapter_id: "source-clang-facts".into(),
                backend: SourceBackendKind::LibclangBackend,
                backend_version: "libclang".into(),
                tu_file: file.clone(),
                tu_spec_hash: "tu".into(),
                toolchain_profile_hash: "toolchain".into(),
                diagnostics: AdapterDiagnostics {
                    visibility: VisibilityStatus::Present,
                    parse: ParseStatus::Parsed,
                    locality: LocalityStatus::RepoLocal,
                    confidence_source: ConfidenceSource::Direct,
                    observed: vec!["parsed".into()],
                    inferred: vec![],
                    adequacy: vec![AdequacyForQuery {
                        family: "source-visibility".into(),
                        intent: AdequacyIntent::ReplaySiting,
                        tier: AdequacyTier::ReplaySitingAdequate,
                        required_facts_satisfied: vec!["callsites".into()],
                    }],
                },
                methods: vec![method],
                calls: vec![direct_call],
                score_trace: ScoreTrace {
                    adapters: vec!["source-clang-facts:LibclangBackend".into()],
                    family_pack_hits: vec!["source-visibility".into()],
                    penalties: vec![],
                    locality_notes: vec![],
                },
            },
        ],
        merged_observed: vec![],
        merged_inferred: vec![],
        cache: None,
        metadata: BTreeMap::new(),
    };

    let fused = fuse_source_analysis(Some(&summary));
    let call = fused
        .calls
        .iter()
        .find(|call| call.callee_name == "CopyBytes")
        .expect("fused call");
    assert_eq!(call.basis, EvidenceBasis::ObservedFromAstFacts);
}
