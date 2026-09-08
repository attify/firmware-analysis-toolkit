use fat_query::result::{
    DerivedAnalysis, DerivedFact, EvidenceBasis, FamilyPack, FusedSourceEvidence, ReplayAnalysis,
    ReplayCandidate, ReplayRole, SourceCallFact, SourceMethodFact,
};
use fat_query::roll_resolver::resolve_roll_locality;
use fat_query::variant_hunter::hunt_variants;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn roll_resolver_marks_repo_local_when_no_roll_signals_exist() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("patch.diff"), "diff --git a/a.cc b/a.cc\n").expect("patch");

    let resolution = resolve_roll_locality(dir.path()).expect("resolve roll locality");

    assert_eq!(
        resolution.locality,
        fat_query::result::LocalityStatus::RepoLocal
    );
    assert!(!resolution.allow_vendored_scan);
}

#[test]
fn roll_resolver_loads_explicit_roll_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("third_party/libdemo")).expect("vendored dir");
    std::fs::write(
        dir.path().join("fat-roll-metadata.json"),
        r#"{
  "likely_upstream_repo": "https://example.invalid/upstream.git",
  "vendored_nearby_path": "third_party/libdemo",
  "local_patch_touching_vendored_code": true
}"#,
    )
    .expect("metadata");

    let resolution = resolve_roll_locality(dir.path()).expect("resolve roll locality");

    assert_eq!(
        resolution.locality,
        fat_query::result::LocalityStatus::VendoredLocal
    );
    assert!(resolution.allow_vendored_scan);
    assert_eq!(
        resolution.likely_upstream_repo.as_deref(),
        Some("https://example.invalid/upstream.git")
    );
}

#[test]
fn vendored_locality_allows_variant_hunter_to_emit_vendored_neighbor() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("third_party/libdemo")).expect("vendored dir");
    std::fs::write(
        dir.path().join("fat-roll-metadata.json"),
        r#"{
  "likely_upstream_repo": "https://example.invalid/upstream.git",
  "vendored_nearby_path": "third_party/libdemo",
  "local_patch_touching_vendored_code": true
}"#,
    )
    .expect("metadata");

    let locality = resolve_roll_locality(dir.path()).expect("resolve roll locality");
    assert!(locality.allow_vendored_scan);

    let file = PathBuf::from("/tmp/service.cpp");
    let fused = FusedSourceEvidence {
        methods: vec![
            SourceMethodFact {
                qualified_name: "SurfaceSeed".into(),
                signature_hash: "a".into(),
                file: file.clone(),
                line: 1,
                begin_line: 1,
                end_line: 4,
            },
            SourceMethodFact {
                qualified_name: "SurfaceNeighbor".into(),
                signature_hash: "b".into(),
                file: file.clone(),
                line: 6,
                begin_line: 6,
                end_line: 9,
            },
        ],
        calls: vec![SourceCallFact {
            callee_name: "enforcePermission".into(),
            enclosing_symbol: "SurfaceSeed".into(),
            file: file.clone(),
            line: 2,
            basis: EvidenceBasis::ObservedFromAstFacts,
        }],
        adapters: vec!["source-clang-facts:LibclangBackend".into()],
        observed: vec![],
        inferred: vec![],
    };
    let derived = DerivedAnalysis {
        facts: vec![DerivedFact {
            family_pack: FamilyPack::ValidationPolicy,
            kind: "override_permission_site".into(),
            subject: "SurfaceSeed".into(),
            source_file: None,
            evidence_basis: EvidenceBasis::ObservedFromAstFacts,
            detail: "seed".into(),
        }],
        family_scores: BTreeMap::from([("validation-policy".into(), 1usize)]),
        observed: vec![],
        inferred: vec![],
    };
    let replay = ReplayAnalysis {
        reference_symbols: vec!["SurfaceSeed".into()],
        required_roles: vec![ReplayRole::GuardValidation],
        candidates: vec![ReplayCandidate {
            symbol: "SurfaceSeed".into(),
            file: Some(file.clone()),
            score: 30,
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

    let leads = hunt_variants(&replay, &fused, &derived, &locality, &[], 5);
    assert!(leads
        .iter()
        .any(|lead| lead.symbol == "vendored-neighborhood:third_party/libdemo"));
}
