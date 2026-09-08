use std::process::Command;

use fat_query::discovery::{
    AnalysisScope, BugFamily, CandidateStatus, DiscoveryLead, ForbiddenTransitionRef, ProofSignal,
    RequiredEnvironment, StateHypothesis, TriggerRecipeStep,
};
use fat_query::result::{EvidenceBasis, LocalityStatus, ScoreTrace};
use fat_query::target_lanes::TARGET_LANE_SCHEMA_VERSION;
use serde_json::json;
use tempfile::tempdir;

fn hypothesis(
    lead_id: &str,
    machine_id: &str,
    transition_id: &str,
    expected_proof_class: &str,
    actors: &[&str],
) -> StateHypothesis {
    StateHypothesis {
        hypothesis_id: format!("{lead_id}::h0"),
        machine_id: machine_id.into(),
        actors: actors.iter().map(|value| value.to_string()).collect(),
        active_regions: vec!["default".into()],
        key_states: vec!["Pending".into(), "Invalidated".into()],
        ghost_states: vec!["FixtureState".into()],
        invalidating_events: vec![transition_id.into()],
        required_guards: vec!["fixture-guard".into()],
        forbidden_transitions: vec![ForbiddenTransitionRef {
            transition_id: transition_id.into(),
            expected_proof_class: expected_proof_class.into(),
            rationale: vec!["fixture rationale".into()],
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
) -> DiscoveryLead {
    lead_with_status(
        lead_id,
        symbol,
        family,
        locality,
        transition_id,
        expected_proof_class,
        actors,
        CandidateStatus::Primary,
    )
}

fn lead_with_status(
    lead_id: &str,
    symbol: &str,
    family: BugFamily,
    locality: LocalityStatus,
    transition_id: &str,
    expected_proof_class: &str,
    actors: &[&str],
    candidate_status: CandidateStatus,
) -> DiscoveryLead {
    DiscoveryLead {
        lead_id: lead_id.into(),
        symbol: symbol.into(),
        family: family.clone(),
        family_confidence: 0.92,
        family_pack_version: "hsm-cli-fixture".into(),
        analysis_scope: AnalysisScope::WholeTu,
        candidate_status,
        matched_roles: Vec::new(),
        why_matched: vec!["cli fixture".into()],
        evidence_basis: vec![EvidenceBasis::ObservedFromAstFacts],
        locality: locality.clone(),
        sibling_candidates: Vec::new(),
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: transition_id.into(),
            detail: "cli fixture trigger".into(),
        }],
        required_environment: RequiredEnvironment {
            execution_mode: "test".into(),
            platform_constraints: vec!["asan".into()],
        },
        expected_proof_signal: vec![ProofSignal {
            kind: expected_proof_class.into(),
            detail: "cli fixture proof".into(),
        }],
        state_hypotheses: vec![hypothesis(
            lead_id,
            family.as_str(),
            transition_id,
            expected_proof_class,
            actors,
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
        ),
        lead(
            "lead-protocol",
            "MapDestroySequence",
            BugFamily::GpuProtocolOrderLifecycle,
            LocalityStatus::RepoLocal,
            "destroy-device-before-completion",
            "guard-trip",
            &["Device", "Mapping"],
        ),
        lead(
            "lead-size",
            "UploadSubImage",
            BugFamily::SizeStrideArithmetic,
            LocalityStatus::RepoLocal,
            "copy-size-exceeds-allocation",
            "asan-heap-buffer-overflow",
            &["Buffer", "Copy"],
        ),
        lead(
            "lead-validation",
            "ValidateRemoteAction",
            BugFamily::ValidationTrustBoundary,
            LocalityStatus::RepoLocal,
            "use-before-validation",
            "bad-message",
            &["Input", "Validator"],
        ),
    ]
}

fn write_lane_manifest(path: &std::path::Path, family: &str, source_root: &std::path::Path) {
    let build_dir = path.parent().expect("parent").join("build");
    let artifact_dir = path.parent().expect("parent").join("artifacts");
    std::fs::create_dir_all(&build_dir).expect("build dir");
    std::fs::create_dir_all(&artifact_dir).expect("artifact dir");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": TARGET_LANE_SCHEMA_VERSION,
            "lanes": [{
                "lane_id": format!("{family}-lane"),
                "family_allowlist": [family],
                "source_root": source_root,
                "build_dir": build_dir,
                "binary_or_driver": "/bin/true",
                "launcher_command": ["/bin/true"],
                "required_env": { "TEST_MODE": "fixture" },
                "timeout_ms": 1000,
                "artifact_dir": artifact_dir,
                "sanitizer_mode": "asan",
                "proof_class_allowlist": ["asan-heap-buffer-overflow", "bad-message", "guard-trip"],
                "preflight_checks": [{
                    "check_id": "env",
                    "kind": "env-nonempty",
                    "target": "TEST_MODE",
                    "detail": "fixture env present"
                }]
            }]
        }))
        .expect("manifest json"),
    )
    .expect("write manifest");
}

#[test]
fn hsm_registry_cli_lists_registered_families() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["hsm", "registry"])
        .output()
        .expect("fat hsm registry runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lifetime-reentrancy"), "{stdout}");
    assert!(stdout.contains("gpu-protocol-order-lifecycle"), "{stdout}");
    assert!(stdout.contains("size-stride-arithmetic"), "{stdout}");
    assert!(stdout.contains("validation-trust-boundary"), "{stdout}");
}

#[test]
fn hsm_derive_and_query_cli_render_expected_json() {
    let dir = tempdir().expect("tempdir");
    let leads_file = dir.path().join("leads.json");
    let machines_file = dir.path().join("machines.json");
    std::fs::write(
        &leads_file,
        serde_json::to_vec_pretty(&json!({ "leads": sample_leads() })).expect("json"),
    )
    .expect("write leads");

    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--out-file",
            machines_file.to_str().expect("path"),
            "--json",
        ])
        .output()
        .expect("fat hsm derive runs");
    assert!(derive.status.success(), "{derive:?}");
    let derive_stdout = String::from_utf8_lossy(&derive.stdout);
    assert!(derive_stdout.contains("\"machine_id\": \"lifetime-reentrancy\""));
    assert!(derive_stdout.contains("\"machine_id\": \"gpu-protocol-order-lifecycle\""));
    assert!(derive_stdout.contains("\"machine_id\": \"size-stride-arithmetic\""));
    assert!(derive_stdout.contains("\"machine_id\": \"validation-trust-boundary\""));
    assert!(machines_file.exists(), "expected snapshot file");

    let query = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "query",
            "event-path",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--machine-id",
            "lifetime-reentrancy",
            "--event",
            "DestroyOwner",
            "--json",
        ])
        .output()
        .expect("fat hsm query event-path runs");
    assert!(query.status.success(), "{query:?}");
    let query_stdout = String::from_utf8_lossy(&query.stdout);
    assert!(query_stdout.contains("\"transition_id\": \"destroy-owner-during-callback\""));
    assert!(query_stdout.contains("\"event_id\": \"DestroyOwner\""));

    let size_query = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "query",
            "event-path",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--machine-id",
            "size-stride-arithmetic",
            "--event",
            "CopyWithMismatchedPitch",
            "--json",
        ])
        .output()
        .expect("fat hsm query size event-path runs");
    assert!(size_query.status.success(), "{size_query:?}");
    let size_query_stdout = String::from_utf8_lossy(&size_query.stdout);
    assert!(size_query_stdout.contains("\"transition_id\": \"copy-size-exceeds-allocation\""));

    let persisted_query = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "query",
            "event-path",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--machine-id",
            "size-stride-arithmetic",
            "--event",
            "CopyWithMismatchedPitch",
            "--json",
        ])
        .output()
        .expect("fat hsm query from machines file runs");
    assert!(persisted_query.status.success(), "{persisted_query:?}");
    let persisted_query_stdout = String::from_utf8_lossy(&persisted_query.stdout);
    assert!(persisted_query_stdout.contains("\"transition_id\": \"copy-size-exceeds-allocation\""));

    let ghost_query = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "query",
            "ghost-state",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--machine-id",
            "size-stride-arithmetic",
            "--json",
        ])
        .output()
        .expect("fat hsm query ghost-state runs");
    assert!(ghost_query.status.success(), "{ghost_query:?}");
    let ghost_query_stdout = String::from_utf8_lossy(&ghost_query.stdout);
    assert!(ghost_query_stdout.contains("\"state_id\": \"FixtureState\""));

    let counterfactual_query = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "query",
            "counterfactual",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--machine-id",
            "validation-trust-boundary",
            "--guard",
            "fixture-guard",
            "--json",
        ])
        .output()
        .expect("fat hsm query counterfactual runs");
    assert!(
        counterfactual_query.status.success(),
        "{counterfactual_query:?}"
    );
    let counterfactual_stdout = String::from_utf8_lossy(&counterfactual_query.stdout);
    assert!(counterfactual_stdout.contains("\"transition_id\": \"use-before-validation\""));
}

#[test]
fn hsm_derive_cli_can_analyze_fixture_directly() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/discovery/size-stride");
    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--fixture",
            fixture.to_str().expect("fixture path"),
            "--family",
            "size",
            "--mode",
            "deep",
            "--json",
        ])
        .output()
        .expect("fat hsm derive --fixture runs");

    assert!(derive.status.success(), "{derive:?}");
    let stdout = String::from_utf8_lossy(&derive.stdout);
    assert!(
        stdout.contains("\"machine_id\": \"size-stride-arithmetic\""),
        "{stdout}"
    );
}

#[test]
fn hsm_derive_cli_can_analyze_manifest_directly() {
    let dir = tempdir().expect("tempdir");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/discovery/size-stride");
    let manifest = dir.path().join("lanes.json");
    write_lane_manifest(&manifest, "size-stride-arithmetic", &fixture);

    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--manifest",
            manifest.to_str().expect("manifest"),
            "--family",
            "size",
            "--mode",
            "deep",
            "--json",
        ])
        .output()
        .expect("fat hsm derive --manifest runs");

    assert!(derive.status.success(), "{derive:?}");
    let stdout = String::from_utf8_lossy(&derive.stdout);
    assert!(
        stdout.contains("\"machine_id\": \"size-stride-arithmetic\""),
        "{stdout}"
    );
}

#[test]
fn hsm_plan_cli_emits_persisted_machine_backed_summary() {
    let dir = tempdir().expect("tempdir");
    let leads_file = dir.path().join("leads.json");
    let machines_file = dir.path().join("machines.json");
    let manifest = dir.path().join("lanes.json");
    std::fs::write(
        &leads_file,
        serde_json::to_vec_pretty(&json!({ "leads": sample_leads() })).expect("json"),
    )
    .expect("write leads");
    write_lane_manifest(
        &manifest,
        "validation-trust-boundary",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
    );

    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--out-file",
            machines_file.to_str().expect("path"),
            "--json",
        ])
        .output()
        .expect("fat hsm derive runs");
    assert!(derive.status.success(), "{derive:?}");

    let plan = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "plan",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--manifest",
            manifest.to_str().expect("manifest"),
            "--machine-id",
            "validation-trust-boundary",
            "--transition-id",
            "use-before-validation",
            "--json",
        ])
        .output()
        .expect("fat hsm plan runs");
    assert!(plan.status.success(), "{plan:?}");
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(
        stdout.contains("\"lane_id\": \"validation-trust-boundary-lane\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"transition_id\": \"use-before-validation\""),
        "{stdout}"
    );
}

#[test]
fn hsm_plan_cli_returns_empty_for_unknown_transition_filter() {
    let dir = tempdir().expect("tempdir");
    let leads_file = dir.path().join("leads.json");
    let machines_file = dir.path().join("machines.json");
    let manifest = dir.path().join("lanes.json");
    std::fs::write(
        &leads_file,
        serde_json::to_vec_pretty(&json!({ "leads": sample_leads() })).expect("json"),
    )
    .expect("write leads");
    write_lane_manifest(
        &manifest,
        "size-stride-arithmetic",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
    );

    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--out-file",
            machines_file.to_str().expect("path"),
            "--json",
        ])
        .output()
        .expect("fat hsm derive runs");
    assert!(derive.status.success(), "{derive:?}");

    let plan = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "plan",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--manifest",
            manifest.to_str().expect("manifest"),
            "--machine-id",
            "size-stride-arithmetic",
            "--transition-id",
            "definitely-not-a-real-transition",
            "--json",
        ])
        .output()
        .expect("fat hsm plan runs");
    assert!(plan.status.success(), "{plan:?}");
    let parsed: serde_json::Value = serde_json::from_slice(&plan.stdout).expect("plan json");
    assert_eq!(parsed["plan_count"].as_u64(), Some(0));
    assert!(parsed["records"]
        .as_array()
        .is_some_and(|values| values.is_empty()));
}

#[test]
fn hsm_plan_cli_omits_blocked_by_locality_records() {
    let dir = tempdir().expect("tempdir");
    let leads_file = dir.path().join("leads.json");
    let machines_file = dir.path().join("machines.json");
    let manifest = dir.path().join("lanes.json");
    let blocked_lead = lead_with_status(
        "lead-blocked",
        "AsyncCallbackDestroy",
        BugFamily::LifetimeReentrancy,
        LocalityStatus::RepoLocal,
        "destroy-owner-during-callback",
        "asan-use-after-free",
        &["Owner", "Callback"],
        CandidateStatus::BlockedByLocality,
    );
    std::fs::write(
        &leads_file,
        serde_json::to_vec_pretty(&json!({ "leads": vec![blocked_lead] })).expect("json"),
    )
    .expect("write leads");
    write_lane_manifest(
        &manifest,
        "lifetime-reentrancy",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
    );

    let derive = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "derive",
            "--leads-file",
            leads_file.to_str().expect("path"),
            "--out-file",
            machines_file.to_str().expect("path"),
            "--json",
        ])
        .output()
        .expect("fat hsm derive runs");
    assert!(derive.status.success(), "{derive:?}");

    let plan = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "hsm",
            "plan",
            "--machines-file",
            machines_file.to_str().expect("path"),
            "--manifest",
            manifest.to_str().expect("manifest"),
            "--machine-id",
            "lifetime-reentrancy",
            "--transition-id",
            "destroy-owner-during-callback",
            "--json",
        ])
        .output()
        .expect("fat hsm plan runs");
    assert!(plan.status.success(), "{plan:?}");
    let parsed: serde_json::Value = serde_json::from_slice(&plan.stdout).expect("plan json");
    assert_eq!(parsed["plan_count"].as_u64(), Some(0));
    assert!(parsed["records"]
        .as_array()
        .is_some_and(|values| values.is_empty()));
}
