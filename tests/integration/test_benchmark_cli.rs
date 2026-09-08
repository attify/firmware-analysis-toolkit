use std::path::{Path, PathBuf};
use std::process::Command;

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::benchmark::{
    BenchmarkComparator, BenchmarkOutcomeClass, BenchmarkRunMode, BenchmarkRunRecord,
    BenchmarkStageStatus, BenchmarkTarget, ComparatorKind,
};
use fat_core::debug::{ObservedNetworkEntry, ObservedNetworkSnapshot};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::recipes::RecipeRecord;
use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::runs::{RunOrigin, RunRecord, RunStatus, SubstrateKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};
use fat_core::targets::derive_target_id;
use tempfile::tempdir;

#[test]
fn fat_benchmark_replay_json_includes_discovery_metrics() {
    let manifest = format!(
        "{}/../../tests/fixtures/benchmarks/runtime_replay_manifest.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["benchmark", "replay", "--manifest", &manifest, "--json"])
        .output()
        .expect("fat benchmark replay runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"sibling_top1\""), "{stdout}");
    assert!(stdout.contains("\"lead_queue_rate\""), "{stdout}");
    assert!(stdout.contains("\"harvester_expansion_rate\""), "{stdout}");
    assert!(stdout.contains("\"harness_attempt_validity\""), "{stdout}");
    assert!(stdout.contains("\"proof_yield\""), "{stdout}");
    assert!(stdout.contains("\"family_match_rate\""), "{stdout}");
    assert!(stdout.contains("\"hard_negative_precision\""), "{stdout}");
    assert!(
        stdout.contains("\"vendored_locality_accuracy\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"locality_blocked_correctness\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"trigger_recipe_coverage\""), "{stdout}");
    assert!(
        stdout.contains("\"proof_signal_family_correctness\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"gpu-protocol-order-lifecycle\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"validation-policy\""), "{stdout}");
}

#[test]
fn fat_benchmark_score_persists_a_fat_native_outcome() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_partial_runtime(&project_dir, "smoke-1");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-1",
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("comparator: fat"), "{stdout}");
    assert!(stdout.contains("run mode: fat-native"), "{stdout}");
    assert!(stdout.contains("outcome class: partial"), "{stdout}");

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let runs = store.read_benchmark_runs().expect("benchmark runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].comparator.comparator_id, "fat");
    assert_eq!(runs[0].comparator.run_mode, BenchmarkRunMode::FatNative);
    assert_eq!(runs[0].execution_id, seeded.run_id);

    let outcomes = store.read_benchmark_outcomes().expect("benchmark outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome_class, BenchmarkOutcomeClass::Partial);
}

#[test]
fn fat_benchmark_score_credits_booted_services_unreachable_summary_boundary() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    seed_upstream_observation_runtime(&project_dir, "smoke-upstream-1");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-upstream-1",
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("outcome class: partial"), "{stdout}");

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let outcomes = store.read_benchmark_outcomes().expect("benchmark outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome_class, BenchmarkOutcomeClass::Partial);
    assert_eq!(
        outcomes[0].stage_vector.reachability.status,
        fat_core::benchmark::BenchmarkStageStatus::Partial
    );
}

#[test]
fn fat_benchmark_score_prefers_readiness_report_when_present() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_partial_runtime(&project_dir, "smoke-ready-1");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let readiness = ReadinessReport::new(
        "demo",
        target_id.clone(),
        seeded.session_id.clone(),
        seeded.run_id.clone(),
        vec!["shell-access".to_string(), "http-validation".to_string()],
        vec![
            RuntimeSurfaceRecord::new(
                "demo",
                target_id.clone(),
                seeded.session_id.clone(),
                seeded.run_id.clone(),
                "shell",
                "shell",
                "ssh://127.0.0.1:10022",
                SurfaceReadiness::Ready,
            )
            .with_host("127.0.0.1")
            .with_port(10022)
            .with_uri("ssh://127.0.0.1:10022"),
            RuntimeSurfaceRecord::new(
                "demo",
                target_id,
                seeded.session_id.clone(),
                seeded.run_id.clone(),
                "port-80",
                "service",
                "http://127.0.0.1:80",
                SurfaceReadiness::Validated,
            )
            .with_host("127.0.0.1")
            .with_port(80)
            .with_uri("http://127.0.0.1:80"),
        ],
    )
    .with_summary("launch completed with ready surfaces")
    .with_validated_goals(vec!["http-validation".to_string()]);
    store
        .write_readiness_report(&readiness)
        .expect("readiness report");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-ready-1",
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let outcomes = store.read_benchmark_outcomes().expect("benchmark outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].stage_vector.operator_access.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcomes[0].stage_vector.reachability.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcomes[0].stage_vector.exploit_readiness.status,
        BenchmarkStageStatus::Reached
    );
}

#[test]
fn fat_benchmark_score_prefers_persisted_readiness_report_over_summary_labels() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_partial_runtime(&project_dir, "smoke-ready-1");
    seed_readiness_report(
        &project_dir,
        &seeded.session_id,
        &seeded.run_id,
        "demo",
        "demo.bin",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-ready-1",
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("outcome class: strong"), "{stdout}");
    assert!(
        stdout.contains(
            "stages: intake=reached boot=reached reachability=reached operator-access=reached research-utility=reached exploit-readiness=reached"
        ),
        "{stdout}"
    );

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let outcomes = store.read_benchmark_outcomes().expect("benchmark outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome_class, BenchmarkOutcomeClass::Strong);
    assert_eq!(
        outcomes[0].stage_vector.reachability.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcomes[0].stage_vector.operator_access.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        outcomes[0].stage_vector.exploit_readiness.status,
        BenchmarkStageStatus::Reached
    );
}

#[test]
fn fat_benchmark_score_run_id_selects_the_requested_execution() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_multi_run_runtime(&project_dir, "smoke-1");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-1",
            "--run-id",
            &seeded.first_run_id,
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let runs = store.read_benchmark_runs().expect("benchmark runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].execution_id, seeded.first_run_id);
}

#[test]
fn fat_benchmark_score_run_id_falls_back_when_session_run_ids_are_stale() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_run_without_session_metadata(&project_dir, "smoke-stale");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--run-id",
            &seeded.run_id,
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(output.status.success(), "{output:?}");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let runs = store.read_benchmark_runs().expect("benchmark runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].execution_id, seeded.run_id);
}

#[test]
fn fat_benchmark_import_persists_external_comparator_results() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let report_path = project_dir.join("firmae-run.json");
    std::fs::write(
        &report_path,
        serde_json::json!({
            "comparator_id": "firmae",
            "run_mode": "raw-upstream",
            "host_profile": "apple-silicon-laptop",
            "outcome_class": "partial",
            "evidence_grade": "moderate",
            "stage_vector": {
                "intake": { "status": "reached" },
                "boot": { "status": "reached" },
                "reachability": { "status": "partial" },
                "operator_access": { "status": "not-reached" },
                "research_utility": { "status": "reached" },
                "exploit_readiness": { "status": "not-reached" }
            }
        })
        .to_string(),
    )
    .expect("report fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "import",
            "--project",
            project_dir.to_str().expect("project path"),
            "--report",
            report_path.to_str().expect("report path"),
        ])
        .output()
        .expect("fat benchmark import runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("comparator: firmae"), "{stdout}");
    assert!(stdout.contains("run mode: raw-upstream"), "{stdout}");
    assert!(stdout.contains("outcome class: partial"), "{stdout}");

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let runs = store.read_benchmark_runs().expect("benchmark runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].comparator.comparator_id, "firmae");
    assert_eq!(runs[0].comparator.run_mode, BenchmarkRunMode::RawUpstream);

    let outcomes = store.read_benchmark_outcomes().expect("benchmark outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome_class, BenchmarkOutcomeClass::Partial);
}

#[test]
fn fat_benchmark_report_surfaces_a_validated_comparator_tuned_example() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_named_project(
        projects_dir.path(),
        "demo-camera-v1",
        "demo-camera-v1-1.3.8.bin.dec",
        "arch:mipsel\nfs:squashfs\nweb:cgi\n",
    );
    seed_partial_runtime_for(
        &project_dir,
        "comparator-example-1",
        "demo-camera-v1",
        "demo-camera-v1-1.3.8.bin.dec",
    );

    let score_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "comparator-example-1",
        ])
        .output()
        .expect("fat benchmark score runs");
    assert!(score_output.status.success(), "{score_output:?}");

    let report_path = project_dir.join("comparator-validated.json");
    std::fs::copy(
        fixture_path("comparator-tuned-partial-outcome.json"),
        &report_path,
    )
    .expect("report fixture");
    let import_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "import",
            "--project",
            project_dir.to_str().expect("project path"),
            "--report",
            report_path.to_str().expect("report path"),
        ])
        .output()
        .expect("fat benchmark import runs");
    assert!(import_output.status.success(), "{import_output:?}");

    let report_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "report",
            "--project",
            project_dir.to_str().expect("project path"),
            "--json",
        ])
        .output()
        .expect("fat benchmark report runs");
    assert!(report_output.status.success(), "{report_output:?}");

    let report: serde_json::Value =
        serde_json::from_slice(&report_output.stdout).expect("report json");
    let targets = report
        .get("targets")
        .and_then(|value| value.as_array())
        .expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]
            .get("display_name")
            .and_then(|value| value.as_str()),
        Some("demo-camera-v1")
    );

    let rows = targets[0]
        .get("comparisons")
        .and_then(|value| value.as_array())
        .expect("comparisons array");
    assert!(rows.iter().any(|row| {
        row.get("comparator_id").and_then(|value| value.as_str()) == Some("fat")
            && row.get("run_mode").and_then(|value| value.as_str()) == Some("fat-native")
    }));
    assert!(rows.iter().any(|row| {
        row.get("comparator_id").and_then(|value| value.as_str()) == Some("firmae")
            && row.get("run_mode").and_then(|value| value.as_str()) == Some("comparator-tuned")
            && row.get("outcome_class").and_then(|value| value.as_str()) == Some("partial")
            && row
                .get("host_profile")
                .and_then(|value| value.as_str())
                == Some("native-arm64-docker-desktop")
            && row
                .get("evidence_grade")
                .and_then(|value| value.as_str())
                == Some("moderate")
            && row
                .get("stage_summary")
                .and_then(|value| value.as_str())
                == Some(
                    "intake=reached boot=reached reachability=partial operator-access=not-reached research-utility=reached exploit-readiness=not-reached"
                )
            && row
                .get("stage_vector")
                .and_then(|value| value.get("boot"))
                .and_then(|value| value.as_str())
                == Some("reached")
            && row
                .get("stage_vector")
                .and_then(|value| value.get("reachability"))
                .and_then(|value| value.as_str())
                == Some("partial")
            && row
                .get("stage_vector")
                .and_then(|value| value.get("operator_access"))
                .and_then(|value| value.as_str())
                == Some("not-reached")
            && row
                .get("stage_vector")
                .and_then(|value| value.get("research_utility"))
                .and_then(|value| value.as_str())
                == Some("reached")
    }));
}

#[test]
fn fat_benchmark_replay_reports_family_and_variant_metrics() {
    let manifest = fixture_path("benchmarks/runtime_replay_manifest.json");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "replay",
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("fat benchmark replay runs");

    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("benchmark replay json");
    assert_eq!(
        report.get("family").and_then(|value| value.as_str()),
        Some("fat-replay-family-architecture")
    );
    assert_eq!(
        report
            .get("cases")
            .and_then(|value| value.as_array())
            .map(|cases| cases.len()),
        Some(12)
    );
    assert!(
        report
            .get("metrics")
            .and_then(|value| value.get("variant_top3"))
            .and_then(|value| value.as_f64())
            .expect("variant_top3")
            > 0.0
    );
    assert!(
        report
            .get("metrics")
            .and_then(|value| value.get("variant_top1"))
            .and_then(|value| value.as_f64())
            .expect("variant_top1")
            > 0.0
    );
    assert!(report
        .get("family_metrics")
        .and_then(|value| value.get("gpu-protocol-order-lifecycle"))
        .is_some());
    assert!(report
        .get("family_metrics")
        .and_then(|value| value.get("validation-policy"))
        .is_some());
    assert!(
        report
            .get("family_metrics")
            .and_then(|value| value.get("lifetime-ownership"))
            .and_then(|value| value.get("positive_cases"))
            .and_then(|value| value.as_u64())
            .expect("lifetime positive_cases")
            >= 1
    );
    assert!(
        report
            .get("family_metrics")
            .and_then(|value| value.get("dependency-roll-upstream-hidden"))
            .and_then(|value| value.get("positive_cases"))
            .and_then(|value| value.as_u64())
            .expect("dependency roll positive_cases")
            == 2
    );
    assert_eq!(
        report
            .get("family_metrics")
            .and_then(|value| value.get("dependency-roll-upstream-hidden"))
            .and_then(|value| value.get("negative_cases"))
            .and_then(|value| value.as_u64())
            .expect("dependency roll negative_cases"),
        1
    );
    assert!(
        report
            .get("family_metrics")
            .and_then(|value| value.get("validation-policy"))
            .and_then(|value| value.get("replay_top3"))
            .and_then(|value| value.as_f64())
            .expect("validation replay_top3")
            >= 1.0
    );
    assert!(
        report
            .get("ablations")
            .and_then(|value| value.get("vendored_expansion"))
            .and_then(|value| value.get("top1"))
            .and_then(|value| value.as_f64())
            .expect("vendored expansion top1")
            > 0.0
    );
    let cases = report
        .get("cases")
        .and_then(|value| value.as_array())
        .expect("cases array");
    let vendored_case = cases
        .iter()
        .find(|case| {
            case.get("id").and_then(|value| value.as_str())
                == Some("dependency-roll-vendored-positive")
        })
        .expect("vendored roll case");
    assert_eq!(
        vendored_case
            .get("locality")
            .and_then(|value| value.as_str()),
        Some("VendoredLocal")
    );
    assert_eq!(
        vendored_case
            .get("allow_vendored_scan")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let upstream_hidden_case = cases
        .iter()
        .find(|case| {
            case.get("id").and_then(|value| value.as_str())
                == Some("dependency-roll-upstream-hidden-positive")
        })
        .expect("upstream-hidden roll case");
    assert_eq!(
        upstream_hidden_case
            .get("locality")
            .and_then(|value| value.as_str()),
        Some("UpstreamHidden")
    );
    assert_eq!(
        upstream_hidden_case
            .get("allow_vendored_scan")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
}

#[test]
fn fat_benchmark_report_joins_targets_runs_and_outcomes() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    seed_partial_runtime(&project_dir, "smoke-1");

    let score_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-1",
        ])
        .output()
        .expect("fat benchmark score runs");
    assert!(score_output.status.success(), "{score_output:?}");

    let report_path = project_dir.join("penguin-run.json");
    std::fs::write(
        &report_path,
        serde_json::json!({
            "comparator_id": "penguin",
            "run_mode": "raw-upstream",
            "host_profile": "lab-host",
            "outcome_class": "failed",
            "evidence_grade": "minimal",
            "stage_vector": {
                "intake": { "status": "reached" },
                "boot": { "status": "not-reached" },
                "reachability": { "status": "not-reached" },
                "operator_access": { "status": "not-reached" },
                "research_utility": { "status": "not-reached" },
                "exploit_readiness": { "status": "not-reached" }
            }
        })
        .to_string(),
    )
    .expect("report fixture");
    let import_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "import",
            "--project",
            project_dir.to_str().expect("project path"),
            "--report",
            report_path.to_str().expect("report path"),
        ])
        .output()
        .expect("fat benchmark import runs");
    assert!(import_output.status.success(), "{import_output:?}");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "report",
            "--project",
            project_dir.to_str().expect("project path"),
            "--json",
        ])
        .output()
        .expect("fat benchmark report runs");

    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report json");
    let targets = report
        .get("targets")
        .and_then(|value| value.as_array())
        .expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]
            .get("display_name")
            .and_then(|value| value.as_str()),
        Some("demo")
    );
    assert_eq!(
        targets[0]
            .get("architecture")
            .and_then(|value| value.as_str()),
        Some("armel")
    );
    assert_eq!(
        targets[0].get("packaging").and_then(|value| value.as_str()),
        Some("vendor-firmware-blob")
    );

    let rows = targets[0]
        .get("comparisons")
        .and_then(|value| value.as_array())
        .expect("comparisons array");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| {
        row.get("comparator_id").and_then(|value| value.as_str()) == Some("fat")
            && row.get("run_mode").and_then(|value| value.as_str()) == Some("fat-native")
            && row.get("outcome_class").and_then(|value| value.as_str()) == Some("partial")
            && row
                .get("stage_summary")
                .and_then(|value| value.as_str())
                == Some(
                    "intake=reached boot=reached reachability=partial operator-access=not-reached research-utility=reached exploit-readiness=not-reached"
                )
            && row
                .get("stage_vector")
                .and_then(|value| value.get("operator_access"))
                .and_then(|value| value.as_str())
                == Some("not-reached")
            && row
                .get("stage_vector")
                .and_then(|value| value.get("research_utility"))
                .and_then(|value| value.as_str())
                == Some("reached")
    }));
    assert!(rows.iter().any(|row| {
        row.get("comparator_id").and_then(|value| value.as_str()) == Some("penguin")
            && row.get("run_mode").and_then(|value| value.as_str()) == Some("raw-upstream")
            && row.get("outcome_class").and_then(|value| value.as_str()) == Some("failed")
            && row
                .get("stage_vector")
                .and_then(|value| value.get("exploit_readiness"))
                .and_then(|value| value.as_str())
                == Some("not-reached")
    }));

    let text_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "report",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat benchmark report text runs");
    assert!(text_output.status.success(), "{text_output:?}");
    let text_stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(text_stdout.contains("target: demo"), "{text_stdout}");
    assert!(text_stdout.contains("architecture: armel"), "{text_stdout}");
    assert!(
        text_stdout.contains("packaging: vendor-firmware-blob"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("comparator: fat [fat-native]"),
        "{text_stdout}"
    );
    assert!(text_stdout.contains("benchmark run: "), "{text_stdout}");
    assert!(
        text_stdout.contains("outcome class: partial"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("evidence grade: moderate"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains(
            "stages: intake=reached boot=reached reachability=partial operator-access=not-reached research-utility=reached exploit-readiness=not-reached"
        ),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains(
            "stages: intake=reached boot=not-reached reachability=not-reached operator-access=not-reached research-utility=not-reached exploit-readiness=not-reached"
        ),
        "{text_stdout}"
    );
}

#[test]
fn fat_benchmark_report_text_disambiguates_duplicate_comparator_rows() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());

    let report_a_path = project_dir.join("penguin-run-a.json");
    std::fs::write(
        &report_a_path,
        serde_json::json!({
            "comparator_id": "penguin",
            "run_mode": "raw-upstream",
            "host_profile": "lab-host-a",
            "outcome_class": "partial",
            "evidence_grade": "moderate",
            "stage_vector": {
                "intake": { "status": "reached" },
                "boot": { "status": "reached" },
                "reachability": { "status": "partial" },
                "operator_access": { "status": "not-reached" },
                "research_utility": { "status": "reached" },
                "exploit_readiness": { "status": "not-reached" }
            }
        })
        .to_string(),
    )
    .expect("report fixture a");
    let report_b_path = project_dir.join("penguin-run-b.json");
    std::fs::write(
        &report_b_path,
        serde_json::json!({
            "comparator_id": "penguin",
            "run_mode": "raw-upstream",
            "host_profile": "lab-host-b",
            "outcome_class": "failed",
            "evidence_grade": "minimal",
            "stage_vector": {
                "intake": { "status": "reached" },
                "boot": { "status": "not-reached" },
                "reachability": { "status": "not-reached" },
                "operator_access": { "status": "not-reached" },
                "research_utility": { "status": "not-reached" },
                "exploit_readiness": { "status": "not-reached" }
            }
        })
        .to_string(),
    )
    .expect("report fixture b");

    for report_path in [&report_a_path, &report_b_path] {
        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .args([
                "benchmark",
                "import",
                "--project",
                project_dir.to_str().expect("project path"),
                "--report",
                report_path.to_str().expect("report path"),
            ])
            .output()
            .expect("fat benchmark import runs");
        assert!(output.status.success(), "{output:?}");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "report",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat benchmark report text runs");

    assert!(output.status.success(), "{output:?}");
    let text_stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        text_stdout
            .matches("comparator: penguin [raw-upstream]")
            .count(),
        2,
        "{text_stdout}"
    );
    assert_eq!(
        text_stdout.matches("benchmark run: ").count(),
        2,
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("host profile: lab-host-a"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("host profile: lab-host-b"),
        "{text_stdout}"
    );
}

#[test]
fn fat_benchmark_report_fails_loudly_when_a_run_has_no_outcome() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");

    store
        .write_benchmark_target(&BenchmarkTarget::new(
            target_id.clone(),
            "demo",
            "armel",
            "vendor-firmware-blob",
        ))
        .expect("benchmark target");
    let run = BenchmarkRunRecord::try_new(
        target_id,
        BenchmarkComparator::new("fat", ComparatorKind::Internal, BenchmarkRunMode::FatNative),
        "local-test-host",
        "run-1",
    )
    .expect("benchmark run");
    store.write_benchmark_run(&run).expect("benchmark run");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "report",
            "--project",
            project_dir.to_str().expect("project path"),
            "--json",
        ])
        .output()
        .expect("fat benchmark report runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing benchmark outcome"),
        "expected missing-outcome error, got:\n{stderr}"
    );
}

#[test]
fn fat_benchmark_score_fails_when_newest_runtime_summary_is_malformed() {
    let projects_dir = tempdir().expect("projects dir");
    let project_dir = create_project(projects_dir.path());
    let seeded = seed_partial_runtime(&project_dir, "smoke-1");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let malformed_path = project_dir
        .join("work")
        .join("managed-runtime-summary-newest.json");
    std::fs::write(&malformed_path, "{not-json").expect("malformed summary");
    let malformed_artifact = ArtifactRecord::new(
        "demo",
        target_id,
        seeded.session_id.clone(),
        seeded.run_id.clone(),
        ArtifactKind::RuntimeState,
        "managed-runtime-summary",
        "fat-cli",
        "benchmark-test",
        "unix-ms:1710000000001",
        malformed_path.to_string_lossy(),
        "application/json",
        std::fs::metadata(&malformed_path)
            .expect("malformed metadata")
            .len(),
        None,
        "integration-test",
        ArtifactRetentionPolicy::Session,
    );
    store.write_artifact(&malformed_artifact).expect("artifact");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "score",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-1",
        ])
        .output()
        .expect("fat benchmark score runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("managed-runtime-summary")
            || stderr.contains("failed to parse managed runtime summary"),
        "expected malformed-summary error, got:\n{stderr}"
    );
}

#[test]
fn fat_benchmark_help_lists_subcommands_and_descriptions() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["benchmark", "--help"])
        .output()
        .expect("fat benchmark --help runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Score, import, and report benchmark data for FAT analyses and emulation"),
        "{stdout}"
    );
    assert!(stdout.contains("score"), "{stdout}");
    assert!(stdout.contains("import"), "{stdout}");
    assert!(stdout.contains("report"), "{stdout}");
}

struct SeededRuntime {
    session_id: String,
    run_id: String,
}

struct MultiRunSeed {
    first_run_id: String,
}

fn create_project(projects_dir: &Path) -> PathBuf {
    create_named_project(
        projects_dir,
        "demo",
        "demo.bin",
        "arch:armel\nfs:squashfs\nweb:cgi\n",
    )
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn create_named_project(
    projects_dir: &Path,
    project_name: &str,
    firmware_name: &str,
    signals: &str,
) -> PathBuf {
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join(firmware_name);
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--name",
            project_name,
            "--projects-dir",
            projects_dir.to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.join(project_name);
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(project_dir.join("analysis").join("signals.txt"), signals)
        .expect("signals file");
    project_dir
}

#[allow(dead_code)]
fn persist_network_snapshot(
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
    project_name: &str,
    firmware_name: &str,
    name: &str,
    host: &str,
    port: u16,
    uri: &str,
) {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id(project_name, firmware_name);
    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    std::fs::create_dir_all(&outputs_dir).expect("outputs dir");
    let snapshot_path = outputs_dir.join("network-snapshot.json");
    let snapshot = ObservedNetworkSnapshot {
        session_id: session_id.to_string(),
        run_id: run_id.to_string(),
        backend_id: "emux".to_string(),
        substrate_kind: SubstrateKind::DockerEngine,
        endpoints: vec![ObservedNetworkEntry::new(
            fat_core::debug::DebugSurfaceKind::Service,
            name,
            host,
            port,
        )
        .with_uri(uri)
        .with_target_port(port)],
    };
    let snapshot_json = serde_json::to_string_pretty(&snapshot).expect("snapshot json");
    std::fs::write(&snapshot_path, snapshot_json.as_bytes()).expect("snapshot file");

    let artifact = ArtifactRecord::new(
        project_name,
        target_id,
        session_id.to_string(),
        run_id.to_string(),
        ArtifactKind::RuntimeCapture,
        "network-snapshot",
        "fat-cli",
        "test-fixture",
        "unix-ms:1710000000600",
        snapshot_path.to_string_lossy().into_owned(),
        "application/json",
        snapshot_json.len() as u64,
        None,
        "integration-test",
        ArtifactRetentionPolicy::Session,
    );
    store.write_artifact(&artifact).expect("artifact");
    store
        .append_artifact_index(&artifact)
        .expect("artifact index");
}

fn seed_partial_runtime(project_dir: &Path, requested_session_id: &str) -> SeededRuntime {
    seed_partial_runtime_for(project_dir, requested_session_id, "demo", "demo.bin")
}

fn seed_upstream_observation_runtime(
    project_dir: &Path,
    requested_session_id: &str,
) -> SeededRuntime {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let created_at = "unix-ms:1710000000200";

    let recipe = RecipeRecord::new(
        target_id.clone(),
        "fat-strategy-v1",
        "benchmark-fat-native",
        "firmae",
        "managed-linux-vm",
    );
    let session = SessionRecord::new(
        "demo",
        target_id.clone(),
        "benchmark-fat-native",
        "managed-linux-vm",
        SessionOrigin::Manual,
        created_at,
    )
    .with_requested_session_id(requested_session_id)
    .with_status(SessionStatus::Active)
    .with_progress(GoalProgress::Partial);
    let run = RunRecord::new(
        session.session_id.clone(),
        recipe.recipe_id.clone(),
        "firmae",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);
    let session = session.with_run_ids(vec![run.run_id.clone()]);

    store.write_session(&session).expect("session");
    store
        .write_recipe(&session.session_id, &recipe)
        .expect("recipe");
    store.write_run(&run).expect("run");

    let observation_path = project_dir
        .join("work")
        .join("firmae-upstream-observation.json");
    std::fs::create_dir_all(observation_path.parent().expect("observation parent"))
        .expect("observation dir");
    let observation_json = serde_json::json!({
        "observation_source": "bounded-live-inspection",
        "observation_timestamp": "unix-ms:1710000000300",
        "container_name": "firmae-upstream-1",
        "container_running": true,
        "scratch_artifacts_present": true,
        "observed_artifact_paths": [
            "/tmp/firmae/scratch/1/qemu.initial.serial.log",
            "/tmp/firmae/scratch/1/qemu.final.serial.log",
            "/tmp/firmae/scratch/1/makeNetwork.log"
        ],
        "guest_ip": "192.168.0.1",
        "guest_reachable": true,
        "port_80_reachable": false,
        "port_31337_reachable": false,
        "port_31338_reachable": false,
        "runtime_status": {
            "backend_id": "firmae",
            "driver_profile": "firmae-managed-legacy-wrapper",
            "control_contract": "firmae-legacy-wrapper-v1",
            "lifecycle_adapter": "legacy-wrapper",
            "phase": "probe-unreachable",
            "runtime_outcome": "booted-services-unreachable",
            "workspace_dir": project_dir.join("work").display().to_string(),
            "services": [],
            "launch_mode": "upstream-launch",
            "stop_mode": "legacy-wrapper-stop",
            "launch_manifest_present": true,
            "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
            "probe_result_contract_verified": true,
            "probe_source": "probe-on-status",
            "probe_outcome": "unreachable"
        }
    });
    std::fs::write(&observation_path, observation_json.to_string()).expect("observation json");
    let observation_artifact = ArtifactRecord::new(
        "demo",
        target_id,
        session.session_id.clone(),
        run.run_id.clone(),
        ArtifactKind::RuntimeState,
        "firmae-upstream-observation",
        "fat-cli",
        "benchmark-test",
        created_at,
        observation_path.to_string_lossy(),
        "application/json",
        std::fs::metadata(&observation_path)
            .expect("observation metadata")
            .len(),
        None,
        "integration-test",
        ArtifactRetentionPolicy::Session,
    );
    store
        .write_artifact(&observation_artifact)
        .expect("artifact");

    SeededRuntime {
        session_id: session.session_id,
        run_id: run.run_id,
    }
}

fn seed_partial_runtime_for(
    project_dir: &Path,
    requested_session_id: &str,
    project_name: &str,
    firmware_name: &str,
) -> SeededRuntime {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id(project_name, firmware_name);
    let created_at = "unix-ms:1710000000000";

    let recipe = RecipeRecord::new(
        target_id.clone(),
        "fat-strategy-v1",
        "benchmark-fat-native",
        "firmae",
        "managed-linux-vm",
    );
    let session = SessionRecord::new(
        project_name,
        target_id.clone(),
        "benchmark-fat-native",
        "managed-linux-vm",
        SessionOrigin::Manual,
        created_at,
    )
    .with_requested_session_id(requested_session_id)
    .with_status(SessionStatus::Active)
    .with_progress(GoalProgress::Partial);
    let run = RunRecord::new(
        session.session_id.clone(),
        recipe.recipe_id.clone(),
        "firmae",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);
    let session = session.with_run_ids(vec![run.run_id.clone()]);

    store.write_session(&session).expect("session");
    store
        .write_recipe(&session.session_id, &recipe)
        .expect("recipe");
    store.write_run(&run).expect("run");

    let summary_path = project_dir
        .join("work")
        .join("managed-runtime-summary.json");
    std::fs::create_dir_all(summary_path.parent().expect("summary parent")).expect("summary dir");
    let summary_json = serde_json::json!({
        "backend_id": "firmae",
        "control_contract": "firmae-legacy-wrapper-v1",
        "driver_profile": "firmae-managed-legacy-wrapper",
        "lifecycle_adapter": "legacy-wrapper",
        "runtime_phase": "probe-unreachable",
        "workspace_dir": project_dir.join("work").display().to_string(),
        "services": [],
        "launch_mode": "legacy-wrapper-launch",
        "stop_mode": "legacy-wrapper-stop",
        "launch_manifest_present": false,
        "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
        "probe_result_contract_verified": true,
        "probe_source": "supervisor",
        "probe_outcome": "unreachable"
    });
    std::fs::write(&summary_path, summary_json.to_string()).expect("summary json");
    let artifact = ArtifactRecord::new(
        project_name,
        target_id,
        session.session_id.clone(),
        run.run_id.clone(),
        ArtifactKind::RuntimeState,
        "managed-runtime-summary",
        "fat-cli",
        "benchmark-test",
        created_at,
        summary_path.to_string_lossy(),
        "application/json",
        std::fs::metadata(&summary_path)
            .expect("summary metadata")
            .len(),
        None,
        "integration-test",
        ArtifactRetentionPolicy::Session,
    );
    store.write_artifact(&artifact).expect("artifact");

    let diagnostic = DiagnosticRecord::new(
        run.run_id.clone(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::Observer,
        DiagnosticClass::GuestUnreachable,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "supervisor could not reach guest services",
        vec![artifact.artifact_id.clone()],
        Vec::new(),
        vec!["retry probe".to_string()],
    );
    store
        .write_diagnostic_for_session(&session.session_id, &diagnostic)
        .expect("diagnostic");

    SeededRuntime {
        session_id: session.session_id,
        run_id: run.run_id,
    }
}

fn seed_readiness_report(
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
    project_name: &str,
    firmware_name: &str,
) {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id(project_name, firmware_name);
    let shell = RuntimeSurfaceRecord::new(
        project_name,
        &target_id,
        session_id,
        run_id,
        "shell",
        "shell",
        "ssh://127.0.0.1:10022",
        SurfaceReadiness::Ready,
    )
    .with_host("127.0.0.1")
    .with_port(10022)
    .with_uri("ssh://127.0.0.1:10022");
    let service = RuntimeSurfaceRecord::new(
        project_name,
        &target_id,
        session_id,
        run_id,
        "uhttpd",
        "service",
        "http://127.0.0.1:80",
        SurfaceReadiness::Validated,
    )
    .with_host("127.0.0.1")
    .with_port(80)
    .with_uri("http://127.0.0.1:80");
    let port_forward = RuntimeSurfaceRecord::new(
        project_name,
        &target_id,
        session_id,
        run_id,
        "http-forward",
        "port-forward",
        "tcp://127.0.0.1:8080",
        SurfaceReadiness::Ready,
    )
    .with_host("127.0.0.1")
    .with_port(8080)
    .with_uri("tcp://127.0.0.1:8080");
    let readiness = ReadinessReport::new(
        project_name,
        &target_id,
        session_id,
        run_id,
        vec![
            "shell-access".to_string(),
            "http-reachability".to_string(),
            "http-validation".to_string(),
        ],
        vec![shell, service, port_forward],
    )
    .with_summary("shell, service, and port-forward surfaces validated")
    .with_validated_goals(vec![
        "shell-access".to_string(),
        "http-validation".to_string(),
    ]);

    store
        .write_readiness_report(&readiness)
        .expect("readiness report");
}

fn seed_multi_run_runtime(project_dir: &Path, requested_session_id: &str) -> MultiRunSeed {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let recipe = RecipeRecord::new(
        target_id.clone(),
        "fat-strategy-v1",
        "benchmark-fat-native",
        "firmae",
        "managed-linux-vm",
    );
    let session = SessionRecord::new(
        "demo",
        target_id.clone(),
        "benchmark-fat-native",
        "managed-linux-vm",
        SessionOrigin::Manual,
        "unix-ms:1710000000000",
    )
    .with_requested_session_id(requested_session_id)
    .with_status(SessionStatus::Active)
    .with_progress(GoalProgress::Partial);
    let first_run = RunRecord::new(
        session.session_id.clone(),
        recipe.recipe_id.clone(),
        "firmae",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);
    let second_run = RunRecord::new(
        session.session_id.clone(),
        recipe.recipe_id.clone(),
        "firmae",
        SubstrateKind::ManagedLinuxVm,
        2,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);
    let session = session.with_run_ids(vec![first_run.run_id.clone(), second_run.run_id.clone()]);

    store.write_session(&session).expect("session");
    store
        .write_recipe(&session.session_id, &recipe)
        .expect("recipe");
    store.write_run(&first_run).expect("first run");
    store.write_run(&second_run).expect("second run");

    write_runtime_summary_artifact(
        project_dir,
        &store,
        &target_id,
        &session.session_id,
        &first_run.run_id,
        "managed-runtime-summary-first.json",
        "unix-ms:1710000000000",
        "probe-unreachable",
    );
    write_runtime_summary_artifact(
        project_dir,
        &store,
        &target_id,
        &session.session_id,
        &second_run.run_id,
        "managed-runtime-summary-second.json",
        "unix-ms:1710000000001",
        "probe-unreachable",
    );

    let diagnostic = DiagnosticRecord::new(
        first_run.run_id.clone(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::Observer,
        DiagnosticClass::GuestUnreachable,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "supervisor could not reach guest services",
        Vec::new(),
        Vec::new(),
        vec!["retry probe".to_string()],
    );
    store
        .write_diagnostic_for_session(&session.session_id, &diagnostic)
        .expect("diagnostic");

    MultiRunSeed {
        first_run_id: first_run.run_id,
    }
}

fn seed_run_without_session_metadata(
    project_dir: &Path,
    requested_session_id: &str,
) -> SeededRuntime {
    let store = RuntimeStore::open(project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    let created_at = "unix-ms:1710000000100";
    let recipe = RecipeRecord::new(
        target_id.clone(),
        "fat-strategy-v1",
        "benchmark-fat-native",
        "firmae",
        "managed-linux-vm",
    );
    let session = SessionRecord::new(
        "demo",
        target_id.clone(),
        "benchmark-fat-native",
        "managed-linux-vm",
        SessionOrigin::Manual,
        created_at,
    )
    .with_requested_session_id(requested_session_id)
    .with_status(SessionStatus::Active)
    .with_progress(GoalProgress::Partial);
    let run = RunRecord::new(
        session.session_id.clone(),
        recipe.recipe_id.clone(),
        "firmae",
        SubstrateKind::ManagedLinuxVm,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running);

    store.write_session(&session).expect("session");
    store
        .write_recipe(&session.session_id, &recipe)
        .expect("recipe");
    store.write_run(&run).expect("run");
    let artifact = write_runtime_summary_artifact(
        project_dir,
        &store,
        &target_id,
        &session.session_id,
        &run.run_id,
        "managed-runtime-summary-stale-metadata.json",
        created_at,
        "probe-unreachable",
    );
    let diagnostic = DiagnosticRecord::new(
        run.run_id.clone(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::Observer,
        DiagnosticClass::GuestUnreachable,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "supervisor could not reach guest services",
        vec![artifact.artifact_id.clone()],
        Vec::new(),
        vec!["retry probe".to_string()],
    );
    store
        .write_diagnostic_for_session(&session.session_id, &diagnostic)
        .expect("diagnostic");

    SeededRuntime {
        session_id: session.session_id,
        run_id: run.run_id,
    }
}

fn write_runtime_summary_artifact(
    project_dir: &Path,
    store: &RuntimeStore,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    file_name: &str,
    created_at: &str,
    runtime_phase: &str,
) -> ArtifactRecord {
    let summary_path = project_dir.join("work").join(file_name);
    std::fs::create_dir_all(summary_path.parent().expect("summary parent")).expect("summary dir");
    let summary_json = serde_json::json!({
        "backend_id": "firmae",
        "control_contract": "firmae-legacy-wrapper-v1",
        "driver_profile": "firmae-managed-legacy-wrapper",
        "lifecycle_adapter": "legacy-wrapper",
        "runtime_phase": runtime_phase,
        "workspace_dir": project_dir.join("work").display().to_string(),
        "services": [],
        "launch_mode": "legacy-wrapper-launch",
        "stop_mode": "legacy-wrapper-stop",
        "launch_manifest_present": false,
        "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
        "probe_result_contract_verified": true,
        "probe_source": "supervisor",
        "probe_outcome": "unreachable"
    });
    std::fs::write(&summary_path, summary_json.to_string()).expect("summary json");
    let artifact = ArtifactRecord::new(
        "demo",
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        ArtifactKind::RuntimeState,
        "managed-runtime-summary",
        "fat-cli",
        "benchmark-test",
        created_at.to_string(),
        summary_path.to_string_lossy(),
        "application/json",
        std::fs::metadata(&summary_path)
            .expect("summary metadata")
            .len(),
        None,
        "integration-test",
        ArtifactRetentionPolicy::Session,
    );
    store.write_artifact(&artifact).expect("artifact");
    artifact
}
