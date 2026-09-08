use std::fs;

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::benchmark::{
    BenchmarkComparator, BenchmarkEvidenceGrade, BenchmarkOutcomeClass, BenchmarkOutcomeRecord,
    BenchmarkRunMode, BenchmarkRunRecord, BenchmarkStageScore, BenchmarkStageStatus,
    BenchmarkStageVector, BenchmarkTarget, ComparatorKind,
};
use fat_core::database::ProjectDb;
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity, TargetDiagnosticRecord,
};
use fat_core::discovery::{
    DiscoveryLeadRecord, DiscoveryLifecycleStatus, DiscoveryOutcomeClass,
    DiscoveryProofSignalRecord, DiscoveryStateHypothesisRecord, DiscoveryTriggerRecipeStepRecord,
    ForbiddenTransitionRecord, HarnessAttemptRecord, HarvesterExpansionRecord, TriageRecord,
};
use fat_core::fingerprint::FirmwareFingerprint;
use fat_core::ids::stable_prefixed_id;
use fat_core::project::{Project, ProjectLayoutMarker, PROJECT_LAYOUT_VERSION};
use fat_core::recipes::{FallbackPolicy, RecipeRecord};
use fat_core::runs::{RunOrigin, RunRecord, RunStatus, SubstrateKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::sessions::{SessionOrigin, SessionRecord, SessionStatus};
use fat_core::targets::TargetArtifactRecord;

fn sample_session() -> SessionRecord {
    SessionRecord::new(
        "project-1",
        "target-1",
        "reach shell",
        "qemu-direct",
        SessionOrigin::Manual,
        "2026-03-27T00:00:00Z",
    )
    .with_status(SessionStatus::Active)
}

fn sample_run(session_id: &str) -> RunRecord {
    RunRecord::new(
        session_id,
        "recipe-1",
        "qemu-direct",
        SubstrateKind::NativeHost,
        1,
        RunOrigin::Manual,
    )
    .with_status(RunStatus::Running)
}

fn sample_artifact(session_id: &str, run_id: &str) -> ArtifactRecord {
    ArtifactRecord::new(
        "project-1",
        "target-1",
        session_id,
        run_id,
        ArtifactKind::RuntimeLog,
        "console",
        "backend-driver",
        "driver-1",
        "2026-03-27T00:01:00Z",
        "runs/run-1/logs/console.txt",
        "text/plain",
        120,
        None,
        "run-scoped evidence",
        ArtifactRetentionPolicy::Session,
    )
}

fn sample_recipe() -> RecipeRecord {
    RecipeRecord::new(
        "target-1",
        "slice-1",
        "reach shell",
        "qemu-direct",
        "native-host",
    )
    .with_launch_parameters(vec!["backend=qemu-direct".to_string()])
    .with_fallback_policy(FallbackPolicy::RetryWithFallback)
}

fn sample_diagnostic(run_id: &str, artifact_id: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id,
        DiagnosticPhase::Boot,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some("qemu-exit".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        "boot exited before userspace",
        vec![artifact_id.to_string()],
        vec![],
        vec!["retry with alternate substrate".to_string()],
    )
}

fn sample_benchmark_target() -> BenchmarkTarget {
    BenchmarkTarget::new(
        "target-demo-camera-v1",
        "Demo Camera v1",
        "mipsel",
        "vendor-firmware-blob",
    )
}

fn sample_benchmark_run(target_id: &str, execution_id: &str) -> BenchmarkRunRecord {
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    BenchmarkRunRecord::try_new(target_id, comparator, "apple-silicon-laptop", execution_id)
        .unwrap()
}

fn sample_benchmark_outcome(run_id: &str) -> BenchmarkOutcomeRecord {
    BenchmarkOutcomeRecord::new(
        run_id,
        BenchmarkOutcomeClass::Partial,
        BenchmarkEvidenceGrade::Moderate,
        BenchmarkStageVector {
            intake: BenchmarkStageScore::reached(),
            boot: BenchmarkStageScore::reached(),
            reachability: BenchmarkStageScore::partial(),
            operator_access: BenchmarkStageScore::not_reached(),
            research_utility: BenchmarkStageScore::reached(),
            exploit_readiness: BenchmarkStageScore::not_reached(),
        },
    )
}

fn write_legacy_benchmark_outcome(
    store: &RuntimeStore,
    legacy_benchmark_run_id: &str,
) -> std::io::Result<()> {
    fs::write(
        store.benchmark_outcome_path(legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "outcome_class": "partial",
  "evidence_grade": "moderate",
  "stage_vector": {{
    "intake": {{ "status": "reached" }},
    "boot": {{ "status": "reached" }},
    "reachability": {{ "status": "partial" }},
    "operator_access": {{ "status": "not-reached" }},
    "research_utility": {{ "status": "reached" }},
    "exploit_readiness": {{ "status": "not-reached" }}
  }}
}}"#
        ),
    )
}

#[test]
fn project_db_initializes_a_deterministic_runtime_layout() {
    let dir = tempfile::tempdir().unwrap();
    let db = ProjectDb::open(dir.path()).unwrap();

    let project_dir = dir.path();
    assert!(project_dir.join("project.json").exists());
    assert!(project_dir.join("targets").is_dir());
    assert!(project_dir.join("sessions").is_dir());
    assert!(project_dir.join("index").is_dir());

    let marker: ProjectLayoutMarker =
        serde_json::from_str(&fs::read_to_string(project_dir.join("project.json")).unwrap())
            .unwrap();
    assert_eq!(marker.layout_version, PROJECT_LAYOUT_VERSION);

    let project = Project {
        name: "demo".to_string(),
        firmware_name: "firmware.bin".to_string(),
        status: fat_core::project::ProjectStatus::Created,
        fingerprint: Some(FirmwareFingerprint::new("a".repeat(64), 42)),
    };
    db.save(&project).unwrap();
    assert!(db.get("demo").unwrap().is_some());
}

#[test]
fn project_db_open_surfaces_layout_version_errors_honestly() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("project.json"), r#"{"layout_version":99}"#).unwrap();

    let err = ProjectDb::open(dir.path()).unwrap_err();
    match err {
        fat_core::database::ProjectDbError::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
            assert!(io_err
                .to_string()
                .contains("unsupported project layout version"));
        }
        other => panic!("expected io layout error, got {other:?}"),
    }
}

#[test]
fn session_run_artifact_and_diagnostic_records_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();

    let session = sample_session();
    let run = sample_run(&session.session_id);
    let recipe = sample_recipe();
    let artifact = sample_artifact(&session.session_id, &run.run_id);
    let diagnostic = sample_diagnostic(&run.run_id, &artifact.artifact_id);

    store.write_session(&session).unwrap();
    store.write_run(&run).unwrap();
    store.write_recipe(&session.session_id, &recipe).unwrap();
    store.write_artifact(&artifact).unwrap();
    store
        .write_diagnostic(&session.session_id, &diagnostic)
        .unwrap();

    assert!(store
        .session_path(&session.session_id)
        .ends_with("session.json"));
    assert_eq!(
        store.session_path(&session.session_id),
        dir.path()
            .join("sessions")
            .join(&session.session_id)
            .join("session.json")
    );
    assert_eq!(
        store.run_path(&session.session_id, &run.run_id),
        dir.path()
            .join("sessions")
            .join(&session.session_id)
            .join("runs")
            .join(&run.run_id)
            .join("run.json")
    );
    let artifact_path =
        store.artifact_path(&session.session_id, &run.run_id, &artifact.artifact_id);
    assert!(artifact_path.starts_with(
        dir.path()
            .join("sessions")
            .join(&session.session_id)
            .join("runs")
            .join(&run.run_id)
            .join("artifacts")
    ));
    let diagnostic_path =
        store.diagnostic_path(&session.session_id, &run.run_id, &diagnostic.diagnostic_id);
    assert!(diagnostic_path.starts_with(
        dir.path()
            .join("sessions")
            .join(&session.session_id)
            .join("runs")
            .join(&run.run_id)
            .join("diagnostics")
    ));

    assert_eq!(store.read_session(&session.session_id).unwrap(), session);
    assert_eq!(
        store.read_run(&session.session_id, &run.run_id).unwrap(),
        run
    );
    assert_eq!(
        store
            .read_recipe(&session.session_id, &recipe.recipe_id)
            .unwrap(),
        recipe
    );
    assert_eq!(
        store
            .read_artifact(&session.session_id, &run.run_id, &artifact.artifact_id)
            .unwrap(),
        artifact
    );
    assert_eq!(
        store
            .read_diagnostic(&session.session_id, &run.run_id, &diagnostic.diagnostic_id)
            .unwrap(),
        diagnostic
    );
}

#[test]
fn artifact_and_diagnostic_indices_append_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();

    let session = sample_session();
    let run = sample_run(&session.session_id);
    let artifact_a = sample_artifact(&session.session_id, &run.run_id);
    let artifact_b = ArtifactRecord::new(
        "project-1",
        "target-1",
        &session.session_id,
        &run.run_id,
        ArtifactKind::RuntimeState,
        "state",
        "backend-driver",
        "driver-1",
        "2026-03-27T00:02:00Z",
        "runs/run-1/state.json",
        "application/json",
        64,
        None,
        "run-scoped evidence",
        ArtifactRetentionPolicy::Session,
    );
    let diagnostic_a = sample_diagnostic(&run.run_id, &artifact_a.artifact_id);
    let diagnostic_b = DiagnosticRecord::new(
        &run.run_id,
        DiagnosticPhase::Analysis,
        DiagnosticOwner::Analyzer,
        DiagnosticClass::AnalysisFailed,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::Medium,
        DiagnosticActionability::Retryable,
        "analysis could not resolve state",
        vec![artifact_b.artifact_id.clone()],
        vec![],
        vec!["re-run the analyzer".to_string()],
    );
    let target_artifact = TargetArtifactRecord::new(
        "project-1",
        "target-1",
        ArtifactKind::Analysis,
        "summary",
        "fat-cli",
        "fat-cli analyze",
        "2026-03-27T00:03:00Z",
        "analysis/summary.txt",
        "text/plain",
        32,
        None,
        "target-scoped evidence",
        ArtifactRetentionPolicy::Project,
    );

    store.write_session(&session).unwrap();
    store.write_run(&run).unwrap();
    store.write_artifact(&artifact_a).unwrap();
    store.write_artifact(&artifact_b).unwrap();
    store
        .write_diagnostic(&session.session_id, &diagnostic_a)
        .unwrap();
    store
        .write_diagnostic(&session.session_id, &diagnostic_b)
        .unwrap();

    store.append_artifact_index(&artifact_a).unwrap();
    store.append_artifact_index(&artifact_b).unwrap();
    store
        .append_target_artifact_index(&target_artifact)
        .unwrap();
    store.append_diagnostic_index(&diagnostic_a).unwrap();
    store.append_diagnostic_index(&diagnostic_b).unwrap();

    let indexed_artifacts = store.read_artifact_index().unwrap();
    assert_eq!(indexed_artifacts.len(), 3);
    assert_eq!(indexed_artifacts[0], artifact_a.clone());
    assert_eq!(indexed_artifacts[1], artifact_b.clone());
    assert_eq!(
        indexed_artifacts[2].artifact_id,
        target_artifact.artifact_id
    );
    assert_eq!(indexed_artifacts[2].target_id, target_artifact.target_id);
    assert!(indexed_artifacts[2].session_id.is_empty());
    assert!(indexed_artifacts[2].run_id.is_empty());
    assert_eq!(
        store.read_diagnostic_index().unwrap(),
        vec![diagnostic_a.clone(), diagnostic_b.clone()]
    );
    let artifact_name = store
        .artifact_path(&session.session_id, &run.run_id, &artifact_a.artifact_id)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(artifact_name.ends_with(".json"));
    assert!(artifact_name.contains(&artifact_a.artifact_id[artifact_a.artifact_id.len() - 16..]));

    let diagnostic_name = store
        .diagnostic_path(
            &session.session_id,
            &run.run_id,
            &diagnostic_a.diagnostic_id,
        )
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(diagnostic_name.ends_with(".json"));
    assert!(diagnostic_name
        .contains(&diagnostic_a.diagnostic_id[diagnostic_a.diagnostic_id.len() - 16..]));
}

#[test]
fn target_diagnostic_records_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let diagnostic = TargetDiagnosticRecord::new(
        "project-1",
        "target-1",
        DiagnosticPhase::Analysis,
        DiagnosticOwner::Analyzer,
        DiagnosticClass::AnalysisFailed,
        Some("static-coverage".to_string()),
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::Medium,
        DiagnosticActionability::FallbackRecommended,
        "static analysis inputs were incomplete",
        vec!["tart-1".to_string()],
        Vec::new(),
        vec!["collect additional extracted artifacts".to_string()],
    );

    store.write_target_diagnostic(&diagnostic).unwrap();

    assert_eq!(
        store
            .read_target_diagnostic(&diagnostic.target_id, &diagnostic.diagnostic_id)
            .unwrap(),
        diagnostic
    );
    assert_eq!(
        store
            .read_target_diagnostics(&diagnostic.target_id)
            .unwrap(),
        vec![diagnostic]
    );
}

#[test]
fn benchmark_records_round_trip_through_runtime_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();

    let target = sample_benchmark_target();
    let run = sample_benchmark_run(&target.target_id, "exec-1");
    let outcome = sample_benchmark_outcome(&run.benchmark_run_id);

    store.write_benchmark_target(&target).unwrap();
    store.write_benchmark_run(&run).unwrap();
    store.write_benchmark_outcome(&outcome).unwrap();

    assert_eq!(
        store.read_benchmark_target(&target.target_id).unwrap(),
        target
    );
    assert_eq!(
        store.read_benchmark_run(&run.benchmark_run_id).unwrap(),
        run
    );
    let loaded_outcome = store.read_benchmark_outcome(&run.benchmark_run_id).unwrap();
    assert_eq!(loaded_outcome.outcome_class, BenchmarkOutcomeClass::Partial);
    assert_eq!(
        loaded_outcome.stage_vector.boot.status,
        BenchmarkStageStatus::Reached
    );
    assert_eq!(
        loaded_outcome.stage_vector.reachability.status,
        BenchmarkStageStatus::Partial
    );
    assert_eq!(store.read_benchmark_targets().unwrap(), vec![target]);
    assert_eq!(store.read_benchmark_runs().unwrap(), vec![run]);
    assert_eq!(store.read_benchmark_outcomes().unwrap(), vec![outcome]);
}

#[test]
fn benchmark_runs_with_distinct_execution_ids_do_not_overwrite_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();

    let target = sample_benchmark_target();
    let run_a = sample_benchmark_run(&target.target_id, "exec-1");
    let run_b = sample_benchmark_run(&target.target_id, "exec-2");
    let outcome_a = sample_benchmark_outcome(&run_a.benchmark_run_id);
    let outcome_b = sample_benchmark_outcome(&run_b.benchmark_run_id);

    assert_ne!(run_a.benchmark_run_id, run_b.benchmark_run_id);

    store.write_benchmark_target(&target).unwrap();
    store.write_benchmark_run(&run_a).unwrap();
    store.write_benchmark_outcome(&outcome_a).unwrap();
    store.write_benchmark_run(&run_b).unwrap();
    store.write_benchmark_outcome(&outcome_b).unwrap();

    // Both records must persist independently; read order is id-sorted and not
    // semantically meaningful, so compare as sets.
    let runs = store.read_benchmark_runs().unwrap();
    assert_eq!(runs.len(), 2);
    assert!(runs.contains(&run_a));
    assert!(runs.contains(&run_b));
    let outcomes = store.read_benchmark_outcomes().unwrap();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.contains(&outcome_a));
    assert!(outcomes.contains(&outcome_b));
    assert_eq!(
        store.read_benchmark_run(&run_a.benchmark_run_id).unwrap(),
        run_a
    );
    assert_eq!(
        store.read_benchmark_run(&run_b.benchmark_run_id).unwrap(),
        run_b
    );
    assert_eq!(
        store
            .read_benchmark_outcome(&run_a.benchmark_run_id)
            .unwrap(),
        outcome_a
    );
    assert_eq!(
        store
            .read_benchmark_outcome(&run_b.benchmark_run_id)
            .unwrap(),
        outcome_b
    );
}

#[test]
fn runtime_store_reads_legacy_benchmark_run_without_execution_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let migrated_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
            legacy_benchmark_run_id.as_str(),
        ],
    );

    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();

    let run = store.read_benchmark_run(&legacy_benchmark_run_id).unwrap();

    assert_eq!(run.benchmark_run_id, migrated_benchmark_run_id);
    assert_eq!(run.execution_id, legacy_benchmark_run_id);
}

#[test]
fn legacy_benchmark_run_round_trips_through_runtime_store_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );

    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();

    let migrated_run = store.read_benchmark_run(&legacy_benchmark_run_id).unwrap();
    assert_ne!(migrated_run.benchmark_run_id, legacy_benchmark_run_id);

    store.write_benchmark_run(&migrated_run).unwrap();

    let rewritten_run = store
        .read_benchmark_run(&migrated_run.benchmark_run_id)
        .unwrap();

    assert_eq!(rewritten_run, migrated_run);
}

#[test]
fn read_benchmark_runs_migrates_legacy_run_and_outcome_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let legacy_run_json = format!(
        r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
    );

    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        legacy_run_json,
    )
    .unwrap();
    write_legacy_benchmark_outcome(&store, &legacy_benchmark_run_id).unwrap();

    let runs = store.read_benchmark_runs().unwrap();

    assert_eq!(runs.len(), 1);
    let migrated_run = &runs[0];
    assert_ne!(migrated_run.benchmark_run_id, legacy_benchmark_run_id);
    assert_eq!(migrated_run.execution_id, legacy_benchmark_run_id);
    assert!(!store.benchmark_run_path(&legacy_benchmark_run_id).exists());
    assert!(store
        .benchmark_run_path(&migrated_run.benchmark_run_id)
        .exists());
    assert!(!store
        .benchmark_outcome_path(&legacy_benchmark_run_id)
        .exists());
    assert!(store
        .benchmark_outcome_path(&migrated_run.benchmark_run_id)
        .exists());

    assert_eq!(
        store
            .read_benchmark_run(&migrated_run.benchmark_run_id)
            .unwrap(),
        *migrated_run
    );
    let migrated_outcome = store
        .read_benchmark_outcome(&migrated_run.benchmark_run_id)
        .unwrap();
    assert_eq!(
        migrated_outcome.benchmark_run_id,
        migrated_run.benchmark_run_id
    );
    assert_eq!(store.read_benchmark_runs().unwrap(), runs);
}

#[test]
fn read_benchmark_run_by_legacy_id_remains_stable_after_migration() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );

    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();

    let first = store.read_benchmark_run(&legacy_benchmark_run_id).unwrap();
    let second = store.read_benchmark_run(&legacy_benchmark_run_id).unwrap();

    assert_eq!(first, second);
    assert_ne!(first.benchmark_run_id, legacy_benchmark_run_id);
    assert!(!store.benchmark_run_path(&legacy_benchmark_run_id).exists());
    assert!(store.benchmark_run_path(&first.benchmark_run_id).exists());
}

#[test]
fn read_benchmark_outcome_by_legacy_id_migrates_to_canonical_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );

    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();
    write_legacy_benchmark_outcome(&store, &legacy_benchmark_run_id).unwrap();

    let outcome = store
        .read_benchmark_outcome(&legacy_benchmark_run_id)
        .unwrap();
    let run = store.read_benchmark_run(&legacy_benchmark_run_id).unwrap();

    assert_eq!(outcome.benchmark_run_id, run.benchmark_run_id);
    assert_ne!(outcome.benchmark_run_id, legacy_benchmark_run_id);
    assert!(!store
        .benchmark_outcome_path(&legacy_benchmark_run_id)
        .exists());
    assert!(store
        .benchmark_outcome_path(&outcome.benchmark_run_id)
        .exists());
}

#[test]
fn read_benchmark_outcome_by_canonical_id_migrates_legacy_alias_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let canonical_run = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        &legacy_benchmark_run_id,
    )
    .unwrap();

    store.write_benchmark_run(&canonical_run).unwrap();
    write_legacy_benchmark_outcome(&store, &legacy_benchmark_run_id).unwrap();

    let outcome = store
        .read_benchmark_outcome(&canonical_run.benchmark_run_id)
        .unwrap();

    assert_eq!(outcome.benchmark_run_id, canonical_run.benchmark_run_id);
    assert!(!store
        .benchmark_outcome_path(&legacy_benchmark_run_id)
        .exists());
    assert!(store
        .benchmark_outcome_path(&canonical_run.benchmark_run_id)
        .exists());
}

#[test]
fn read_benchmark_outcomes_canonicalizes_legacy_alias_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let canonical_run = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        &legacy_benchmark_run_id,
    )
    .unwrap();

    store.write_benchmark_run(&canonical_run).unwrap();
    write_legacy_benchmark_outcome(&store, &legacy_benchmark_run_id).unwrap();

    let outcomes = store.read_benchmark_outcomes().unwrap();

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].benchmark_run_id, canonical_run.benchmark_run_id);
    assert!(!store
        .benchmark_outcome_path(&legacy_benchmark_run_id)
        .exists());
    assert!(store
        .benchmark_outcome_path(&canonical_run.benchmark_run_id)
        .exists());
}

#[test]
fn identical_canonical_and_legacy_benchmark_records_cleanup_aliases_without_clobbering() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let canonical_run = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        &legacy_benchmark_run_id,
    )
    .unwrap();
    let canonical_outcome = sample_benchmark_outcome(&canonical_run.benchmark_run_id);

    store.write_benchmark_run(&canonical_run).unwrap();
    store.write_benchmark_outcome(&canonical_outcome).unwrap();
    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();
    write_legacy_benchmark_outcome(&store, &legacy_benchmark_run_id).unwrap();

    let runs = store.read_benchmark_runs().unwrap();
    let outcomes = store.read_benchmark_outcomes().unwrap();

    assert_eq!(runs, vec![canonical_run.clone()]);
    assert_eq!(outcomes, vec![canonical_outcome.clone()]);
    assert!(!store.benchmark_run_path(&legacy_benchmark_run_id).exists());
    assert!(!store
        .benchmark_outcome_path(&legacy_benchmark_run_id)
        .exists());
    assert_eq!(
        store
            .read_benchmark_run(&canonical_run.benchmark_run_id)
            .unwrap(),
        canonical_run
    );
    assert_eq!(
        store
            .read_benchmark_outcome(&canonical_outcome.benchmark_run_id)
            .unwrap(),
        canonical_outcome
    );
}

#[test]
fn divergent_canonical_and_legacy_benchmark_records_fail_migration_with_invalid_data() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let canonical_run = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        &legacy_benchmark_run_id,
    )
    .unwrap();

    fs::write(
        store.benchmark_run_path(&canonical_run.benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{canonical_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "different-host",
  "execution_id": "{execution_id}"
}}"#,
            canonical_id = canonical_run.benchmark_run_id,
            execution_id = legacy_benchmark_run_id,
        ),
    )
    .unwrap();
    fs::write(
        store.benchmark_run_path(&legacy_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{legacy_benchmark_run_id}",
  "target_id": "target-demo-camera-v1",
  "comparator": {{
    "comparator_id": "firmae",
    "kind": "external",
    "run_mode": "raw-upstream"
  }},
  "host_profile": "apple-silicon-laptop"
}}"#
        ),
    )
    .unwrap();

    let err = store.read_benchmark_runs().unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn write_benchmark_run_rejects_invalid_record_built_without_try_new() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let invalid_run = BenchmarkRunRecord {
        benchmark_run_id: "brun-invalid".to_string(),
        target_id: "target-demo-camera-v1".to_string(),
        comparator: BenchmarkComparator::new(
            "firmae",
            ComparatorKind::External,
            BenchmarkRunMode::RawUpstream,
        ),
        host_profile: "apple-silicon-laptop".to_string(),
        execution_id: "   ".to_string(),
    };

    let err = store.write_benchmark_run(&invalid_run).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn write_benchmark_outcome_rejects_orphan_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let outcome = sample_benchmark_outcome("brun-missing-run");

    let err = store.write_benchmark_outcome(&outcome).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn alias_outcome_with_mismatched_embedded_run_id_fails_migration() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let legacy_benchmark_run_id = stable_prefixed_id(
        "brun",
        [
            "target-demo-camera-v1",
            "firmae",
            "external",
            "raw-upstream",
            "apple-silicon-laptop",
        ],
    );
    let comparator = BenchmarkComparator::new(
        "firmae",
        ComparatorKind::External,
        BenchmarkRunMode::RawUpstream,
    );
    let canonical_run = BenchmarkRunRecord::try_new(
        "target-demo-camera-v1",
        comparator,
        "apple-silicon-laptop",
        &legacy_benchmark_run_id,
    )
    .unwrap();

    store.write_benchmark_run(&canonical_run).unwrap();
    fs::write(
        store.benchmark_outcome_path(&legacy_benchmark_run_id),
        r#"{
  "benchmark_run_id": "brun-some-other-id",
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
}"#,
    )
    .unwrap();

    let err = store
        .read_benchmark_outcome(&canonical_run.benchmark_run_id)
        .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn shared_execution_ids_do_not_create_arbitrary_run_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let run_a = sample_benchmark_run("target-demo-camera-v1", "shared-execution-id");
    let run_b = BenchmarkRunRecord::try_new(
        "target-demo-camera-v2",
        BenchmarkComparator::new(
            "firmae",
            ComparatorKind::External,
            BenchmarkRunMode::RawUpstream,
        ),
        "apple-silicon-laptop",
        "shared-execution-id",
    )
    .unwrap();

    store.write_benchmark_run(&run_a).unwrap();
    store.write_benchmark_run(&run_b).unwrap();

    let err = store.read_benchmark_run("shared-execution-id").unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn orphan_outcome_files_are_rejected_by_single_and_bulk_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();
    let orphan_benchmark_run_id = "brun-orphan-outcome";

    fs::write(
        store.benchmark_outcome_path(orphan_benchmark_run_id),
        format!(
            r#"{{
  "benchmark_run_id": "{orphan_benchmark_run_id}",
  "outcome_class": "partial",
  "evidence_grade": "moderate",
  "stage_vector": {{
    "intake": {{ "status": "reached" }},
    "boot": {{ "status": "reached" }},
    "reachability": {{ "status": "partial" }},
    "operator_access": {{ "status": "not-reached" }},
    "research_utility": {{ "status": "reached" }},
    "exploit_readiness": {{ "status": "not-reached" }}
  }}
}}"#
        ),
    )
    .unwrap();

    let read_err = store
        .read_benchmark_outcome(orphan_benchmark_run_id)
        .unwrap_err();
    let list_err = store.read_benchmark_outcomes().unwrap_err();

    assert_eq!(read_err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(list_err.kind(), std::io::ErrorKind::InvalidData);
}

fn sample_discovery_lead() -> DiscoveryLeadRecord {
    DiscoveryLeadRecord {
        discovery_lead_id: "lead-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Queued,
        family: "lifetime-reentrancy".to_string(),
        symbol: "Demo::Callback".to_string(),
        family_confidence: 0.91,
        family_pack_version: "lifetime-pack-v1".to_string(),
        analysis_scope: "WholeTu".to_string(),
        candidate_status: "Primary".to_string(),
        locality: "RepoLocal".to_string(),
        trigger_recipe: vec![DiscoveryTriggerRecipeStepRecord {
            kind: "destroy-owner-during-callback".to_string(),
            detail: "destroy the owner before callback completion".to_string(),
        }],
        expected_proof_signals: vec![DiscoveryProofSignalRecord {
            kind: "asan-use-after-free".to_string(),
            detail: "callback path dereferences stale owner".to_string(),
        }],
        state_hypotheses: vec![DiscoveryStateHypothesisRecord {
            hypothesis_id: "lead-1::h0".to_string(),
            machine_id: "lifetime-reentrancy".to_string(),
            actors: vec!["Owner".to_string(), "Callback".to_string()],
            active_regions: vec!["lifecycle".to_string()],
            key_states: vec!["CallbackPending".to_string(), "OwnerDestroyed".to_string()],
            ghost_states: vec!["OwnerAlive".to_string()],
            invalidating_events: vec!["destroy-owner-during-callback".to_string()],
            required_guards: vec!["safe_invalidation_guard".to_string()],
            forbidden_transitions: vec![ForbiddenTransitionRecord {
                transition_id: "destroy-owner-during-callback".to_string(),
                expected_proof_class: "asan-use-after-free".to_string(),
                rationale: vec!["stale callback reaches destroyed owner".to_string()],
            }],
            confidence: 0.91,
        }],
        summary: "candidate lead".to_string(),
    }
}

fn sample_harvester_expansion() -> HarvesterExpansionRecord {
    HarvesterExpansionRecord {
        harvester_expansion_id: "hexp-1".to_string(),
        lead_id: "lead-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Ready,
        attempt_plan_hash: "plan-hash-1".to_string(),
        artifact_root: "/tmp/artifacts/expansion-1".to_string(),
        retry_count: 2,
        sibling_fingerprint: Some("fingerprint-1".to_string()),
        family_overlap: vec!["lifetime-reentrancy".to_string()],
        role_overlap: vec!["callback-teardown".to_string()],
        locality_notes: vec!["vendored-local".to_string()],
        suppression_reasons: vec!["guarded-negative".to_string()],
    }
}

fn sample_harness_attempt_pre_result() -> HarnessAttemptRecord {
    HarnessAttemptRecord {
        harness_attempt_id: "hat-1".to_string(),
        expansion_id: "hexp-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Queued,
        outcome: None,
        attempt_plan_hash: "plan-hash-1".to_string(),
        artifact_root: "/tmp/artifacts/attempt-1".to_string(),
        retry_count: 3,
        launcher_command: "fat discover run".to_string(),
        generated_binding_id: Some("hexp-1::g0".to_string()),
        generated_input_bindings: std::collections::BTreeMap::from([
            ("arg_size".to_string(), "32".to_string()),
            (
                "vk_icd_filenames".to_string(),
                "/tmp/swiftshader_icd.json".to_string(),
            ),
        ]),
        resolved_argv: vec!["fat".to_string(), "discover".to_string(), "run".to_string()],
        resolved_env: std::collections::BTreeMap::from([(
            "ASAN_OPTIONS".to_string(),
            "symbolize=1".to_string(),
        )]),
        resolved_cwd: "/tmp/runtime/cwd".to_string(),
        timeout_ms: 1000,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("destroy-owner-during-callback".to_string()),
        attempted_transition_summary: Some(
            "destroy-owner-during-callback: stale callback reaches destroyed owner".to_string(),
        ),
    }
}

fn sample_harness_attempt_terminal() -> HarnessAttemptRecord {
    HarnessAttemptRecord {
        harness_attempt_id: "hat-2".to_string(),
        expansion_id: "hexp-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Completed,
        outcome: Some(DiscoveryOutcomeClass::AsanUseAfterFree),
        attempt_plan_hash: "plan-hash-2".to_string(),
        artifact_root: "/tmp/artifacts/attempt-2".to_string(),
        retry_count: 0,
        launcher_command: "fat discover run".to_string(),
        generated_binding_id: Some("hexp-1::g1".to_string()),
        generated_input_bindings: std::collections::BTreeMap::from([
            ("arg_size".to_string(), "16".to_string()),
            (
                "vk_icd_filenames".to_string(),
                "/tmp/swiftshader_icd.json".to_string(),
            ),
        ]),
        resolved_argv: vec!["fat".to_string(), "discover".to_string(), "run".to_string()],
        resolved_env: std::collections::BTreeMap::from([(
            "ASAN_OPTIONS".to_string(),
            "symbolize=1".to_string(),
        )]),
        resolved_cwd: "/tmp/runtime/cwd".to_string(),
        timeout_ms: 1000,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("destroy-owner-during-callback".to_string()),
        attempted_transition_summary: Some(
            "destroy-owner-during-callback: stale callback reaches destroyed owner".to_string(),
        ),
    }
}

fn sample_triage_pre_result() -> TriageRecord {
    TriageRecord {
        triage_id: "tri-1".to_string(),
        harness_attempt_id: "hat-1".to_string(),
        lifecycle: DiscoveryLifecycleStatus::Running,
        outcome: None,
        attempt_plan_hash: "plan-hash-1".to_string(),
        artifact_root: "/tmp/artifacts/triage-1".to_string(),
        retry_count: 4,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("destroy-owner-during-callback".to_string()),
        attempted_transition_summary: Some(
            "destroy-owner-during-callback: stale callback reaches destroyed owner".to_string(),
        ),
        summary: "triage deferred for local-only lane".to_string(),
    }
}

fn sample_triage_terminal() -> TriageRecord {
    TriageRecord {
        triage_id: "tri-2".to_string(),
        harness_attempt_id: "hat-2".to_string(),
        lifecycle: DiscoveryLifecycleStatus::NeedsReview,
        outcome: Some(DiscoveryOutcomeClass::BlockedByLocality),
        attempt_plan_hash: "plan-hash-2".to_string(),
        artifact_root: "/tmp/artifacts/triage-2".to_string(),
        retry_count: 1,
        state_hypothesis_id: Some("lead-1::h0".to_string()),
        forbidden_transition_id: Some("destroy-owner-during-callback".to_string()),
        attempted_transition_summary: Some(
            "destroy-owner-during-callback: stale callback reaches destroyed owner".to_string(),
        ),
        summary: "triage deferred for local-only lane".to_string(),
    }
}

#[test]
fn discovery_queue_records_round_trip_through_runtime_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = RuntimeStore::open(dir.path()).unwrap();

    let lead = sample_discovery_lead();
    let expansion = sample_harvester_expansion();
    let pre_result_attempt = sample_harness_attempt_pre_result();
    let terminal_attempt = sample_harness_attempt_terminal();
    let pre_result_triage = sample_triage_pre_result();
    let terminal_triage = sample_triage_terminal();

    store.write_discovery_lead(&lead).unwrap();
    store.write_harvester_expansion(&expansion).unwrap();
    store.write_harness_attempt(&pre_result_attempt).unwrap();
    store.write_harness_attempt(&terminal_attempt).unwrap();
    store.write_triage(&pre_result_triage).unwrap();
    store.write_triage(&terminal_triage).unwrap();

    assert_eq!(
        store.read_discovery_lead(&lead.discovery_lead_id).unwrap(),
        lead
    );
    assert_eq!(
        store
            .read_harvester_expansion(&expansion.harvester_expansion_id)
            .unwrap(),
        expansion
    );
    assert_eq!(
        store
            .read_harness_attempt(&pre_result_attempt.harness_attempt_id)
            .unwrap(),
        pre_result_attempt
    );
    assert_eq!(
        store
            .read_harness_attempt(&terminal_attempt.harness_attempt_id)
            .unwrap(),
        terminal_attempt
    );
    assert_eq!(
        store.read_triage(&pre_result_triage.triage_id).unwrap(),
        pre_result_triage
    );
    assert_eq!(
        store.read_triage(&terminal_triage.triage_id).unwrap(),
        terminal_triage
    );
    assert_ne!(
        pre_result_attempt.generated_binding_id,
        terminal_attempt.generated_binding_id
    );

    assert_eq!(store.read_discovery_leads().unwrap(), vec![lead]);
    assert_eq!(store.read_harvester_expansions().unwrap(), vec![expansion]);
    assert_eq!(
        store.read_harness_attempts().unwrap(),
        vec![pre_result_attempt, terminal_attempt]
    );
    assert_eq!(
        store.read_triage_records().unwrap(),
        vec![pre_result_triage, terminal_triage]
    );
    assert_eq!(store.read_harness_attempts().unwrap()[0].outcome, None);
    assert_eq!(
        store.read_harness_attempts().unwrap()[1].outcome,
        Some(DiscoveryOutcomeClass::AsanUseAfterFree)
    );
    assert_eq!(
        store.read_harness_attempts().unwrap()[0]
            .generated_input_bindings
            .get("arg_size")
            .map(String::as_str),
        Some("32")
    );
    assert_eq!(
        store.read_harness_attempts().unwrap()[0].resolved_argv,
        vec!["fat".to_string(), "discover".to_string(), "run".to_string()]
    );
    assert_eq!(store.read_triage_records().unwrap()[0].outcome, None);
    assert_eq!(
        store.read_triage_records().unwrap()[1].outcome,
        Some(DiscoveryOutcomeClass::BlockedByLocality)
    );

    let pre_result_attempt_json =
        serde_json::to_value(store.read_harness_attempt("hat-1").unwrap()).unwrap();
    let terminal_attempt_json =
        serde_json::to_value(store.read_harness_attempt("hat-2").unwrap()).unwrap();
    let pre_result_triage_json = serde_json::to_value(store.read_triage("tri-1").unwrap()).unwrap();
    let terminal_triage_json = serde_json::to_value(store.read_triage("tri-2").unwrap()).unwrap();

    assert!(pre_result_attempt_json.get("outcome").is_none());
    assert_eq!(
        terminal_attempt_json
            .get("outcome")
            .and_then(|value| value.as_str()),
        Some("asan-use-after-free")
    );
    assert_eq!(
        terminal_attempt_json
            .get("generated_binding_id")
            .and_then(|value| value.as_str()),
        Some("hexp-1::g1")
    );
    assert_eq!(
        terminal_attempt_json
            .get("generated_input_bindings")
            .and_then(|value| value.get("arg_size"))
            .and_then(|value| value.as_str()),
        Some("16")
    );
    assert!(pre_result_triage_json.get("outcome").is_none());
    assert_eq!(
        terminal_triage_json
            .get("outcome")
            .and_then(|value| value.as_str()),
        Some("blocked-by-locality")
    );
}

#[test]
fn discovery_lifecycle_and_outcome_round_trip_independently() {
    let lifecycle_values = [
        serde_json::to_value(DiscoveryLifecycleStatus::Queued).unwrap(),
        serde_json::to_value(DiscoveryLifecycleStatus::Ready).unwrap(),
        serde_json::to_value(DiscoveryLifecycleStatus::Running).unwrap(),
        serde_json::to_value(DiscoveryLifecycleStatus::Completed).unwrap(),
        serde_json::to_value(DiscoveryLifecycleStatus::FailedInfra).unwrap(),
        serde_json::to_value(DiscoveryLifecycleStatus::NeedsReview).unwrap(),
    ];
    let outcome_values = [
        serde_json::to_value(DiscoveryOutcomeClass::AsanUseAfterFree).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::AsanHeapBufferOverflow).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::UbsanIntegerOverflow).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::GuardTrip).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::BadMessage).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::BlockedByLocality).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::NoSignal).unwrap(),
        serde_json::to_value(DiscoveryOutcomeClass::Flaky).unwrap(),
    ];

    assert_eq!(
        serde_json::from_value::<DiscoveryLifecycleStatus>(lifecycle_values[0].clone()).unwrap(),
        DiscoveryLifecycleStatus::Queued
    );
    assert_eq!(
        serde_json::from_value::<DiscoveryLifecycleStatus>(lifecycle_values[5].clone()).unwrap(),
        DiscoveryLifecycleStatus::NeedsReview
    );
    assert_eq!(
        serde_json::from_value::<DiscoveryOutcomeClass>(outcome_values[0].clone()).unwrap(),
        DiscoveryOutcomeClass::AsanUseAfterFree
    );
    assert_eq!(
        serde_json::from_value::<DiscoveryOutcomeClass>(outcome_values[7].clone()).unwrap(),
        DiscoveryOutcomeClass::Flaky
    );
}
