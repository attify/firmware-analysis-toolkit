use std::fs;
use std::process::Command;

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::diff::{diff_runs, summarize_session};
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_core::project::{Project, ProjectStatus};
use fat_core::runs::{GoalProgressDelta, RunOrigin, RunRecord, RunStatus, SubstrateKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};
use fat_core::targets::{derive_target_id, TargetRecord};
use tempfile::tempdir;

#[test]
fn run_diff_helpers_compare_services_diagnostics_and_findings() {
    let base_findings = vec![Finding::new(
        "finding-base",
        "Old management surface",
        FindingSeverity::Medium,
        FindingSubject::Project,
    )
    .with_plugin_id("web-surface-static")];
    let head_findings = vec![Finding::new(
        "finding-head",
        "New runtime management surface",
        FindingSeverity::High,
        FindingSubject::Project,
    )
    .with_plugin_id("service-runtime")];
    let base_diagnostics = vec![diagnostic("run-1", "old launch issue")];
    let head_diagnostics = vec![diagnostic("run-2", "new reachability issue")];
    let diff = diff_runs(
        "run-1",
        "run-2",
        &base_findings,
        &head_findings,
        &base_diagnostics,
        &head_diagnostics,
        &["dropbear 0.0.0.0:22".to_string()],
        &["uhttpd 0.0.0.0:80".to_string()],
        &["firmae:launch-complete".to_string()],
        &["firmae:probe-healthy".to_string()],
    );

    assert_eq!(diff.added_services, vec!["uhttpd 0.0.0.0:80".to_string()]);
    assert_eq!(
        diff.removed_services,
        vec!["dropbear 0.0.0.0:22".to_string()]
    );
    assert!(diff
        .added_findings
        .iter()
        .any(|finding| finding.contains("service-runtime")));
    assert!(diff
        .removed_findings
        .iter()
        .any(|finding| finding.contains("web-surface-static")));
    assert!(diff
        .added_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.contains("new reachability issue")));
    assert_eq!(
        diff.added_runtime_states,
        vec!["firmae:probe-healthy".to_string()]
    );
    assert_eq!(
        diff.removed_runtime_states,
        vec!["firmae:launch-complete".to_string()]
    );

    let summary = summarize_session(
        "sess-1",
        2,
        &[base_findings[0].clone(), head_findings[0].clone()],
        &[base_diagnostics[0].clone(), head_diagnostics[0].clone()],
        &[
            "dropbear 0.0.0.0:22".to_string(),
            "uhttpd 0.0.0.0:80".to_string(),
        ],
        &[
            "firmae:launch-complete".to_string(),
            "firmae:probe-healthy".to_string(),
        ],
    );
    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.total_findings, 2);
    assert_eq!(summary.total_diagnostics, 2);
    assert!(summary
        .service_names
        .contains(&"uhttpd 0.0.0.0:80".to_string()));
    assert!(summary
        .runtime_states
        .contains(&"firmae:probe-healthy".to_string()));
}

#[test]
fn fat_info_reports_session_summary_and_attempt_diffs() {
    let project_root = tempdir().expect("project root");
    let project_dir = project_root.path().join("demo");
    fs::create_dir_all(&project_dir).expect("project dir");

    let db = ProjectDb::open(&project_dir).expect("project db");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_id = derive_target_id("demo", "demo.bin");
    db.save(&Project {
        name: "demo".to_string(),
        firmware_name: "demo.bin".to_string(),
        status: ProjectStatus::Analyzed,
        fingerprint: None,
    })
    .expect("save project");
    store
        .write_target(&TargetRecord::new("demo", &target_id, "demo", "unix-ms:1"))
        .expect("target record");
    store
        .write_target_finding(
            &target_id,
            &Finding::new(
                "target-finding",
                "Static web management surface",
                FindingSeverity::Medium,
                FindingSubject::Project,
            )
            .with_plugin_id("web-surface-static"),
        )
        .expect("target finding");

    let session = SessionRecord::new(
        "demo",
        &target_id,
        "emulate firmware",
        "fat-emulate",
        SessionOrigin::Automatic,
        "unix-ms:10",
    )
    .with_status(SessionStatus::Completed)
    .with_progress(GoalProgress::Achieved)
    .with_run_ids(vec!["run-a".to_string(), "run-b".to_string()])
    .with_updated_at("unix-ms:20");
    store.write_session(&session).expect("session");

    let run_a = seeded_run(&session.session_id, "run-a", 1, "unix-ms:11", "unix-ms:12");
    let run_b = seeded_run(&session.session_id, "run-b", 2, "unix-ms:13", "unix-ms:14");
    store.write_run(&run_a).expect("run a");
    store.write_run(&run_b).expect("run b");

    let outputs_a = project_dir
        .join("sessions")
        .join(&session.session_id)
        .join("runs")
        .join("run-a")
        .join("outputs");
    let outputs_b = project_dir
        .join("sessions")
        .join(&session.session_id)
        .join("runs")
        .join("run-b")
        .join("outputs");
    fs::create_dir_all(&outputs_a).expect("outputs a");
    fs::create_dir_all(&outputs_b).expect("outputs b");
    let status_a_path = outputs_a.join("managed-runtime-summary.json");
    let status_b_path = outputs_b.join("managed-runtime-summary.json");
    fs::write(
        &status_a_path,
        serde_json::json!({
            "backend_id": "firmae",
            "driver_profile": "firmae-managed-legacy-wrapper",
            "control_contract": "firmae-legacy-wrapper-v1",
            "lifecycle_adapter": "legacy-wrapper",
            "runtime_phase": "launch-complete",
            "workspace_dir": "/tmp/firmae/run-a",
            "services": [
                {
                    "name": "dropbear",
                    "endpoint": "ssh://127.0.0.1:10022"
                }
            ],
            "launch_mode": "legacy-wrapper-launch",
            "stop_mode": "legacy-wrapper-stop",
            "launch_manifest_present": false
        })
        .to_string(),
    )
    .expect("status a");
    fs::write(
        &status_b_path,
        serde_json::json!({
            "backend_id": "firmae",
            "driver_profile": "firmae-managed-legacy-wrapper",
            "control_contract": "firmae-legacy-wrapper-v1",
            "lifecycle_adapter": "legacy-wrapper",
            "runtime_phase": "probe-healthy",
            "workspace_dir": "/tmp/firmae/run-b",
            "services": [
                {
                    "name": "uhttpd",
                    "endpoint": "http://127.0.0.1:18080"
                }
            ],
            "launch_mode": "legacy-wrapper-launch",
            "stop_mode": "legacy-wrapper-stop",
            "launch_manifest_present": false,
            "probe_source": "background-supervisor",
            "probe_outcome": "healthy",
            "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
            "probe_result_contract_verified": true
        })
        .to_string(),
    )
    .expect("status b");

    store
        .write_artifact(&runtime_state(
            &session.session_id,
            "run-a",
            &status_a_path,
            "managed-runtime-summary",
        ))
        .expect("artifact a");
    store
        .write_artifact(&runtime_state(
            &session.session_id,
            "run-b",
            &status_b_path,
            "managed-runtime-summary",
        ))
        .expect("artifact b");

    store
        .write_run_finding(
            &session.session_id,
            "run-a",
            &Finding::new(
                "finding-a",
                "Run A management surface",
                FindingSeverity::Medium,
                FindingSubject::Project,
            )
            .with_plugin_id("service-runtime"),
        )
        .expect("finding a");
    store
        .write_run_finding(
            &session.session_id,
            "run-b",
            &Finding::new(
                "finding-b",
                "Run B management surface",
                FindingSeverity::High,
                FindingSubject::Project,
            )
            .with_plugin_id("service-runtime"),
        )
        .expect("finding b");

    let diagnostic_a = diagnostic("run-a", "old launch issue");
    let diagnostic_b = diagnostic("run-b", "new reachability issue");
    store
        .write_diagnostic(&session.session_id, &diagnostic_a)
        .expect("diagnostic a");
    store
        .write_diagnostic(&session.session_id, &diagnostic_b)
        .expect("diagnostic b");

    let info_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["info", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat info runs");
    assert!(info_output.status.success(), "{info_output:?}");

    let stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(stdout.contains("target findings: 1"), "{stdout}");
    assert!(
        stdout.contains("session summary: 2 runs, 2 findings, 2 diagnostics"),
        "{stdout}"
    );
    assert!(
        stdout.contains("session runtime states: firmae:launch-complete, firmae:probe-healthy"),
        "{stdout}"
    );
    assert!(stdout.contains("what changed between attempts"), "{stdout}");
    assert!(
        stdout.contains("added services: uhttpd http://127.0.0.1:18080"),
        "{stdout}"
    );
    assert!(
        stdout.contains("removed services: dropbear ssh://127.0.0.1:10022"),
        "{stdout}"
    );
    assert!(
        stdout.contains("added runtime states: firmae:probe-healthy"),
        "{stdout}"
    );
    assert!(
        stdout.contains("removed runtime states: firmae:launch-complete"),
        "{stdout}"
    );
    assert!(
        stdout.contains("added findings: service-runtime:Run B management surface"),
        "{stdout}"
    );
    assert!(
        stdout.contains("removed findings: service-runtime:Run A management surface"),
        "{stdout}"
    );
}

fn seeded_run(
    session_id: &str,
    run_id: &str,
    sequence: u32,
    started_at: &str,
    finished_at: &str,
) -> RunRecord {
    let mut run = RunRecord::new(
        session_id,
        "recipe-1",
        "qemu-direct",
        SubstrateKind::NativeHost,
        sequence,
        RunOrigin::Automatic,
    )
    .with_status(RunStatus::Completed)
    .with_goal_progress_delta(GoalProgressDelta::new(
        GoalProgress::Substantial,
        GoalProgress::Achieved,
    ))
    .with_started_at(Some(started_at.to_string()))
    .with_finished_at(Some(finished_at.to_string()));
    run.run_id = run_id.to_string();
    run
}

fn runtime_state(
    session_id: &str,
    run_id: &str,
    path: &std::path::Path,
    subkind: &str,
) -> ArtifactRecord {
    ArtifactRecord::new(
        "demo",
        derive_target_id("demo", "demo.bin"),
        session_id,
        run_id,
        ArtifactKind::RuntimeState,
        subkind,
        "fat-cli",
        "fat-cli emulate",
        "unix-ms:15",
        path.to_string_lossy().into_owned(),
        "application/json",
        fs::metadata(path).expect("metadata").len(),
        None,
        "runtime output",
        ArtifactRetentionPolicy::Session,
    )
}

fn diagnostic(run_id: &str, summary: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id,
        DiagnosticPhase::Observation,
        DiagnosticOwner::Analyzer,
        DiagnosticClass::GuestUnreachable,
        None,
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        summary,
        Vec::new(),
        Vec::new(),
        vec!["retry".to_string()],
    )
}
