use std::fs;

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::finding::Finding;
use fat_core::inventory::{AnalysisSnapshot, Architecture, BinaryRecord};
use fat_core::project::{Project, ProjectStatus};
use fat_core::runs::{RunOrigin, RunRecord, RunStatus, SubstrateKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};
use fat_core::targets::{derive_target_id, TargetArtifactRecord, TargetRecord};
use fat_plugin_api::AnalysisTrigger;

#[test]
fn plugin_host_dispatches_target_and_run_analysis_from_runtime_store() {
    let project_root = tempfile::tempdir().expect("project root");
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
        .expect("target");

    let analysis_dir = project_dir.join("analysis");
    fs::create_dir_all(&analysis_dir).expect("analysis dir");
    let summary_path = analysis_dir.join("summary.txt");
    fs::write(&summary_path, "web interface present\n").expect("summary");
    store
        .write_target_artifact(&TargetArtifactRecord::new(
            "demo",
            &target_id,
            ArtifactKind::Analysis,
            "summary",
            "fat-cli",
            "fat-cli analyze",
            "unix-ms:2",
            summary_path.to_string_lossy().into_owned(),
            "text/plain",
            fs::metadata(&summary_path).expect("metadata").len(),
            None,
            "analysis summary",
            ArtifactRetentionPolicy::Project,
        ))
        .expect("target artifact");

    let target_result = fat_plugin_host::dispatch_target_analysis(
        &project_dir,
        &target_id,
        AnalysisTrigger::AnalysisRequested,
        Some(AnalysisSnapshot {
            binaries: vec![BinaryRecord {
                id: "bin-1".to_string(),
                name: "httpd".to_string(),
                rel_path: "/bin/httpd".to_string(),
                architecture: Architecture::Armel,
                nx: None,
                pie: None,
                canary: None,
            }],
            findings: Vec::new(),
        }),
    )
    .expect("target dispatch");
    assert!(target_result
        .findings
        .iter()
        .any(|finding| { finding.plugin_id.as_deref() == Some("web-surface-static") }));

    let session_id = "sess-1";
    let run_id = "run-1";
    let mut session = SessionRecord::new(
        "demo",
        &target_id,
        "emulate firmware",
        "fat-emulate",
        SessionOrigin::Automatic,
        "unix-ms:3",
    )
    .with_status(SessionStatus::Completed)
    .with_progress(GoalProgress::Achieved)
    .with_run_ids(vec![run_id.to_string()]);
    session.session_id = session_id.to_string();
    store.write_session(&session).expect("session");
    let mut run = RunRecord::new(
        session_id,
        "recipe-1",
        "qemu-direct",
        SubstrateKind::NativeHost,
        1,
        RunOrigin::Automatic,
    )
    .with_status(RunStatus::Completed);
    run.run_id = run_id.to_string();
    store.write_run(&run).expect("run");
    let outputs_dir = project_dir
        .join("sessions")
        .join(session_id)
        .join("runs")
        .join(run_id)
        .join("outputs");
    fs::create_dir_all(&outputs_dir).expect("outputs");
    let log_path = outputs_dir.join("launch-stdout.log");
    fs::write(&log_path, "uhttpd 0.0.0.0:80\n").expect("runtime log");
    store
        .write_artifact(&ArtifactRecord::new(
            "demo",
            &target_id,
            session_id,
            run_id,
            ArtifactKind::RuntimeLog,
            "launch-stdout",
            "fat-cli",
            "fat-cli emulate",
            "unix-ms:3",
            log_path.to_string_lossy().into_owned(),
            "text/plain",
            fs::metadata(&log_path).expect("metadata").len(),
            None,
            "runtime log",
            ArtifactRetentionPolicy::Session,
        ))
        .expect("run artifact");

    let run_result = fat_plugin_host::dispatch_run_analysis(
        &project_dir,
        AnalysisTrigger::RunCompleted,
        session_id,
        run_id,
    )
    .expect("run dispatch");
    assert!(run_result
        .findings
        .iter()
        .any(|finding| { finding.plugin_id.as_deref() == Some("service-runtime") }));
    let persisted = store
        .read_run_findings(session_id, run_id)
        .expect("persisted run findings");
    assert!(persisted
        .iter()
        .any(|finding: &Finding| { finding.plugin_id.as_deref() == Some("service-runtime") }));
}
