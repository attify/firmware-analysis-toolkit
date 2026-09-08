use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fat_analyze::request::{ArtifactDocument, NormalizedAnalysisRequest};
use fat_core::artifacts::ArtifactRecord;
use fat_core::database::ProjectDb;
use fat_core::diagnostics::{DiagnosticRecord, TargetDiagnosticRecord};
use fat_core::finding::Finding;
use fat_core::inventory::AnalysisSnapshot;
use fat_core::project::Project;
use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::TargetArtifactRecord;
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, ArtifactRef, ArtifactScope, ProducedArtifact,
};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn dispatch_target_analysis(
    project_dir: &Path,
    target_id: &str,
    trigger: AnalysisTrigger,
    snapshot: Option<AnalysisSnapshot>,
) -> DynResult<AnalysisResult> {
    let store = RuntimeStore::open(project_dir)?;
    let project = load_project(project_dir)?;
    let target_artifacts = store.read_target_artifacts(target_id)?;
    let mut request =
        NormalizedAnalysisRequest::new(trigger, project.name.clone(), target_id.to_string())
            .with_artifacts(target_artifact_refs(&target_artifacts))
            .with_artifact_documents(target_artifact_documents(project_dir, &target_artifacts)?);
    if let Some(snapshot) = snapshot {
        request = request.with_snapshot(snapshot);
    }

    let mut result = fat_analyze::built_in_engine().analyze_request(&request);
    persist_target_findings(&store, target_id, &result.findings)?;
    persist_target_diagnostics(&store, &project, target_id, &result.diagnostics)?;
    result.produced_artifact_ids = persist_produced_artifacts(
        &store,
        &project,
        target_id,
        request.request.session_id.as_deref(),
        request.request.run_id.as_deref(),
        &result.produced_artifacts,
    )?;
    Ok(result)
}

pub fn dispatch_run_analysis(
    project_dir: &Path,
    trigger: AnalysisTrigger,
    session_id: &str,
    run_id: &str,
) -> DynResult<AnalysisResult> {
    let store = RuntimeStore::open(project_dir)?;
    let project = load_project(project_dir)?;
    let session = store.read_session(session_id)?;
    let run_artifacts = store.read_run_artifacts(session_id, run_id)?;
    let diagnostics = sort_diagnostics(store.read_run_diagnostics(session_id, run_id)?);
    let historical_diagnostics = sort_diagnostics(store.read_diagnostic_index()?);
    let request =
        NormalizedAnalysisRequest::new(trigger, project.name.clone(), session.target_id.clone())
            .with_session_id(session_id)
            .with_run_id(run_id)
            .with_artifacts(run_artifact_refs(&run_artifacts))
            .with_artifact_documents(run_artifact_documents(project_dir, &run_artifacts)?)
            .with_diagnostics(diagnostics)
            .with_historical_diagnostics(historical_diagnostics);

    let mut result = fat_analyze::built_in_engine().analyze_request(&request);
    persist_run_findings(&store, session_id, run_id, &result.findings)?;
    persist_run_diagnostics(&store, session_id, &result.diagnostics)?;
    result.produced_artifact_ids = persist_produced_artifacts(
        &store,
        &project,
        &session.target_id,
        Some(session_id),
        Some(run_id),
        &result.produced_artifacts,
    )?;
    Ok(result)
}

fn target_artifact_refs(artifacts: &[TargetArtifactRecord]) -> Vec<ArtifactRef> {
    let mut refs = artifacts
        .iter()
        .map(|artifact| {
            ArtifactRef::new(&artifact.artifact_id, artifact.kind, ArtifactScope::Target)
        })
        .collect::<Vec<_>>();
    refs.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    refs
}

fn run_artifact_refs(artifacts: &[ArtifactRecord]) -> Vec<ArtifactRef> {
    let mut refs = artifacts
        .iter()
        .map(|artifact| ArtifactRef::new(&artifact.artifact_id, artifact.kind, ArtifactScope::Run))
        .collect::<Vec<_>>();
    refs.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    refs
}

fn target_artifact_documents(
    project_dir: &Path,
    artifacts: &[TargetArtifactRecord],
) -> DynResult<Vec<ArtifactDocument>> {
    let mut documents = artifacts
        .iter()
        .map(|artifact| {
            build_document(
                project_dir,
                ArtifactScope::Target,
                &artifact.artifact_id,
                artifact.kind,
                &artifact.subkind,
                &artifact.path,
                &artifact.content_type,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    documents.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(documents)
}

fn run_artifact_documents(
    project_dir: &Path,
    artifacts: &[ArtifactRecord],
) -> DynResult<Vec<ArtifactDocument>> {
    let mut documents = artifacts
        .iter()
        .map(|artifact| {
            build_document(
                project_dir,
                ArtifactScope::Run,
                &artifact.artifact_id,
                artifact.kind,
                &artifact.subkind,
                &artifact.path,
                &artifact.content_type,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    documents.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(documents)
}

fn build_document(
    project_dir: &Path,
    scope: ArtifactScope,
    artifact_id: &str,
    kind: fat_core::artifacts::ArtifactKind,
    subkind: &str,
    path: &str,
    content_type: &str,
) -> DynResult<ArtifactDocument> {
    let artifact_path = std::path::PathBuf::from(path);
    let rel_path = artifact_path
        .strip_prefix(project_dir)
        .ok()
        .map(|path| path.display().to_string())
        .or_else(|| Some(path.to_string()));
    let text_content = if content_type.starts_with("text/") || content_type == "application/json" {
        Some(fs::read_to_string(&artifact_path)?)
    } else {
        None
    };

    Ok(ArtifactDocument::new(
        artifact_id,
        kind,
        scope,
        subkind,
        rel_path,
        content_type,
        text_content,
    ))
}

fn persist_target_findings(
    store: &RuntimeStore,
    target_id: &str,
    findings: &[Finding],
) -> DynResult<()> {
    for finding in findings {
        store.write_target_finding(target_id, finding)?;
    }
    Ok(())
}

fn persist_run_findings(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
    findings: &[Finding],
) -> DynResult<()> {
    for finding in findings {
        store.write_run_finding(session_id, run_id, finding)?;
    }
    Ok(())
}

fn persist_run_diagnostics(
    store: &RuntimeStore,
    session_id: &str,
    diagnostics: &[DiagnosticRecord],
) -> DynResult<()> {
    for diagnostic in diagnostics {
        store.write_diagnostic(session_id, diagnostic)?;
        store.append_diagnostic_index(diagnostic)?;
    }
    Ok(())
}

fn persist_target_diagnostics(
    store: &RuntimeStore,
    project: &Project,
    target_id: &str,
    diagnostics: &[DiagnosticRecord],
) -> DynResult<()> {
    for diagnostic in diagnostics {
        store.write_target_diagnostic(&TargetDiagnosticRecord::from_runless_diagnostic(
            project.name.clone(),
            target_id.to_string(),
            diagnostic,
        ))?;
    }
    Ok(())
}

fn persist_produced_artifacts(
    store: &RuntimeStore,
    project: &Project,
    target_id: &str,
    session_id: Option<&str>,
    run_id: Option<&str>,
    artifacts: &[ProducedArtifact],
) -> DynResult<Vec<String>> {
    let mut artifact_ids = Vec::new();
    for artifact in artifacts {
        match artifact.scope {
            ArtifactScope::Run => {
                let Some(session_id) = session_id else {
                    continue;
                };
                let Some(run_id) = run_id else {
                    continue;
                };
                let persisted =
                    persist_run_artifact(store, project, target_id, session_id, run_id, artifact)?;
                artifact_ids.push(persisted.artifact_id);
            }
            ArtifactScope::Target => {
                let persisted = persist_target_artifact(store, project, target_id, artifact)?;
                artifact_ids.push(persisted.artifact_id);
            }
        }
    }
    Ok(artifact_ids)
}

fn persist_run_artifact(
    store: &RuntimeStore,
    project: &Project,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    artifact: &ProducedArtifact,
) -> DynResult<ArtifactRecord> {
    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&outputs_dir)?;
    let path = outputs_dir.join(format!("{}.json", artifact.subkind));
    fs::write(&path, &artifact.text_content)?;
    let record = ArtifactRecord::new(
        project.name.clone(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        artifact.kind,
        artifact.subkind.clone(),
        "analyzer",
        artifact.subkind.clone(),
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        artifact.content_type.clone(),
        artifact.text_content.len() as u64,
        None,
        artifact.provenance.clone(),
        fat_core::artifacts::ArtifactRetentionPolicy::Session,
    )
    .with_labels(artifact.labels.clone())
    .with_related_artifact_ids(artifact.related_artifact_ids.clone())
    .with_phase("analysis");
    store.write_artifact(&record)?;
    store.append_artifact_index(&record)?;
    Ok(record)
}

fn persist_target_artifact(
    store: &RuntimeStore,
    project: &Project,
    target_id: &str,
    artifact: &ProducedArtifact,
) -> DynResult<TargetArtifactRecord> {
    let outputs_dir = store.project_dir().join("analysis").join("generated");
    fs::create_dir_all(&outputs_dir)?;
    let path = outputs_dir.join(format!("{}.json", artifact.subkind));
    fs::write(&path, &artifact.text_content)?;
    let record = TargetArtifactRecord::new(
        project.name.clone(),
        target_id.to_string(),
        artifact.kind,
        artifact.subkind.clone(),
        "analyzer",
        artifact.subkind.clone(),
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        artifact.content_type.clone(),
        artifact.text_content.len() as u64,
        None,
        artifact.provenance.clone(),
        fat_core::artifacts::ArtifactRetentionPolicy::Project,
    )
    .with_labels(artifact.labels.clone())
    .with_related_artifact_ids(artifact.related_artifact_ids.clone())
    .with_phase("analysis");
    store.write_target_artifact(&record)?;
    store.append_target_artifact_index(&record)?;
    Ok(record)
}

fn current_timestamp_string() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis();
    format!("unix-ms:{millis}")
}

fn load_project(project_dir: &Path) -> DynResult<Project> {
    let db = ProjectDb::open(project_dir)?;
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn sort_diagnostics(mut diagnostics: Vec<DiagnosticRecord>) -> Vec<DiagnosticRecord> {
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics
}
