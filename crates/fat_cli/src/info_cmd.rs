use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Serialize;

use fat_core::artifacts::ArtifactRecord;
use fat_core::database::ProjectDb;
use fat_core::diff::{diff_runs, summarize_session};
use fat_core::project::Project;
use fat_core::rehosting_policy::SelectionTrace;
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runtime_store::RuntimeStore;
use fat_core::services::{
    managed_runtime_phase_signature_from_json, managed_runtime_phase_signature_from_summary_json,
    managed_runtime_summary_from_runtime_status_json, managed_runtime_summary_from_summary_json,
    services_from_runtime_state_json, services_from_runtime_summary_json, ServiceSummaryArtifact,
};
use fat_core::targets::derive_target_id;

use crate::debug_cmd::load_latest_readiness_report;
use crate::emulate_cmd::parse_unix_ms;
use crate::{emulate_cmd, run_cmd};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
struct FatInfoSummary {
    project: FatProjectIdentity,
    target: FatTargetIdentity,
    counts: FatProjectCounts,
    active_runtime: Option<FatActiveRuntimeSummary>,
    latest_session: Option<FatLatestSessionSummary>,
}

#[derive(Debug, Serialize)]
struct FatProjectIdentity {
    name: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct FatTargetIdentity {
    display_name: String,
    target_id: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct FatProjectCounts {
    target_artifacts: usize,
    target_findings: usize,
    target_diagnostics: usize,
    analysis_artifacts: usize,
    diagnostic_support_artifacts: usize,
    session_records: usize,
    run_records: usize,
}

#[derive(Debug, Serialize)]
struct FatActiveRuntimeSummary {
    session_id: String,
    run_id: String,
    recipe_id: String,
    backend: String,
    substrate: String,
    logical_substrate: Option<String>,
    substrate_preference: Option<String>,
    session_status: String,
    run_status: String,
    health_state: String,
    diagnostics: usize,
    active_endpoints: usize,
    runtime_phase: Option<String>,
    readiness_summary: Option<String>,
    readiness_surface_count: usize,
    requested_readiness_goals: usize,
    validated_readiness_goals: usize,
    fidelity_caveats: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FatLatestSessionSummary {
    session_id: String,
    run_count: usize,
    total_findings: usize,
    total_diagnostics: usize,
    service_names: Vec<String>,
    runtime_states: Vec<String>,
}

pub fn run(project_dir: &Path, json: bool) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let project = load_project(&db, &project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let target_id = derive_target_id(&project.name, &project.firmware_name);
    let target = store.read_target(&target_id).map_err(|err| {
        format!(
            "target record missing for {} ({target_id}): {err}",
            project.name
        )
    })?;
    let target_artifacts = store.read_target_artifacts(&target_id)?;
    let target_findings = sort_findings(store.read_target_findings(&target_id)?);
    let target_diagnostics = sort_target_diagnostics(store.read_target_diagnostics(&target_id)?);
    let sessions = latest_sessions(&store)?;
    let session_count = count_direct_children(&project_dir.join("sessions"))?;
    let run_count = count_run_children(&project_dir.join("sessions"))?;
    let analysis_count = target_artifacts
        .iter()
        .filter(|artifact| matches!(artifact.kind, fat_core::artifacts::ArtifactKind::Analysis))
        .count();
    let diagnostic_support_count = target_artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.kind,
                fat_core::artifacts::ArtifactKind::DiagnosticSupport
            )
        })
        .count();
    let active_runtime = emulate_cmd::load_runtime_view_with_refresh(&project_dir, &store, None)?;
    let latest_session_summary = sessions
        .last()
        .map(|session| {
            let run_ids = session.run_ids.clone();
            let (summary, _) = summarize_session_state(&store, &session.session_id, &run_ids)?;
            Ok::<FatLatestSessionSummary, Box<dyn Error>>(FatLatestSessionSummary {
                session_id: session.session_id.clone(),
                run_count: summary.run_count,
                total_findings: summary.total_findings,
                total_diagnostics: summary.total_diagnostics,
                service_names: summary.service_names,
                runtime_states: summary.runtime_states,
            })
        })
        .transpose()?;

    let palette = crate::style::Palette::stdout();
    if json {
        let summary = FatInfoSummary {
            project: FatProjectIdentity {
                name: project.name.clone(),
                path: project_dir.display().to_string(),
            },
            target: FatTargetIdentity {
                display_name: target.display_name.clone(),
                target_id: target.target_id.clone(),
                created_at: target.created_at.clone(),
                updated_at: target.updated_at.clone(),
            },
            counts: FatProjectCounts {
                target_artifacts: target_artifacts.len(),
                target_findings: target_findings.len(),
                target_diagnostics: target_diagnostics.len(),
                analysis_artifacts: analysis_count,
                diagnostic_support_artifacts: diagnostic_support_count,
                session_records: session_count,
                run_records: run_count,
            },
            active_runtime: active_runtime
                .as_ref()
                .map(|view| build_active_runtime_summary(&store, view))
                .transpose()?,
            latest_session: latest_session_summary,
        };
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    if palette.enabled() {
        render_info_panel(
            &palette,
            &project,
            &project_dir,
            &target,
            target_artifacts.len(),
            target_findings.len(),
            target_diagnostics.len(),
            analysis_count,
            diagnostic_support_count,
            session_count,
            run_count,
        );
        if let Some(view) = active_runtime {
            print!("{}", run_cmd::render_runtime_view("active ", &view));
        }
        if let Some(session) = sessions.last() {
            let run_ids = session.run_ids.clone();
            let (summary, diff) = summarize_session_state(&store, &session.session_id, &run_ids)?;
            println!(
                "session summary: {} runs, {} findings, {} diagnostics",
                summary.run_count, summary.total_findings, summary.total_diagnostics
            );
            if !summary.service_names.is_empty() {
                println!("session services: {}", summary.service_names.join(", "));
            }
            if !summary.runtime_states.is_empty() {
                println!(
                    "session runtime states: {}",
                    summary.runtime_states.join(", ")
                );
            }
            if let Some(diff) = diff {
                println!(
                    "what changed between attempts ({} -> {}):",
                    diff.base_run_id, diff.head_run_id
                );
                render_changes("added services", &diff.added_services);
                render_changes("removed services", &diff.removed_services);
                render_changes("added runtime states", &diff.added_runtime_states);
                render_changes("removed runtime states", &diff.removed_runtime_states);
                render_changes("added findings", &diff.added_findings);
                render_changes("removed findings", &diff.removed_findings);
                render_changes("added diagnostics", &diff.added_diagnostics);
                render_changes("removed diagnostics", &diff.removed_diagnostics);
            }
        }
        println!("{}", info_next_hint(&palette, project.status));
        return Ok(());
    }

    println!("project: {}", project.name);
    println!("target: {}", target.display_name);
    println!("target id: {}", target.target_id);
    println!("target created_at: {}", target.created_at);
    println!("target updated_at: {}", target.updated_at);
    println!("target artifacts: {}", target_artifacts.len());
    println!("target findings: {}", target_findings.len());
    println!("target diagnostics: {}", target_diagnostics.len());
    println!("analysis artifacts: {analysis_count}");
    println!("diagnostic support artifacts: {diagnostic_support_count}");
    println!("session records: {session_count}");
    println!("run records: {run_count}");

    if let Some(view) = active_runtime {
        let active_summary = build_active_runtime_summary(&store, &view)?;
        print!("{}", run_cmd::render_runtime_view("active ", &view));
        if let Some(logical_substrate) = active_summary.logical_substrate.as_deref() {
            println!("active logical substrate: {logical_substrate}");
        }
        if let Some(substrate_preference) = active_summary.substrate_preference.as_deref() {
            println!("active substrate preference: {substrate_preference}");
        }
        for caveat in &active_summary.fidelity_caveats {
            println!("active fidelity caveat: {caveat}");
        }
        render_readiness_summary(
            &store,
            &view.session.session_id,
            &view.run.run_id,
            "active ",
        )?;
        render_managed_runtime_summary(
            &store,
            &view.session.session_id,
            &view.run.run_id,
            "active ",
        )?;
    }

    if let Some(session) = sessions.last() {
        let run_ids = session.run_ids.clone();
        let (summary, diff) = summarize_session_state(&store, &session.session_id, &run_ids)?;
        println!(
            "session summary: {} runs, {} findings, {} diagnostics",
            summary.run_count, summary.total_findings, summary.total_diagnostics
        );
        if !summary.service_names.is_empty() {
            println!("session services: {}", summary.service_names.join(", "));
        }
        if !summary.runtime_states.is_empty() {
            println!(
                "session runtime states: {}",
                summary.runtime_states.join(", ")
            );
        }

        if let Some(diff) = diff {
            println!(
                "what changed between attempts ({} -> {}):",
                diff.base_run_id, diff.head_run_id
            );
            render_changes("added services", &diff.added_services);
            render_changes("removed services", &diff.removed_services);
            render_changes("added runtime states", &diff.added_runtime_states);
            render_changes("removed runtime states", &diff.removed_runtime_states);
            render_changes("added findings", &diff.added_findings);
            render_changes("removed findings", &diff.removed_findings);
            render_changes("added diagnostics", &diff.added_diagnostics);
            render_changes("removed diagnostics", &diff.removed_diagnostics);
        }
    }

    Ok(())
}

fn build_active_runtime_summary(
    store: &RuntimeStore,
    view: &run_cmd::RuntimeView,
) -> DynResult<FatActiveRuntimeSummary> {
    let readiness_report =
        load_latest_readiness_report(store, &view.session.session_id, &view.run.run_id)?;
    let rehosting_recipe =
        load_latest_rehosting_recipe(store, &view.session.session_id, &view.run.run_id)?;
    let selection_trace =
        load_latest_selection_trace(store, &view.session.session_id, &view.run.run_id)?;
    Ok(FatActiveRuntimeSummary {
        session_id: view.session.session_id.clone(),
        run_id: view.run.run_id.clone(),
        recipe_id: view.run.recipe_id.clone(),
        backend: view.run.backend_driver.clone(),
        substrate: view.run.substrate_kind.as_str().to_string(),
        logical_substrate: rehosting_recipe
            .as_ref()
            .map(|recipe| recipe.selected_substrate.as_str().to_string()),
        substrate_preference: selection_trace
            .as_ref()
            .map(|trace| trace.preference.as_str().to_string()),
        session_status: view.session.status.as_str().to_string(),
        run_status: run_status_label(view.run.status).to_string(),
        health_state: view.run.health_state.as_str().to_string(),
        diagnostics: view.diagnostics.len(),
        active_endpoints: view.run.active_endpoints.len(),
        runtime_phase: load_runtime_phase_signature(
            store,
            &view.session.session_id,
            &view.run.run_id,
        )?,
        readiness_summary: readiness_report
            .as_ref()
            .and_then(|report| report.summary.clone()),
        readiness_surface_count: readiness_report
            .as_ref()
            .map(|report| report.surfaces.len())
            .unwrap_or(0),
        requested_readiness_goals: readiness_report
            .as_ref()
            .map(|report| report.requested_goals.len())
            .unwrap_or(0),
        validated_readiness_goals: readiness_report
            .as_ref()
            .map(|report| report.validated_goals.len())
            .unwrap_or(0),
        fidelity_caveats: rehosting_recipe
            .map(|recipe| recipe.fidelity_caveats)
            .unwrap_or_default(),
    })
}

fn load_latest_rehosting_recipe(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<RehostingRecipe>> {
    let recipes_dir = store
        .run_path(session_id, run_id)
        .parent()
        .ok_or("run path missing parent")?
        .join("rehosting")
        .join("recipes");
    if !recipes_dir.exists() {
        return Ok(None);
    }

    let mut records: Vec<RehostingRecipe> = fs::read_dir(&recipes_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<RehostingRecipe>(&bytes).ok())
        .collect();
    records.sort_by(|left, right| left.rehosting_recipe_id.cmp(&right.rehosting_recipe_id));
    Ok(records.pop())
}

fn load_latest_selection_trace(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<SelectionTrace>> {
    let selection_dir = store
        .run_path(session_id, run_id)
        .parent()
        .ok_or("run path missing parent")?
        .join("rehosting")
        .join("selection");
    if !selection_dir.exists() {
        return Ok(None);
    }

    let mut records: Vec<SelectionTrace> = fs::read_dir(&selection_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<SelectionTrace>(&bytes).ok())
        .collect();
    records.sort_by(|left, right| left.selection_trace_id.cmp(&right.selection_trace_id));
    Ok(records.pop())
}

fn render_readiness_summary(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
    prefix: &str,
) -> DynResult<()> {
    let Some(report) = load_latest_readiness_report(store, session_id, run_id)? else {
        return Ok(());
    };

    if let Some(summary) = report.summary.as_deref() {
        println!("{prefix}readiness summary: {summary}");
    }
    println!(
        "{prefix}readiness goals: {}/{} validated",
        report.validated_goals.len(),
        report.requested_goals.len()
    );
    println!("{prefix}readiness surfaces: {}", report.surfaces.len());
    Ok(())
}

fn normalize_project_dir(project_dir: &Path) -> DynResult<std::path::PathBuf> {
    if project_dir.is_dir() {
        Ok(project_dir.to_path_buf())
    } else {
        Err(format!("project path does not exist: {}", project_dir.display()).into())
    }
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn count_direct_children(dir: &Path) -> DynResult<usize> {
    if !dir.exists() {
        return Ok(0);
    }

    Ok(fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .count())
}

fn count_run_children(sessions_dir: &Path) -> DynResult<usize> {
    if !sessions_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for session in fs::read_dir(sessions_dir)? {
        let session = session?;
        let runs_dir = session.path().join("runs");
        if !runs_dir.exists() {
            continue;
        }
        count += fs::read_dir(runs_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .count();
    }

    Ok(count)
}

fn latest_sessions(store: &RuntimeStore) -> DynResult<Vec<fat_core::sessions::SessionRecord>> {
    let mut sessions = store.read_sessions()?;
    sessions.sort_by_key(|session| parse_unix_ms(&session.updated_at));
    Ok(sessions)
}

fn load_runtime_phase_signature(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<String>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    if let Some(summary) = read_latest_runtime_state(&artifacts, "managed-runtime-summary")? {
        let summary = managed_runtime_summary_from_summary_json(&summary.to_string())
            .map(|summary| summary.runtime_phase);
        if summary.is_some() {
            return Ok(summary);
        }
    }

    if let Some(status) = read_latest_runtime_state(&artifacts, "managed-runtime-status")? {
        let summary = managed_runtime_summary_from_runtime_status_json(&status.to_string())
            .map(|summary| summary.runtime_phase);
        if summary.is_some() {
            return Ok(summary);
        }
    }

    Ok(extract_runtime_states(store, session_id, run_id)?
        .into_iter()
        .next())
}

fn summarize_session_state(
    store: &RuntimeStore,
    session_id: &str,
    run_ids: &[String],
) -> DynResult<(
    fat_core::diff::SessionSummary,
    Option<fat_core::diff::RunDiff>,
)> {
    let mut all_findings = Vec::new();
    let mut all_diagnostics = Vec::new();
    let mut all_services = Vec::new();
    let mut all_runtime_states = Vec::new();

    for run_id in run_ids {
        all_findings.extend(sort_findings(store.read_run_findings(session_id, run_id)?));
        all_diagnostics.extend(sort_diagnostics(
            store.read_run_diagnostics(session_id, run_id)?,
        ));
        all_services.extend(extract_services(store, session_id, run_id)?);
        all_runtime_states.extend(extract_runtime_states(store, session_id, run_id)?);
    }

    let summary = summarize_session(
        session_id,
        run_ids.len(),
        &all_findings,
        &all_diagnostics,
        &all_services,
        &all_runtime_states,
    );

    let diff = if run_ids.len() >= 2 {
        let base_run_id = &run_ids[run_ids.len() - 2];
        let head_run_id = &run_ids[run_ids.len() - 1];
        Some(diff_runs(
            base_run_id,
            head_run_id,
            &sort_findings(store.read_run_findings(session_id, base_run_id)?),
            &sort_findings(store.read_run_findings(session_id, head_run_id)?),
            &sort_diagnostics(store.read_run_diagnostics(session_id, base_run_id)?),
            &sort_diagnostics(store.read_run_diagnostics(session_id, head_run_id)?),
            &extract_services(store, session_id, base_run_id)?,
            &extract_services(store, session_id, head_run_id)?,
            &extract_runtime_states(store, session_id, base_run_id)?,
            &extract_runtime_states(store, session_id, head_run_id)?,
        ))
    } else {
        None
    };

    Ok((summary, diff))
}

fn extract_services(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Vec<String>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    let mut services = Vec::new();

    if let Some(summary) = read_latest_runtime_state(&artifacts, "managed-runtime-summary")? {
        services.extend(extract_services_from_managed_runtime_summary(&summary));
        if !services.is_empty() {
            services.sort();
            services.dedup();
            return Ok(services);
        }
    }

    if let Some(status) = read_latest_runtime_state(&artifacts, "managed-runtime-status")? {
        services.extend(extract_services_from_managed_runtime_status(&status));
        if !services.is_empty() {
            services.sort();
            services.dedup();
            return Ok(services);
        }
    }

    for artifact in artifacts {
        if artifact.kind != fat_core::artifacts::ArtifactKind::RuntimeState
            || artifact.subkind != "service-summary"
            || artifact.content_type != "application/json"
        {
            continue;
        }
        let content = fs::read_to_string(&artifact.path)?;
        let summary: ServiceSummaryArtifact = serde_json::from_str(&content)?;
        services.extend(summary.service_labels());
    }

    services.sort();
    services.dedup();
    Ok(services)
}

fn extract_runtime_states(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Vec<String>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    if let Some(artifact) = artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == fat_core::artifacts::ArtifactKind::RuntimeState
                && artifact.subkind == "managed-runtime-summary"
                && artifact.content_type == "application/json"
        })
        .max_by_key(|artifact| parse_unix_ms(&artifact.created_at))
    {
        let content = fs::read_to_string(&artifact.path)?;
        return Ok(managed_runtime_phase_signature_from_summary_json(&content)
            .into_iter()
            .collect());
    }

    let Some(artifact) = artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == fat_core::artifacts::ArtifactKind::RuntimeState
                && artifact.subkind == "managed-runtime-status"
                && artifact.content_type == "application/json"
        })
        .max_by_key(|artifact| parse_unix_ms(&artifact.created_at))
    else {
        return Ok(Vec::new());
    };
    let content = fs::read_to_string(&artifact.path)?;
    Ok(managed_runtime_phase_signature_from_json(&content)
        .into_iter()
        .collect())
}

fn extract_services_from_managed_runtime_status(state: &serde_json::Value) -> Vec<String> {
    services_from_runtime_state_json(&state.to_string())
        .into_iter()
        .map(|service| service.display_label())
        .collect()
}

fn extract_services_from_managed_runtime_summary(state: &serde_json::Value) -> Vec<String> {
    services_from_runtime_summary_json(&state.to_string())
        .into_iter()
        .map(|service| service.display_label())
        .collect()
}

fn sort_findings(mut findings: Vec<fat_core::finding::Finding>) -> Vec<fat_core::finding::Finding> {
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    findings
}

fn sort_diagnostics(
    mut diagnostics: Vec<fat_core::diagnostics::DiagnosticRecord>,
) -> Vec<fat_core::diagnostics::DiagnosticRecord> {
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics
}

fn sort_target_diagnostics(
    mut diagnostics: Vec<fat_core::diagnostics::TargetDiagnosticRecord>,
) -> Vec<fat_core::diagnostics::TargetDiagnosticRecord> {
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics
}

fn run_status_label(status: fat_core::runs::RunStatus) -> &'static str {
    match status {
        fat_core::runs::RunStatus::Created => "created",
        fat_core::runs::RunStatus::Queued => "queued",
        fat_core::runs::RunStatus::Provisioning => "provisioning",
        fat_core::runs::RunStatus::Preparing => "preparing",
        fat_core::runs::RunStatus::Synthesizing => "synthesizing",
        fat_core::runs::RunStatus::Launching => "launching",
        fat_core::runs::RunStatus::Booting => "booting",
        fat_core::runs::RunStatus::UserspaceStarting => "userspace-starting",
        fat_core::runs::RunStatus::Running => "running",
        fat_core::runs::RunStatus::DegradedRunning => "degraded-running",
        fat_core::runs::RunStatus::Paused => "paused",
        fat_core::runs::RunStatus::Stopping => "stopping",
        fat_core::runs::RunStatus::Completed => "completed",
        fat_core::runs::RunStatus::DegradedCompleted => "degraded-completed",
        fat_core::runs::RunStatus::Failed => "failed",
        fat_core::runs::RunStatus::Cancelled => "cancelled",
        fat_core::runs::RunStatus::TimedOut => "timed-out",
        fat_core::runs::RunStatus::CleanupFailed => "cleanup-failed",
    }
}

fn render_changes(label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    println!("{label}: {}", values.join(", "));
}

/// Panel-mode project summary: status, grouped counts, and human-readable
/// timestamps. The facts are the same ones the plain listing prints; only the
/// layout, glyphs, and hint differ.
#[allow(clippy::too_many_arguments)]
fn render_info_panel(
    palette: &crate::style::Palette,
    project: &Project,
    project_dir: &Path,
    target: &fat_core::targets::TargetRecord,
    target_artifacts: usize,
    target_findings: usize,
    target_diagnostics: usize,
    analysis_artifacts: usize,
    diagnostic_support_artifacts: usize,
    session_records: usize,
    run_records: usize,
) {
    let (dot, word) = match project.status {
        fat_core::project::ProjectStatus::Created
        | fat_core::project::ProjectStatus::Extracted
        | fat_core::project::ProjectStatus::Analyzed
        | fat_core::project::ProjectStatus::Emulating => {
            (palette.dot_ok(), palette.good(project.status.as_str()))
        }
        fat_core::project::ProjectStatus::Extracting
        | fat_core::project::ProjectStatus::Analyzing => {
            (palette.dot_warn(), palette.warn(project.status.as_str()))
        }
        fat_core::project::ProjectStatus::Error => {
            (palette.dot_bad(), palette.bad(project.status.as_str()))
        }
    };

    let lines = vec![
        format!("{dot} status: {word}"),
        palette.kv("target", &target.display_name),
        palette.muted(format!("target id: {}", target.target_id)),
        format!(
            "{}  {}",
            render_unix_ms(palette, "created", &target.created_at),
            render_unix_ms(palette, "updated", &target.updated_at),
        ),
        String::new(),
        format!(
            "{} artifacts: {}  {}",
            palette.dot_ok(),
            target_artifacts,
            palette.muted(format!(
                "(analysis {analysis_artifacts} · diagnostic support {diagnostic_support_artifacts})"
            ))
        ),
        format!("{} findings: {}", palette.dot_warn(), target_findings),
        format!("{} diagnostics: {}", palette.dot_muted(), target_diagnostics),
        palette.kv(
            "sessions",
            format!("{session_records} sessions · {run_records} runs"),
        ),
        String::new(),
        palette.muted(project_dir.display().to_string()),
    ];
    println!(
        "{}",
        palette.panel(&format!("fat info · {}", project.name), &lines)
    );
}

/// The workflow hand-off for the project's current lifecycle position.
fn info_next_hint(
    palette: &crate::style::Palette,
    status: fat_core::project::ProjectStatus,
) -> String {
    let hint = match status {
        fat_core::project::ProjectStatus::Created
        | fat_core::project::ProjectStatus::Extracting => "fat extract <project>",
        fat_core::project::ProjectStatus::Extracted
        | fat_core::project::ProjectStatus::Analyzing => "fat analyze <project>",
        fat_core::project::ProjectStatus::Analyzed => "fat preflight <project>",
        fat_core::project::ProjectStatus::Emulating => "fat emulate <project> --status",
        fat_core::project::ProjectStatus::Error => "fat extract <project> --force",
    };
    palette.next_hint(hint)
}

/// Render a `unix-ms:` stamp as a UTC timestamp plus a coarse relative age,
/// keeping the raw stamp as dimmed metadata so machines still get the source
/// value. Anything unparseable prints verbatim.
fn render_unix_ms(palette: &crate::style::Palette, label: &str, raw: &str) -> String {
    let millis = raw
        .strip_prefix("unix-ms:")
        .and_then(|value| value.parse::<u128>().ok());
    let Some(millis) = millis else {
        return format!("{label}: {}", palette.muted(raw));
    };
    let seconds = (millis / 1000) as i64;
    let days = seconds.div_euclid(86_400);
    let day_secs = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (day_secs / 3600, (day_secs % 3600) / 60, day_secs % 60);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_secs() as i64)
        .unwrap_or(seconds);
    let age = now_secs - seconds;
    let relative = if age < 0 {
        String::new()
    } else if age < 60 {
        "just now".to_string()
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86_400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86_400)
    };
    let mut rendered =
        format!("{label} {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC");
    if !relative.is_empty() {
        rendered.push_str(&format!(" ({relative})"));
    }
    format!("{}  {}", rendered, palette.muted(raw))
}

/// Days since the Unix epoch to (year, month, day), proleptic Gregorian.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn render_managed_runtime_summary(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
    prefix: &str,
) -> DynResult<()> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    if let Some(runtime_summary) = read_latest_runtime_state(&artifacts, "managed-runtime-summary")?
    {
        if let Some(summary) =
            managed_runtime_summary_from_summary_json(&runtime_summary.to_string())
        {
            println!(
                "{prefix}managed control contract: {}",
                summary.control_contract
            );
            println!("{prefix}managed driver profile: {}", summary.driver_profile);
            println!(
                "{prefix}managed lifecycle adapter: {}",
                summary.lifecycle_adapter
            );
            println!("{prefix}managed runtime phase: {}", summary.runtime_phase);
            if let Some(ref value) = summary.runtime_outcome {
                println!("{prefix}managed runtime outcome: {value}");
            }
            if !summary.services.is_empty() {
                println!(
                    "{prefix}managed services: {}",
                    summary.service_labels().join(", ")
                );
            }
            if let Some(value) = summary.launch_mode {
                println!("{prefix}managed launch mode: {value}");
            }
            if let Some(value) = summary.stop_mode {
                println!("{prefix}managed stop mode: {value}");
            }
            if let Some(value) = summary.launch_manifest_present {
                println!("{prefix}managed launch manifest present: {value}");
            }
            if let Some(value) = summary.probe_result_contract {
                println!("{prefix}managed probe result contract: {value}");
            }
            if let Some(value) = summary.probe_result_contract_verified {
                println!("{prefix}managed probe result contract verified: {value}");
            }
            if let Some(value) = summary.probe_source {
                println!("{prefix}managed last probe source: {value}");
            }
            if let Some(value) = summary.probe_outcome {
                println!("{prefix}managed last probe outcome: {value}");
            }
            if let Some(value) = summary.stop_result_contract {
                println!("{prefix}managed stop result contract: {value}");
            }
            if let Some(value) = summary.stop_result_contract_verified {
                println!("{prefix}managed stop result contract verified: {value}");
            }
            if let Some(value) = summary.workspace_removed {
                println!("{prefix}managed workspace removed: {value}");
            }
        }
        return Ok(());
    }

    if let Some(runtime_status) = read_latest_runtime_state(&artifacts, "managed-runtime-status")? {
        if let Some(summary) =
            managed_runtime_summary_from_runtime_status_json(&runtime_status.to_string())
        {
            println!(
                "{prefix}managed control contract: {}",
                summary.control_contract
            );
            println!("{prefix}managed driver profile: {}", summary.driver_profile);
            println!(
                "{prefix}managed lifecycle adapter: {}",
                summary.lifecycle_adapter
            );
            println!("{prefix}managed runtime phase: {}", summary.runtime_phase);
            if let Some(ref value) = summary.runtime_outcome {
                println!("{prefix}managed runtime outcome: {value}");
            }
            if let Some(value) = summary.launch_mode {
                println!("{prefix}managed launch mode: {value}");
            }
            if let Some(value) = summary.stop_mode {
                println!("{prefix}managed stop mode: {value}");
            }
            if let Some(value) = summary.launch_manifest_present {
                println!("{prefix}managed launch manifest present: {value}");
            }
            if let Some(value) = summary.probe_result_contract {
                println!("{prefix}managed probe result contract: {value}");
            }
            if let Some(value) = summary.probe_result_contract_verified {
                println!("{prefix}managed probe result contract verified: {value}");
            }
            if let Some(value) = summary.probe_source {
                println!("{prefix}managed last probe source: {value}");
            }
            if let Some(value) = summary.probe_outcome {
                println!("{prefix}managed last probe outcome: {value}");
            }
            if let Some(value) = summary.stop_result_contract {
                println!("{prefix}managed stop result contract: {value}");
            }
            if let Some(value) = summary.stop_result_contract_verified {
                println!("{prefix}managed stop result contract verified: {value}");
            }
            if let Some(value) = summary.workspace_removed {
                println!("{prefix}managed workspace removed: {value}");
            }
        }
        return Ok(());
    }

    let Some(launch_state) =
        read_latest_runtime_state(&artifacts, "managed-linux-vm-launch-state")?
    else {
        return Ok(());
    };

    render_managed_field(
        prefix,
        "managed control contract",
        &launch_state,
        "control_contract",
    );
    render_managed_field(
        prefix,
        "managed driver profile",
        &launch_state,
        "driver_profile",
    );
    render_managed_field(
        prefix,
        "managed lifecycle adapter",
        &launch_state,
        "lifecycle_adapter",
    );
    render_managed_field(prefix, "managed launch mode", &launch_state, "launch_mode");
    render_managed_field(prefix, "managed stop mode", &launch_state, "stop_mode");
    render_managed_bool_field(
        prefix,
        "managed launch manifest present",
        &launch_state,
        "launch_manifest_present",
    );

    if let Some(probe_state) =
        read_latest_runtime_state(&artifacts, "managed-linux-vm-probe-state")?
    {
        render_managed_field(
            prefix,
            "managed probe result contract",
            &probe_state,
            "result_contract",
        );
        render_managed_bool_field(
            prefix,
            "managed probe result contract verified",
            &probe_state,
            "result_contract_verified",
        );
        render_managed_field(
            prefix,
            "managed last probe source",
            &probe_state,
            "probe_source",
        );
        render_managed_field(
            prefix,
            "managed last probe outcome",
            &probe_state,
            "outcome",
        );
    }

    if let Some(stop_state) = read_latest_runtime_state(&artifacts, "managed-linux-vm-stop-state")?
    {
        render_managed_field(
            prefix,
            "managed stop result contract",
            &stop_state,
            "result_contract",
        );
        render_managed_bool_field(
            prefix,
            "managed stop result contract verified",
            &stop_state,
            "result_contract_verified",
        );
        render_managed_field(prefix, "managed stop mode", &stop_state, "stop_mode");
        render_managed_bool_field(
            prefix,
            "managed workspace removed",
            &stop_state,
            "workspace_removed",
        );
    }

    Ok(())
}

fn read_latest_runtime_state(
    artifacts: &[ArtifactRecord],
    subkind: &str,
) -> DynResult<Option<serde_json::Value>> {
    let Some(artifact) = artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == fat_core::artifacts::ArtifactKind::RuntimeState
                && artifact.subkind == subkind
                && artifact.content_type == "application/json"
        })
        .max_by_key(|artifact| parse_unix_ms(&artifact.created_at))
    else {
        return Ok(None);
    };

    Ok(Some(serde_json::from_slice(&fs::read(&artifact.path)?)?))
}

fn render_managed_field(prefix: &str, label: &str, state: &serde_json::Value, key: &str) {
    if let Some(value) = state.get(key).and_then(|value| value.as_str()) {
        println!("{prefix}{label}: {value}");
    }
}

fn render_managed_bool_field(prefix: &str, label: &str, state: &serde_json::Value, key: &str) {
    if let Some(value) = state.get(key).and_then(|value| value.as_bool()) {
        println!("{prefix}{label}: {value}");
    }
}
