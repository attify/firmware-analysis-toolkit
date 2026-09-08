use std::error::Error;
use std::fs;

use crate::emulate_cmd::parse_unix_ms;
use fat_core::diagnostics::DiagnosticRecord;
use fat_core::runs::{RunRecord, RuntimeEndpoint};
use fat_core::runtime_store::RuntimeStore;
use fat_core::sessions::SessionRecord;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone)]
pub struct RuntimeView {
    pub session: SessionRecord,
    pub run: RunRecord,
    pub diagnostics: Vec<DiagnosticRecord>,
}

pub fn load_runtime_view(
    store: &RuntimeStore,
    requested_session_id: Option<&str>,
) -> DynResult<Option<RuntimeView>> {
    let session = match requested_session_id {
        Some(session_id) => resolve_session(store, session_id)?,
        None => latest_session(store)?,
    };

    let Some(session) = session else {
        return Ok(None);
    };
    let Some(run) = load_run_for_session(store, &session)? else {
        return Ok(None);
    };
    let diagnostics = load_diagnostics_for_run(store, &session.session_id, &run.run_id)?;

    Ok(Some(RuntimeView {
        session,
        run,
        diagnostics,
    }))
}

fn resolve_session(
    store: &RuntimeStore,
    session_id_or_alias: &str,
) -> DynResult<Option<SessionRecord>> {
    match store.read_session(session_id_or_alias) {
        Ok(session) => Ok(Some(session)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut sessions = store.read_sessions()?;
            sessions.sort_by_key(|session| parse_unix_ms(&session.updated_at));
            Ok(sessions.into_iter().rev().find(|session| {
                session.requested_session_id.as_deref() == Some(session_id_or_alias)
            }))
        }
        Err(err) => Err(err.into()),
    }
}

pub fn render_runtime_view(prefix: &str, view: &RuntimeView) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "session"),
        view.session.session_id
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "run"),
        view.run.run_id
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "recipe"),
        view.run.recipe_id
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "backend"),
        view.run.backend_driver
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "substrate"),
        view.run.substrate_kind.as_str()
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "status"),
        view.session.status.as_str()
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "session status"),
        view.session.status.as_str()
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "run-status"),
        run_status_label(view.run.status)
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "run status"),
        run_status_label(view.run.status)
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "supervision mode"),
        view.run.supervision_mode.as_str()
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "health state"),
        view.run.health_state.as_str()
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "last health check"),
        view.run.last_health_check_at.as_deref().unwrap_or("never")
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "supervisor pid"),
        view.run
            .supervisor_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "none".to_string())
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "last heartbeat"),
        view.run.last_heartbeat_at.as_deref().unwrap_or("never")
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_key(prefix, "supervision lease expires"),
        view.run
            .supervision_lease_expires_at
            .as_deref()
            .unwrap_or("never")
    ));
    output.push_str(&format!(
        "{}: {}\n",
        prefixed_endpoints_key(prefix),
        view.run.active_endpoints.len()
    ));
    for endpoint in &view.run.active_endpoints {
        output.push_str(&format!("{}\n", format_endpoint(endpoint)));
    }
    if !view.diagnostics.is_empty() {
        output.push_str(&format!("diagnostics: {}\n", view.diagnostics.len()));
    }
    output
}

fn prefixed_endpoints_key(prefix: &str) -> String {
    if prefix.is_empty() {
        "active endpoints".to_string()
    } else {
        prefixed_key(prefix, "endpoints")
    }
}

fn format_endpoint(endpoint: &RuntimeEndpoint) -> String {
    match &endpoint.uri {
        Some(uri) => format!("endpoint {}: {}", endpoint.name, uri),
        None => format!(
            "endpoint {}: {}:{}",
            endpoint.name, endpoint.host, endpoint.port
        ),
    }
}

fn prefixed_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}{key}")
    }
}

fn latest_session(store: &RuntimeStore) -> DynResult<Option<SessionRecord>> {
    let sessions_dir = store.project_dir().join("sessions");
    if !sessions_dir.exists() {
        return Ok(None);
    }

    let mut sessions = Vec::new();
    for entry in fs::read_dir(sessions_dir)? {
        let entry = entry?;
        let path = entry.path().join("session.json");
        if !path.is_file() {
            continue;
        }
        sessions.push(serde_json::from_slice::<SessionRecord>(&fs::read(path)?)?);
    }

    sessions.sort_by_key(|session| parse_unix_ms(&session.updated_at));
    Ok(sessions.pop())
}

fn load_run_for_session(
    store: &RuntimeStore,
    session: &SessionRecord,
) -> DynResult<Option<RunRecord>> {
    if let Some(run_id) = session.run_ids.last() {
        return Ok(Some(store.read_run(&session.session_id, run_id)?));
    }

    let Some(runs_dir) = store
        .session_path(&session.session_id)
        .parent()
        .map(|path| path.join("runs"))
    else {
        return Ok(None);
    };
    if !runs_dir.exists() {
        return Ok(None);
    }

    let mut runs = Vec::new();
    for entry in fs::read_dir(runs_dir)? {
        let entry = entry?;
        let path = entry.path().join("run.json");
        if !path.is_file() {
            continue;
        }
        runs.push(serde_json::from_slice::<RunRecord>(&fs::read(path)?)?);
    }
    runs.sort_by_key(|run| run.sequence_in_session);
    Ok(runs.pop())
}

fn load_diagnostics_for_run(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Vec<DiagnosticRecord>> {
    let diagnostics_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("diagnostics"))
        .ok_or("run path missing parent")?;
    if !diagnostics_dir.exists() {
        return Ok(Vec::new());
    }

    let mut diagnostics = Vec::new();
    for entry in fs::read_dir(diagnostics_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        diagnostics.push(serde_json::from_slice::<DiagnosticRecord>(&fs::read(
            path,
        )?)?);
    }
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    Ok(diagnostics)
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
