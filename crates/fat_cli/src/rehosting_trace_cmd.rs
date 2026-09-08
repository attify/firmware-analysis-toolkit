use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Serialize;

use fat_core::database::ProjectDb;
use fat_core::rehosting_policy::{
    FallbackReason, SelectionTrace, SubstrateAttemptState, SubstrateKind as LogicalSubstrateKind,
    SubstratePreference,
};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runtime_store::RuntimeStore;

use crate::emulate_cmd;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
struct RehostingTraceView {
    session_id: String,
    run_id: String,
    backend: String,
    physical_substrate: String,
    logical_substrate: Option<String>,
    substrate_preference: Option<String>,
    attempts: Vec<RehostingTraceAttemptView>,
    fidelity_caveats: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RehostingTraceAttemptView {
    substrate: String,
    state: String,
    reason: Option<String>,
    detail: String,
}

pub fn run(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let project_dir = crate::normalize_project_dir(project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let _project = crate::load_project(&db, &project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let view = emulate_cmd::load_runtime_view_with_refresh(&project_dir, &store, session_id)?
        .ok_or("no runtime session records available")?;
    let selection_trace =
        load_latest_selection_trace(&store, &view.session.session_id, &view.run.run_id)?;
    let rehosting_recipe =
        load_latest_rehosting_recipe(&store, &view.session.session_id, &view.run.run_id)?;

    let trace = RehostingTraceView {
        session_id: view.session.session_id.clone(),
        run_id: view.run.run_id.clone(),
        backend: view.run.backend_driver.clone(),
        physical_substrate: view.run.substrate_kind.as_str().to_string(),
        logical_substrate: rehosting_recipe
            .as_ref()
            .map(|recipe| recipe.selected_substrate.as_str().to_string()),
        substrate_preference: selection_trace
            .as_ref()
            .map(|trace| substrate_preference_label(trace.preference).to_string()),
        attempts: selection_trace
            .as_ref()
            .map(|trace| {
                trace
                    .attempts
                    .iter()
                    .map(|attempt| RehostingTraceAttemptView {
                        substrate: logical_substrate_label(attempt.substrate).to_string(),
                        state: attempt_state_label(attempt.state).to_string(),
                        reason: attempt
                            .reason
                            .map(|reason| fallback_reason_label(reason).to_string()),
                        detail: attempt.detail.clone().unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        fidelity_caveats: rehosting_recipe
            .map(|recipe| recipe.fidelity_caveats)
            .unwrap_or_default(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&trace)?);
    } else {
        render_trace(&trace);
    }
    Ok(())
}

fn logical_substrate_label(kind: LogicalSubstrateKind) -> &'static str {
    match kind {
        LogicalSubstrateKind::Service => "service",
        LogicalSubstrateKind::System => "system",
        LogicalSubstrateKind::Reference => "reference",
    }
}

fn substrate_preference_label(preference: SubstratePreference) -> &'static str {
    match preference {
        SubstratePreference::ServiceFirst => "service-first",
        SubstratePreference::SystemFirst => "system-first",
        SubstratePreference::ReferenceOnly => "reference-only",
        SubstratePreference::Auto => "auto",
    }
}

fn attempt_state_label(state: SubstrateAttemptState) -> &'static str {
    match state {
        SubstrateAttemptState::Considered => "considered",
        SubstrateAttemptState::Skipped => "skipped",
        SubstrateAttemptState::Unavailable => "unavailable",
        SubstrateAttemptState::Failed => "failed",
        SubstrateAttemptState::Selected => "selected",
    }
}

fn fallback_reason_label(reason: FallbackReason) -> &'static str {
    match reason {
        FallbackReason::ExplicitRequest => "explicit-request",
        FallbackReason::Unavailable => "unavailable",
        FallbackReason::ExecutionFailed => "execution-failed",
        FallbackReason::EscalatedForFidelity => "escalated-for-fidelity",
        FallbackReason::EscalatedForRecovery => "escalated-for-recovery",
    }
}

fn render_trace(trace: &RehostingTraceView) {
    println!("session: {}", trace.session_id);
    println!("run: {}", trace.run_id);
    println!("backend: {}", trace.backend);
    println!("physical substrate: {}", trace.physical_substrate);
    if let Some(logical_substrate) = trace.logical_substrate.as_deref() {
        println!("logical substrate: {logical_substrate}");
    }
    if let Some(substrate_preference) = trace.substrate_preference.as_deref() {
        println!("substrate preference: {substrate_preference}");
    }
    println!("attempt count: {}", trace.attempts.len());
    for attempt in &trace.attempts {
        match attempt.reason.as_deref() {
            Some(reason) => println!(
                "attempt {} [{}] reason={} detail={}",
                attempt.substrate, attempt.state, reason, attempt.detail
            ),
            None => println!(
                "attempt {} [{}] detail={}",
                attempt.substrate, attempt.state, attempt.detail
            ),
        }
    }
    for caveat in &trace.fidelity_caveats {
        println!("fidelity caveat: {caveat}");
    }
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
