use std::path::Path;
use std::time::Duration;

use fat_core::runtime_store::RuntimeStore;

use crate::emulate_cmd;
use crate::emulate_config::load_config;
use crate::emulate_list::ProcessState;

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
pub struct GcReport {
    pub stopped_sessions: Vec<GcStopEntry>,
    pub marked_stale: Vec<String>,
    pub pruned_staging_dirs: Vec<String>,
}

#[derive(Debug)]
pub struct GcStopEntry {
    pub session_id: String,
    pub run_id: String,
    pub backend: String,
    pub outcome: String,
}

pub fn run_gc(project_dir: &Path, store: &RuntimeStore) -> DynResult<()> {
    let config = load_config(project_dir, emulate_cmd::resolve_data_root().as_deref());
    let idle_timeout = Duration::from_secs(config.lifecycle.idle_timeout_secs);
    let prune = config.lifecycle.prune_staging_on_stop;

    let sessions = store
        .read_sessions()
        .map_err(|err| format!("failed to read sessions: {err}"))?;
    let now = crate::emulate_cmd::current_timestamp_millis();

    let mut report = GcReport {
        stopped_sessions: Vec::new(),
        marked_stale: Vec::new(),
        pruned_staging_dirs: Vec::new(),
    };

    // Same walk and the same liveness verdict `fat emulate list` reports, so a
    // session the list calls live can never be swept as stale here.
    for live_run in crate::emulate_list::collect_live_runs(store)
        .map_err(|err| format!("failed to read live runs: {err}"))?
    {
        let (session, run) = (&live_run.session, &live_run.run);

        match live_run.state {
            ProcessState::Live => {
                let updated_ms = crate::emulate_cmd::parse_unix_ms(&session.updated_at);
                let elapsed_ms = now.saturating_sub(updated_ms);
                if elapsed_ms > idle_timeout.as_millis() {
                    // The same stop `fat emulate --stop` performs, rather than a
                    // second dispatch table that only knew two backends: this
                    // covers every backend, tears the runtime down the way that
                    // backend requires, completes the records, and dispatches
                    // post-run analysis. A swept session and a hand-stopped one
                    // now end identically.
                    let outcome =
                        emulate_cmd::stop_session(project_dir, store, Some(&session.session_id))
                            .map(|()| "stopped".to_string())
                            .unwrap_or_else(|err| format!("stop-failed: {err}"));
                    report.stopped_sessions.push(GcStopEntry {
                        session_id: session.session_id.clone(),
                        run_id: run.run_id.clone(),
                        backend: run.backend_driver.clone(),
                        outcome,
                    });
                }
            }
            ProcessState::Stale => {
                // Process gone but the record still claims it is running.
                mark_session_stale(store, session, run)?;
                report.marked_stale.push(run.run_id.clone());
            }
            // No pid was ever recorded, so there is nothing to decide against.
            ProcessState::Unknown => {}
        }
    }

    // Prune staging directories for completed/abandoned/stale sessions.
    if prune {
        let rehost_root = project_dir.join("work").join("rehosting");
        if rehost_root.is_dir() {
            let entries = std::fs::read_dir(&rehost_root)
                .map_err(|err| format!("failed to read rehosting dir: {err}"))?;
            for entry in entries.flatten() {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                // Staging directories are named with session key prefixes
                if !dir_name.starts_with("stgsess-") && !dir_name.starts_with("stgrun-") {
                    continue;
                }
                let has_active = sessions.iter().any(|s| {
                    s.status == fat_core::sessions::SessionStatus::Active
                        && dir_name.contains(&s.session_id[..12.min(s.session_id.len())])
                });
                if !has_active {
                    let _ = std::fs::remove_dir_all(entry.path());
                    report.pruned_staging_dirs.push(dir_name);
                }
            }
        }
    }

    if report.stopped_sessions.is_empty()
        && report.marked_stale.is_empty()
        && report.pruned_staging_dirs.is_empty()
    {
        println!("gc: nothing to clean up");
    } else {
        for entry in &report.stopped_sessions {
            println!(
                "gc: stopped  {} ({} / {}) — {}",
                entry.session_id, entry.backend, entry.run_id, entry.outcome
            );
        }
        for run_id in &report.marked_stale {
            println!("gc: marked stale  {}", run_id);
        }
        for staging in &report.pruned_staging_dirs {
            println!("gc: pruned staging  {}", staging);
        }
    }

    Ok(())
}

fn mark_session_stale(
    store: &RuntimeStore,
    session: &fat_core::sessions::SessionRecord,
    run: &fat_core::runs::RunRecord,
) -> DynResult<()> {
    let emu_session = fat_emulate::EmulationSession::new(
        session.session_id.clone(),
        session.clone(),
        fat_emulate::EmulationRun::new(run.clone()),
    );
    let degraded = emu_session.into_active_run().degraded_running_at(
        crate::emulate_cmd::current_timestamp_string(),
        fat_core::diagnostics::DiagnosticRecord::new(
            run.run_id.clone(),
            fat_core::diagnostics::DiagnosticPhase::Observation,
            fat_core::diagnostics::DiagnosticOwner::Policy,
            fat_core::diagnostics::DiagnosticClass::SubstrateUnhealthy,
            Some("gc-sweep-stale".to_string()),
            fat_core::diagnostics::DiagnosticSeverity::Medium,
            fat_core::diagnostics::DiagnosticConfidence::High,
            fat_core::diagnostics::DiagnosticActionability::TerminalForThisStrategy,
            "session process no longer alive; marked stale by gc sweep".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    );
    store
        .write_session(degraded.session_record())
        .map_err(|err| format!("failed to write stale session: {err}"))?;
    store
        .write_run(degraded.run_record())
        .map_err(|err| format!("failed to write stale run: {err}"))?;
    Ok(())
}
