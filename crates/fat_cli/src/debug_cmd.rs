use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use fat_backend::emux::{configure_emux_container_runtime, EmuxRuntimeStatus, EMUX_DIR_ENV};
use fat_backend::{BackendDriverPhase, BackendRegistry};
use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::debug::{
    DebugCapability, DebugGdbTranscript, DebugMapsTranscript, DebugMonitorTranscript,
    DebugShellTranscript, DebugSuggestion, DebugSuggestionReport, DebugSurface, DebugSurfaceKind,
    DebugSurfaceReport, DebugSurfaceState, ObservedNetworkEntry, ObservedNetworkSnapshot,
    ObservedProcessEntry, ObservedProcessSnapshot, ObservedServiceEntry, ObservedServiceSnapshot,
};
use fat_core::diagnostics::DiagnosticRecord;
use fat_core::project::Project;
use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::runs::{HealthState, RunStatus, RuntimeEndpoint, RuntimeEndpointKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::services::{
    managed_runtime_summary_from_runtime_status_json, managed_runtime_summary_from_summary_json,
    ServiceSummaryArtifact,
};
use fat_core::targets::derive_target_id;
use fat_emulate::preflight::PreflightReport;
use walkdir::WalkDir;

use crate::emulate_cmd::parse_unix_ms;
use crate::{emulate_cmd, run_cmd};

pub(crate) type DynResult<T> = Result<T, Box<dyn Error>>;

pub(crate) struct DebugContext {
    pub project: Project,
    pub store: RuntimeStore,
    pub view: run_cmd::RuntimeView,
    pub project_dir: PathBuf,
}

pub fn run_surfaces(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let readiness_report = load_latest_readiness_report(
        &context.store,
        &context.view.session.session_id,
        &context.view.run.run_id,
    )?;
    let report = build_surface_report(&context.view, readiness_report.as_ref());
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &report.session_id,
        &report.run_id,
        ArtifactKind::RuntimeDebug,
        "debug-surface-report",
        "fat debug surfaces",
        "debug surface discovery report",
        "debug",
        &report.backend_id,
        report.substrate_kind,
        &serde_json::to_string_pretty(&report)?,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_surface_report(&report));
    }
    Ok(())
}

pub fn run_suggest(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let services = build_service_snapshot(&context.store, &context.view)?;
    let network = build_network_snapshot(&context)?;
    let readiness_report = load_latest_readiness_report(
        &context.store,
        &context.view.session.session_id,
        &context.view.run.run_id,
    )?;
    let diagnostics = if context.view.diagnostics.is_empty() {
        load_session_diagnostics(&context.store, &context.view.session.session_id)?
    } else {
        context.view.diagnostics.clone()
    };
    let retry_backend =
        select_retry_backend(&context.project_dir, &context.view.run.backend_driver)?;
    let report = build_suggestion_report(
        &context.view,
        &diagnostics,
        &services,
        &network,
        &context.project_dir,
        retry_backend.as_ref(),
        readiness_report.as_ref(),
    );
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &report.session_id,
        &report.run_id,
        ArtifactKind::RuntimeDebug,
        "debug-suggestion-report",
        "fat debug suggest",
        "debug suggestion report",
        "debug",
        &report.backend_id,
        context.view.run.substrate_kind,
        &serde_json::to_string_pretty(&report)?,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_suggestion_report(&report));
    }
    Ok(())
}

pub fn run_maps(project_dir: &Path, session_id: Option<&str>, target: &str) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    ensure_emux_runtime(&context)?;
    let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
    let output = invoke_emux_helper(&emux_dir, "emuxmaps", &[target])?;
    let transcript = DebugMapsTranscript {
        session_id: context.view.session.session_id.clone(),
        run_id: context.view.run.run_id.clone(),
        backend_id: context.view.run.backend_driver.clone(),
        target: target.to_string(),
        maps_uri: format!("emux://maps/{target}"),
        command: output.command,
        exit_code: output.exit_code.unwrap_or(-1),
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
    };
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &transcript.session_id,
        &transcript.run_id,
        ArtifactKind::RuntimeDebug,
        "debug-maps-transcript",
        "fat debug maps",
        "debug maps transcript",
        "debug",
        &transcript.backend_id,
        context.view.run.substrate_kind,
        &serde_json::to_string_pretty(&transcript)?,
    )?;

    print!("{}", transcript.stdout);
    eprint!("{}", transcript.stderr);
    if transcript.exit_code == 0 {
        Ok(())
    } else {
        Err(format!(
            "emux maps helper exited with status {}",
            transcript.exit_code
        )
        .into())
    }
}

pub fn run_shell(
    project_dir: &Path,
    session_id: Option<&str>,
    command: Option<&str>,
) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    if context.view.run.backend_driver == "emux" {
        return run_emux_shell(&context, command);
    }
    let target = resolve_shell_target(&context.view)?;
    let ssh_binary = find_ssh_binary().ok_or("ssh is unavailable on this host")?;
    let ssh_target = format!("root@{}", target.host);
    let port = target.port.to_string();

    if let Some(command_text) = command {
        let output = ProcessCommand::new(&ssh_binary)
            .args(["-p", &port, &ssh_target, "--", command_text])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        print!("{stdout}");
        eprint!("{stderr}");

        let transcript = DebugShellTranscript {
            session_id: context.view.session.session_id.clone(),
            run_id: context.view.run.run_id.clone(),
            backend_id: context.view.run.backend_driver.clone(),
            shell_uri: target.uri,
            command: command_text.to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
        };
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &transcript.session_id,
            &transcript.run_id,
            ArtifactKind::RuntimeDebug,
            "debug-shell-transcript",
            "fat debug shell",
            "debug shell transcript",
            "debug",
            &transcript.backend_id,
            context.view.run.substrate_kind,
            &serde_json::to_string_pretty(&transcript)?,
        )?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("ssh command exited with status {}", output.status).into())
        }
    } else {
        let status = ProcessCommand::new(&ssh_binary)
            .args(["-p", &port, &ssh_target])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("ssh exited with status {status}").into())
        }
    }
}

pub fn run_monitor(
    project_dir: &Path,
    session_id: Option<&str>,
    command: Option<&str>,
) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    if context.view.run.backend_driver == "emux" {
        return run_emux_monitor(&context, command);
    }
    let target = resolve_monitor_target(&context.view)?;

    if let Some(command_text) = command {
        let mut stream = TcpStream::connect((target.host.as_str(), target.port))?;
        use std::io::Write as _;
        stream.write_all(command_text.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.shutdown(Shutdown::Write)?;

        let mut stdout = String::new();
        stream.read_to_string(&mut stdout)?;
        print!("{stdout}");
        let stderr = String::new();

        let transcript = DebugMonitorTranscript {
            session_id: context.view.session.session_id.clone(),
            run_id: context.view.run.run_id.clone(),
            backend_id: context.view.run.backend_driver.clone(),
            monitor_uri: target.uri,
            command: command_text.to_string(),
            exit_code: 0,
            stdout,
            stderr,
        };
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &transcript.session_id,
            &transcript.run_id,
            ArtifactKind::RuntimeDebug,
            "debug-monitor-transcript",
            "fat debug monitor",
            "debug monitor transcript",
            "debug",
            &transcript.backend_id,
            context.view.run.substrate_kind,
            &serde_json::to_string_pretty(&transcript)?,
        )?;

        Ok(())
    } else {
        let monitor_binary =
            find_monitor_binary().ok_or("monitor attach utility is unavailable on this host")?;
        let status = ProcessCommand::new(&monitor_binary)
            .args([&target.host, &target.port.to_string()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("monitor attach exited with status {status}").into())
        }
    }
}

pub fn run_gdb(
    project_dir: &Path,
    session_id: Option<&str>,
    target: Option<&str>,
    command: Option<&str>,
) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    if context.view.run.backend_driver == "emux" {
        return run_emux_gdb(&context, target, command);
    }
    let target = resolve_debugger_target(&context.view)?;
    let gdb_binary = find_gdb_binary().ok_or("gdb is unavailable on this host")?;
    let target_remote = format!("target remote {}:{}", target.host, target.port);

    if let Some(command_text) = command {
        let output = ProcessCommand::new(&gdb_binary)
            .args([
                "--quiet",
                "--batch",
                "-ex",
                &target_remote,
                "-ex",
                command_text,
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        print!("{stdout}");
        eprint!("{stderr}");

        let transcript = DebugGdbTranscript {
            session_id: context.view.session.session_id.clone(),
            run_id: context.view.run.run_id.clone(),
            backend_id: context.view.run.backend_driver.clone(),
            debugger_uri: target.uri,
            target: None,
            command: Some(command_text.to_string()),
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
        };
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &transcript.session_id,
            &transcript.run_id,
            ArtifactKind::RuntimeDebug,
            "debug-gdb-transcript",
            "fat debug gdb",
            "debug gdb transcript",
            "debug",
            &transcript.backend_id,
            context.view.run.substrate_kind,
            &serde_json::to_string_pretty(&transcript)?,
        )?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("gdb command exited with status {}", output.status).into())
        }
    } else {
        let status = ProcessCommand::new(&gdb_binary)
            .args(["--quiet", "-ex", &target_remote])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("gdb exited with status {status}").into())
        }
    }
}

fn run_emux_gdb(
    context: &DebugContext,
    target: Option<&str>,
    command: Option<&str>,
) -> DynResult<()> {
    ensure_emux_runtime(context)?;
    let target = target.ok_or("emux gdb requires --target <pid-or-name>")?;
    let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
    let output = if let Some(command_text) = command {
        let gdb_command = format!(
            "printf '%s\\n' {} quit | /emux/run/emuxgdb {}",
            shell_quote(command_text),
            shell_quote(target),
        );
        let raw = spawn_emux_helper_command(&emux_dir, &gdb_command)?.output()?;
        EmuxCommandOutput {
            command: gdb_command,
            exit_code: raw.status.code(),
            stdout: sanitize_script_output(&String::from_utf8_lossy(&raw.stdout)),
            stderr: sanitize_script_output(&String::from_utf8_lossy(&raw.stderr)),
        }
    } else {
        invoke_emux_helper(&emux_dir, "emuxgdb", &[target])?
    };
    let transcript = DebugGdbTranscript {
        session_id: context.view.session.session_id.clone(),
        run_id: context.view.run.run_id.clone(),
        backend_id: context.view.run.backend_driver.clone(),
        debugger_uri: format!("emux://gdb/{target}"),
        target: Some(target.to_string()),
        command: command
            .map(str::to_string)
            .or_else(|| Some(output.command.clone())),
        exit_code: output.exit_code.unwrap_or(-1),
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
    };
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &transcript.session_id,
        &transcript.run_id,
        ArtifactKind::RuntimeDebug,
        "debug-gdb-transcript",
        "fat debug gdb",
        "debug gdb transcript",
        "debug",
        &transcript.backend_id,
        context.view.run.substrate_kind,
        &serde_json::to_string_pretty(&transcript)?,
    )?;
    print!("{}", transcript.stdout);
    eprint!("{}", transcript.stderr);
    if transcript.exit_code == 0 {
        Ok(())
    } else {
        Err(format!(
            "emux gdb helper exited with status {}",
            transcript.exit_code
        )
        .into())
    }
}

pub(crate) fn load_context(
    project_dir: &Path,
    session_id: Option<&str>,
) -> DynResult<DebugContext> {
    let project_dir = normalize_project_dir(project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let project = load_project(&db, &project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let Some(view) = emulate_cmd::load_runtime_view_with_refresh(&project_dir, &store, session_id)?
    else {
        return Err("no session records available for debug inspection".into());
    };

    Ok(DebugContext {
        project,
        store,
        view,
        project_dir,
    })
}

pub(crate) fn build_surface_report(
    view: &run_cmd::RuntimeView,
    readiness_report: Option<&ReadinessReport>,
) -> DebugSurfaceReport {
    let mut surfaces: Vec<DebugSurface> = view
        .run
        .active_endpoints
        .iter()
        .map(map_runtime_endpoint)
        .collect();

    if view.run.backend_driver == "emux" && matches!(view.run.status, RunStatus::Running) {
        ensure_emux_surface(
            &mut surfaces,
            DebugSurface::new(
                DebugSurfaceKind::Shell,
                DebugSurfaceState::Ready,
                "emux-userspace",
                "emux-docker",
                22222,
            )
            .with_uri("emux://userspace"),
        );
        ensure_emux_surface(
            &mut surfaces,
            DebugSurface::new(
                DebugSurfaceKind::Monitor,
                DebugSurfaceState::Ready,
                "emux-monitor",
                "emux-docker",
                55555,
            )
            .with_uri("emux://monitor"),
        );
        ensure_emux_surface(
            &mut surfaces,
            DebugSurface::new(
                DebugSurfaceKind::Debugger,
                DebugSurfaceState::Ready,
                "emux-gdb",
                "emux-docker",
                0,
            )
            .with_uri("emux://gdb"),
        );
    }
    if let Some(readiness_report) = readiness_report {
        overlay_surface_readiness(&mut surfaces, readiness_report);
    }

    let mut capabilities = Vec::new();
    if let Some(contract) = BackendRegistry::with_test_backends()
        .driver_contracts()
        .into_iter()
        .find(|contract| contract.backend_id == view.run.backend_driver)
    {
        if contract.phases.contains(&BackendDriverPhase::Observation) {
            capabilities.push(DebugCapability::ObserveSupported);
        }
        if contract.phases.contains(&BackendDriverPhase::Diagnostics) {
            capabilities.push(DebugCapability::DiagnosticsSupported);
        }
    }
    if surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Shell)
    {
        capabilities.push(DebugCapability::ShellAttachable);
    }
    if surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Debugger)
    {
        capabilities.push(DebugCapability::DebuggerAttachable);
    }
    if surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Monitor)
    {
        capabilities.push(DebugCapability::MonitorAttachable);
    }

    DebugSurfaceReport {
        session_id: view.session.session_id.clone(),
        run_id: view.run.run_id.clone(),
        backend_id: view.run.backend_driver.clone(),
        substrate_kind: view.run.substrate_kind,
        run_status: view.run.status,
        health_state: view.run.health_state,
        surfaces,
        capabilities,
    }
}

fn ensure_emux_surface(surfaces: &mut Vec<DebugSurface>, candidate: DebugSurface) {
    let duplicate = surfaces.iter().any(|surface| {
        surface.surface_kind == candidate.surface_kind
            && surface.name == candidate.name
            && surface.uri == candidate.uri
    });
    if !duplicate {
        surfaces.push(candidate);
    }
}

pub(crate) fn load_latest_readiness_report(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<ReadinessReport>> {
    let readiness_dir = store
        .run_path(session_id, run_id)
        .parent()
        .ok_or("run path missing parent")?
        .join("rehosting")
        .join("readiness");
    if !readiness_dir.exists() {
        return Ok(None);
    }

    let mut report_paths: Vec<_> = fs::read_dir(&readiness_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    report_paths.sort();

    let Some(path) = report_paths.pop() else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub(crate) fn build_service_snapshot(
    store: &RuntimeStore,
    view: &run_cmd::RuntimeView,
) -> DynResult<ObservedServiceSnapshot> {
    let artifacts = store.read_run_artifacts(&view.session.session_id, &view.run.run_id)?;
    let mut services = Vec::new();

    if let Some(artifact) = artifacts
        .iter()
        .rev()
        .find(|artifact| artifact.subkind == "managed-runtime-summary")
    {
        let text = fs::read_to_string(&artifact.path)?;
        if let Some(summary) = managed_runtime_summary_from_summary_json(&text) {
            services.extend(summary.services.into_iter().map(|service| {
                ObservedServiceEntry::new(
                    service.name,
                    service.endpoint.as_deref(),
                    "managed-runtime-summary",
                )
            }));
        }
    } else if let Some(artifact) = artifacts
        .iter()
        .rev()
        .find(|artifact| artifact.subkind == "managed-runtime-status")
    {
        let text = fs::read_to_string(&artifact.path)?;
        if let Some(summary) = managed_runtime_summary_from_runtime_status_json(&text) {
            services.extend(summary.services.into_iter().map(|service| {
                ObservedServiceEntry::new(
                    service.name,
                    service.endpoint.as_deref(),
                    "managed-runtime-status",
                )
            }));
        }
    } else if let Some(artifact) = artifacts
        .iter()
        .rev()
        .find(|artifact| artifact.subkind == "service-summary")
    {
        let text = fs::read_to_string(&artifact.path)?;
        let summary: ServiceSummaryArtifact = serde_json::from_str(&text)?;
        services.extend(summary.services.into_iter().map(|service| {
            ObservedServiceEntry::new(service.name, service.endpoint.as_deref(), "service-summary")
        }));
    } else {
        services.extend(
            view.run
                .active_endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == RuntimeEndpointKind::Service)
                .map(|endpoint| {
                    ObservedServiceEntry::new(
                        endpoint.name.clone(),
                        endpoint.uri.as_deref(),
                        "runtime-endpoint",
                    )
                }),
        );
    }

    let mut deduped = BTreeMap::new();
    for service in services {
        let key = format!(
            "{}:{}",
            service.name.to_ascii_lowercase(),
            service.endpoint.as_deref().unwrap_or("")
        );
        deduped.insert(key, service);
    }

    Ok(ObservedServiceSnapshot {
        session_id: view.session.session_id.clone(),
        run_id: view.run.run_id.clone(),
        backend_id: view.run.backend_driver.clone(),
        services: deduped.into_values().collect(),
    })
}

pub(crate) fn build_network_snapshot(context: &DebugContext) -> DynResult<ObservedNetworkSnapshot> {
    let endpoints = if context.view.run.backend_driver == "emux" {
        let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
        let output = invoke_emux_helper(&emux_dir, "emuxnetstat", &["-tnl"])?;
        parse_emux_netstat_output(&output.stdout)
    } else {
        context
            .view
            .run
            .active_endpoints
            .iter()
            .map(map_network_endpoint)
            .collect()
    };

    Ok(ObservedNetworkSnapshot {
        session_id: context.view.session.session_id.clone(),
        run_id: context.view.run.run_id.clone(),
        backend_id: context.view.run.backend_driver.clone(),
        substrate_kind: context.view.run.substrate_kind,
        endpoints,
    })
}

pub(crate) fn build_process_snapshot(context: &DebugContext) -> DynResult<ObservedProcessSnapshot> {
    ensure_emux_runtime(context)?;
    let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
    let output = invoke_emux_helper(&emux_dir, "emuxps", &[])?;
    if output.exit_code.unwrap_or(-1) != 0 {
        return Err(format!(
            "emux ps helper exited with status {}",
            output.exit_code.unwrap_or(-1)
        )
        .into());
    }

    let processes = parse_emux_ps_output(&output.stdout);
    Ok(ObservedProcessSnapshot {
        session_id: context.view.session.session_id.clone(),
        run_id: context.view.run.run_id.clone(),
        backend_id: context.view.run.backend_driver.clone(),
        processes,
    })
}

fn build_suggestion_report(
    view: &run_cmd::RuntimeView,
    diagnostics: &[DiagnosticRecord],
    services: &ObservedServiceSnapshot,
    network: &ObservedNetworkSnapshot,
    project_dir: &Path,
    retry_backend: Option<&RetryBackendHint>,
    readiness_report: Option<&ReadinessReport>,
) -> DebugSuggestionReport {
    let surfaces = build_surface_report(view, readiness_report);
    let mut suggestions = Vec::new();
    let attach_surface_count = surfaces
        .surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.surface_kind,
                DebugSurfaceKind::Shell | DebugSurfaceKind::Debugger | DebugSurfaceKind::Monitor
            )
        })
        .count();

    if matches!(
        view.run.health_state,
        HealthState::Stale | HealthState::Unreachable | HealthState::GuestUnreachable
    ) {
        suggestions.push(
            DebugSuggestion::new(
                "Refresh runtime status before attach",
                "run health is not currently healthy",
            )
            .with_command(format!(
                "fat emulate --project {} --session-id {} --status",
                project_dir.display(),
                view.session
                    .requested_session_id
                    .as_deref()
                    .unwrap_or(&view.session.session_id)
            )),
        );
    }

    if attach_surface_count == 0
        && matches!(
            view.run.status,
            fat_core::runs::RunStatus::Failed
                | fat_core::runs::RunStatus::DegradedRunning
                | fat_core::runs::RunStatus::DegradedCompleted
                | fat_core::runs::RunStatus::CleanupFailed
        )
    {
        let lead_diagnostic = select_lead_diagnostic(diagnostics);
        suggestions.push(match lead_diagnostic {
            Some(diagnostic) => DebugSuggestion::new(
                format!("Lead failure diagnostic: {}", diagnostic.summary),
                format!(
                    "highest-priority recorded diagnostic for this failed runtime (phase: {}, class: {})",
                    diagnostic.phase.as_str(),
                    diagnostic.class.as_str()
                ),
            ),
            None => DebugSuggestion::new(
                "Lead failure diagnostic: run failed before attach and FAT did not persist a launch diagnostic",
                "no attachable surfaces were published and no launch diagnostic record was available in the runtime store",
            ),
        });
        let rationale = lead_diagnostic
            .map(|diagnostic| {
                format!(
                    "run has no attachable surfaces and FAT already recorded diagnostics: {}",
                    diagnostic.summary
                )
            })
            .unwrap_or_else(|| {
                "run has no attachable surfaces and the active runtime failed before attach"
                    .to_string()
            });
        suggestions.push(
            DebugSuggestion::new("Inspect launch diagnostics in fat info", rationale)
                .with_command(format!("fat info {}", project_dir.display())),
        );
        suggestions.push(
            DebugSuggestion::new(
                "Re-run preflight before retry",
                "preflight can confirm whether the current host/backend path is viable before another launch attempt",
            )
            .with_command(format!("fat preflight {}", project_dir.display())),
        );
        if let Some(retry_backend) = retry_backend {
            suggestions.push(
                DebugSuggestion::new(
                    format!("Retry with available backend: {}", retry_backend.backend_id),
                    format!(
                        "project signals still rank {} as available ({}) while the current {} run failed before attach",
                        retry_backend.display_name,
                        retry_backend.availability_detail,
                        view.run.backend_driver
                    ),
                )
                .with_command(format!(
                    "fat emulate --project {} --backend {}",
                    project_dir.display(),
                    retry_backend.backend_id
                )),
            );
        }
    }

    if !services.services.is_empty() {
        suggestions.push(
            DebugSuggestion::new(
                "Observe services before debugger attach",
                "runtime evidence already exposes concrete service endpoints",
            )
            .with_command(format!(
                "fat observe services --project {} --session-id {}",
                project_dir.display(),
                view.session
                    .requested_session_id
                    .as_deref()
                    .unwrap_or(&view.session.session_id)
            )),
        );
    }

    if surfaces
        .surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Shell)
        && !matches!(
            view.run.health_state,
            HealthState::Stale | HealthState::Unreachable | HealthState::GuestUnreachable
        )
    {
        suggestions.push(DebugSuggestion::new(
            "Prefer shell attach first",
            "shell surface is available and run health is not stale",
        ));
    } else if surfaces
        .surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Monitor)
    {
        suggestions.push(
            DebugSuggestion::new(
                "Prefer monitor attach first",
                "monitor surface is available while shell attach is not the lead path",
            )
            .with_command(format!(
                "fat debug monitor --project {} --session-id {}",
                project_dir.display(),
                view.session
                    .requested_session_id
                    .as_deref()
                    .unwrap_or(&view.session.session_id)
            )),
        );
    } else if surfaces
        .surfaces
        .iter()
        .any(|surface| surface.surface_kind == DebugSurfaceKind::Debugger)
    {
        suggestions.push(
            DebugSuggestion::new(
                "Prefer debugger attach first",
                "debugger surface is available while shell and monitor are not the lead paths",
            )
            .with_command(format!(
                "fat debug gdb --project {} --session-id {}",
                project_dir.display(),
                view.session
                    .requested_session_id
                    .as_deref()
                    .unwrap_or(&view.session.session_id)
            )),
        );
    }

    if !network.endpoints.is_empty() {
        suggestions.push(
            DebugSuggestion::new(
                "Inspect host-visible network surfaces",
                "runtime endpoints already expose reachable services and debug channels",
            )
            .with_command(format!(
                "fat observe net --project {} --session-id {}",
                project_dir.display(),
                view.session
                    .requested_session_id
                    .as_deref()
                    .unwrap_or(&view.session.session_id)
            )),
        );
    }

    DebugSuggestionReport {
        session_id: view.session.session_id.clone(),
        run_id: view.run.run_id.clone(),
        backend_id: view.run.backend_driver.clone(),
        suggestions,
    }
}

pub(crate) fn write_runtime_json_artifact(
    store: &RuntimeStore,
    project: &Project,
    session_id: &str,
    run_id: &str,
    kind: ArtifactKind,
    subkind: &str,
    producer_id: &str,
    provenance: &str,
    phase: &str,
    backend_id: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    contents: &str,
) -> DynResult<()> {
    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&outputs_dir)?;
    let path = outputs_dir.join(format!("{subkind}.json"));
    fs::write(&path, contents)?;

    let artifact = ArtifactRecord::new(
        project.name.clone(),
        derive_target_id(&project.name, &project.firmware_name),
        session_id.to_string(),
        run_id.to_string(),
        kind,
        subkind,
        "fat",
        producer_id,
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        "application/json",
        contents.len() as u64,
        None,
        provenance,
        ArtifactRetentionPolicy::Session,
    )
    .with_phase(phase)
    .with_backend_driver(backend_id.to_string())
    .with_substrate_kind(substrate_kind)
    .with_tool_version(env!("CARGO_PKG_VERSION"));
    store.write_artifact(&artifact)?;
    store.append_artifact_index(&artifact)?;
    Ok(())
}

fn map_runtime_endpoint(endpoint: &RuntimeEndpoint) -> DebugSurface {
    let surface_kind = match endpoint.kind {
        RuntimeEndpointKind::Shell => DebugSurfaceKind::Shell,
        RuntimeEndpointKind::Debugger => DebugSurfaceKind::Debugger,
        RuntimeEndpointKind::Monitor => DebugSurfaceKind::Monitor,
        RuntimeEndpointKind::PortForward => DebugSurfaceKind::ForwardedPort,
        RuntimeEndpointKind::Service => DebugSurfaceKind::Service,
    };

    let mut surface = DebugSurface::new(
        surface_kind,
        match endpoint.kind {
            RuntimeEndpointKind::Shell => DebugSurfaceState::Ready,
            RuntimeEndpointKind::Debugger => DebugSurfaceState::Ready,
            RuntimeEndpointKind::Monitor => DebugSurfaceState::Ready,
            RuntimeEndpointKind::PortForward => DebugSurfaceState::Registered,
            RuntimeEndpointKind::Service => DebugSurfaceState::Registered,
        },
        endpoint.name.clone(),
        endpoint.host.clone(),
        endpoint.port,
    );
    if let Some(target_port) = endpoint.target_port {
        surface = surface.with_target_port(target_port);
    }
    if let Some(uri) = &endpoint.uri {
        surface = surface.with_uri(uri.clone());
    }
    surface
}

fn overlay_surface_readiness(surfaces: &mut [DebugSurface], readiness_report: &ReadinessReport) {
    for surface in surfaces {
        if let Some(record) = readiness_report
            .surfaces
            .iter()
            .find(|record| runtime_surface_record_matches_surface(record, surface))
        {
            surface.state = debug_surface_state_from_readiness(record.readiness);
        }
    }
}

fn runtime_surface_record_matches_surface(
    record: &RuntimeSurfaceRecord,
    surface: &DebugSurface,
) -> bool {
    runtime_surface_kind_matches(record.kind.as_str(), surface.surface_kind)
        && record.name == surface.name
        && match (record.uri.as_deref(), surface.uri.as_deref()) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => match (record.host.as_deref(), record.port) {
                (Some(expected_host), Some(expected_port)) => {
                    expected_host == surface.host && expected_port == surface.port
                }
                _ => false,
            },
            (None, _) => match (record.host.as_deref(), record.port) {
                (Some(expected_host), Some(expected_port)) => {
                    expected_host == surface.host && expected_port == surface.port
                }
                _ => false,
            },
        }
}

pub(crate) fn readiness_state_for_network_entry(
    readiness_report: Option<&ReadinessReport>,
    endpoint: &ObservedNetworkEntry,
) -> Option<DebugSurfaceState> {
    let readiness_report = readiness_report?;
    let surface = DebugSurface::new(
        endpoint.surface_kind,
        DebugSurfaceState::Registered,
        endpoint.name.clone(),
        endpoint.host.clone(),
        endpoint.port,
    );
    let mut surface = match endpoint.target_port {
        Some(target_port) => surface.with_target_port(target_port),
        None => surface,
    };
    if let Some(uri) = endpoint.uri.as_ref() {
        surface = surface.with_uri(uri.clone());
    }

    readiness_report
        .surfaces
        .iter()
        .find(|record| runtime_surface_record_matches_surface(record, &surface))
        .map(|record| debug_surface_state_from_readiness(record.readiness))
}

fn runtime_surface_kind_matches(record_kind: &str, surface_kind: DebugSurfaceKind) -> bool {
    match record_kind {
        "shell" => matches!(surface_kind, DebugSurfaceKind::Shell),
        "debugger" => matches!(surface_kind, DebugSurfaceKind::Debugger),
        "monitor" => matches!(surface_kind, DebugSurfaceKind::Monitor),
        "port-forward" => matches!(surface_kind, DebugSurfaceKind::ForwardedPort),
        "service" => matches!(surface_kind, DebugSurfaceKind::Service),
        _ => false,
    }
}

fn debug_surface_state_from_readiness(readiness: SurfaceReadiness) -> DebugSurfaceState {
    match readiness {
        SurfaceReadiness::Registered => DebugSurfaceState::Registered,
        SurfaceReadiness::Ready => DebugSurfaceState::Ready,
        SurfaceReadiness::Validated => DebugSurfaceState::Validated,
    }
}

struct ShellAttachTarget {
    host: String,
    port: u16,
    uri: String,
}

struct MonitorAttachTarget {
    host: String,
    port: u16,
    uri: String,
}

struct DebuggerAttachTarget {
    host: String,
    port: u16,
    uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetryBackendHint {
    backend_id: String,
    display_name: String,
    availability_detail: String,
}

fn resolve_shell_target(view: &run_cmd::RuntimeView) -> DynResult<ShellAttachTarget> {
    let endpoint = view
        .run
        .active_endpoints
        .iter()
        .find(|endpoint| endpoint.kind == RuntimeEndpointKind::Shell)
        .ok_or("selected run does not expose a shell surface")?;

    if let Some(uri) = &endpoint.uri {
        if !uri.starts_with("ssh://") {
            return Err(format!("unsupported shell surface URI: {uri}").into());
        }
    }

    Ok(ShellAttachTarget {
        host: endpoint.host.clone(),
        port: endpoint.port,
        uri: endpoint
            .uri
            .clone()
            .unwrap_or_else(|| format!("ssh://{}:{}", endpoint.host, endpoint.port)),
    })
}

fn resolve_monitor_target(view: &run_cmd::RuntimeView) -> DynResult<MonitorAttachTarget> {
    let endpoint = view
        .run
        .active_endpoints
        .iter()
        .find(|endpoint| endpoint.kind == RuntimeEndpointKind::Monitor)
        .ok_or("selected run does not expose a monitor surface")?;

    if let Some(uri) = &endpoint.uri {
        if !uri.starts_with("tcp://") {
            return Err(format!("unsupported monitor surface URI: {uri}").into());
        }
    }

    Ok(MonitorAttachTarget {
        host: endpoint.host.clone(),
        port: endpoint.port,
        uri: endpoint
            .uri
            .clone()
            .unwrap_or_else(|| format!("tcp://{}:{}", endpoint.host, endpoint.port)),
    })
}

fn resolve_debugger_target(view: &run_cmd::RuntimeView) -> DynResult<DebuggerAttachTarget> {
    let endpoint = view
        .run
        .active_endpoints
        .iter()
        .find(|endpoint| endpoint.kind == RuntimeEndpointKind::Debugger)
        .ok_or("selected run does not expose a debugger surface")?;

    if let Some(uri) = &endpoint.uri {
        if !uri.starts_with("tcp://") {
            return Err(format!("unsupported debugger surface URI: {uri}").into());
        }
    }

    Ok(DebuggerAttachTarget {
        host: endpoint.host.clone(),
        port: endpoint.port,
        uri: endpoint
            .uri
            .clone()
            .unwrap_or_else(|| format!("tcp://{}:{}", endpoint.host, endpoint.port)),
    })
}

fn load_project_signals(project_dir: &Path) -> DynResult<Vec<String>> {
    let path = project_dir.join("analysis").join("signals.txt");
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn select_retry_backend(
    project_dir: &Path,
    current_backend: &str,
) -> DynResult<Option<RetryBackendHint>> {
    let signals = match load_project_signals(project_dir) {
        Ok(signals) if !signals.is_empty() => signals,
        _ => return Ok(None),
    };

    let report = PreflightReport::from_signals(signals);
    Ok(report
        .backends
        .into_iter()
        .find(|backend| backend.is_available && backend.backend_id != current_backend)
        .map(|backend| RetryBackendHint {
            backend_id: backend.backend_id,
            display_name: backend.display_name,
            availability_detail: backend.availability_detail,
        }))
}

fn select_lead_diagnostic(diagnostics: &[DiagnosticRecord]) -> Option<&DiagnosticRecord> {
    diagnostics.iter().max_by_key(|diagnostic| {
        (
            diagnostic_severity_rank(diagnostic.severity),
            diagnostic_confidence_rank(diagnostic.confidence),
            diagnostic_actionability_rank(diagnostic.actionability),
        )
    })
}

fn diagnostic_severity_rank(severity: fat_core::diagnostics::DiagnosticSeverity) -> u8 {
    match severity {
        fat_core::diagnostics::DiagnosticSeverity::Info => 0,
        fat_core::diagnostics::DiagnosticSeverity::Low => 1,
        fat_core::diagnostics::DiagnosticSeverity::Medium => 2,
        fat_core::diagnostics::DiagnosticSeverity::High => 3,
        fat_core::diagnostics::DiagnosticSeverity::Critical => 4,
    }
}

fn diagnostic_confidence_rank(confidence: fat_core::diagnostics::DiagnosticConfidence) -> u8 {
    match confidence {
        fat_core::diagnostics::DiagnosticConfidence::Low => 0,
        fat_core::diagnostics::DiagnosticConfidence::Medium => 1,
        fat_core::diagnostics::DiagnosticConfidence::High => 2,
    }
}

fn diagnostic_actionability_rank(
    actionability: fat_core::diagnostics::DiagnosticActionability,
) -> u8 {
    match actionability {
        fat_core::diagnostics::DiagnosticActionability::FallbackRecommended => 4,
        fat_core::diagnostics::DiagnosticActionability::Retryable => 3,
        fat_core::diagnostics::DiagnosticActionability::RequiresUserInput => 2,
        fat_core::diagnostics::DiagnosticActionability::RequiresProfileFix => 2,
        fat_core::diagnostics::DiagnosticActionability::RequiresBackendFix => 1,
        fat_core::diagnostics::DiagnosticActionability::RequiresSubstrateFix => 1,
        fat_core::diagnostics::DiagnosticActionability::RequiresTargetChange => 1,
        fat_core::diagnostics::DiagnosticActionability::TerminalForThisStrategy => 0,
    }
}

fn load_session_diagnostics(
    store: &RuntimeStore,
    session_id: &str,
) -> DynResult<Vec<DiagnosticRecord>> {
    let diagnostics_root = store.session_path(session_id).join("runs");
    if !diagnostics_root.exists() {
        return Ok(Vec::new());
    }

    let mut diagnostics = Vec::new();
    for entry in WalkDir::new(diagnostics_root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if !path.to_string_lossy().contains("/diagnostics/") {
            continue;
        }
        diagnostics.push(serde_json::from_slice::<DiagnosticRecord>(&fs::read(
            path,
        )?)?);
    }
    diagnostics.sort_by(|left, right| left.diagnostic_id.cmp(&right.diagnostic_id));
    diagnostics.dedup_by(|left, right| left.diagnostic_id == right.diagnostic_id);
    Ok(diagnostics)
}

fn map_network_endpoint(endpoint: &RuntimeEndpoint) -> ObservedNetworkEntry {
    let surface_kind = match endpoint.kind {
        RuntimeEndpointKind::Shell => DebugSurfaceKind::Shell,
        RuntimeEndpointKind::Debugger => DebugSurfaceKind::Debugger,
        RuntimeEndpointKind::Monitor => DebugSurfaceKind::Monitor,
        RuntimeEndpointKind::PortForward => DebugSurfaceKind::ForwardedPort,
        RuntimeEndpointKind::Service => DebugSurfaceKind::Service,
    };

    let mut entry = ObservedNetworkEntry::new(
        surface_kind,
        endpoint.name.clone(),
        endpoint.host.clone(),
        endpoint.port,
    );
    if let Some(target_port) = endpoint.target_port {
        entry = entry.with_target_port(target_port);
    }
    if let Some(uri) = &endpoint.uri {
        entry = entry.with_uri(uri.clone());
    }
    entry
}

fn render_surface_report(report: &DebugSurfaceReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("session: {}\n", report.session_id));
    output.push_str(&format!("run: {}\n", report.run_id));
    output.push_str(&format!("backend: {}\n", report.backend_id));
    output.push_str(&format!("substrate: {}\n", report.substrate_kind.as_str()));
    output.push_str(&format!(
        "run status: {}\n",
        run_status_label(report.run_status)
    ));
    output.push_str(&format!("health state: {}\n", report.health_state.as_str()));
    output.push_str(&format!("surface count: {}\n", report.surfaces.len()));
    for surface in &report.surfaces {
        let target = surface
            .uri
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}:{}", surface.host, surface.port));
        output.push_str(&format!(
            "surface {} [{}] state={}: {}\n",
            surface.name,
            surface.surface_kind.as_str(),
            surface.state.as_str(),
            target
        ));
    }
    for capability in &report.capabilities {
        output.push_str(&format!("capability: {}\n", capability.as_str()));
    }
    output
}

fn render_suggestion_report(report: &DebugSuggestionReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("session: {}\n", report.session_id));
    output.push_str(&format!("run: {}\n", report.run_id));
    output.push_str(&format!("backend: {}\n", report.backend_id));
    output.push_str(&format!("suggestion count: {}\n", report.suggestions.len()));
    for suggestion in &report.suggestions {
        output.push_str(&format!("suggestion: {}\n", suggestion.summary));
        output.push_str(&format!("  rationale: {}\n", suggestion.rationale));
        if let Some(command) = &suggestion.command {
            output.push_str(&format!("  command: {command}\n"));
        }
    }
    output
}

fn normalize_project_dir(project_dir: &Path) -> DynResult<PathBuf> {
    if project_dir.is_dir() {
        Ok(project_dir.to_path_buf())
    } else {
        Err(format!("project path does not exist: {}", project_dir.display()).into())
    }
}

fn emux_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(EMUX_DIR_ENV).map(PathBuf::from)
}

fn ensure_emux_runtime(context: &DebugContext) -> DynResult<()> {
    if context.view.run.backend_driver != "emux" {
        return Err("selected run is not an emux runtime".into());
    }
    let status = load_emux_runtime_status(
        &context.store,
        &context.view.session.session_id,
        &context.view.run.run_id,
    )?
    .ok_or("missing emux runtime status artifact for selected run")?;
    if status.backend_id != "emux" {
        return Err("selected run does not anchor an emux runtime status".into());
    }
    Ok(())
}

fn load_emux_runtime_status(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<EmuxRuntimeStatus>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    let Some(artifact) = artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == ArtifactKind::RuntimeState
                && artifact.subkind == "emux-runtime-status"
                && artifact.content_type == "application/json"
        })
        .max_by_key(|artifact| parse_unix_ms(&artifact.created_at))
    else {
        return Ok(None);
    };

    Ok(Some(serde_json::from_slice(&fs::read(&artifact.path)?)?))
}

fn invoke_emux_helper(
    emux_dir: &Path,
    helper: &str,
    args: &[&str],
) -> DynResult<EmuxCommandOutput> {
    let helper_path = format!("/emux/run/{helper}");
    let command = if args.is_empty() {
        helper_path.clone()
    } else {
        format!(
            "{helper_path} {}",
            args.iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let output = spawn_emux_helper_command(emux_dir, &command)?.output()?;

    Ok(EmuxCommandOutput {
        command,
        exit_code: output.status.code(),
        stdout: sanitize_script_output(&String::from_utf8_lossy(&output.stdout)),
        stderr: sanitize_script_output(&String::from_utf8_lossy(&output.stderr)),
    })
}

fn spawn_emux_helper_command(emux_dir: &Path, command: &str) -> DynResult<ProcessCommand> {
    let mut child = ProcessCommand::new("docker");
    child
        .current_dir(emux_dir)
        .arg("exec")
        .arg("emux-docker")
        .arg("/bin/bash")
        .arg("-lc")
        .arg(command);
    configure_emux_container_runtime(&mut child)?;
    Ok(child)
}

fn sanitize_script_output(raw: &str) -> String {
    let mut output = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\u{8}' | '\u{7f}' => {
                output.pop();
            }
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
            }
            '\r' => {}
            '\n' | '\t' => output.push(ch),
            ch if !ch.is_control() => output.push(ch),
            _ => {}
        }
    }
    output
}

fn run_emux_shell(context: &DebugContext, command: Option<&str>) -> DynResult<()> {
    ensure_emux_runtime(context)?;
    let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
    let shell_uri = "emux://userspace".to_string();

    if let Some(command_text) = command {
        let shell_command = format!(
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22222 root@192.168.100.2 -- {}",
            shell_quote(command_text)
        );
        let output = spawn_emux_helper_command(&emux_dir, &shell_command)?.output()?;
        let stdout = sanitize_script_output(&String::from_utf8_lossy(&output.stdout));
        let stderr = sanitize_script_output(&String::from_utf8_lossy(&output.stderr));
        print!("{stdout}");
        eprint!("{stderr}");

        let transcript = DebugShellTranscript {
            session_id: context.view.session.session_id.clone(),
            run_id: context.view.run.run_id.clone(),
            backend_id: context.view.run.backend_driver.clone(),
            shell_uri,
            command: command_text.to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
        };
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &transcript.session_id,
            &transcript.run_id,
            ArtifactKind::RuntimeDebug,
            "debug-shell-transcript",
            "fat debug shell",
            "debug shell transcript",
            "debug",
            &transcript.backend_id,
            context.view.run.substrate_kind,
            &serde_json::to_string_pretty(&transcript)?,
        )?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("emux shell command exited with status {}", output.status).into())
        }
    } else {
        let status = spawn_emux_interactive(
            &emux_dir,
            &[
                "docker",
                "exec",
                "-it",
                "emux-docker",
                "/bin/bash",
                "-lc",
                "ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22222 root@192.168.100.2",
            ],
        )?
        .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("emux shell attach exited with status {status}").into())
        }
    }
}

fn run_emux_monitor(context: &DebugContext, command: Option<&str>) -> DynResult<()> {
    ensure_emux_runtime(context)?;
    let emux_dir = emux_dir_from_env().ok_or("missing FAT_EMUX_DIR")?;
    if let Some(command_text) = command {
        let output = invoke_emux_monitor_command(&emux_dir, command_text)?;
        let transcript = DebugMonitorTranscript {
            session_id: context.view.session.session_id.clone(),
            run_id: context.view.run.run_id.clone(),
            backend_id: context.view.run.backend_driver.clone(),
            monitor_uri: "emux://monitor".to_string(),
            command: command_text.to_string(),
            exit_code: output.exit_code.unwrap_or(-1),
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        };
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &transcript.session_id,
            &transcript.run_id,
            ArtifactKind::RuntimeDebug,
            "debug-monitor-transcript",
            "fat debug monitor",
            "debug monitor transcript",
            "debug",
            &transcript.backend_id,
            context.view.run.substrate_kind,
            &serde_json::to_string_pretty(&transcript)?,
        )?;
        print!("{}", transcript.stdout);
        eprint!("{}", transcript.stderr);
        if transcript.exit_code == 0 {
            Ok(())
        } else {
            Err(format!(
                "emux monitor command exited with status {}",
                transcript.exit_code
            )
            .into())
        }
    } else {
        let status = spawn_emux_interactive(
            &emux_dir,
            &["docker", "exec", "-it", "emux-docker", "/emux/run/monitor"],
        )?
        .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("emux monitor attach exited with status {status}").into())
        }
    }
}

fn invoke_emux_monitor_command(
    emux_dir: &Path,
    command_text: &str,
) -> DynResult<EmuxCommandOutput> {
    let monitor_script = [
        "import os",
        "import select",
        "import socket",
        "import sys",
        "",
        "command = os.environ['EMUX_MONITOR_COMMAND']",
        "sock = socket.create_connection(('127.0.0.1', 55555), timeout=3)",
        "sock.sendall((command + '\\n').encode('utf-8'))",
        "chunks = []",
        "while True:",
        "    ready, _, _ = select.select([sock], [], [], 0.5)",
        "    if not ready:",
        "        break",
        "    chunk = sock.recv(65535)",
        "    if not chunk:",
        "        break",
        "    chunks.append(chunk)",
        "sock.close()",
        "sys.stdout.write(b''.join(chunks).decode('utf-8', 'replace'))",
    ]
    .join("\n");
    let monitor_command = format!(
        "EMUX_MONITOR_COMMAND={} python3 - <<'PY'\n{}\nPY",
        shell_quote(command_text),
        monitor_script,
    );
    let output = spawn_emux_helper_command(emux_dir, &monitor_command)?.output()?;
    Ok(EmuxCommandOutput {
        command: monitor_command,
        exit_code: output.status.code(),
        stdout: sanitize_script_output(&String::from_utf8_lossy(&output.stdout)),
        stderr: sanitize_script_output(&String::from_utf8_lossy(&output.stderr)),
    })
}

fn spawn_emux_interactive(emux_dir: &Path, args: &[&str]) -> DynResult<ProcessCommand> {
    let script_path = script_binary_path();
    if cfg!(target_os = "macos") {
        let mut child = ProcessCommand::new(&script_path);
        child
            .current_dir(emux_dir)
            .arg("-q")
            .arg("/dev/null")
            .args(args);
        configure_emux_container_runtime(&mut child)?;
        return Ok(child);
    }

    let mut child = ProcessCommand::new(&script_path);
    child
        .current_dir(emux_dir)
        .arg("-qefc")
        .arg(
            args.iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        )
        .arg("/dev/null");
    configure_emux_container_runtime(&mut child)?;
    Ok(child)
}

fn script_binary_path() -> PathBuf {
    let preferred = PathBuf::from("/usr/bin/script");
    if preferred.is_file() {
        preferred
    } else {
        PathBuf::from("script")
    }
}

fn parse_emux_ps_output(stdout: &str) -> Vec<ObservedProcessEntry> {
    let mut processes = Vec::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut parts = line.split_whitespace();
        let Some(pid_text) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        let _tty = parts.next();
        let _stat = parts.next();
        let _time = parts.next();
        let command = parts.collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            continue;
        }
        processes.push(ObservedProcessEntry::new(pid, command, "emuxps"));
    }
    processes
}

fn parse_emux_netstat_output(stdout: &str) -> Vec<ObservedNetworkEntry> {
    let mut endpoints = Vec::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with("Proto ")
            || line.starts_with("Active Internet connections")
            || line.starts_with("/home/r0/.bashrc:")
        {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(proto) = parts.next() else {
            continue;
        };
        let _recv_q = parts.next();
        let _send_q = parts.next();
        let Some(local_addr) = parts.next() else {
            continue;
        };
        let _foreign_addr = parts.next();
        let state = parts.next().unwrap_or("");

        let Some((host, port_text)) = local_addr.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port_text.parse::<u16>() else {
            continue;
        };

        endpoints.push(
            ObservedNetworkEntry::new(
                DebugSurfaceKind::Service,
                format!("{proto}-{port}-{state}"),
                host,
                port,
            )
            .with_uri(format!("{proto}://{host}:{port}")),
        );
    }
    endpoints
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if !value.contains('\'') {
        return format!("'{value}'");
    }
    let mut quoted = String::from("'");
    for segment in value.split('\'') {
        quoted.push_str(segment);
        quoted.push_str("'\"'\"'");
    }
    quoted.pop();
    quoted.push('\'');
    quoted
}

fn find_ssh_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            let candidate = entry.join("ssh");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    for fallback in ["/usr/bin/ssh", "/opt/homebrew/bin/ssh"] {
        let candidate = PathBuf::from(fallback);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn find_monitor_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            for binary in ["nc", "netcat", "ncat"] {
                let candidate = entry.join(binary);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    for fallback in ["/usr/bin/nc", "/opt/homebrew/bin/nc", "/usr/bin/netcat"] {
        let candidate = PathBuf::from(fallback);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn find_gdb_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            for binary in ["gdb", "gdb-multiarch"] {
                let candidate = entry.join(binary);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    for fallback in [
        "/usr/bin/gdb",
        "/opt/homebrew/bin/gdb",
        "/usr/local/bin/gdb",
    ] {
        let candidate = PathBuf::from(fallback);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

#[derive(Debug)]
struct EmuxCommandOutput {
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

pub(crate) fn current_timestamp_string() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("unix-ms:{millis}")
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
