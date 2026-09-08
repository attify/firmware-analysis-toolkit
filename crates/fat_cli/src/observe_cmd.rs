use std::error::Error;
use std::path::Path;

use fat_core::artifacts::ArtifactKind;

use crate::debug_cmd::{
    build_network_snapshot, build_process_snapshot, build_service_snapshot, load_context,
    load_latest_readiness_report, readiness_state_for_network_entry, write_runtime_json_artifact,
};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run_ps(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let snapshot = build_process_snapshot(&context)?;
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &snapshot.session_id,
        &snapshot.run_id,
        ArtifactKind::RuntimeCapture,
        "process-snapshot",
        "fat observe ps",
        "normalized observed processes",
        "observe",
        &snapshot.backend_id,
        context.view.run.substrate_kind,
        &serde_json::to_string_pretty(&snapshot)?,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        print!("{}", render_process_snapshot(&snapshot));
    }
    Ok(())
}

pub fn run_services(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let snapshot = build_service_snapshot(&context.store, &context.view)?;
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &snapshot.session_id,
        &snapshot.run_id,
        ArtifactKind::RuntimeCapture,
        "service-snapshot",
        "fat observe services",
        "normalized observed services",
        "observe",
        &snapshot.backend_id,
        context.view.run.substrate_kind,
        &serde_json::to_string_pretty(&snapshot)?,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        print!("{}", render_service_snapshot(&snapshot));
    }
    Ok(())
}

fn render_process_snapshot(snapshot: &fat_core::debug::ObservedProcessSnapshot) -> String {
    let mut output = String::new();
    output.push_str(&format!("session: {}\n", snapshot.session_id));
    output.push_str(&format!("run: {}\n", snapshot.run_id));
    output.push_str(&format!("backend: {}\n", snapshot.backend_id));
    output.push_str(&format!("process count: {}\n", snapshot.processes.len()));
    for process in &snapshot.processes {
        output.push_str(&format!(
            "process {} [{}]: {}\n",
            process.pid, process.source_kind, process.command
        ));
    }
    output
}

pub fn run_net(project_dir: &Path, session_id: Option<&str>, json: bool) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let snapshot = build_network_snapshot(&context)?;
    let readiness_report = load_latest_readiness_report(
        &context.store,
        &context.view.session.session_id,
        &context.view.run.run_id,
    )?;
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &snapshot.session_id,
        &snapshot.run_id,
        ArtifactKind::RuntimeCapture,
        "network-snapshot",
        "fat observe net",
        "normalized observed network endpoints",
        "observe",
        &snapshot.backend_id,
        snapshot.substrate_kind,
        &serde_json::to_string_pretty(&snapshot)?,
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        print!(
            "{}",
            render_network_snapshot(&snapshot, readiness_report.as_ref())
        );
    }
    Ok(())
}

fn render_service_snapshot(snapshot: &fat_core::debug::ObservedServiceSnapshot) -> String {
    let mut output = String::new();
    output.push_str(&format!("session: {}\n", snapshot.session_id));
    output.push_str(&format!("run: {}\n", snapshot.run_id));
    output.push_str(&format!("backend: {}\n", snapshot.backend_id));
    output.push_str(&format!("service count: {}\n", snapshot.services.len()));
    for service in &snapshot.services {
        match &service.endpoint {
            Some(endpoint) => output.push_str(&format!(
                "service {} {} [{}]\n",
                service.name, endpoint, service.source_kind
            )),
            None => output.push_str(&format!(
                "service {} [{}]\n",
                service.name, service.source_kind
            )),
        }
    }
    output
}

fn render_network_snapshot(
    snapshot: &fat_core::debug::ObservedNetworkSnapshot,
    readiness_report: Option<&fat_core::rehosting::ReadinessReport>,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("session: {}\n", snapshot.session_id));
    output.push_str(&format!("run: {}\n", snapshot.run_id));
    output.push_str(&format!("backend: {}\n", snapshot.backend_id));
    output.push_str(&format!(
        "network endpoint count: {}\n",
        snapshot.endpoints.len()
    ));
    for endpoint in &snapshot.endpoints {
        let rendered = endpoint
            .uri
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}:{}", endpoint.host, endpoint.port));
        match readiness_state_for_network_entry(readiness_report, endpoint) {
            Some(state) => output.push_str(&format!(
                "network {} [{}] state={}: {}\n",
                endpoint.name,
                endpoint.surface_kind.as_str(),
                state.as_str(),
                rendered
            )),
            None => output.push_str(&format!(
                "network {} [{}]: {}\n",
                endpoint.name,
                endpoint.surface_kind.as_str(),
                rendered
            )),
        }
    }
    output
}
