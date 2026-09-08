use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use fat_backend::emux::{
    remove_emux_container_if_present, EmuxManager, EmuxRequest, EMUX_DIR_ENV,
    EMUX_REFERENCE_DEVICE_ENV,
};
use fat_backend::managed_linux_vm::{
    firmae_host_python_from_env, firmae_upstream_dir_from_env,
    managed_linux_vm_bundle_dir_from_env, managed_linux_vm_bundle_version_from_env,
    ManagedLinuxVmLaunchResult, ManagedLinuxVmLaunchState, ManagedLinuxVmManager,
    ManagedLinuxVmProbeOutcome, ManagedLinuxVmProbeSource, ManagedLinuxVmRequest,
    ManagedLinuxVmRuntimeOutcome, ManagedLinuxVmRuntimePhase, ManagedLinuxVmRuntimeStatus,
    ManagedLinuxVmUpstreamLaunchRequest, ManagedLinuxVmUpstreamLaunchResult,
    ManagedLinuxVmUpstreamObservationRequest, ManagedLinuxVmUpstreamStopRequest,
};
use fat_backend::qemu_direct::{QemuDirectDriver, QemuDirectRequest};
use fat_backend::service_user_mode::{
    ServiceUserModeLaunchManifest, ServiceUserModeManager, ServiceUserModeRequest,
};
use fat_backend::{BackendSubstrateKind, CommandProbe, PathCommandProbe};
use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::debug::{
    DebugSurfaceKind, ObservedNetworkEntry, ObservedNetworkSnapshot, ObservedProcessEntry,
    ObservedProcessSnapshot, ObservedServiceEntry, ObservedServiceSnapshot,
};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::project::ProjectStatus;
use fat_core::readiness::{ConfidenceLevel, ConfidenceReport};
use fat_core::rehosting::{
    AttemptRecord, ReadinessReport, RehostingMode, RepairActionKind, RepairMaterializationRecord,
    RepairRecord, RuntimeSurfaceRecord, SurfaceReadiness,
};
use fat_core::rehosting_policy::{
    FallbackReason, SelectionTrace, SubstrateAttempt, SubstrateAttemptState,
    SubstrateKind as LogicalSubstrateKind, SubstratePreference,
};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runs::{GoalProgressDelta, RunOrigin, RunStatus};
use fat_core::runtime_store::RuntimeStore;
use fat_core::services::{
    managed_runtime_summary_from_runtime_status_json, managed_runtime_summary_from_summary_json,
};
use fat_core::sessions::GoalProgress;
use fat_core::target_model::TargetModel;
use fat_core::targets::derive_target_id;
use fat_emulate::kernel_catalog::resolve_kernel_asset_source;
use fat_emulate::launch_native_system_with;
use fat_emulate::plan::{create_emulation_bundle_from_request, EmulationBundleRequest};
use fat_emulate::readiness_engine::{build_diagnostic_blocker, build_runtime_confidence};
use fat_emulate::reference_runner::build_reference_runner_blueprint;
use fat_emulate::repair::{apply_repair_for_retry, decide_repair, RepairDecision};
use fat_emulate::service_runner::{build_service_runner_blueprint, launchable_service_executable};
use fat_emulate::strategy::EmulationAutomationMode;
use fat_emulate::substrate_selection::{select_substrate, RunnerKind};
use fat_emulate::synthesizer::{SynthesisContext, SynthesisEngine, SynthesisRequest};
use fat_emulate::system_runner::{build_system_runner_blueprint, SystemRunnerBlueprint};
use fat_emulate::validators::{apply_runtime_validation, RuntimeValidationSnapshot};
use fat_extract::ExtractionManifest;
use fat_plugin_api::AnalysisTrigger;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::run_cmd::{load_runtime_view, render_runtime_view};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NativeSystemAssemblyPartition {
    source_role: String,
    source_path: String,
    destination: String,
    strategy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NativeSystemAssemblyManifest {
    version: u32,
    partitions: Vec<NativeSystemAssemblyPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NativeSystemKernelIdentity {
    version: u32,
    profile_id: String,
    managed_bundle_id: Option<String>,
    compatibility_class: Option<String>,
    artifact_digest: Option<String>,
    source_path: String,
    expected_sha256: Option<String>,
    actual_sha256: String,
    staged_path: Option<String>,
    staged_sha256: Option<String>,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HttpProbeState {
    surface_name: String,
    uri: String,
    method: String,
    probe_path: String,
    timeout_ms: u64,
    connected: bool,
    reply_received: bool,
    status_line: Option<String>,
    status_code: Option<u16>,
    response_bytes: usize,
    failure_mode: Option<String>,
}

struct HttpProbeTarget {
    surface_name: String,
    uri: String,
    host: String,
    port: u16,
    path: String,
    scheme: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessChainBasis {
    selected_service: Option<String>,
    selected_init: Option<String>,
    peer_dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessChainExpectedRole {
    role: String,
    match_kind: String,
    expected: String,
    required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessChainObservedRole {
    role: String,
    matched: bool,
    matched_process: Option<String>,
    matched_service: Option<String>,
    pid: Option<u32>,
    source_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessChainState {
    validator_version: u32,
    substrate_kind: LogicalSubstrateKind,
    observation_method: String,
    chain_basis: ProcessChainBasis,
    expected_roles: Vec<ProcessChainExpectedRole>,
    observed_roles: Vec<ProcessChainObservedRole>,
    missing_roles: Vec<String>,
    validated: bool,
    failure_mode: Option<String>,
}

const DEFAULT_PROJECTS_DIR: &str = ".fat-projects";
const MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS_ENV: &str =
    "FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS";
const MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS_ENV: &str = "FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS";
const MANAGED_LINUX_VM_SUPERVISOR_EXECUTABLE_ENV: &str =
    "FAT_MANAGED_LINUX_VM_SUPERVISOR_EXECUTABLE";
const NATIVE_SYSTEM_ROOTFS_BLOCKS: &str = "262144";
const EXT2_BUILDER_IMAGE_ENV: &str = "FAT_EXT2_BUILDER_IMAGE";
const SYSTEM_KERNEL_SHA256_ENV: &str = "FAT_SYSTEM_KERNEL_SHA256";
const MIPSEL_INIT_TRAMPOLINE: &[u8] = include_bytes!("../assets/fat-init-trampoline.mipsel");
const MIPSEL_INIT_TRAMPOLINE_SHA256: &str =
    "d254a2bf2079f8729a8ee59442c752b8e70c99abee9099f45c6defb10e932b7f";

pub fn run(
    project: Option<PathBuf>,
    backend: Option<String>,
    substrate_policy: Option<String>,
    session_id: Option<String>,
    ports: Vec<u16>,
    status: bool,
    list: bool,
    list_json: bool,
    gc: bool,
    stop: bool,
    instrument: Option<PathBuf>,
    pack: Option<String>,
    experimental_rehosting: bool,
    accept_degraded_rehosting: bool,
    kernel_class: Option<String>,
) -> DynResult<()> {
    let project_dir = resolve_project_dir(project)?;

    if list {
        let report = crate::emulate_list::collect_emulation_list(&project_dir)
            .map_err(|err| format!("failed to collect emulation list: {err}"))?;
        if list_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|err| format!("failed to serialize list report: {err}"))?
            );
        } else {
            print!("{}", crate::emulate_list::render_emulation_table(&report));
        }
        return Ok(());
    }

    let store = RuntimeStore::open(&project_dir)?;

    if gc {
        return crate::emulate_gc::run_gc(&project_dir, &store);
    }

    if status {
        if let Some(view) =
            load_runtime_view_with_refresh(&project_dir, &store, session_id.as_deref())?
        {
            print!("{}", render_runtime_output(&store, "", &view)?);
            return Ok(());
        }
        return Err("no session records available for status inspection".into());
    }

    if stop {
        return stop_session(&project_dir, &store, session_id.as_deref());
    }

    // Checked before the project database is touched: a launch the caps have no
    // room for should cost nothing and change nothing.
    crate::emulate_config::enforce_lifecycle_caps(&project_dir, resolve_data_root().as_deref())?;

    let db = ProjectDb::open(&project_dir)?;
    let project_record = load_project(&db, &project_dir)?;
    if pack.is_some() {
        crate::rehost_cmd::resolve_pack_for_emulate(pack.as_deref(), &[])?;
    }
    parse_substrate_preference(substrate_policy.as_deref())?;

    let result = launch_session(
        &project_dir,
        &store,
        &project_record,
        backend,
        substrate_policy,
        session_id.unwrap_or_else(|| "session-1".to_string()),
        ports,
        instrument,
        pack,
        experimental_rehosting,
        accept_degraded_rehosting,
        kernel_class,
    );
    if result.is_ok() {
        let mut running_project = project_record;
        running_project.status = ProjectStatus::Emulating;
        db.save(&running_project)?;
    }
    result
}

fn resolve_project_dir(project: Option<PathBuf>) -> DynResult<PathBuf> {
    match project {
        Some(project_dir) => normalize_project_dir(&project_dir),
        None => normalize_project_dir(&select_project_dir(Path::new(DEFAULT_PROJECTS_DIR))?),
    }
}

fn select_project_dir(projects_root: &Path) -> DynResult<PathBuf> {
    if !projects_root.exists() {
        return Err(format!(
            "no projects found under {}; pass --project <path>",
            projects_root.display()
        )
        .into());
    }

    let mut project_dirs: Vec<PathBuf> = fs::read_dir(projects_root)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir() && path.join(".fat.db").exists())
        .collect();
    project_dirs.sort();

    match project_dirs.len() {
        1 => Ok(project_dirs.remove(0)),
        0 => Err(format!(
            "no projects found under {}; pass --project <path>",
            projects_root.display()
        )
        .into()),
        _ => Err(format!(
            "multiple projects found under {}; pass --project <path>",
            projects_root.display()
        )
        .into()),
    }
}

/// Resolve a project directory to an absolute, canonical path.
///
/// Native-system launches set the QEMU child working directory to the run
/// directory, so every FAT-generated file argument (kernel, rootfs, serial log,
/// capture files) must be absolute. Anchoring the project directory here keeps
/// `--project ./relative/path` equivalent to the absolute form.
fn normalize_project_dir(project_dir: &Path) -> DynResult<PathBuf> {
    if !project_dir.is_dir() {
        return Err(format!(
            "project path does not exist or is not a directory: {}",
            project_dir.display()
        )
        .into());
    }

    fs::canonicalize(project_dir).map_err(|error| {
        format!(
            "failed to resolve project path {}: {error}",
            project_dir.display()
        )
        .into()
    })
}

fn parse_substrate_preference(raw: Option<&str>) -> DynResult<SubstratePreference> {
    match raw
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("auto") => Ok(SubstratePreference::Auto),
        Some("service-first") => Ok(SubstratePreference::ServiceFirst),
        Some("system-first") => Ok(SubstratePreference::SystemFirst),
        Some("reference-only") => Ok(SubstratePreference::ReferenceOnly),
        Some(other) => Err(format!(
            "unsupported substrate policy: {other} (expected auto, service-first, system-first, or reference-only)"
        )
        .into()),
    }
}

fn effective_substrate_preference(
    requested: SubstratePreference,
    substrate_policy_explicit: bool,
    instrument_requested: bool,
) -> SubstratePreference {
    if instrument_requested && !substrate_policy_explicit && requested == SubstratePreference::Auto
    {
        SubstratePreference::SystemFirst
    } else {
        requested
    }
}

fn pack_substrate_preference(raw: Option<&str>) -> DynResult<Option<SubstratePreference>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("service") => Ok(Some(SubstratePreference::ServiceFirst)),
        Some("system") => Ok(Some(SubstratePreference::SystemFirst)),
        Some("reference") => Ok(Some(SubstratePreference::ReferenceOnly)),
        Some(other) => Err(format!("unsupported rehosting pack substrate: {other}").into()),
    }
}

fn effective_instrument_backend(
    requested_backend: Option<String>,
    instrument_requested: bool,
) -> Option<String> {
    if instrument_requested && requested_backend.is_none() {
        Some("qemu-direct".to_string())
    } else {
        requested_backend
    }
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<fat_core::project::Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn launch_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    backend: Option<String>,
    substrate_policy: Option<String>,
    session_id: String,
    ports: Vec<u16>,
    instrument: Option<PathBuf>,
    pack: Option<String>,
    experimental_rehosting: bool,
    accept_degraded_rehosting: bool,
    kernel_class: Option<String>,
) -> DynResult<()> {
    // Resolve an explicit --pack up front so an invalid one fails fast, before
    // any session records are written.
    let explicit_pack = crate::rehost_cmd::resolve_pack_for_emulate(pack.as_deref(), &[])?;

    let mut target_signals = load_project_signals(project_dir).unwrap_or_default();
    if let Some(kernel_class) = kernel_class {
        target_signals.push(format!("kernel-class:{kernel_class}"));
    }
    if target_signals.is_empty() {
        return Err(format!(
            "project {} has no analysis signals; run `fat analyze --project {}` before emulation",
            project_record.name,
            project_dir.display()
        )
        .into());
    }

    // Choose the pack: an explicit --pack wins; otherwise auto-select the best
    // matching pack for the target's signals (if any).
    let (selected_pack, pack_auto_selected) = match explicit_pack {
        Some(pack) => (Some(pack), false),
        None if experimental_rehosting => (
            crate::rehost_cmd::auto_select_pack(project_dir, &target_signals, &[])
                .map(|(pack, _)| pack),
            true,
        ),
        None => (None, false),
    };
    let pack_overlay = selected_pack
        .as_ref()
        .map(fat_core::rehosting_pack_overlay::PackOverlay::from_pack);
    let family_guess = fat_family::classify(target_signals.iter().map(String::as_str));
    let probe = PathCommandProbe;
    let docker_binary = probe
        .command_path("docker")
        .unwrap_or_else(|| project_dir.join("work").join("missing-docker"));
    let host_capabilities = collect_host_capabilities(project_dir, &probe);
    let requested_preference = parse_substrate_preference(substrate_policy.as_deref())?;
    let pack_preference = pack_substrate_preference(
        pack_overlay
            .as_ref()
            .and_then(|overlay| overlay.requested_substrate.as_deref()),
    )?;
    if requested_preference != SubstratePreference::Auto
        && pack_preference.is_some_and(|pack| pack != requested_preference)
    {
        return Err(format!(
            "rehosting pack substrate conflicts with explicit --substrate-policy {}",
            substrate_policy.as_deref().unwrap_or("auto")
        )
        .into());
    }
    let substrate_preference = effective_substrate_preference(
        pack_preference.unwrap_or(requested_preference),
        substrate_policy.is_some(),
        instrument.is_some(),
    );

    let effective_backend = effective_instrument_backend(backend.clone(), instrument.is_some());

    let mut bundle_request = EmulationBundleRequest::new(session_id, ports)
        .with_target_evidence(target_signals.clone())
        .with_host_capabilities(host_capabilities)
        .with_substrate_preference(substrate_preference);
    if let Some(requested_backend) = effective_backend.clone() {
        bundle_request = bundle_request.with_requested_backend(requested_backend.clone());
        if matches!(requested_backend.as_str(), "firmae" | "firmadyne") {
            bundle_request = bundle_request.with_requested_substrate("managed-linux-vm");
        }
    }

    let mut plan = contextualize_plan(
        create_emulation_bundle_from_request(bundle_request)?,
        project_record,
    );
    ensure_pack_matches_selected_plan(pack_overlay.as_ref(), &plan)?;
    if backend.is_none()
        && plan.rehosting_recipe.selected_substrate == LogicalSubstrateKind::System
        && plan.strategy.selected.backend_id == "firmae"
        && (firmae_upstream_dir_from_env().is_none() || firmae_host_python_from_env().is_none())
    {
        if let Ok(replanned) = create_emulation_bundle_from_request(
            EmulationBundleRequest::new(
                plan.requested_session_id.clone(),
                plan.clone().launch().mapped_ports(),
            )
            .with_target_evidence(target_signals.clone())
            .with_host_capabilities(collect_host_capabilities(project_dir, &probe))
            .with_requested_backend("firmadyne")
            .with_requested_substrate("managed-linux-vm")
            .with_substrate_preference(substrate_preference)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
        ) {
            plan = contextualize_plan(replanned, project_record);
            annotate_system_backend_swap(
                &mut plan,
                "firmadyne selected because firmae upstream inputs are unavailable",
            );
            ensure_pack_matches_selected_plan(pack_overlay.as_ref(), &plan)?;
        }
    }
    // Build typed instrumentation config if --instrument was provided
    if let Some(instrument_path) = instrument {
        let config = build_instrumentation_config(&instrument_path)?;
        plan.rehosting_recipe.instrumentation = Some(config);
    }

    // Surface the selected rehosting pack and what it overrides.
    if let Some(overlay) = &pack_overlay {
        let origin = if pack_auto_selected {
            " (auto-selected)"
        } else {
            ""
        };
        println!("rehosting pack: {}{}", overlay.pack_id, origin);
        if overlay.applied.is_empty() {
            println!("  pack overrides: none");
        } else {
            println!("  pack overrides: {}", overlay.applied.join(", "));
        }
    }

    let session_root_id = plan.session.session_id.clone();
    let mut attempt_trace = plan.selection_trace.attempts.clone();
    let attempt_order = substrate_preference.default_order();
    let mut attempt_sequence = 1u32;

    loop {
        // Re-apply pack overrides each iteration: substrate fallback / repair
        // retries rebuild the recipe, and apply_to_recipe is idempotent.
        if let Some(overlay) = &pack_overlay {
            overlay.apply_to_recipe(&mut plan.rehosting_recipe);
            let report = final_pack_capability_report(overlay, &plan);
            ensure_pack_capability(&report, accept_degraded_rehosting)?;
            plan.rehosting_recipe.rehosting_capability = Some(report);
        }
        let recipe = persist_plan_execution_records(
            project_dir,
            store,
            project_record,
            &plan,
            attempt_sequence,
        )?;
        let current_run_id = plan.run.record.run_id.clone();
        if let Err(error) = dispatch_emulation_plan(
            project_dir,
            store,
            project_record,
            &family_guess.family_id,
            &target_signals,
            docker_binary.clone(),
            recipe,
            plan.clone(),
            &probe,
        ) {
            if store
                .read_run(plan.session.session_id.as_str(), current_run_id.as_str())
                .is_ok()
            {
                mark_project_emulation_error(project_dir, project_record)?;
            }
            return Err(error);
        }
        let run = store.read_run(plan.session.session_id.as_str(), current_run_id.as_str())?;
        if !run_status_is_failed(run.status) {
            return Ok(());
        }
        let diagnostics = store
            .read_run_diagnostics(plan.session.session_id.as_str(), current_run_id.as_str())?;
        let failure_detail = diagnostics
            .last()
            .map(|diagnostic| diagnostic.summary.clone())
            .unwrap_or_else(|| "execution failed".to_string());
        update_attempt_state(
            &mut attempt_trace,
            plan.rehosting_recipe.selected_substrate,
            SubstrateAttemptState::Failed,
            Some(FallbackReason::ExecutionFailed),
            failure_detail.clone(),
        );

        let current_index = attempt_order
            .iter()
            .position(|substrate| *substrate == plan.rehosting_recipe.selected_substrate)
            .unwrap_or(0);
        let existing_session = store.read_session(session_root_id.as_str())?;
        if let Some(repaired_plan) = build_repair_retry_plan(
            store,
            project_record,
            &plan,
            &existing_session,
            current_run_id.as_str(),
            attempt_sequence + 1,
            diagnostics.last(),
            substrate_preference,
            &attempt_trace,
        )? {
            plan = repaired_plan;
            attempt_sequence += 1;
            continue;
        }
        if !should_attempt_substrate_fallback(
            backend.is_some(),
            plan.rehosting_recipe.instrumentation.is_some(),
        ) || selected_pack.is_some()
        {
            if plan.rehosting_recipe.instrumentation.is_some() {
                eprintln!(
                    "Instrumentation active; substrate fallback disabled \
                     (only qemu-direct system-mode supports the TCG hook plugin)."
                );
            }
            mark_project_emulation_error(project_dir, project_record)?;
            return Err(format!(
                "emulation launch failed after exhausting allowed attempts: {failure_detail}"
            )
            .into());
        }
        let mut next_plan = None;

        for substrate in attempt_order.iter().skip(current_index + 1).copied() {
            let Some(candidate_plan) = exact_plan_for_logical_substrate(
                project_record,
                plan.requested_session_id.as_str(),
                plan.clone().launch().mapped_ports(),
                target_signals.clone(),
                collect_host_capabilities(project_dir, &probe),
                substrate,
            )?
            else {
                update_attempt_state(
                    &mut attempt_trace,
                    substrate,
                    SubstrateAttemptState::Unavailable,
                    Some(FallbackReason::Unavailable),
                    "no viable candidate matched current constraints",
                );
                continue;
            };

            let mut rebound = rebind_plan_to_existing_session(
                candidate_plan,
                existing_session.project_id.as_str(),
                existing_session.target_id.as_str(),
                existing_session.session_id.as_str(),
                existing_session.requested_session_id.as_deref(),
                &existing_session.run_ids,
                current_run_id.as_str(),
                attempt_sequence + 1,
            );
            update_attempt_state(
                &mut attempt_trace,
                substrate,
                SubstrateAttemptState::Selected,
                Some(FallbackReason::EscalatedForRecovery),
                format!("fallback after {current_run_id}"),
            );
            rebound.selection_trace = SelectionTrace::new(
                existing_session.project_id.clone(),
                existing_session.target_id.clone(),
                existing_session.session_id.clone(),
                rebound.run.record.run_id.clone(),
            )
            .with_preference(substrate_preference)
            .with_attempts(attempt_trace.clone());
            next_plan = Some(rebound);
            break;
        }

        let Some(fallback_plan) = next_plan else {
            mark_project_emulation_error(project_dir, project_record)?;
            return Err(format!(
                "emulation launch failed after exhausting substrate fallbacks: {failure_detail}"
            )
            .into());
        };

        plan = fallback_plan;
        attempt_sequence += 1;
    }
}

fn ensure_pack_capability(
    report: &fat_core::rehosting_recipe::RehostingCapabilityReport,
    accepted: bool,
) -> DynResult<()> {
    if report.is_degraded() && !accepted {
        let mut limitations = report.unsupported_actions.clone();
        limitations.extend(report.degraded_actions.clone());
        return Err(format!(
            "experimental rehosting pack '{}' has capability gaps: {}; rerun with --experimental-rehosting --accept-degraded-rehosting to accept this degraded run",
            report.pack_id,
            limitations.join(", ")
        )
        .into());
    }
    Ok(())
}

fn ensure_pack_matches_selected_plan(
    overlay: Option<&fat_core::rehosting_pack_overlay::PackOverlay>,
    plan: &fat_emulate::EmulationPlan,
) -> DynResult<()> {
    let Some(overlay) = overlay else {
        return Ok(());
    };
    let Some(requested) = overlay.requested_substrate.as_deref() else {
        return Ok(());
    };
    if plan.rehosting_recipe.selected_substrate.as_str() != requested {
        return Err(format!(
            "rehosting pack '{}' requires logical substrate {}, but the selected plan is backend={} runtime-substrate={} logical-substrate={}",
            overlay.pack_id,
            requested,
            plan.strategy.selected.backend_id,
            plan.strategy.selected.substrate.as_str(),
            plan.rehosting_recipe.selected_substrate.as_str(),
        )
        .into());
    }
    Ok(())
}

fn final_pack_capability_report(
    overlay: &fat_core::rehosting_pack_overlay::PackOverlay,
    plan: &fat_emulate::EmulationPlan,
) -> fat_core::rehosting_recipe::RehostingCapabilityReport {
    let mut report = overlay.capability_report();
    let is_native_qemu_direct = plan.strategy.selected.backend_id == "qemu-direct"
        && plan.strategy.selected.substrate == fat_core::runs::SubstrateKind::NativeHost;
    let consumes_qemu_machine = is_native_qemu_direct
        && plan.rehosting_recipe.selected_substrate == LogicalSubstrateKind::System;
    let consumes_filesystem_transforms = is_native_qemu_direct
        && matches!(
            plan.rehosting_recipe.selected_substrate,
            LogicalSubstrateKind::System | LogicalSubstrateKind::Service
        );
    let consumes_network_configuration = consumes_qemu_machine;
    let consumes_partition_materializations = consumes_qemu_machine;
    let consumes_guest_adaptations = consumes_qemu_machine;
    let has_network_configuration = overlay.network_mode.is_some()
        || overlay.network_interface.is_some()
        || overlay.network_fallback_ip.is_some();
    if !consumes_qemu_machine || !consumes_filesystem_transforms {
        let mut unsupported = Vec::new();
        report.supported_actions.retain(|action| {
            let backend_specific = (action == "qemu-machine" && !consumes_qemu_machine)
                || (action.starts_with("materialize:") && !consumes_filesystem_transforms);
            if backend_specific {
                unsupported.push(action.clone());
            }
            !backend_specific
        });
        for action in unsupported {
            if !report.unsupported_actions.contains(&action) {
                report.unsupported_actions.push(action);
            }
        }
    }
    if consumes_partition_materializations {
        let mut supported_partitions = Vec::new();
        report.unsupported_actions.retain(|action| {
            if action.starts_with("partition:") {
                supported_partitions.push(action.clone());
                false
            } else {
                true
            }
        });
        for action in supported_partitions {
            if !report.supported_actions.contains(&action) {
                report.supported_actions.push(action);
            }
        }
    }
    if consumes_guest_adaptations {
        let mut supported_adaptations = Vec::new();
        report.unsupported_actions.retain(|action| {
            if action.starts_with("repair:skip-command:")
                || action.starts_with("repair:skip-module:")
            {
                supported_adaptations.push(action.clone());
                false
            } else {
                true
            }
        });
        for action in supported_adaptations {
            if !report.supported_actions.contains(&action) {
                report.supported_actions.push(action);
            }
        }
    }
    if has_network_configuration {
        let destination = if consumes_network_configuration {
            &mut report.supported_actions
        } else {
            &mut report.unsupported_actions
        };
        if !destination
            .iter()
            .any(|action| action == "network-configuration")
        {
            destination.push("network-configuration".to_string());
        }
        if consumes_network_configuration {
            report.degraded_actions.retain(|action| {
                action
                    != "network configuration is recorded but backend fidelity remains experimental"
            });
        }
    }
    report.supported_actions.push(format!(
        "selected-backend:{}",
        plan.strategy.selected.backend_id
    ));
    report.supported_actions.push(format!(
        "selected-runtime-substrate:{}",
        plan.strategy.selected.substrate.as_str()
    ));
    report.supported_actions.push(format!(
        "selected-logical-substrate:{}",
        plan.rehosting_recipe.selected_substrate.as_str()
    ));
    report
}

fn mark_project_emulation_error(
    project_dir: &Path,
    project_record: &fat_core::project::Project,
) -> DynResult<()> {
    let mut failed_project = project_record.clone();
    failed_project.status = ProjectStatus::Error;
    ProjectDb::open(project_dir)?.save(&failed_project)?;
    Ok(())
}

fn build_repair_retry_plan(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    current_plan: &fat_emulate::EmulationPlan,
    existing_session: &fat_core::sessions::SessionRecord,
    previous_run_id: &str,
    next_sequence: u32,
    diagnostic: Option<&DiagnosticRecord>,
    substrate_preference: SubstratePreference,
    attempt_trace: &[SubstrateAttempt],
) -> DynResult<Option<fat_emulate::EmulationPlan>> {
    let Some(diagnostic) = diagnostic else {
        return Ok(None);
    };
    let Some((decision, repaired_recipe)) =
        apply_repair_for_retry(&current_plan.rehosting_recipe, diagnostic)
    else {
        return Ok(None);
    };

    let retry_budget = current_plan.rehosting_recipe.retry_budget.max(1);
    let current_substrate = current_plan.rehosting_recipe.selected_substrate;
    let prior_runs_on_substrate = count_runs_for_substrate(
        store,
        existing_session.session_id.as_str(),
        &existing_session.run_ids,
        current_substrate,
    )?;
    if prior_runs_on_substrate >= retry_budget as usize {
        return Ok(None);
    }

    let mut rebound = rebind_plan_to_existing_session(
        current_plan.clone(),
        existing_session.project_id.as_str(),
        existing_session.target_id.as_str(),
        existing_session.session_id.as_str(),
        existing_session.requested_session_id.as_deref(),
        &existing_session.run_ids,
        previous_run_id,
        next_sequence,
    );
    rebound.rehosting_recipe = project_rehosting_recipe_for_plan(
        existing_session.target_id.as_str(),
        rebound.run.record.run_id.as_str(),
        &rebound.target_model,
        &repaired_recipe,
    );
    let mut updated_attempts = attempt_trace.to_vec();
    update_attempt_state(
        &mut updated_attempts,
        current_substrate,
        SubstrateAttemptState::Selected,
        Some(FallbackReason::EscalatedForRecovery),
        format!(
            "auto-repair retry after {} using {}",
            previous_run_id,
            decision.action.as_str()
        ),
    );
    rebound.selection_trace = SelectionTrace::new(
        existing_session.project_id.clone(),
        existing_session.target_id.clone(),
        existing_session.session_id.clone(),
        rebound.run.record.run_id.clone(),
    )
    .with_preference(substrate_preference)
    .with_attempts(updated_attempts);
    Ok(Some(contextualize_plan(rebound, project_record)))
}

fn exact_plan_for_logical_substrate(
    project_record: &fat_core::project::Project,
    requested_session_id: &str,
    mapped_ports: Vec<u16>,
    target_evidence: Vec<String>,
    host_capabilities: Vec<String>,
    substrate: LogicalSubstrateKind,
) -> DynResult<Option<fat_emulate::EmulationPlan>> {
    let preference = match substrate {
        LogicalSubstrateKind::Service => SubstratePreference::ServiceFirst,
        LogicalSubstrateKind::System => SubstratePreference::SystemFirst,
        LogicalSubstrateKind::Reference => SubstratePreference::ReferenceOnly,
    };
    if substrate == LogicalSubstrateKind::System
        && (firmae_upstream_dir_from_env().is_none() || firmae_host_python_from_env().is_none())
    {
        if let Ok(plan) = create_emulation_bundle_from_request(
            EmulationBundleRequest::new(requested_session_id.to_string(), mapped_ports.clone())
                .with_target_evidence(target_evidence.clone())
                .with_host_capabilities(host_capabilities.clone())
                .with_requested_backend("firmadyne")
                .with_requested_substrate("managed-linux-vm")
                .with_substrate_preference(preference)
                .with_automation_mode(EmulationAutomationMode::AutoSafe),
        ) {
            let mut plan = contextualize_plan(plan, project_record);
            annotate_system_backend_swap(
                &mut plan,
                "firmadyne selected because firmae upstream inputs are unavailable",
            );
            return Ok(Some(plan));
        }
    }

    let request = EmulationBundleRequest::new(requested_session_id.to_string(), mapped_ports)
        .with_target_evidence(target_evidence)
        .with_host_capabilities(host_capabilities)
        .with_substrate_preference(preference)
        .with_automation_mode(EmulationAutomationMode::AutoSafe);
    match create_emulation_bundle_from_request(request) {
        Ok(plan) => {
            let plan = contextualize_plan(plan, project_record);
            if plan.rehosting_recipe.selected_substrate == substrate {
                Ok(Some(plan))
            } else {
                Ok(None)
            }
        }
        Err(fat_emulate::EmulationPlanError::UnsupportedBackend { .. }) => Ok(None),
    }
}

fn rebind_plan_to_existing_session(
    mut plan: fat_emulate::EmulationPlan,
    project_id: &str,
    target_id: &str,
    session_id: &str,
    requested_session_id: Option<&str>,
    existing_run_ids: &[String],
    previous_run_id: &str,
    sequence_in_session: u32,
) -> fat_emulate::EmulationPlan {
    plan.session.project_id = project_id.to_string();
    plan.session.target_id = target_id.to_string();
    plan.session.session_id = session_id.to_string();
    plan.session.requested_session_id = requested_session_id.map(str::to_string);

    let new_run = fat_core::runs::RunRecord::new(
        session_id.to_string(),
        plan.recipe.recipe_id.clone(),
        plan.strategy.selected.backend_id.clone(),
        plan.strategy.selected.substrate,
        sequence_in_session,
        RunOrigin::Fallback,
    )
    .with_derived_from_run_id(previous_run_id.to_string())
    .with_goal_progress_delta(GoalProgressDelta::new(
        GoalProgress::NotStarted,
        GoalProgress::NotStarted,
    ))
    .with_active_endpoints(plan.run.record.active_endpoints.clone());
    let new_run_id = new_run.run_id.clone();
    plan.run = fat_emulate::EmulationRun::new(new_run);
    let mut run_ids = existing_run_ids.to_vec();
    run_ids.push(new_run_id.clone());
    plan.session.run_ids = run_ids;
    plan.rehosting_recipe = project_rehosting_recipe_for_plan(
        target_id,
        new_run_id.as_str(),
        &plan.target_model,
        &plan.rehosting_recipe,
    );
    plan.requested_session_id = requested_session_id
        .unwrap_or(plan.requested_session_id.as_str())
        .to_string();
    plan
}

fn update_attempt_state(
    attempts: &mut Vec<SubstrateAttempt>,
    substrate: LogicalSubstrateKind,
    state: SubstrateAttemptState,
    reason: Option<FallbackReason>,
    detail: impl Into<String>,
) {
    let detail = Some(detail.into());
    if let Some(attempt) = attempts
        .iter_mut()
        .find(|attempt| attempt.substrate == substrate)
    {
        attempt.state = state;
        attempt.reason = reason;
        attempt.detail = detail;
        return;
    }
    let mut attempt = SubstrateAttempt::new(substrate, state);
    if let Some(reason) = reason {
        attempt = attempt.with_reason(reason);
    }
    if let Some(detail) = detail {
        attempt = attempt.with_detail(detail);
    }
    attempts.push(attempt);
}

fn run_status_is_failed(status: RunStatus) -> bool {
    matches!(
        status,
        RunStatus::Failed | RunStatus::TimedOut | RunStatus::Cancelled | RunStatus::CleanupFailed
    )
}

fn annotate_system_backend_swap(plan: &mut fat_emulate::EmulationPlan, detail: &str) {
    if plan.rehosting_recipe.selected_substrate != LogicalSubstrateKind::System
        || plan.strategy.selected.backend_id != "firmadyne"
    {
        return;
    }

    update_attempt_state(
        &mut plan.selection_trace.attempts,
        LogicalSubstrateKind::System,
        SubstrateAttemptState::Selected,
        Some(FallbackReason::Unavailable),
        format!(
            "selected backend={} substrate={} because {detail}",
            plan.strategy.selected.backend_id,
            plan.strategy.selected.substrate.as_str(),
        ),
    );
}

fn persist_plan_execution_records(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    plan: &fat_emulate::EmulationPlan,
    attempt_sequence: u32,
) -> DynResult<fat_core::recipes::RecipeRecord> {
    let launch_session = plan.clone().launch();
    let target_id = derive_target_id(&project_record.name, &project_record.firmware_name);
    let attempt = AttemptRecord::new(
        project_record.name.clone(),
        target_id.clone(),
        launch_session.session_id().to_string(),
        launch_session.run_record().run_id.clone(),
        attempt_sequence,
        rehosting_mode_for_logical_substrate(plan.rehosting_recipe.selected_substrate),
    )
    .with_summary(if attempt_sequence == 1 {
        "initial launch attempt registered".to_string()
    } else {
        format!("fallback launch attempt {attempt_sequence} registered")
    });
    let readiness = build_readiness_report(
        project_record,
        &target_id,
        launch_session.session_id(),
        launch_session.run_record().run_id.as_str(),
        &plan.readiness_goals,
        launch_session.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Registered,
        "registered surfaces before launch",
    );
    store.write_target_model(&plan.target_model)?;
    store.write_rehosting_recipe(
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
        &plan.rehosting_recipe,
    )?;
    store.write_selection_trace(&plan.selection_trace)?;
    store.write_target_profile(&plan.profile)?;
    store.write_attempt_record(&attempt)?;
    store.write_readiness_report(&readiness)?;
    persist_runner_blueprint_artifacts(project_dir, store, plan)?;

    let synthesis = SynthesisEngine::new()
        .synthesize(
            SynthesisRequest::from_strategy(plan.strategy.clone()).with_context(
                SynthesisContext::new(
                    plan.requested_session_id.clone(),
                    project_record.name.clone(),
                    plan.session.target_id.clone(),
                    plan.session.session_id.clone(),
                    plan.run.record.run_id.clone(),
                ),
            ),
        )
        .map_err(|err| format!("runtime synthesis failed: {err:?}"))?;
    Ok(plan
        .recipe_record()
        .clone()
        .with_synthesis_steps(synthesis.recipe.synthesis_steps.clone()))
}

fn rehosting_mode_for_logical_substrate(substrate: LogicalSubstrateKind) -> RehostingMode {
    match substrate {
        LogicalSubstrateKind::Service => RehostingMode::Service,
        LogicalSubstrateKind::System => RehostingMode::System,
        LogicalSubstrateKind::Reference => RehostingMode::Reference,
    }
}

fn dispatch_emulation_plan(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    family_id: &str,
    target_signals: &[String],
    docker_binary: PathBuf,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
    probe: &impl CommandProbe,
) -> DynResult<()> {
    let mapped_ports = plan.clone().launch().mapped_ports();
    let selected_run_id = plan.run.record.run_id.clone();
    let selected_backend_id = plan.strategy.selected.backend_id.clone();
    let selected_substrate = plan.strategy.selected.substrate;

    validate_instrumentation_support(&plan)?;

    match (
        plan.strategy.selected.backend_id.as_str(),
        plan.strategy.selected.substrate,
    ) {
        ("qemu-direct", fat_core::runs::SubstrateKind::NativeHost)
            if plan.rehosting_recipe.selected_substrate == LogicalSubstrateKind::System =>
        {
            launch_native_system_session(project_dir, store, project_record, recipe, plan, probe)
        }
        ("qemu-direct", fat_core::runs::SubstrateKind::NativeHost)
            if plan.rehosting_recipe.selected_substrate == LogicalSubstrateKind::Service
                && launchable_service_executable(&plan.target_model).is_some() =>
        {
            launch_service_user_mode_session(
                project_dir,
                store,
                project_record,
                recipe,
                plan,
                probe,
            )
        }
        ("qemu-direct", fat_core::runs::SubstrateKind::NativeHost) => launch_qemu_direct_session(
            project_dir,
            store,
            project_record,
            family_id,
            target_signals,
            docker_binary,
            mapped_ports,
            recipe,
            plan,
            probe,
        ),
        ("emux", fat_core::runs::SubstrateKind::DockerEngine) => {
            prepare_emux_reference_session(project_dir, store, project_record, recipe, plan)
        }
        ("firmae" | "firmadyne", fat_core::runs::SubstrateKind::ManagedLinuxVm) => {
            prepare_managed_linux_vm_session(project_dir, store, project_record, recipe, plan)
        }
        _ => persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            unsupported_runtime_diagnostic(
                &selected_run_id,
                &selected_backend_id,
                selected_substrate,
            ),
        ),
    }
}

fn validate_instrumentation_support(plan: &fat_emulate::EmulationPlan) -> DynResult<()> {
    if plan.rehosting_recipe.instrumentation.is_none() {
        return Ok(());
    }

    let is_native_system = plan.strategy.selected.backend_id == "qemu-direct"
        && plan.strategy.selected.substrate == fat_core::runs::SubstrateKind::NativeHost
        && plan.rehosting_recipe.selected_substrate
            == fat_core::rehosting_policy::SubstrateKind::System;

    if is_native_system {
        return Ok(());
    }

    Err(format!(
        "--instrument requires backend=qemu-direct substrate=native-host logical_substrate=system, \
         but this session selected backend={} substrate={} logical_substrate={}. \
         Try --backend qemu-direct --substrate-policy system-first.",
        plan.strategy.selected.backend_id,
        plan.strategy.selected.substrate.as_str(),
        plan.rehosting_recipe.selected_substrate.as_str(),
    )
    .into())
}

/// Returns `true` when substrate fallback should be attempted after the
/// initial emulation plan fails.  Fallback is blocked when:
///  - a specific backend was requested (`--backend`), or
///  - instrumentation is active (`--instrument`) — only qemu-direct
///    system-mode supports the TCG hook plugin; no fallback substrate
///    can provide it.
fn should_attempt_substrate_fallback(
    backend_explicit: bool,
    instrumentation_present: bool,
) -> bool {
    !backend_explicit && !instrumentation_present
}

fn prepare_emux_reference_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
) -> DynResult<()> {
    let run_id = plan.run.record.run_id.clone();
    let readiness_goals = plan.readiness_goals.clone();
    let Some(emux_dir) = emux_dir_from_env() else {
        return persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            emux_reference_recipe_unavailable_diagnostic(
                &run_id,
                format!("missing {EMUX_DIR_ENV}"),
            ),
        );
    };
    let Some(reference_device_id) = emux_reference_device_from_env() else {
        return persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            emux_reference_recipe_unavailable_diagnostic(
                &run_id,
                format!("missing {EMUX_REFERENCE_DEVICE_ENV}"),
            ),
        );
    };

    let manager = EmuxManager::new();
    let request = EmuxRequest::new(
        emux_dir,
        reference_device_id,
        managed_linux_vm_workspace_root(project_dir, plan.session.session_id.as_str()),
    )
    .with_run_id(run_id.clone());
    let prepared = match manager.prepare(request) {
        Ok(prepared) => prepared,
        Err(err) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                err.diagnostic,
            );
        }
    };
    let launch_result = match manager.launch_reference_device(&prepared) {
        Ok(result) => result,
        Err(err) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                err.diagnostic,
            );
        }
    };
    let launched_at = current_timestamp_string();
    let launch_state = prepared.launch_state(&launch_result);
    let userspace_result = match manager.start_userspace(&prepared, &launch_result) {
        Ok(result) => result,
        Err(err) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                err.diagnostic,
            );
        }
    };
    let userspace_state = prepared.userspace_state(&launch_result, &userspace_result);
    let runtime_status = prepared.runtime_status(&launch_state, Some(&userspace_state));
    let active = plan
        .launch()
        .into_active_run()
        .preparing_at(launched_at.clone())
        .launching_at(launched_at.clone())
        .running_at(launched_at)
        .reattach_endpoint(
            fat_core::runs::RuntimeEndpoint::new(
                fat_core::runs::RuntimeEndpointKind::Shell,
                "emux-userspace",
                "emux-docker",
                22222,
            )
            .with_uri("emux://userspace"),
        )
        .reattach_endpoint(
            fat_core::runs::RuntimeEndpoint::new(
                fat_core::runs::RuntimeEndpointKind::Monitor,
                "emux-monitor",
                "emux-docker",
                55555,
            )
            .with_uri("emux://monitor"),
        )
        .reattach_endpoint(
            fat_core::runs::RuntimeEndpoint::new(
                fat_core::runs::RuntimeEndpointKind::Debugger,
                "emux-gdb",
                "emux-docker",
                0,
            )
            .with_uri("emux://gdb"),
        )
        .with_supervision(
            fat_core::runs::SupervisionMode::None,
            fat_core::runs::HealthState::Unknown,
            None,
        )
        .with_supervisor_runtime(Some(launch_result.supervisor_pid), None, None);

    store.write_recipe(active.session().session_id(), &recipe)?;
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    store.write_readiness_report(&build_readiness_report(
        project_record,
        &derive_target_id(&project_record.name, &project_record.firmware_name),
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &readiness_goals,
        active.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Ready,
        "launch completed with ready surfaces",
    ))?;

    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-launch-command",
        "emux launch command",
        &launch_result.command,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-launch-stdout",
        "emux launch stdout",
        &launch_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-launch-stderr",
        "emux launch stderr",
        &launch_result.stderr,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-userspace-command",
        "emux userspace command",
        &userspace_result.command,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-userspace-stdout",
        "emux userspace stdout",
        &userspace_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-userspace-stderr",
        "emux userspace stderr",
        &userspace_result.stderr,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-launch-state",
        "emux launch state",
        &serde_json::to_string_pretty(&launch_state)?,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-userspace-state",
        "emux userspace state",
        &serde_json::to_string_pretty(&userspace_state)?,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-runtime-status",
        "emux runtime status",
        &serde_json::to_string_pretty(&runtime_status)?,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "emux-reconstruction-state",
        "emux reconstruction state",
        &serde_json::to_string_pretty(&prepared.reconstruction_state())?,
    )?;

    promote_runtime_validation_state(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
    )?;
    let view = load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
        .expect("runtime view");
    print!(
        "{}",
        render_launch_output(
            store,
            &recipe.recipe_id,
            &active.session().mapped_ports(),
            &view,
        )?
    );
    Ok(())
}

pub(crate) fn stop_session(
    project_dir: &Path,
    store: &RuntimeStore,
    session_id: Option<&str>,
) -> DynResult<()> {
    let Some(view) = load_runtime_view_with_refresh(project_dir, store, session_id)? else {
        return Err("no session records available to stop".into());
    };
    if view.run.substrate_kind == fat_core::runs::SubstrateKind::NativeHost
        && view.run.backend_driver == "qemu-direct"
    {
        return stop_native_system_session(project_dir, store, view);
    }
    if matches!(
        view.run.status,
        fat_core::runs::RunStatus::Completed | fat_core::runs::RunStatus::DegradedCompleted
    ) {
        print!("{}", render_runtime_view("", &view));
        return Ok(());
    }
    if view.run.substrate_kind == fat_core::runs::SubstrateKind::ManagedLinuxVm
        && matches!(view.run.backend_driver.as_str(), "firmae" | "firmadyne")
    {
        let managed_identity = if view.run.backend_driver == "firmae" {
            current_firmae_upstream_observation(
                store,
                view.session.session_id.as_str(),
                view.run.run_id.as_str(),
            )?
            .and_then(|observation| observation.container_name)
            .is_some()
        } else {
            firmadyne_cleanup_identity_is_present(project_dir, store, &view)?
        };
        if view.run.status == fat_core::runs::RunStatus::Running || managed_identity {
            return stop_managed_linux_vm_session(project_dir, store, view);
        }
    }
    if view.run.backend_driver == "emux" && view.run.supervisor_pid.is_some() {
        return stop_emux_session(project_dir, store, view);
    }
    if view.run.status != fat_core::runs::RunStatus::Running {
        print!("{}", render_runtime_view("", &view));
        return Ok(());
    }
    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let active = session
        .into_active_run()
        .completed_at(current_timestamp_string());
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    fat_plugin_host::dispatch_run_analysis(
        project_dir,
        AnalysisTrigger::RunCompleted,
        &active.session_record().session_id,
        &active.run_record().run_id,
    )?;
    print!(
        "{}",
        render_runtime_view(
            "",
            &load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
                .expect("runtime view")
        )
    );
    let _ = project_dir;
    Ok(())
}

fn firmadyne_cleanup_identity_is_present(
    project_dir: &Path,
    store: &RuntimeStore,
    view: &crate::run_cmd::RuntimeView,
) -> DynResult<bool> {
    if view.run.supervisor_pid.is_some() {
        return Ok(true);
    }
    let cleanup_failed = store
        .read_run_diagnostics(view.session.session_id.as_str(), view.run.run_id.as_str())?
        .iter()
        .any(|diagnostic| diagnostic.class == DiagnosticClass::CleanupFailed);
    let workspace = managed_linux_vm_workspace_root(project_dir, &view.session.session_id)
        .join("managed-linux-vm")
        .join(&view.run.backend_driver)
        .join(managed_linux_vm_bundle_version_from_env());
    Ok(cleanup_failed || workspace.is_dir())
}

pub fn load_runtime_view_with_refresh(
    project_dir: &Path,
    store: &RuntimeStore,
    requested_session_id: Option<&str>,
) -> DynResult<Option<crate::run_cmd::RuntimeView>> {
    let Some(view) = load_runtime_view(store, requested_session_id)? else {
        return Ok(None);
    };

    if view.run.substrate_kind == fat_core::runs::SubstrateKind::ManagedLinuxVm
        && matches!(view.run.backend_driver.as_str(), "firmae" | "firmadyne")
        && view.run.status == fat_core::runs::RunStatus::Running
    {
        return match view.run.supervision_mode {
            fat_core::runs::SupervisionMode::ProbeOnStatus => Ok(Some(
                refresh_managed_linux_vm_status(project_dir, store, view)?,
            )),
            fat_core::runs::SupervisionMode::BackgroundSupervisor => Ok(Some(
                refresh_managed_linux_vm_background_supervision(project_dir, store, view)?,
            )),
            fat_core::runs::SupervisionMode::None => Ok(Some(view)),
        };
    }

    if view.run.substrate_kind == fat_core::runs::SubstrateKind::NativeHost
        && view.run.backend_driver == "qemu-direct"
        && view.run.status == fat_core::runs::RunStatus::Running
        && view.run.supervisor_pid.is_some()
    {
        return Ok(Some(refresh_native_system_status(
            project_dir,
            store,
            view,
        )?));
    }

    Ok(Some(view))
}

fn refresh_native_system_status(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<crate::run_cmd::RuntimeView> {
    if view.run.supervisor_pid.is_some_and(process_is_running) {
        let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
        refresh_native_system_serial_artifact(project_dir, store, &project_record, &view)?;
        promote_runtime_validation_state(
            store,
            &project_record,
            view.session.session_id.as_str(),
            view.run.run_id.as_str(),
        )?;
        return load_runtime_view(store, Some(view.session.session_id.as_str()))?
            .ok_or_else(|| "native system runtime view disappeared during refresh".into());
    }

    let checked_at = current_timestamp_string();
    let diagnostic = DiagnosticRecord::new(
        view.run.run_id.clone(),
        DiagnosticPhase::SteadyState,
        DiagnosticOwner::Substrate,
        DiagnosticClass::GuestUnreachable,
        Some("native-system-process-exited".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "native-host QEMU process is no longer running",
        Vec::new(),
        Vec::new(),
        vec![
            "inspect the run-scoped serial and stderr logs".to_string(),
            "retry after correcting the last observed boot failure".to_string(),
        ],
    );
    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let failed = session
        .into_active_run()
        .failed_at(checked_at.clone(), diagnostic.clone())
        .with_supervision(
            fat_core::runs::SupervisionMode::ProbeOnStatus,
            fat_core::runs::HealthState::Unreachable,
            Some(checked_at),
        )
        .with_supervisor_runtime(None, None, None);
    store.write_diagnostic(failed.session_record().session_id.as_str(), &diagnostic)?;
    store.append_diagnostic_index(&diagnostic)?;
    store.write_session(failed.session_record())?;
    store.write_run(failed.run_record())?;

    Ok(crate::run_cmd::RuntimeView {
        session: failed.session_record().clone(),
        run: failed.run_record().clone(),
        diagnostics: store.read_run_diagnostics(
            failed.session_record().session_id.as_str(),
            failed.run_record().run_id.as_str(),
        )?,
    })
}

fn refresh_native_system_serial_artifact(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    view: &crate::run_cmd::RuntimeView,
) -> DynResult<()> {
    let artifacts =
        store.read_run_artifacts(view.session.session_id.as_str(), view.run.run_id.as_str())?;
    let Some(serial_path) = artifacts
        .iter()
        .rev()
        .find(|artifact| artifact.subkind == "native-system-launch-state")
        .and_then(|artifact| artifact_json_string(artifact, "serial_log_path"))
        .map(PathBuf::from)
    else {
        return Ok(());
    };
    let project_root = fs::canonicalize(project_dir)?;
    let serial_path = match fs::canonicalize(&serial_path) {
        Ok(path) if path.starts_with(&project_root) => path,
        _ => return Ok(()),
    };
    let serial_log = fs::read_to_string(serial_path)?;
    let existing = artifacts
        .iter()
        .rev()
        .find(|artifact| artifact.subkind == "native-system-serial-log")
        .and_then(artifact_text)
        .unwrap_or_default();
    if serial_log == existing {
        return Ok(());
    }
    write_runtime_log_artifact(
        store,
        project_record,
        view.session.session_id.as_str(),
        view.run.run_id.as_str(),
        view.run.backend_driver.as_str(),
        view.run.substrate_kind,
        "native-system-serial-log",
        "run-scoped native-host system serial log",
        &serial_log,
    )
}

fn persist_failed_launch(
    project_dir: &Path,
    store: &RuntimeStore,
    recipe: &fat_core::recipes::RecipeRecord,
    session: fat_emulate::EmulationSession,
    diagnostic: DiagnosticRecord,
) -> DynResult<()> {
    let failed = fat_emulate::ActiveRun::from_session(session)
        .failed_at(current_timestamp_string(), diagnostic.clone());
    let bound_diagnostic =
        rebind_diagnostic_to_run(&diagnostic, failed.run_record().run_id.as_str());
    store.write_recipe(failed.session_record().session_id.as_str(), recipe)?;
    store.write_session(failed.session_record())?;
    store.write_run(failed.run_record())?;
    store.write_diagnostic(
        failed.session_record().session_id.as_str(),
        &bound_diagnostic,
    )?;
    store.append_diagnostic_index(&bound_diagnostic)?;
    if let Some(rehosting_recipe) = load_rehosting_recipe_record(
        store,
        failed.session_record().session_id.as_str(),
        failed.run_record().run_id.as_str(),
    )? {
        if let Some(blocker) = build_diagnostic_blocker(
            failed.session_record().project_id.as_str(),
            failed.session_record().target_id.as_str(),
            failed.session_record().session_id.as_str(),
            failed.run_record().run_id.as_str(),
            &rehosting_recipe,
            &bound_diagnostic,
        ) {
            let confidence = ConfidenceReport::new(
                failed.session_record().project_id.clone(),
                failed.session_record().target_id.clone(),
                failed.session_record().session_id.clone(),
                failed.run_record().run_id.clone(),
                Some(rehosting_recipe.selected_substrate),
                ConfidenceLevel::Low,
                20,
            )
            .with_summary("launch failed before requested goals were validated")
            .with_blockers(vec![blocker.blocker_id.clone()])
            .with_fidelity_caveats(rehosting_recipe.fidelity_caveats.clone());
            store.write_blocker_record(&blocker)?;
            store.write_confidence_report(&confidence)?;
        }
    }
    persist_repair_artifacts(
        store,
        failed.session_record(),
        failed.run_record(),
        &bound_diagnostic,
    )?;
    fat_plugin_host::dispatch_run_analysis(
        project_dir,
        AnalysisTrigger::RunFailed,
        failed.session_record().session_id.as_str(),
        failed.run_record().run_id.as_str(),
    )?;
    println!(
        "{}diagnostics: 1",
        render_runtime_view(
            "",
            &crate::run_cmd::RuntimeView {
                session: failed.session_record().clone(),
                run: failed.run_record().clone(),
                diagnostics: vec![bound_diagnostic],
            }
        )
    );
    Ok(())
}

fn rebind_diagnostic_to_run(diagnostic: &DiagnosticRecord, run_id: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        diagnostic.phase,
        diagnostic.owner,
        diagnostic.class,
        diagnostic.subclass.clone(),
        diagnostic.severity,
        diagnostic.confidence,
        diagnostic.actionability,
        diagnostic.summary.clone(),
        diagnostic.evidence_artifact_ids.clone(),
        diagnostic.contradicted_artifact_ids.clone(),
        diagnostic.suggested_next_actions.clone(),
    )
}

fn persist_runner_blueprint_artifacts(
    project_dir: &Path,
    store: &RuntimeStore,
    plan: &fat_emulate::EmulationPlan,
) -> DynResult<()> {
    let staging_root = runtime_staging_root(project_dir, plan);
    let selection = select_substrate(plan);
    match selection.kind {
        RunnerKind::Service => {
            let blueprint = build_service_runner_blueprint(plan, &staging_root);
            store.write_staging_manifest(&blueprint.staging)?;
            store.write_confidence_report(&blueprint.initial_confidence)?;
        }
        RunnerKind::System => {
            let blueprint = build_system_runner_blueprint(plan, &staging_root);
            store.write_staging_manifest(&blueprint.staging)?;
            store.write_confidence_report(&blueprint.initial_confidence)?;
        }
        RunnerKind::Reference => {
            let blueprint = build_reference_runner_blueprint(plan, &staging_root);
            store.write_staging_manifest(&blueprint.staging)?;
            store.write_confidence_report(&blueprint.initial_confidence)?;
        }
    }
    Ok(())
}

fn runtime_staging_root(project_dir: &Path, plan: &fat_emulate::EmulationPlan) -> PathBuf {
    let session_key = short_runtime_path_key("stgsess", plan.session.session_id.as_str());
    let run_key = short_runtime_path_key("stgrun", plan.run.record.run_id.as_str());
    project_dir
        .join("work")
        .join("rehosting")
        .join(session_key)
        .join(run_key)
}

fn load_rehosting_recipe_record(
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

    let mut recipes: Vec<RehostingRecipe> = fs::read_dir(&recipes_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<RehostingRecipe>(&bytes).ok())
        .collect();
    recipes.sort_by(|left, right| left.rehosting_recipe_id.cmp(&right.rehosting_recipe_id));
    Ok(recipes.pop())
}

fn load_readiness_report_record(
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
    let Some(path) = first_json_record_path(&readiness_dir)? else {
        return Ok(None);
    };
    let bytes = fs::read(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn first_json_record_path(dir: &Path) -> DynResult<Option<PathBuf>> {
    let mut entries = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect::<Vec<_>>(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    entries.sort();
    Ok(entries.into_iter().next())
}

fn promote_runtime_validation_state(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
) -> DynResult<()> {
    let Some(recipe) = load_rehosting_recipe_record(store, session_id, run_id)? else {
        return Ok(());
    };
    let Some(readiness) = load_readiness_report_record(store, session_id, run_id)? else {
        return Ok(());
    };
    let run = store.read_run(session_id, run_id)?;
    let existing_artifacts = store
        .read_run_artifacts(session_id, run_id)
        .unwrap_or_default();
    let has_successful_http_probe = existing_artifacts.iter().any(|artifact| {
        artifact.subkind == "http-probe-state"
            && artifact_json_bool(artifact, "reply_received").unwrap_or(false)
    });
    if !has_successful_http_probe {
        persist_http_probe_artifact(
            store,
            project_record,
            session_id,
            run_id,
            &run.backend_driver,
            run.substrate_kind,
            &readiness,
        )?;
    }
    if !existing_artifacts
        .iter()
        .any(|artifact| artifact.subkind == "process-chain-state")
    {
        let target_model = store.read_session(session_id).ok().and_then(|session| {
            store
                .read_target_model(&session.target_id, &recipe.target_model_id)
                .ok()
        });
        persist_process_chain_artifact(
            store,
            project_record,
            session_id,
            run_id,
            &run.backend_driver,
            run.substrate_kind,
            recipe.selected_substrate,
            target_model.as_ref(),
            &existing_artifacts,
        )?;
    }
    let artifacts = store
        .read_run_artifacts(session_id, run_id)
        .unwrap_or_default();
    let snapshot = runtime_validation_snapshot(&readiness, &run, &artifacts);
    let validated = apply_runtime_validation(&recipe, &readiness, &snapshot);
    store.write_readiness_report(&validated)?;

    let confidence = build_runtime_confidence(
        validated.project_id.as_str(),
        validated.target_id.as_str(),
        &validated,
        &recipe,
    );
    store.write_confidence_report(&confidence)?;

    if let Some(blocker) = fat_emulate::blocker::blocker_from_readiness(
        validated.project_id.as_str(),
        validated.target_id.as_str(),
        &validated,
        &recipe,
    ) {
        store.write_blocker_record(&blocker)?;
    }

    Ok(())
}

fn runtime_validation_snapshot(
    readiness: &ReadinessReport,
    run: &fat_core::runs::RunRecord,
    artifacts: &[ArtifactRecord],
) -> RuntimeValidationSnapshot {
    let mut snapshot = RuntimeValidationSnapshot::default();

    for surface in &readiness.surfaces {
        let is_ready = matches!(
            surface.readiness,
            SurfaceReadiness::Ready | SurfaceReadiness::Validated
        );
        if !is_ready {
            continue;
        }
        match surface.kind.as_str() {
            "shell" => snapshot.shell_surface_ready = true,
            "monitor" => snapshot.monitor_surface_ready = true,
            "debugger" => snapshot.debugger_surface_ready = true,
            "service" => {
                snapshot.service_surface_ready = true;
                snapshot.service_listener_bound = true;
            }
            "port-forward" => {
                if surface
                    .uri
                    .as_deref()
                    .map(|uri| uri.starts_with("http://") || uri.starts_with("https://"))
                    .unwrap_or_else(|| surface.port == Some(80))
                {
                    snapshot.service_surface_ready = true;
                }
                snapshot.service_listener_bound = true;
            }
            _ => {}
        }
    }

    for artifact in artifacts {
        match artifact.subkind.as_str() {
            "process-snapshot" => {
                snapshot.process_snapshot_present = true;
                if let Ok(process_snapshot) = serde_json::from_str::<ObservedProcessSnapshot>(
                    &artifact_text(artifact).unwrap_or_default(),
                ) {
                    for process in process_snapshot.processes {
                        let executable = process
                            .command
                            .split_whitespace()
                            .next()
                            .unwrap_or(process.command.as_str());
                        push_unique(&mut snapshot.process_names, executable.to_string());
                        if let Some(name) = executable.rsplit('/').next() {
                            push_unique(&mut snapshot.process_names, name.to_string());
                        }
                    }
                }
            }
            "service-snapshot" => {
                snapshot.service_surface_ready = true;
                snapshot.service_listener_bound = true;
                snapshot.service_snapshot_present = true;
            }
            "network-snapshot" => {
                snapshot.service_surface_ready = true;
                snapshot.service_listener_bound = true;
                snapshot.network_snapshot_present = true;
                if let Ok(network_snapshot) = serde_json::from_str::<ObservedNetworkSnapshot>(
                    &artifact_text(artifact).unwrap_or_default(),
                ) {
                    for endpoint in network_snapshot.endpoints {
                        push_unique(
                            &mut snapshot.listener_ports,
                            endpoint.target_port.unwrap_or(endpoint.port),
                        );
                    }
                }
            }
            "emux-launch-state" | "emux-userspace-state" | "emux-runtime-status" => {
                snapshot.reference_runtime_ready = true;
            }
            "http-probe-state" => {
                if artifact_json_bool(artifact, "reply_received").unwrap_or(false) {
                    snapshot.http_reply_received = true;
                    if let Some(surface_name) = artifact_json_string(artifact, "surface_name") {
                        if let Some(endpoint) = run
                            .active_endpoints
                            .iter()
                            .find(|endpoint| endpoint.name == surface_name)
                        {
                            push_unique(
                                &mut snapshot.http_reply_ports,
                                endpoint.target_port.unwrap_or(endpoint.port),
                            );
                        }
                    }
                }
            }
            "process-chain-state" => {
                if artifact_json_bool(artifact, "validated").unwrap_or(false) {
                    snapshot.process_chain_observed = true;
                }
            }
            "http-transcript" => {
                if artifact_text(artifact)
                    .map(|text| text.contains("HTTP/"))
                    .unwrap_or(false)
                {
                    snapshot.http_reply_received = true;
                }
            }
            "native-system-serial-log" => {
                if let Some(text) = artifact_text(artifact) {
                    if !snapshot.serial_log.is_empty() {
                        snapshot.serial_log.push('\n');
                    }
                    snapshot.serial_log.push_str(&text);
                }
            }
            "managed-runtime-status" => {
                if let Some(value) = artifact_json_string(artifact, "phase") {
                    if matches!(
                        value.as_str(),
                        "probe-healthy" | "boot-complete" | "services-ready"
                    ) {
                        snapshot.managed_probe_healthy = true;
                        snapshot.init_stage_complete = true;
                    }
                }
                if let Some(value) = artifact_json_string(artifact, "runtime_outcome") {
                    if matches!(
                        value.as_str(),
                        "booted-services-reachable" | "booted-services-unreachable"
                    ) {
                        snapshot.init_stage_complete = true;
                    }
                    if value == "booted-services-reachable" {
                        snapshot.managed_services_reachable = true;
                    }
                }
            }
            _ => {}
        }
    }

    snapshot
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn persist_http_probe_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    readiness: &ReadinessReport,
) -> DynResult<()> {
    let Some(target) = select_http_probe_target(readiness) else {
        return Ok(());
    };
    let (state, transcript) = execute_http_probe(&target, 1000);
    write_runtime_state_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "http-probe-state",
        "fat owned bounded http validator probe state",
        &serde_json::to_string_pretty(&state)?,
    )?;
    if !transcript.is_empty() {
        write_runtime_capture_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "http-transcript",
            "fat owned bounded http validator transcript",
            &transcript,
        )?;
    }
    Ok(())
}

fn persist_process_chain_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    logical_substrate: LogicalSubstrateKind,
    target_model: Option<&TargetModel>,
    artifacts: &[ArtifactRecord],
) -> DynResult<()> {
    let state = build_process_chain_state(logical_substrate, target_model, artifacts)?;
    write_runtime_state_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "process-chain-state",
        "fat owned bounded process chain validator state",
        &serde_json::to_string_pretty(&state)?,
    )?;
    Ok(())
}

fn build_process_chain_state(
    logical_substrate: LogicalSubstrateKind,
    target_model: Option<&TargetModel>,
    artifacts: &[ArtifactRecord],
) -> DynResult<ProcessChainState> {
    let Some(target_model) = target_model else {
        return Ok(ProcessChainState {
            validator_version: 1,
            substrate_kind: logical_substrate,
            observation_method: "snapshot-match".to_string(),
            chain_basis: ProcessChainBasis {
                selected_service: None,
                selected_init: None,
                peer_dependencies: Vec::new(),
            },
            expected_roles: Vec::new(),
            observed_roles: Vec::new(),
            missing_roles: Vec::new(),
            validated: false,
            failure_mode: Some("insufficient-model".to_string()),
        });
    };

    let selected_service = launchable_service_executable(target_model).or_else(|| {
        target_model
            .service_candidates
            .first()
            .map(|candidate| candidate.path.clone())
    });
    let selected_init = if logical_substrate == LogicalSubstrateKind::System {
        target_model
            .init_candidates
            .first()
            .map(|candidate| candidate.path.clone())
    } else {
        None
    };
    let peer_dependencies = target_model.peer_dependencies.clone();
    let chain_basis = ProcessChainBasis {
        selected_service: selected_service.clone(),
        selected_init: selected_init.clone(),
        peer_dependencies: peer_dependencies.clone(),
    };

    let mut expected_roles = Vec::new();
    if let Some(init) = selected_init.as_ref() {
        expected_roles.push(ProcessChainExpectedRole {
            role: "init-anchor".to_string(),
            match_kind: "executable".to_string(),
            expected: init.clone(),
            required: true,
        });
    }
    if let Some(service) = selected_service.as_ref() {
        expected_roles.push(ProcessChainExpectedRole {
            role: "primary-service".to_string(),
            match_kind: "executable".to_string(),
            expected: service.clone(),
            required: true,
        });
    }
    for dependency in &peer_dependencies {
        expected_roles.push(ProcessChainExpectedRole {
            role: "peer-service".to_string(),
            match_kind: "service-name".to_string(),
            expected: dependency.clone(),
            required: true,
        });
    }

    if expected_roles.is_empty() {
        return Ok(ProcessChainState {
            validator_version: 1,
            substrate_kind: logical_substrate,
            observation_method: "snapshot-match".to_string(),
            chain_basis,
            expected_roles,
            observed_roles: Vec::new(),
            missing_roles: Vec::new(),
            validated: false,
            failure_mode: Some("insufficient-model".to_string()),
        });
    }

    let process_snapshot = read_latest_typed_runtime_capture_from_artifacts::<
        ObservedProcessSnapshot,
    >(artifacts, "process-snapshot")?;
    let service_snapshot = read_latest_typed_runtime_capture_from_artifacts::<
        ObservedServiceSnapshot,
    >(artifacts, "service-snapshot")?;
    if process_snapshot.is_none() && service_snapshot.is_none() {
        return Ok(ProcessChainState {
            validator_version: 1,
            substrate_kind: logical_substrate,
            observation_method: "snapshot-match".to_string(),
            chain_basis,
            expected_roles,
            observed_roles: Vec::new(),
            missing_roles: Vec::new(),
            validated: false,
            failure_mode: Some("no-runtime-observation".to_string()),
        });
    }

    let processes = process_snapshot
        .as_ref()
        .map(|snapshot| snapshot.processes.as_slice())
        .unwrap_or(&[]);
    let services = service_snapshot
        .as_ref()
        .map(|snapshot| snapshot.services.as_slice())
        .unwrap_or(&[]);
    let mut observed_roles = Vec::new();
    let mut missing_roles = Vec::new();
    for role in &expected_roles {
        let observed = match role.role.as_str() {
            "primary-service" | "init-anchor" => {
                observe_process_chain_process_role(role, processes)
            }
            "peer-service" => observe_process_chain_peer_role(role, processes, services),
            _ => ProcessChainObservedRole {
                role: role.role.clone(),
                matched: false,
                matched_process: None,
                matched_service: None,
                pid: None,
                source_kind: None,
            },
        };
        if role.required && !observed.matched {
            missing_roles.push(role.role.clone());
        }
        observed_roles.push(observed);
    }

    let validated = missing_roles.is_empty();
    Ok(ProcessChainState {
        validator_version: 1,
        substrate_kind: logical_substrate,
        observation_method: "snapshot-match".to_string(),
        chain_basis,
        expected_roles,
        observed_roles,
        missing_roles,
        validated,
        failure_mode: if validated {
            None
        } else {
            Some("missing-required-roles".to_string())
        },
    })
}

fn observe_process_chain_process_role(
    role: &ProcessChainExpectedRole,
    processes: &[ObservedProcessEntry],
) -> ProcessChainObservedRole {
    if let Some(process) = processes.iter().find(|process| {
        process_command_matches_expected(process.command.as_str(), role.expected.as_str())
    }) {
        return ProcessChainObservedRole {
            role: role.role.clone(),
            matched: true,
            matched_process: Some(process.command.clone()),
            matched_service: None,
            pid: Some(process.pid),
            source_kind: Some(process.source_kind.clone()),
        };
    }

    ProcessChainObservedRole {
        role: role.role.clone(),
        matched: false,
        matched_process: None,
        matched_service: None,
        pid: None,
        source_kind: None,
    }
}

fn observe_process_chain_peer_role(
    role: &ProcessChainExpectedRole,
    processes: &[ObservedProcessEntry],
    services: &[ObservedServiceEntry],
) -> ProcessChainObservedRole {
    if let Some(service) = services
        .iter()
        .find(|service| names_match_expected(service.name.as_str(), role.expected.as_str()))
    {
        return ProcessChainObservedRole {
            role: role.role.clone(),
            matched: true,
            matched_process: None,
            matched_service: Some(service.name.clone()),
            pid: None,
            source_kind: Some(service.source_kind.clone()),
        };
    }

    if let Some(process) = processes.iter().find(|process| {
        process_command_matches_expected(process.command.as_str(), role.expected.as_str())
    }) {
        return ProcessChainObservedRole {
            role: role.role.clone(),
            matched: true,
            matched_process: Some(process.command.clone()),
            matched_service: None,
            pid: Some(process.pid),
            source_kind: Some(process.source_kind.clone()),
        };
    }

    ProcessChainObservedRole {
        role: role.role.clone(),
        matched: false,
        matched_process: None,
        matched_service: None,
        pid: None,
        source_kind: None,
    }
}

fn process_command_matches_expected(command: &str, expected: &str) -> bool {
    let executable = command.split_whitespace().next().unwrap_or(command);
    executable == expected || names_match_expected(executable, expected)
}

fn names_match_expected(actual: &str, expected: &str) -> bool {
    actual == expected
        || actual
            .rsplit('/')
            .next()
            .zip(expected.rsplit('/').next())
            .map(|(left, right)| left == right)
            .unwrap_or(false)
}

fn select_http_probe_target(readiness: &ReadinessReport) -> Option<HttpProbeTarget> {
    readiness
        .surfaces
        .iter()
        .find_map(http_probe_target_from_surface)
}

fn http_probe_target_from_surface(
    surface: &fat_core::rehosting::RuntimeSurfaceRecord,
) -> Option<HttpProbeTarget> {
    match surface.kind.as_str() {
        "service" | "port-forward" => {}
        _ => return None,
    }

    if let Some(uri) = surface.uri.as_ref() {
        if let Some(target) = parse_http_probe_uri(surface.name.as_str(), uri) {
            return Some(target);
        }
    }

    let host = surface.host.clone()?;
    let port = surface.port?;
    Some(HttpProbeTarget {
        surface_name: surface.name.clone(),
        uri: format!("http://{host}:{port}"),
        host,
        port,
        path: "/".to_string(),
        scheme: "http".to_string(),
    })
}

fn parse_http_probe_uri(surface_name: &str, uri: &str) -> Option<HttpProbeTarget> {
    let (scheme, remainder, default_port) = if let Some(rest) = uri.strip_prefix("http://") {
        ("http", rest, 80)
    } else {
        let rest = uri.strip_prefix("https://")?;
        ("https", rest, 443)
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, "/".to_string()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    let (host, port) = authority
        .rsplit_once(':')
        .and_then(|(host, port)| {
            port.parse::<u16>()
                .ok()
                .map(|port| (host.to_string(), port))
        })
        .unwrap_or_else(|| (authority.to_string(), default_port));
    Some(HttpProbeTarget {
        surface_name: surface_name.to_string(),
        uri: uri.to_string(),
        host,
        port,
        path,
        scheme: scheme.to_string(),
    })
}

fn execute_http_probe(target: &HttpProbeTarget, timeout_ms: u64) -> (HttpProbeState, String) {
    let mut state = HttpProbeState {
        surface_name: target.surface_name.clone(),
        uri: target.uri.clone(),
        method: "GET".to_string(),
        probe_path: target.path.clone(),
        timeout_ms,
        connected: false,
        reply_received: false,
        status_line: None,
        status_code: None,
        response_bytes: 0,
        failure_mode: None,
    };

    if target.scheme != "http" {
        state.failure_mode = Some("unsupported-scheme".to_string());
        return (state, String::new());
    }

    let timeout = Duration::from_millis(timeout_ms);
    let Some(address) = format!("{}:{}", target.host, target.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        state.failure_mode = Some("resolve-failed".to_string());
        return (state, String::new());
    };

    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        state.failure_mode = Some("connect-refused".to_string());
        return (state, String::new());
    };
    state.connected = true;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    if stream.write_all(request.as_bytes()).is_err() {
        state.failure_mode = Some("write-failed".to_string());
        return (state, String::new());
    }

    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            state.failure_mode = Some("timeout".to_string());
            return (state, String::new());
        }
        Err(_) => {
            state.failure_mode = Some("read-failed".to_string());
            return (state, String::new());
        }
    }

    state.response_bytes = response.len();
    if response.is_empty() {
        state.failure_mode = Some("empty-reply".to_string());
        return (state, String::new());
    }

    let transcript = String::from_utf8_lossy(&response).into_owned();
    let first_line = transcript.lines().next().map(str::trim).unwrap_or_default();
    if first_line.starts_with("HTTP/") {
        state.reply_received = true;
        state.status_line = Some(first_line.to_string());
        state.status_code = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok());
    } else {
        state.failure_mode = Some("non-http-reply".to_string());
    }

    (state, transcript)
}

fn count_runs_for_substrate(
    store: &RuntimeStore,
    session_id: &str,
    run_ids: &[String],
    substrate: LogicalSubstrateKind,
) -> DynResult<usize> {
    let mut count = 0usize;
    for run_id in run_ids {
        if let Some(recipe) = load_rehosting_recipe_record(store, session_id, run_id)? {
            if recipe.selected_substrate == substrate {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn artifact_text(artifact: &ArtifactRecord) -> Option<String> {
    fs::read_to_string(&artifact.path).ok()
}

fn artifact_json_bool(artifact: &ArtifactRecord, key: &str) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_str(&artifact_text(artifact)?).ok()?;
    value.get(key)?.as_bool()
}

fn artifact_json_string(artifact: &ArtifactRecord, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(&artifact_text(artifact)?).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

fn persist_repair_artifacts(
    store: &RuntimeStore,
    session_record: &fat_core::sessions::SessionRecord,
    run_record: &fat_core::runs::RunRecord,
    diagnostic: &DiagnosticRecord,
) -> DynResult<()> {
    let planned_repair = load_rehosting_recipe_record(
        store,
        session_record.session_id.as_str(),
        run_record.run_id.as_str(),
    )?
    .and_then(|recipe| apply_repair_for_retry(&recipe, diagnostic));
    let Some(decision) = planned_repair
        .as_ref()
        .map(|(decision, _)| decision.clone())
        .or_else(|| decide_repair(diagnostic))
    else {
        return Ok(());
    };

    let prior_attempt = load_latest_attempt_record(
        store,
        session_record.session_id.as_str(),
        run_record.run_id.as_str(),
    )?;
    let target_id = session_record.target_id.clone();
    let project_id = session_record.project_id.clone();

    if decision.retry_allowed {
        let retry_sequence = prior_attempt
            .as_ref()
            .map(|attempt| attempt.sequence.saturating_add(1))
            .unwrap_or(2);
        let retry_mode = retry_mode_for_decision(&decision, prior_attempt.as_ref());
        let retry_attempt = AttemptRecord::new(
            project_id.clone(),
            target_id.clone(),
            session_record.session_id.clone(),
            run_record.run_id.clone(),
            retry_sequence,
            retry_mode,
        )
        .with_summary(format!(
            "bounded repair retry: {}",
            decision.action.as_str()
        ));
        store.write_attempt_record(&retry_attempt)?;
        let repair = RepairRecord::new(
            project_id,
            target_id,
            session_record.session_id.clone(),
            run_record.run_id.clone(),
            retry_attempt.attempt_id.clone(),
            decision.failure_class,
            decision.action,
        )
        .with_detail(diagnostic.summary.clone());
        store.write_repair_record(&repair)?;
        persist_repair_materialization_artifact(
            store,
            &repair,
            planned_repair.as_ref().map(|(_, recipe)| recipe),
            diagnostic,
        )?;
        return Ok(());
    }

    let repair = RepairRecord::new(
        project_id,
        target_id,
        session_record.session_id.clone(),
        run_record.run_id.clone(),
        prior_attempt
            .as_ref()
            .map(|attempt| attempt.attempt_id.clone())
            .unwrap_or_else(|| run_record.run_id.clone()),
        decision.failure_class,
        decision.action,
    )
    .with_detail(diagnostic.summary.clone());
    store.write_repair_record(&repair)?;
    persist_repair_materialization_artifact(
        store,
        &repair,
        planned_repair.as_ref().map(|(_, recipe)| recipe),
        diagnostic,
    )?;
    Ok(())
}

fn persist_repair_materialization_artifact(
    store: &RuntimeStore,
    repair: &RepairRecord,
    repaired_recipe: Option<&RehostingRecipe>,
    diagnostic: &DiagnosticRecord,
) -> DynResult<()> {
    let Some(repaired_recipe) = repaired_recipe else {
        return Ok(());
    };

    if repaired_recipe.device_nodes.is_empty()
        && repaired_recipe.filesystem_transforms.is_empty()
        && repaired_recipe.launch_plan.is_none()
    {
        return Ok(());
    }

    let materialization = RepairMaterializationRecord::new(
        repair.project_id.clone(),
        repair.target_id.clone(),
        repair.session_id.clone(),
        repair.run_id.clone(),
        repair.attempt_id.clone(),
        repair.repair_id.clone(),
        repair.action,
        repaired_recipe.device_nodes.clone(),
        repaired_recipe.filesystem_transforms.clone(),
        repaired_recipe.launch_plan.clone(),
    )
    .with_detail(diagnostic.summary.clone());
    store.write_repair_materialization_record(&materialization)?;
    Ok(())
}

fn contextualize_plan(
    mut plan: fat_emulate::EmulationPlan,
    project_record: &fat_core::project::Project,
) -> fat_emulate::EmulationPlan {
    let target_id = derive_target_id(&project_record.name, &project_record.firmware_name);
    plan.session.project_id = project_record.name.clone();
    plan.session.target_id = target_id.clone();
    plan.recipe.target_id = target_id.clone();
    plan.target_model =
        project_target_model_for_project(&project_record.name, &target_id, &plan.target_model);
    plan.profile = plan.target_model.to_execution_profile();
    plan.rehosting_recipe = project_rehosting_recipe_for_plan(
        &target_id,
        plan.run.record.run_id.as_str(),
        &plan.target_model,
        &plan.rehosting_recipe,
    );
    plan.selection_trace.project_id = project_record.name.clone();
    plan.selection_trace.target_id = target_id;
    plan
}

fn load_latest_attempt_record(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<AttemptRecord>> {
    let attempts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .ok_or("run path missing parent")?
        .join("rehosting")
        .join("attempts");
    if !attempts_dir.exists() {
        return Ok(None);
    }

    let mut attempts: Vec<AttemptRecord> = fs::read_dir(&attempts_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<AttemptRecord>(&bytes).ok())
        .collect();
    attempts.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then(left.attempt_id.cmp(&right.attempt_id))
    });
    Ok(attempts.pop())
}

fn retry_mode_for_decision(
    decision: &RepairDecision,
    prior_attempt: Option<&AttemptRecord>,
) -> RehostingMode {
    if let Some(attempt) = prior_attempt {
        return attempt.mode;
    }

    match decision.action {
        RepairActionKind::StartPeerService => RehostingMode::Service,
        RepairActionKind::CreateNode
        | RepairActionKind::PatchConfig
        | RepairActionKind::RetryPlan
        | RepairActionKind::InjectEnv => RehostingMode::System,
    }
}

fn project_target_model_for_project(
    project_id: &str,
    target_id: &str,
    source: &TargetModel,
) -> TargetModel {
    let mut model = TargetModel::new(
        project_id.to_string(),
        target_id.to_string(),
        source.architecture.as_deref(),
        source.family_id.as_deref(),
        source.evidence.clone(),
    )
    .with_secondary_arches(source.secondary_arches.clone())
    .with_init_candidates(source.init_candidates.clone())
    .with_service_candidates(source.service_candidates.clone())
    .with_peer_dependencies(source.peer_dependencies.clone())
    .with_network_hypotheses(source.network_hypotheses.clone())
    .with_nvram_facts(source.nvram_facts.clone())
    .with_device_dependencies(source.device_dependencies.clone())
    .with_ipc_dependencies(source.ipc_dependencies.clone())
    .with_validator_candidates(source.validator_candidates.clone())
    .with_substrate_viability_hints(source.substrate_viability_hints.clone());
    if let Some(loader_path) = source.loader_path.as_ref() {
        model = model.with_loader_path(loader_path.clone());
    }
    if let Some(libc_family) = source.libc_family.as_ref() {
        model = model.with_libc_family(libc_family.clone());
    }
    model
}

fn project_rehosting_recipe_for_plan(
    target_id: &str,
    run_id: &str,
    target_model: &TargetModel,
    source: &RehostingRecipe,
) -> RehostingRecipe {
    let mut recipe = RehostingRecipe::new(
        target_id.to_string(),
        target_model.model_id.clone(),
        run_id.to_string(),
        source.goal.clone(),
        source.substrate_preference,
        source.selected_substrate,
    )
    .with_filesystem_transforms(source.filesystem_transforms.clone())
    .with_env_injections(source.env_injections.clone())
    .with_device_nodes(source.device_nodes.clone())
    .with_validators(source.validators.clone())
    .with_retry_budget(source.retry_budget)
    .with_instrumentation_flags(source.instrumentation_flags.clone())
    .with_fidelity_caveats(source.fidelity_caveats.clone());
    if let Some(selected_backend) = source.selected_backend.as_ref() {
        recipe = recipe.with_selected_backend(selected_backend.clone());
    }
    if let Some(launch_plan) = source.launch_plan.as_ref() {
        recipe = recipe.with_launch_plan(launch_plan.clone());
    }
    if let Some(instrumentation) = source.instrumentation.as_ref() {
        recipe = recipe.with_instrumentation(instrumentation.clone());
    }
    recipe.qemu_machine = source.qemu_machine.clone();
    recipe.network = source.network.clone();
    recipe.rehosting_capability = source.rehosting_capability.clone();
    recipe
}

fn build_readiness_report(
    project_record: &fat_core::project::Project,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    requested_goals: &[String],
    endpoints: &[fat_core::runs::RuntimeEndpoint],
    readiness: SurfaceReadiness,
    summary: impl Into<String>,
) -> ReadinessReport {
    let surfaces = endpoints
        .iter()
        .map(|endpoint| {
            runtime_surface_record_from_endpoint(
                project_record,
                target_id,
                session_id,
                run_id,
                endpoint,
                readiness,
            )
        })
        .collect();

    ReadinessReport::new(
        project_record.name.clone(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        requested_goals.to_vec(),
        surfaces,
    )
    .with_summary(summary)
}

fn runtime_surface_record_from_endpoint(
    project_record: &fat_core::project::Project,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    endpoint: &fat_core::runs::RuntimeEndpoint,
    readiness: SurfaceReadiness,
) -> RuntimeSurfaceRecord {
    let identity_hint = endpoint
        .uri
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", endpoint.host, endpoint.port));
    let mut surface = RuntimeSurfaceRecord::new(
        project_record.name.clone(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        endpoint.name.clone(),
        runtime_endpoint_kind_label(endpoint.kind),
        identity_hint,
        readiness,
    )
    .with_host(endpoint.host.clone())
    .with_port(endpoint.port);
    if let Some(uri) = endpoint.uri.as_ref() {
        surface = surface.with_uri(uri.clone());
    }
    surface
}

fn runtime_endpoint_kind_label(kind: fat_core::runs::RuntimeEndpointKind) -> &'static str {
    match kind {
        fat_core::runs::RuntimeEndpointKind::Shell => "shell",
        fat_core::runs::RuntimeEndpointKind::Debugger => "debugger",
        fat_core::runs::RuntimeEndpointKind::Monitor => "monitor",
        fat_core::runs::RuntimeEndpointKind::PortForward => "port-forward",
        fat_core::runs::RuntimeEndpointKind::Service => "service",
    }
}

fn collect_host_capabilities(project_dir: &Path, probe: &impl CommandProbe) -> Vec<String> {
    let mut capabilities = vec!["native-host".to_string()];
    if probe
        .command_path("docker")
        .unwrap_or_else(|| project_dir.join("work").join("missing-docker"))
        .is_file()
    {
        capabilities.push("docker-engine".to_string());
    }
    if fat_backend::managed_linux_vm::inspect_managed_linux_vm_bundle_from_env()
        .map(|result| result.is_ok())
        .unwrap_or(false)
        || (firmae_upstream_dir_from_env().is_some() && firmae_host_python_from_env().is_some())
    {
        capabilities.push("managed-linux-vm".to_string());
    }
    capabilities
}

fn launch_service_user_mode_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
    probe: &impl CommandProbe,
) -> DynResult<()> {
    let readiness_goals = plan.readiness_goals.clone();
    let run_id = plan.run.record.run_id.clone();
    let target_id = derive_target_id(&project_record.name, &project_record.firmware_name);
    let blueprint =
        build_service_runner_blueprint(&plan, &runtime_staging_root(project_dir, &plan));
    let Some(executable_path) = blueprint.executable.clone() else {
        return persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            missing_service_candidate_diagnostic(&run_id),
        );
    };

    let architecture = plan
        .target_model
        .architecture
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let qemu_binary = find_first_command(probe, qemu_user_candidates_for_arch(&architecture))
        .unwrap_or_else(|| project_dir.join("work").join("missing-qemu-user"));
    let manager = ServiceUserModeManager::new();
    let prepared = match manager.prepare(
        ServiceUserModeRequest::new(
            project_record.name.clone(),
            target_id.clone(),
            architecture,
            qemu_binary,
            project_dir.join("extracted"),
            PathBuf::from(blueprint.staging.source_root.clone()),
            PathBuf::from(blueprint.staging.staging_root.clone()),
            executable_path,
        )
        .with_env_injections(plan.rehosting_recipe.env_injections.clone())
        .with_device_nodes(plan.rehosting_recipe.device_nodes.clone())
        .with_filesystem_transforms(plan.rehosting_recipe.filesystem_transforms.clone()),
    ) {
        Ok(prepared) => prepared,
        Err(diagnostic) => {
            return persist_failed_launch(project_dir, store, &recipe, plan.launch(), diagnostic);
        }
    };
    let launch_result = match manager.launch(&prepared) {
        Ok(result) => result,
        Err(diagnostic) => {
            return persist_failed_launch(project_dir, store, &recipe, plan.launch(), diagnostic);
        }
    };

    let mut active = plan
        .launch()
        .into_active_run()
        .preparing_at(current_timestamp_string())
        .launching_at(current_timestamp_string())
        .running_at(current_timestamp_string())
        .with_supervision(
            fat_core::runs::SupervisionMode::ProbeOnStatus,
            fat_core::runs::HealthState::Unknown,
            None,
        );
    for endpoint in &launch_result.endpoints {
        active = active.reattach_endpoint(endpoint.clone());
    }

    store.write_recipe(active.session().session_id(), &recipe)?;
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    store.write_readiness_report(&build_readiness_report(
        project_record,
        &target_id,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &readiness_goals,
        active.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Ready,
        "service runner launched with qemu-user staging",
    ))?;

    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "launch-stdout",
        "launch stdout",
        &launch_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "launch-stderr",
        "launch stderr",
        &launch_result.stderr,
    )?;
    if let Some(launch_manifest) = launch_result.launch_manifest.as_ref() {
        persist_service_user_mode_manifest(store, project_record, &active, launch_manifest)?;
    }

    promote_runtime_validation_state(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
    )?;
    let view = load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
        .expect("runtime view");
    print!(
        "{}",
        render_launch_output(
            store,
            &recipe.recipe_id,
            &active.session().mapped_ports(),
            &view,
        )?
    );
    Ok(())
}

fn launch_native_system_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
    probe: &impl CommandProbe,
) -> DynResult<()> {
    let readiness_goals = plan.readiness_goals.clone();
    let target_id = derive_target_id(&project_record.name, &project_record.firmware_name);
    let mut blueprint =
        build_system_runner_blueprint(&plan, &runtime_staging_root(project_dir, &plan));

    // Forward typed instrumentation config to the launch spec
    if let Some(instrumentation) = plan.rehosting_recipe.instrumentation.clone() {
        blueprint.launch.instrumentation = Some(instrumentation);
    }

    if let Err(diagnostic) =
        materialize_native_system_boot_assets(project_dir, &plan, &blueprint, probe)
    {
        return persist_failed_launch(project_dir, store, &recipe, plan.launch(), diagnostic);
    }
    let launch_result = match launch_native_system_with(
        &blueprint.launch,
        crate::launch_guard::arm_process_group,
    ) {
        Ok(result) => result,
        Err(diagnostic) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                classify_native_system_launch_failure(diagnostic),
            );
        }
    };

    let launch_session = plan.launch();
    let predeclared_service_surfaces = launch_session.run_record().active_endpoints.clone();
    let mut active = launch_session
        .into_active_run()
        .preparing_at(current_timestamp_string())
        .launching_at(current_timestamp_string())
        .running_at(current_timestamp_string())
        .with_supervision(
            fat_core::runs::SupervisionMode::ProbeOnStatus,
            fat_core::runs::HealthState::Unknown,
            None,
        );
    active = active.with_supervisor_runtime(launch_result.process_id, None, None);
    for endpoint in &launch_result.registered_surfaces {
        active = active.reattach_endpoint(endpoint.clone());
    }

    // The emulator is running but no record names it until these land, so a
    // failure here has to take the process with it.
    if let Err(error) = persist_native_launch_records(store, &recipe, &active) {
        crate::launch_guard::terminate_and_disarm();
        return Err(error);
    }
    crate::launch_guard::disarm();

    store.write_readiness_report(&build_readiness_report(
        project_record,
        &target_id,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &readiness_goals,
        active.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Registered,
        "native-host system launcher registered surfaces",
    ))?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "native-system-launch-command",
        "native-host system launch command",
        &launch_result.command.join(" "),
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "native-system-serial-log",
        "native-host system serial log",
        &launch_result.stdout,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "native-system-launch-state",
        "native-host system launch state",
        &serde_json::to_string_pretty(&serde_json::json!({
            "command": launch_result.command,
            "exit_code": launch_result.exit_code,
            "process_id": launch_result.process_id,
            "stdout_log_path": launch_result.stdout_log_path,
            "stderr_log_path": launch_result.stderr_log_path,
            "serial_log_path": blueprint.launch.serial_log,
            "registered_surfaces": launch_result.registered_surfaces,
            "boot_artifacts": blueprint.launch.boot_artifacts,
        }))?,
    )?;
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "native-system-surface-manifest",
        "native-host system surface manifest",
        &serde_json::to_string_pretty(&serde_json::json!({
            "registered_surfaces": active.run_record().active_endpoints,
            "predeclared_service_surfaces": predeclared_service_surfaces,
            "launch_command_artifact": "outputs/native-system-launch-command.log",
            "serial_log_artifact": "outputs/native-system-serial-log.log",
            "stdout_log_path": launch_result.stdout_log_path,
            "stderr_log_path": launch_result.stderr_log_path,
            "serial_log_path": blueprint.launch.serial_log,
            "boot_artifacts": blueprint.launch.boot_artifacts,
        }))?,
    )?;

    let view = load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
        .expect("runtime view");
    print!(
        "{}",
        render_launch_output(
            store,
            &recipe.recipe_id,
            &active.session().mapped_ports(),
            &view,
        )?
    );
    Ok(())
}

fn verify_native_system_kernel_identity(
    profile: &fat_emulate::kernel_catalog::KernelProfile,
    kernel_path: &Path,
    expected_sha256: Option<&str>,
) -> Result<NativeSystemKernelIdentity, String> {
    let operator_sha256 = expected_sha256
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let managed_sha256 = profile
        .artifact_digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .map(str::to_ascii_lowercase);
    if profile.managed_bundle_id.is_some() && managed_sha256.is_none() {
        return Err("managed kernel profile requires a sha256: artifact digest".to_string());
    }
    if profile.support_tier == "external-required" && operator_sha256.is_none() {
        return Err(format!(
            "operator-supplied kernel {} requires {}=<64-hex-sha256>",
            kernel_path.display(),
            SYSTEM_KERNEL_SHA256_ENV
        ));
    }
    if let (Some(managed), Some(operator)) = (&managed_sha256, &operator_sha256) {
        if managed != operator {
            return Err(format!(
                "operator kernel SHA-256 conflicts with managed artifact digest: {operator} != {managed}"
            ));
        }
    }
    let expected_sha256 = managed_sha256.or(operator_sha256);
    if let Some(expected) = expected_sha256.as_deref() {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "{} must contain exactly 64 hexadecimal characters",
                SYSTEM_KERNEL_SHA256_ENV
            ));
        }
    }
    let actual_sha256 = sha256_file_hex(kernel_path)
        .map_err(|err| format!("failed to hash kernel {}: {err}", kernel_path.display()))?;
    if let Some(expected) = expected_sha256.as_deref() {
        if expected != actual_sha256 {
            return Err(format!(
                "operator-supplied kernel SHA-256 does not match: expected {expected}, observed {actual_sha256}"
            ));
        }
    }

    Ok(NativeSystemKernelIdentity {
        version: 1,
        profile_id: profile.profile_id.clone(),
        managed_bundle_id: profile.managed_bundle_id.clone(),
        compatibility_class: profile
            .compatibility_class
            .map(|class| class.as_str().to_string()),
        artifact_digest: profile.artifact_digest.clone(),
        source_path: kernel_path.display().to_string(),
        verified: expected_sha256.is_some(),
        expected_sha256,
        actual_sha256,
        staged_path: None,
        staged_sha256: None,
    })
}

fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn materialize_native_system_boot_assets(
    project_dir: &Path,
    plan: &fat_emulate::EmulationPlan,
    blueprint: &SystemRunnerBlueprint,
    probe: &impl CommandProbe,
) -> Result<(), DiagnosticRecord> {
    let kernel_profile = blueprint.kernel_profile.as_ref().ok_or_else(|| {
        native_system_preparation_error(plan, "no vendored kernel profile was selected")
    })?;
    let kernel_source = resolve_kernel_asset_source(kernel_profile);
    if !kernel_source.is_file() {
        return Err(native_system_preparation_error(
            plan,
            format!(
                "vendored kernel asset is missing: {}",
                kernel_source.display()
            ),
        ));
    }
    let expected_kernel_sha256 = std::env::var(SYSTEM_KERNEL_SHA256_ENV).ok();
    let mut kernel_identity = verify_native_system_kernel_identity(
        kernel_profile,
        &kernel_source,
        expected_kernel_sha256.as_deref(),
    )
    .map_err(|detail| native_system_preparation_error(plan, detail))?;

    let source_root = Path::new(&blueprint.staging.source_root);
    let guest_root = Path::new(&blueprint.staging.staging_root);
    let launch_root = Path::new(&blueprint.launch.serial_log)
        .parent()
        .ok_or_else(|| native_system_preparation_error(plan, "launch root is missing"))?;
    if plan.rehosting_recipe.partition_materializations.is_empty() {
        let source_rootfs = locate_native_system_rootfs(project_dir)
            .map_err(|detail| native_system_preparation_error(plan, detail))?;
        let manifest = ExtractionManifest {
            rootfs_path: Some(source_rootfs.clone()),
            filesystem_trees: vec![fat_extract::manifest::ExtractedFilesystemTree {
                role: "rootfs".to_string(),
                path: source_rootfs,
                tree_kind: "rootfs".to_string(),
            }],
            ..ExtractionManifest::default()
        };
        assemble_native_system_partitions(
            &manifest,
            &[
                fat_core::rehosting_recipe::RecipePartitionMaterialization::new(
                    "rootfs",
                    "/",
                    "staged-copy",
                ),
            ],
            source_root,
            guest_root,
        )
        .map_err(|detail| native_system_preparation_error(plan, detail))?;
    } else {
        let manifest = load_native_system_extraction_manifest(project_dir)
            .map_err(|detail| native_system_preparation_error(plan, detail))?;
        assemble_native_system_partitions(
            &manifest,
            &plan.rehosting_recipe.partition_materializations,
            source_root,
            guest_root,
        )
        .map_err(|detail| native_system_preparation_error(plan, detail))?;
    }
    materialize_native_system_recipe_transforms(guest_root, plan).map_err(|detail| {
        native_system_preparation_error(plan, format!("failed to materialize recipe: {detail}"))
    })?;
    materialize_native_system_guest_adaptations(guest_root, plan).map_err(|detail| {
        native_system_preparation_error(
            plan,
            format!("failed to materialize guest adaptations: {detail}"),
        )
    })?;
    fs::create_dir_all(launch_root).map_err(|err| {
        native_system_preparation_error(plan, format!("failed to create boot root: {err}"))
    })?;

    for path in [
        guest_root.join("fat"),
        guest_root.join("dev"),
        guest_root.join("proc"),
        guest_root.join("sys"),
        guest_root.join("tmp"),
        guest_root.join("var/run"),
    ] {
        fs::create_dir_all(&path).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!(
                    "failed to create staged runtime path {}: {err}",
                    path.display()
                ),
            )
        })?;
    }

    if kernel_profile.architecture == "mipsel" {
        let actual_sha256 = format!("{:x}", Sha256::digest(MIPSEL_INIT_TRAMPOLINE));
        if actual_sha256 != MIPSEL_INIT_TRAMPOLINE_SHA256 {
            return Err(native_system_preparation_error(
                plan,
                format!(
                    "embedded MIPSEL init trampoline digest changed: expected {}, observed {}",
                    MIPSEL_INIT_TRAMPOLINE_SHA256, actual_sha256
                ),
            ));
        }
        let trampoline_path = guest_root.join("fat/init-trampoline");
        fs::write(&trampoline_path, MIPSEL_INIT_TRAMPOLINE).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to write MIPSEL init trampoline: {err}"),
            )
        })?;
        mark_executable(&trampoline_path).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to mark MIPSEL init trampoline executable: {err}"),
            )
        })?;
        fs::write(
            guest_root.join("fat/init-trampoline-identity.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "architecture": "mipsel",
                "path": "/fat/init-trampoline",
                "sha256": actual_sha256,
                "purpose": "replace inherited PID 1 environment before FAT preinit handoff",
            }))
            .map_err(|err| {
                native_system_preparation_error(
                    plan,
                    format!("failed to serialize init trampoline identity: {err}"),
                )
            })?,
        )
        .map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to write init trampoline identity: {err}"),
            )
        })?;
    }

    let staged_kernel_path = Path::new(&blueprint.launch.kernel_path);
    fs::copy(&kernel_source, staged_kernel_path).map_err(|err| {
        native_system_preparation_error(
            plan,
            format!(
                "failed to stage kernel {} -> {}: {err}",
                kernel_source.display(),
                blueprint.launch.kernel_path
            ),
        )
    })?;
    let staged_sha256 = sha256_file_hex(staged_kernel_path).map_err(|err| {
        native_system_preparation_error(
            plan,
            format!(
                "failed to hash staged kernel {}: {err}",
                staged_kernel_path.display()
            ),
        )
    })?;
    if staged_sha256 != kernel_identity.actual_sha256 {
        return Err(native_system_preparation_error(
            plan,
            format!(
                "staged kernel digest changed: source {} staged {}",
                kernel_identity.actual_sha256, staged_sha256
            ),
        ));
    }
    kernel_identity.staged_path = Some(staged_kernel_path.display().to_string());
    kernel_identity.staged_sha256 = Some(staged_sha256);
    fs::write(
        Path::new(&blueprint.launch.preinit_path),
        native_system_preinit_script(&blueprint.init_plan, &plan.rehosting_recipe),
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write preinit script: {err}"))
    })?;
    mark_executable(Path::new(&blueprint.launch.preinit_path)).map_err(|err| {
        native_system_preparation_error(
            plan,
            format!("failed to mark preinit script executable: {err}"),
        )
    })?;

    fs::write(
        guest_root.join("kernel-profile.json"),
        serde_json::to_vec_pretty(kernel_profile).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to serialize kernel profile: {err}"),
            )
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write kernel-profile.json: {err}"))
    })?;
    fs::write(
        guest_root.join("kernel-identity.json"),
        serde_json::to_vec_pretty(&kernel_identity).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to serialize kernel identity: {err}"),
            )
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(
            plan,
            format!("failed to write kernel-identity.json: {err}"),
        )
    })?;
    fs::write(
        guest_root.join("nvram-seed.json"),
        serde_json::to_vec_pretty(&blueprint.nvram_seed).map_err(|err| {
            native_system_preparation_error(plan, format!("failed to serialize nvram seed: {err}"))
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write nvram-seed.json: {err}"))
    })?;
    fs::write(
        guest_root.join("network-seed.json"),
        serde_json::to_vec_pretty(&blueprint.network_seed).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to serialize network seed: {err}"),
            )
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write network-seed.json: {err}"))
    })?;
    fs::write(
        guest_root.join("init-plan.json"),
        serde_json::to_vec_pretty(&blueprint.init_plan).map_err(|err| {
            native_system_preparation_error(plan, format!("failed to serialize init plan: {err}"))
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write init-plan.json: {err}"))
    })?;

    let rootfs_image = Path::new(&blueprint.launch.rootfs_image);
    if rootfs_image.exists() {
        fs::remove_file(rootfs_image).map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to clear previous rootfs image: {err}"),
            )
        })?;
    }
    build_ext2_rootfs_image(guest_root, rootfs_image, probe).map_err(|err| {
        native_system_preparation_error(plan, format!("failed to build rootfs image: {err}"))
    })?;

    let launch_command_path = launch_root.join("qemu-command.sh");
    fs::write(
        &launch_command_path,
        render_native_system_launch_script(&blueprint.launch),
    )
    .map_err(|err| {
        native_system_preparation_error(plan, format!("failed to write qemu-command.sh: {err}"))
    })?;
    mark_executable(&launch_command_path).map_err(|err| {
        native_system_preparation_error(
            plan,
            format!("failed to mark qemu-command.sh executable: {err}"),
        )
    })?;
    fs::write(
        launch_root.join("surface-manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "registered_surfaces": &blueprint.launch.registered_surfaces,
            "boot_args": &blueprint.launch.boot_args,
            "kernel_path": &blueprint.launch.kernel_path,
            "rootfs_image": &blueprint.launch.rootfs_image,
            "preinit_path": &blueprint.launch.preinit_path,
            "host_forwards": &blueprint.launch.host_forwards,
        }))
        .map_err(|err| {
            native_system_preparation_error(
                plan,
                format!("failed to serialize surface manifest: {err}"),
            )
        })?,
    )
    .map_err(|err| {
        native_system_preparation_error(
            plan,
            format!("failed to write surface-manifest.json: {err}"),
        )
    })?;

    Ok(())
}

fn materialize_native_system_recipe_transforms(
    guest_root: &Path,
    plan: &fat_emulate::EmulationPlan,
) -> Result<(), String> {
    for transform in &plan.rehosting_recipe.filesystem_transforms {
        let relative = transform.destination.trim().trim_start_matches('/');
        let destination = safe_guest_destination(guest_root, relative)?;
        reject_symlink_ancestry(guest_root, &destination)?;
        let source = if transform.destination_kind
            == fat_core::rehosting_recipe::RecipePathKind::File
            && !matches!(
                transform.source.as_str(),
                "synth:repair-init" | "synth:repair-config"
            ) {
            let source_relative = transform.source.trim().trim_start_matches('/');
            let source = safe_guest_destination(guest_root, source_relative)?;
            reject_symlink_ancestry(guest_root, &source)?;
            Some(source)
        } else {
            None
        };
        match transform.destination_kind {
            fat_core::rehosting_recipe::RecipePathKind::Directory => {
                fs::create_dir_all(&destination)
                    .map_err(|err| format!("create directory {}: {err}", destination.display()))?;
            }
            fat_core::rehosting_recipe::RecipePathKind::File => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|err| format!("create {}: {err}", parent.display()))?;
                }
                if matches!(
                    transform.source.as_str(),
                    "synth:repair-init" | "synth:repair-config"
                ) {
                    let contents = format!(
                        "# synthesized by FAT repair loop\nkind={}\nsource={}\n",
                        transform.transform_kind, transform.source
                    );
                    fs::write(&destination, contents).map_err(|err| {
                        format!("write synthesized {}: {err}", destination.display())
                    })?;
                    if transform.source == "synth:repair-init" {
                        mark_executable(&destination).map_err(|err| {
                            format!("mark {} executable: {err}", destination.display())
                        })?;
                    }
                } else {
                    let source = source.as_ref().expect("non-synthetic source validated");
                    if !source.is_file() {
                        return Err(format!(
                            "file transform source is unavailable: {}",
                            transform.source
                        ));
                    }
                    fs::copy(source, &destination).map_err(|err| {
                        format!(
                            "copy transform {} -> {}: {err}",
                            source.display(),
                            destination.display()
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn materialize_native_system_guest_adaptations(
    guest_root: &Path,
    plan: &fat_emulate::EmulationPlan,
) -> Result<(), String> {
    let fat_root = safe_guest_destination(guest_root, "fat")?;
    let shims_root = safe_guest_destination(guest_root, "fat/shims")?;
    reject_symlink_ancestry(guest_root, &fat_root)?;
    reject_symlink_ancestry(guest_root, &shims_root)?;
    fs::create_dir_all(&shims_root)
        .map_err(|err| format!("create adaptation shims {}: {err}", shims_root.display()))?;

    let mut adaptations = Vec::new();
    let staged_destinations = plan
        .rehosting_recipe
        .partition_materializations
        .iter()
        .filter(|partition| partition.strategy == "staged-copy" && partition.destination != "/")
        .map(|partition| partition.destination.clone())
        .collect::<Vec<_>>();
    if !staged_destinations.is_empty() {
        let mut cases = String::new();
        for destination in &staged_destinations {
            cases.push_str(&format!(
                "  {}) echo 'FAT_NATIVE_MOUNT_ALREADY_MATERIALIZED:{}' >&2; exit 0 ;;\n",
                shell_quote(destination),
                destination
            ));
        }
        let script = format!(
            "#!/bin/sh\ntarget=\nfor arg in \"$@\"; do target=$arg; done\ncase \"$target\" in\n{cases}esac\nif [ -x /bin/mount ]; then exec /bin/mount \"$@\"; fi\nexec /bin/busybox mount \"$@\"\n"
        );
        write_guest_shim(guest_root, &shims_root, "mount", &script)?;
        adaptations.push(serde_json::json!({
            "kind": "mount-shim",
            "name": "mount",
            "staged_destinations": staged_destinations,
        }));
    }

    for command in &plan.rehosting_recipe.guest_adaptations.command_shims {
        if !safe_guest_adaptation_token(command, false)
            || matches!(command.as_str(), "mount" | "insmod")
        {
            return Err(format!("unsafe or reserved command shim name: {command}"));
        }
        let script =
            format!("#!/bin/sh\necho 'FAT_NATIVE_COMMAND_SKIPPED:{command}' >&2\nexit 0\n");
        write_guest_shim(guest_root, &shims_root, command, &script)?;
        adaptations.push(serde_json::json!({
            "kind": "command-shim",
            "name": command,
        }));
    }

    let module_patterns = &plan.rehosting_recipe.guest_adaptations.module_skip_patterns;
    if !module_patterns.is_empty() {
        for pattern in module_patterns {
            if !safe_guest_adaptation_token(pattern, true) {
                return Err(format!("unsafe module skip pattern: {pattern}"));
            }
        }
        let cases = module_patterns
            .iter()
            .map(|pattern| {
                format!("  {pattern}) echo \"FAT_NATIVE_MODULE_SKIPPED:$module\" >&2; exit 0 ;;")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let script = format!(
            "#!/bin/sh\nmodule=${{1##*/}}\ncase \"$module\" in\n{cases}\nesac\nif [ -x /sbin/insmod ]; then exec /sbin/insmod \"$@\"; fi\nexec /bin/busybox insmod \"$@\"\n"
        );
        write_guest_shim(guest_root, &shims_root, "insmod", &script)?;
        adaptations.push(serde_json::json!({
            "kind": "module-filter-shim",
            "name": "insmod",
            "patterns": module_patterns,
        }));
    }

    let manifest_path = fat_root.join("adaptation-manifest.json");
    reject_symlink_ancestry(guest_root, &manifest_path)?;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "adaptations": adaptations,
        }))
        .map_err(|err| format!("serialize adaptation manifest: {err}"))?,
    )
    .map_err(|err| format!("write {}: {err}", manifest_path.display()))?;
    Ok(())
}

fn safe_guest_adaptation_token(value: &str, allow_glob: bool) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'+')
                || (allow_glob && matches!(byte, b'*' | b'?'))
        })
}

fn write_guest_shim(
    guest_root: &Path,
    shims_root: &Path,
    name: &str,
    script: &str,
) -> Result<(), String> {
    let path = shims_root.join(name);
    reject_symlink_ancestry(guest_root, &path)?;
    fs::write(&path, script).map_err(|err| format!("write shim {}: {err}", path.display()))?;
    mark_executable(&path).map_err(|err| format!("mark shim {} executable: {err}", path.display()))
}

fn safe_guest_destination(guest_root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty()
        || Path::new(relative).components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!("unsafe guest path: {relative}"));
    }
    Ok(guest_root.join(relative))
}

fn reject_symlink_ancestry(guest_root: &Path, path: &Path) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(guest_root)
        .map_err(|err| format!("inspect guest root {}: {err}", guest_root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(format!(
            "guest root must be a real directory without symlinks: {}",
            guest_root.display()
        ));
    }
    let canonical_root = guest_root
        .canonicalize()
        .map_err(|err| format!("canonicalize guest root {}: {err}", guest_root.display()))?;
    let relative = path
        .strip_prefix(guest_root)
        .map_err(|_| format!("path is outside guest root: {}", path.display()))?;
    let mut current = canonical_root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!("unsafe guest path component in {}", path.display()));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "guest path contains symlink ancestry: {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(format!("inspect guest path {}: {err}", current.display()));
            }
        }
    }
    if !current.starts_with(&canonical_root) {
        return Err(format!(
            "path escapes canonical guest root: {}",
            path.display()
        ));
    }
    Ok(())
}

fn native_system_preparation_error(
    plan: &fat_emulate::EmulationPlan,
    detail: impl Into<String>,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        plan.run.record.run_id.clone(),
        DiagnosticPhase::Preparation,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::PreparationFailed,
        Some("native-host-system-assets".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("fat-emulate: {}", detail.into()),
        Vec::new(),
        Vec::new(),
        vec![
            "inspect the staged system boot assets".to_string(),
            "verify the extraction manifest rootfs and vendored kernel inputs".to_string(),
        ],
    )
}

fn missing_qemu_runtime_diagnostic(run_id: &str, family_id: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Preparation,
        DiagnosticOwner::Substrate,
        DiagnosticClass::SubstrateUnavailable,
        Some("qemu-runtime-missing".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("no compatible QEMU executable was found for family {family_id}"),
        Vec::new(),
        Vec::new(),
        vec!["install the required QEMU system emulator and rerun `fat doctor`".to_string()],
    )
}

fn managed_supervisor_spawn_diagnostic(run_id: &str, detail: String) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::Substrate,
        DiagnosticClass::LaunchFailed,
        Some("managed-supervisor-spawn".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("managed runtime supervisor failed to start: {detail}"),
        Vec::new(),
        Vec::new(),
        vec!["verify the FAT executable can spawn the managed supervisor".to_string()],
    )
}

fn locate_native_system_rootfs(project_dir: &Path) -> Result<PathBuf, String> {
    let extracted = project_dir.join("extracted");
    if extracted.exists() {
        return extracted.canonicalize().map_err(|err| {
            format!(
                "failed to resolve extracted rootfs view {}: {err}",
                extracted.display()
            )
        });
    }

    let manifest = load_native_system_extraction_manifest(project_dir)?;
    let rootfs_path = manifest
        .rootfs_path
        .ok_or_else(|| "extracted rootfs is missing".to_string())?;
    if !rootfs_path.exists() {
        return Err(format!(
            "extracted rootfs is missing: {}",
            rootfs_path.display()
        ));
    }
    Ok(rootfs_path)
}

fn load_native_system_extraction_manifest(
    project_dir: &Path,
) -> Result<ExtractionManifest, String> {
    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let bytes = fs::read(&manifest_path).map_err(|err| {
        format!(
            "failed to read extraction manifest {}: {err}",
            manifest_path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "failed to parse extraction manifest {}: {err}",
            manifest_path.display()
        )
    })
}

fn assemble_native_system_partitions(
    manifest: &ExtractionManifest,
    materializations: &[fat_core::rehosting_recipe::RecipePartitionMaterialization],
    source_root: &Path,
    guest_root: &Path,
) -> Result<NativeSystemAssemblyManifest, String> {
    if materializations.is_empty() {
        return Err("native system partition materialization is empty".to_string());
    }

    let mut seen_roles = std::collections::BTreeSet::new();
    let mut resolved = Vec::with_capacity(materializations.len());
    for materialization in materializations {
        if materialization.strategy != "staged-copy" {
            return Err(format!(
                "unsupported partition materialization '{}' for role '{}'",
                materialization.strategy, materialization.source_role
            ));
        }
        if !seen_roles.insert(materialization.source_role.as_str()) {
            return Err(format!(
                "duplicate partition materialization role '{}'",
                materialization.source_role
            ));
        }
        if !materialization.destination.starts_with('/') {
            return Err(format!(
                "partition destination must be an absolute guest path: {}",
                materialization.destination
            ));
        }
        if materialization.destination != "/" {
            let relative = materialization.destination.trim_start_matches('/');
            safe_guest_destination(guest_root, relative)?;
        }
        let matches = manifest
            .filesystem_trees
            .iter()
            .filter(|tree| tree.role == materialization.source_role)
            .collect::<Vec<_>>();
        let tree = match matches.as_slice() {
            [] => {
                return Err(format!(
                    "missing partition role '{}' in extraction manifest",
                    materialization.source_role
                ));
            }
            [tree] => *tree,
            _ => {
                return Err(format!(
                    "duplicate partition role '{}' in extraction manifest",
                    materialization.source_role
                ));
            }
        };
        validate_partition_source_tree(&tree.path)?;
        resolved.push((materialization, tree));
    }

    let roots = resolved
        .iter()
        .filter(|(materialization, _)| materialization.destination == "/")
        .collect::<Vec<_>>();
    let root_tree = match roots.as_slice() {
        [] => return Err("partition materialization must declare one role mounted at /".into()),
        [root] => root.1,
        _ => return Err("partition materialization declares multiple roles mounted at /".into()),
    };

    reset_directory(source_root)
        .map_err(|err| format!("failed to reset staged source rootfs: {err}"))?;
    copy_tree(&root_tree.path, source_root)
        .map_err(|err| format!("failed to stage source rootfs: {err}"))?;
    reset_directory(guest_root)
        .map_err(|err| format!("failed to reset staged guest rootfs: {err}"))?;
    copy_tree(&root_tree.path, guest_root)
        .map_err(|err| format!("failed to stage guest rootfs: {err}"))?;

    for (materialization, tree) in &resolved {
        if materialization.destination == "/" {
            continue;
        }
        let relative = materialization.destination.trim_start_matches('/');
        let destination = safe_guest_destination(guest_root, relative)?;
        reject_symlink_ancestry(guest_root, &destination)?;
        copy_tree(&tree.path, &destination).map_err(|err| {
            format!(
                "failed to stage partition '{}' at '{}': {err}",
                materialization.source_role, materialization.destination
            )
        })?;
    }

    let assembly = NativeSystemAssemblyManifest {
        version: 1,
        partitions: resolved
            .iter()
            .map(|(materialization, tree)| NativeSystemAssemblyPartition {
                source_role: materialization.source_role.clone(),
                source_path: tree.path.display().to_string(),
                destination: materialization.destination.clone(),
                strategy: materialization.strategy.clone(),
            })
            .collect(),
    };
    let assembly_path = guest_root.join("assembly-manifest.json");
    reject_symlink_ancestry(guest_root, &assembly_path)?;
    fs::write(
        &assembly_path,
        serde_json::to_vec_pretty(&assembly)
            .map_err(|err| format!("serialize assembly manifest: {err}"))?,
    )
    .map_err(|err| format!("write {}: {err}", assembly_path.display()))?;

    Ok(assembly)
}

fn validate_partition_source_tree(source_root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source_root)
        .map_err(|err| format!("inspect partition source {}: {err}", source_root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "partition source must be a real directory: {}",
            source_root.display()
        ));
    }
    validate_partition_source_entries(source_root, source_root)
}

fn validate_partition_source_entries(source_root: &Path, directory: &Path) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|err| format!("read partition source {}: {err}", directory.display()))?
    {
        let entry = entry.map_err(|err| format!("read partition source entry: {err}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("inspect partition source {}: {err}", path.display()))?;
        if file_type.is_dir() {
            validate_partition_source_entries(source_root, &path)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|err| format!("read partition symlink {}: {err}", path.display()))?;
            if target.is_absolute() {
                continue;
            }
            let parent = path.parent().unwrap_or(source_root);
            let parent_relative = parent.strip_prefix(source_root).map_err(|_| {
                format!("partition source path is outside root: {}", path.display())
            })?;
            let mut depth = parent_relative
                .components()
                .filter(|component| matches!(component, std::path::Component::Normal(_)))
                .count();
            for component in target.components() {
                match component {
                    std::path::Component::Normal(_) => depth += 1,
                    std::path::Component::ParentDir if depth == 0 => {
                        return Err(format!(
                            "partition symlink escapes source tree: {} -> {}",
                            path.display(),
                            target.display()
                        ));
                    }
                    std::path::Component::ParentDir => depth -= 1,
                    std::path::Component::CurDir => {}
                    std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                        return Err(format!(
                            "invalid relative partition symlink: {} -> {}",
                            path.display(),
                            target.display()
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn native_system_preinit_script(
    init_plan: &fat_emulate::system_runner::SystemInitPlan,
    recipe: &RehostingRecipe,
) -> String {
    let mut script = String::from(
        "#!/bin/sh\nset +e\necho FAT_NATIVE_PREINIT_START\nmount -t proc proc /proc 2>/dev/null || true\nmount -t sysfs sysfs /sys 2>/dev/null || true\nmount -t devtmpfs devtmpfs /dev 2>/dev/null || true\nmkdir -p /tmp /var/run /fat /fat/shims\ncd / 2>/dev/null || true\nexport PATH=/fat/shims:/bin:/sbin:/usr/bin:/usr/sbin\necho FAT_NATIVE_RUNTIME_PATHS_READY\n",
    );
    if let Some(network) = recipe.network.as_ref() {
        if let Some(interface) = network.interface.as_deref() {
            let interface_quoted = shell_quote(interface);
            let attempt_marker = shell_quote(&format!("FAT_NATIVE_NETWORK_ATTEMPT:{interface}"));
            script.push_str(&format!("echo {attempt_marker}\nfat_network_ready=0\n"));
            // A virtio NIC comes up administratively down. DHCP on a down link
            // cannot work -- udhcpc reports "Network is down" and retries -- so
            // the link is enabled before any addressing is attempted. The static
            // fallback below already did this as part of its own ifconfig; the
            // DHCP path never did.
            script.push_str(&format!(
                "if command -v ip >/dev/null 2>&1; then ip link set {interface_quoted} up 2>/dev/null || true; \
                 elif command -v ifconfig >/dev/null 2>&1; then ifconfig {interface_quoted} up 2>/dev/null || true; fi\n"
            ));
            if network.mode.as_deref() == Some("dhcp") {
                // -t bounds the discover attempts: a rehosting run must not spin
                // on DHCP until the idle sweep reaps the session.
                script.push_str(&format!(
                    "if command -v udhcpc >/dev/null 2>&1 && udhcpc -i {interface_quoted} -n -q -t 3; then fat_network_ready=1; fi\n"
                ));
            }
            if let Some(fallback_ip) = network.fallback_ip.as_deref() {
                script.push_str(&format!(
                    "if [ \"$fat_network_ready\" -ne 1 ]; then ifconfig {interface_quoted} {} netmask 255.255.255.0 up && fat_network_ready=1; fi\n",
                    shell_quote(fallback_ip)
                ));
            }
            let ready_marker = shell_quote(&format!("FAT_NATIVE_NETWORK_READY:{interface}"));
            let failed_marker = shell_quote(&format!("FAT_NATIVE_NETWORK_FAILED:{interface}"));
            script.push_str(&format!(
                "if [ \"$fat_network_ready\" -eq 1 ]; then echo {ready_marker}; else echo {failed_marker} >&2; fi\n"
            ));
        }
    }
    let candidates = native_system_init_handoff_candidates(init_plan);
    for candidate in &candidates {
        if native_system_script_init(candidate) {
            let candidate_quoted = shell_quote(candidate);
            let attempt_marker = shell_quote(&format!("FAT_NATIVE_INIT_ATTEMPT:{candidate}"));
            let failed_marker = shell_quote(&format!("FAT_NATIVE_SYSTEM_INIT_FAILED:{candidate}"));
            script.push_str(&format!(
                "if [ -x {candidate_quoted} ]; then echo {attempt_marker}; {candidate_quoted} || echo {failed_marker} >&2; fi\n"
            ));
        }
    }
    for candidate in candidates {
        if native_system_script_init(&candidate) {
            continue;
        }
        let candidate_quoted = shell_quote(&candidate);
        let attempt_marker = shell_quote(&format!("FAT_NATIVE_INIT_ATTEMPT:{candidate}"));
        script.push_str(&format!(
            "if [ -x {candidate_quoted} ]; then echo {attempt_marker}; exec {candidate_quoted}; fi\n"
        ));
    }
    script.push_str("echo FAT_NATIVE_SYSTEM_PREINIT_NO_INIT >&2\nexec /bin/sh\n");
    script
}

fn native_system_init_handoff_candidates(
    init_plan: &fat_emulate::system_runner::SystemInitPlan,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(selected) = init_plan.selected_init.as_ref() {
        candidates.push(selected.clone());
    }
    candidates.extend(init_plan.alternate_inits.iter().cloned());
    candidates.extend(
        [
            "/etc/init.d/rcS",
            "/etc/rc.d/rcS",
            "/etc/init.d/boot",
            "/etc/preinit",
            "/sbin/preinit",
            "/sbin/init",
            "/etc/init",
            "/bin/init",
        ]
        .into_iter()
        .map(str::to_string),
    );
    let mut unique = Vec::new();
    for candidate in candidates {
        if !candidate.starts_with('/') {
            continue;
        }
        if unique.contains(&candidate) {
            continue;
        }
        unique.push(candidate);
    }
    if unique.is_empty() {
        unique.push("/sbin/init".to_string());
    }
    unique
}

fn native_system_script_init(candidate: &str) -> bool {
    candidate.ends_with(".sh")
        || candidate.starts_with("/etc/init.d/")
        || candidate.ends_with("/rcS")
        || candidate.ends_with("/preinit")
}

#[cfg(test)]
mod tests {
    use super::{
        assemble_native_system_partitions, docker_ext2_args, final_pack_capability_report,
        locate_native_system_rootfs, materialize_native_system_guest_adaptations,
        materialize_native_system_recipe_transforms, native_system_init_handoff_candidates,
        native_system_preinit_script, native_system_script_init, sha256_file_hex,
        validate_ext2_builder_image, verify_native_system_kernel_identity, LogicalSubstrateKind,
    };
    use fat_core::rehosting_pack::PackPartitionRole;
    use fat_core::rehosting_pack_overlay::PackOverlay;
    use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
    use fat_core::rehosting_recipe::{
        RecipeFilesystemTransform, RecipeGuestAdaptations, RecipeNetworkConfig,
        RecipePartitionMaterialization, RehostingRecipe,
    };
    use fat_emulate::system_runner::SystemInitPlan;
    use fat_extract::manifest::{ExtractedFilesystemTree, ExtractionManifest};
    use tempfile::tempdir;

    fn empty_system_recipe() -> RehostingRecipe {
        RehostingRecipe::new(
            "target",
            "model",
            "run",
            "emulate",
            SubstratePreference::SystemFirst,
            SubstrateKind::System,
        )
    }

    #[cfg(unix)]
    #[test]
    fn native_system_rootfs_resolves_the_extracted_view_to_a_real_directory() {
        use std::os::unix::fs::symlink;

        let project = tempdir().expect("project");
        let rootfs = project.path().join("work/extractions/rootfs");
        std::fs::create_dir_all(&rootfs).expect("rootfs");
        symlink(&rootfs, project.path().join("extracted")).expect("extracted view");

        let located = locate_native_system_rootfs(project.path()).expect("located rootfs");

        assert_eq!(located, rootfs.canonicalize().expect("canonical rootfs"));
        assert!(
            !std::fs::symlink_metadata(&located)
                .expect("located metadata")
                .file_type()
                .is_symlink(),
            "partition assembly must receive the real extraction directory"
        );
    }

    #[test]
    fn native_system_preinit_ignores_non_absolute_init_hints_and_tries_firmware_paths() {
        let recipe = empty_system_recipe();
        let script = native_system_preinit_script(
            &SystemInitPlan {
                selected_init: Some("busybox".to_string()),
                alternate_inits: Vec::new(),
            },
            &recipe,
        );

        assert!(
            !script.contains("exec 'busybox'"),
            "preinit should not exec a bare non-absolute init hint: {script}"
        );
        assert!(
            script.contains(
                "if [ -x '/etc/init.d/rcS' ]; then echo 'FAT_NATIVE_INIT_ATTEMPT:/etc/init.d/rcS'"
            ),
            "preinit should try firmware rcS handoff: {script}"
        );
        assert!(
            script.contains("if [ -x '/sbin/init' ]; then echo 'FAT_NATIVE_INIT_ATTEMPT:/sbin/init'; exec '/sbin/init'; fi"),
            "preinit should still fall through to a real init binary: {script}"
        );
    }

    #[test]
    fn native_system_preinit_records_markers_path_and_network_fallback() {
        let mut recipe = empty_system_recipe();
        recipe.network = Some(RecipeNetworkConfig {
            interface: Some("eth0".to_string()),
            mode: Some("dhcp".to_string()),
            fallback_ip: Some("10.0.2.15".to_string()),
        });
        let script = native_system_preinit_script(
            &SystemInitPlan {
                selected_init: Some("/system/init/app_init.sh".to_string()),
                alternate_inits: Vec::new(),
            },
            &recipe,
        );

        assert!(script.contains("FAT_NATIVE_PREINIT_START"), "{script}");
        assert!(
            script.contains("PATH=/fat/shims:/bin:/sbin:/usr/bin:/usr/sbin"),
            "{script}"
        );
        assert!(script.contains("udhcpc -i 'eth0'"), "{script}");
        // The link must be enabled before addressing is attempted, and the
        // DHCP attempt must be bounded.
        let link_up = script
            .find("link set 'eth0' up")
            .or_else(|| script.find("ifconfig 'eth0' up"))
            .unwrap_or_else(|| panic!("preinit never brings the link up: {script}"));
        let dhcp = script.find("udhcpc -i 'eth0'").expect("udhcpc");
        assert!(
            link_up < dhcp,
            "the link must come up before udhcpc runs: {script}"
        );
        assert!(script.contains("udhcpc -i 'eth0' -n -q -t 3"), "{script}");
        assert!(script.contains("ifconfig 'eth0' '10.0.2.15'"), "{script}");
        assert!(script.contains("FAT_NATIVE_NETWORK_READY:eth0"), "{script}");
        assert!(
            script.contains("FAT_NATIVE_INIT_ATTEMPT:/system/init/app_init.sh"),
            "{script}"
        );
    }

    #[test]
    fn native_system_guest_adaptations_create_only_declared_shims_and_manifest() {
        let root = tempdir().expect("guest root");
        let mut plan =
            fat_emulate::EmulationPlan::new("adapt", "qemu-direct", vec![]).expect("plan");
        plan.rehosting_recipe.partition_materializations = vec![
            RecipePartitionMaterialization::new("rootfs", "/", "staged-copy"),
            RecipePartitionMaterialization::new("app", "/system", "staged-copy"),
        ];
        plan.rehosting_recipe.guest_adaptations = RecipeGuestAdaptations {
            command_shims: vec!["devmem".to_string()],
            module_skip_patterns: vec!["tx-isp-*.ko".to_string()],
        };

        materialize_native_system_guest_adaptations(root.path(), &plan)
            .expect("materialize adaptations");

        let shims = root.path().join("fat/shims");
        assert!(shims.join("mount").is_file());
        assert!(shims.join("devmem").is_file());
        assert!(shims.join("insmod").is_file());
        assert!(!shims.join("ubootddr").exists());
        let mount = std::fs::read_to_string(shims.join("mount")).expect("mount shim");
        assert!(mount.contains("/system"), "{mount}");
        assert!(mount.contains("exec /bin/busybox mount"), "{mount}");
        let insmod = std::fs::read_to_string(shims.join("insmod")).expect("insmod shim");
        assert!(insmod.contains("tx-isp-*.ko"), "{insmod}");
        let manifest = std::fs::read_to_string(root.path().join("fat/adaptation-manifest.json"))
            .expect("adaptation manifest");
        assert!(manifest.contains("mount-shim"), "{manifest}");
        assert!(manifest.contains("command-shim"), "{manifest}");
        assert!(manifest.contains("module-filter-shim"), "{manifest}");
    }

    #[test]
    fn native_system_init_handoff_candidates_deduplicate_absolute_candidates() {
        let candidates = native_system_init_handoff_candidates(&SystemInitPlan {
            selected_init: Some("/sbin/preinit".to_string()),
            alternate_inits: vec![
                "busybox".to_string(),
                "/etc/init.d/rcS".to_string(),
                "/sbin/preinit".to_string(),
            ],
        });

        assert_eq!(
            candidates,
            vec![
                "/sbin/preinit".to_string(),
                "/etc/init.d/rcS".to_string(),
                "/etc/rc.d/rcS".to_string(),
                "/etc/init.d/boot".to_string(),
                "/etc/preinit".to_string(),
                "/sbin/init".to_string(),
                "/etc/init".to_string(),
                "/bin/init".to_string(),
            ]
        );
    }

    #[test]
    fn native_system_script_init_classifies_rcs_and_preinit_as_scripts() {
        assert!(native_system_script_init("/etc/init.d/rcS"));
        assert!(native_system_script_init("/sbin/preinit"));
        assert!(!native_system_script_init("/sbin/init"));
    }

    #[test]
    fn external_native_system_kernel_requires_matching_operator_sha256() {
        let dir = tempdir().expect("kernel dir");
        let kernel = dir.path().join("vmlinux.mipsel.4");
        std::fs::write(&kernel, b"operator supplied kernel").expect("kernel");
        let profile = fat_emulate::kernel_catalog::KernelProfile::new(
            "mipsel-external",
            "mipsel",
            "linux-",
            1,
            "vmlinux.mipsel.4",
            "external-required",
            "operator supplied",
        );

        let missing = verify_native_system_kernel_identity(&profile, &kernel, None)
            .expect_err("external kernel without expected digest");
        assert!(missing.contains("FAT_SYSTEM_KERNEL_SHA256"), "{missing}");

        let actual = sha256_file_hex(&kernel).expect("digest");
        let mismatch =
            verify_native_system_kernel_identity(&profile, &kernel, Some(&"0".repeat(64)))
                .expect_err("digest mismatch");
        assert!(mismatch.contains("does not match"), "{mismatch}");

        let identity = verify_native_system_kernel_identity(&profile, &kernel, Some(&actual))
            .expect("verified identity");
        assert!(identity.verified);
        assert_eq!(identity.actual_sha256, actual);
        assert_eq!(identity.expected_sha256.as_deref(), Some(actual.as_str()));
    }

    #[test]
    fn managed_native_system_kernel_uses_catalog_artifact_digest_without_operator_env() {
        let dir = tempdir().expect("kernel dir");
        let kernel = dir.path().join("vmlinux");
        std::fs::write(&kernel, b"fat maintained kernel").expect("kernel");
        let actual = sha256_file_hex(&kernel).expect("digest");
        let mut profile = fat_emulate::kernel_catalog::KernelProfile::new(
            "managed-mipsel",
            "mipsel",
            "linux-",
            0,
            "vmlinux",
            "experimental",
            "managed artifact",
        );
        profile.managed_bundle_id = Some("kab-0123456789abcdef".into());
        profile.artifact_digest = Some(format!("sha256:{actual}"));

        let identity = verify_native_system_kernel_identity(&profile, &kernel, None)
            .expect("managed identity");

        assert!(identity.verified);
        assert_eq!(identity.actual_sha256, actual);
        assert_eq!(identity.expected_sha256.as_deref(), Some(actual.as_str()));
    }

    #[test]
    fn docker_ext2_builder_is_pinned_and_drops_unneeded_privileges() {
        let image = format!("ghcr.io/attify/fat-ext2-builder@sha256:{}", "a".repeat(64));
        let args = docker_ext2_args(
            std::path::Path::new("/tmp/guest"),
            std::path::Path::new("/tmp/output"),
            &image,
            "true",
        )
        .expect("valid builder args");

        assert!(args.iter().any(|arg| arg == &image));
        assert!(!args.iter().any(|arg| arg == "--privileged"));
        assert!(args.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(args.windows(2).any(|pair| pair == ["--pull", "never"]));
        assert!(!args
            .iter()
            .any(|arg| arg.contains("apt-get") || arg.contains("apk add")));
        assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
        assert!(args
            .windows(2)
            .any(|pair| { pair == ["--security-opt", "no-new-privileges:true"] }));
        assert!(args
            .iter()
            .any(|arg| arg == "type=bind,src=/tmp/guest,dst=/source,readonly"));
        assert!(args
            .iter()
            .any(|arg| arg == "type=bind,src=/tmp/output,dst=/output"));
        for capability in ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"] {
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["--cap-add", capability]),
                "missing required capability {capability}: {args:?}"
            );
        }
    }

    #[test]
    fn docker_ext2_builder_rejects_mutable_image_references() {
        assert!(validate_ext2_builder_image("ubuntu:22.04").is_err());
        assert!(validate_ext2_builder_image("ubuntu@sha256:abcd").is_err());
        assert!(validate_ext2_builder_image(&format!("builder@sha256:{}", "f".repeat(64))).is_ok());
    }

    #[test]
    fn native_system_materializes_canonical_synthetic_repair_sources() {
        let root = tempdir().expect("root");
        let mut plan =
            fat_emulate::EmulationPlan::new("repair", "qemu-direct", vec![]).expect("plan");
        plan.rehosting_recipe.filesystem_transforms = vec![
            RecipeFilesystemTransform::new(
                "patch-config",
                "synth:repair-init",
                "/etc/fat/repair-init.sh",
            ),
            RecipeFilesystemTransform::new(
                "patch-config",
                "synth:repair-config",
                "/etc/fat/generated-repair.conf",
            ),
        ];

        materialize_native_system_recipe_transforms(root.path(), &plan).expect("materialize");

        let init = root.path().join("etc/fat/repair-init.sh");
        let config = root.path().join("etc/fat/generated-repair.conf");
        assert!(init.is_file());
        assert!(config.is_file());
        assert!(std::fs::read_to_string(init)
            .unwrap()
            .contains("source=synth:repair-init"));
        assert!(std::fs::read_to_string(config)
            .unwrap()
            .contains("source=synth:repair-config"));
    }

    #[cfg(unix)]
    #[test]
    fn native_system_rejects_destination_symlink_ancestry_without_external_mutation() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("root");
        let external = tempdir().expect("external");
        symlink(external.path(), root.path().join("etc")).expect("etc symlink");
        let mut plan =
            fat_emulate::EmulationPlan::new("repair", "qemu-direct", vec![]).expect("plan");
        plan.rehosting_recipe.filesystem_transforms = vec![RecipeFilesystemTransform::new(
            "patch-config",
            "synth:repair-config",
            "/etc/fat/generated-repair.conf",
        )];

        let error = materialize_native_system_recipe_transforms(root.path(), &plan)
            .expect_err("symlink ancestry must be rejected");

        assert!(error.contains("symlink"), "{error}");
        assert!(
            std::fs::read_dir(external.path())
                .expect("external dir")
                .next()
                .is_none(),
            "external directory must remain unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_system_rejects_source_symlink_ancestry() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("root");
        let external = tempdir().expect("external");
        std::fs::write(external.path().join("secret"), "outside").expect("external source");
        symlink(external.path(), root.path().join("source")).expect("source symlink");
        let mut plan =
            fat_emulate::EmulationPlan::new("repair", "qemu-direct", vec![]).expect("plan");
        plan.rehosting_recipe.filesystem_transforms = vec![RecipeFilesystemTransform::new(
            "copy-file",
            "/source/secret",
            "/etc/copied-secret",
        )];

        let error = materialize_native_system_recipe_transforms(root.path(), &plan)
            .expect_err("source symlink ancestry must be rejected");

        assert!(error.contains("symlink"), "{error}");
        assert!(
            !root.path().join("etc").exists(),
            "source validation must happen before destination mutation"
        );
    }

    fn partition(source_role: &str, destination: &str) -> RecipePartitionMaterialization {
        RecipePartitionMaterialization::new(source_role, destination, "staged-copy")
    }

    fn tree(role: &str, path: &std::path::Path) -> ExtractedFilesystemTree {
        ExtractedFilesystemTree {
            role: role.to_string(),
            path: path.to_path_buf(),
            tree_kind: role.to_string(),
        }
    }

    #[test]
    fn native_system_partition_assembly_rejects_missing_role_before_mutation() {
        let rootfs = tempdir().expect("rootfs");
        let staging = tempdir().expect("staging");
        let source_root = staging.path().join("source");
        let guest_root = staging.path().join("guest");
        let manifest = ExtractionManifest {
            rootfs_path: Some(rootfs.path().to_path_buf()),
            filesystem_trees: vec![tree("rootfs", rootfs.path())],
            ..ExtractionManifest::default()
        };

        let error = assemble_native_system_partitions(
            &manifest,
            &[partition("rootfs", "/"), partition("app", "/system")],
            &source_root,
            &guest_root,
        )
        .expect_err("missing app role");

        assert!(error.contains("missing partition role 'app'"), "{error}");
        assert!(!source_root.exists());
        assert!(!guest_root.exists());
    }

    #[test]
    fn native_system_partition_assembly_rejects_duplicate_manifest_role() {
        let rootfs = tempdir().expect("rootfs");
        let app_a = tempdir().expect("app a");
        let app_b = tempdir().expect("app b");
        let staging = tempdir().expect("staging");
        let manifest = ExtractionManifest {
            rootfs_path: Some(rootfs.path().to_path_buf()),
            filesystem_trees: vec![
                tree("rootfs", rootfs.path()),
                tree("app", app_a.path()),
                tree("app", app_b.path()),
            ],
            ..ExtractionManifest::default()
        };

        let error = assemble_native_system_partitions(
            &manifest,
            &[partition("rootfs", "/"), partition("app", "/system")],
            &staging.path().join("source"),
            &staging.path().join("guest"),
        )
        .expect_err("duplicate app role");

        assert!(error.contains("duplicate partition role 'app'"), "{error}");
    }

    #[test]
    fn native_system_partition_assembly_rejects_parent_destination() {
        let rootfs = tempdir().expect("rootfs");
        let app = tempdir().expect("app");
        let staging = tempdir().expect("staging");
        let manifest = ExtractionManifest {
            rootfs_path: Some(rootfs.path().to_path_buf()),
            filesystem_trees: vec![tree("rootfs", rootfs.path()), tree("app", app.path())],
            ..ExtractionManifest::default()
        };

        let error = assemble_native_system_partitions(
            &manifest,
            &[partition("rootfs", "/"), partition("app", "/../escape")],
            &staging.path().join("source"),
            &staging.path().join("guest"),
        )
        .expect_err("parent destination");

        assert!(error.contains("unsafe guest path"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn native_system_partition_assembly_rejects_destination_symlink_ancestry() {
        use std::os::unix::fs::symlink;

        let rootfs = tempdir().expect("rootfs");
        let app = tempdir().expect("app");
        let external = tempdir().expect("external");
        let staging = tempdir().expect("staging");
        symlink(external.path(), rootfs.path().join("system")).expect("system symlink");
        std::fs::write(app.path().join("payload"), "app").expect("app payload");
        let manifest = ExtractionManifest {
            rootfs_path: Some(rootfs.path().to_path_buf()),
            filesystem_trees: vec![tree("rootfs", rootfs.path()), tree("app", app.path())],
            ..ExtractionManifest::default()
        };

        let error = assemble_native_system_partitions(
            &manifest,
            &[partition("rootfs", "/"), partition("app", "/system")],
            &staging.path().join("source"),
            &staging.path().join("guest"),
        )
        .expect_err("destination symlink ancestry");

        assert!(error.contains("symlink ancestry"), "{error}");
        assert!(!external.path().join("payload").exists());
    }

    #[cfg(unix)]
    #[test]
    fn native_system_partition_assembly_rejects_source_tree_symlink_escape() {
        use std::os::unix::fs::symlink;

        let rootfs = tempdir().expect("rootfs");
        let app_parent = tempdir().expect("app parent");
        let app = app_parent.path().join("app");
        let external = app_parent.path().join("outside");
        let staging = tempdir().expect("staging");
        std::fs::create_dir_all(&app).expect("app");
        std::fs::create_dir_all(&external).expect("outside");
        std::fs::write(external.join("secret"), "outside").expect("outside secret");
        symlink("../outside/secret", app.join("escape")).expect("escaping symlink");
        let manifest = ExtractionManifest {
            rootfs_path: Some(rootfs.path().to_path_buf()),
            filesystem_trees: vec![tree("rootfs", rootfs.path()), tree("app", &app)],
            ..ExtractionManifest::default()
        };

        let error = assemble_native_system_partitions(
            &manifest,
            &[partition("rootfs", "/"), partition("app", "/system")],
            &staging.path().join("source"),
            &staging.path().join("guest"),
        )
        .expect_err("source symlink escape");

        assert!(error.contains("escapes source tree"), "{error}");
        assert!(!staging.path().join("guest").exists());
    }

    #[test]
    fn managed_backend_capability_report_rejects_unconsumed_system_pack_actions() {
        let overlay = PackOverlay {
            pack_id: "test/managed-gap".to_string(),
            partition_roles: vec![PackPartitionRole {
                source: "app".to_string(),
                mount: "/system".to_string(),
                materialization: Some("staged-copy".to_string()),
            }],
            qemu_machine: Some("malta".to_string()),
            network_mode: Some("dhcp".to_string()),
            materialize_transforms: vec![RecipeFilesystemTransform::directory(
                "materialize-directory",
                "/configs",
            )],
            skip_flags: vec!["repair:skip-command:devmem".to_string()],
            ..PackOverlay::default()
        };
        let mut plan =
            fat_emulate::EmulationPlan::new("managed", "qemu-direct", vec![]).expect("plan");
        plan.strategy.selected.backend_id = "firmadyne".to_string();
        plan.strategy.selected.substrate = fat_core::runs::SubstrateKind::ManagedLinuxVm;
        plan.rehosting_recipe.selected_substrate = LogicalSubstrateKind::System;

        let report = final_pack_capability_report(&overlay, &plan);

        for action in [
            "partition:app:/system",
            "qemu-machine",
            "materialize:directory:/configs",
            "network-configuration",
            "repair:skip-command:devmem",
        ] {
            assert!(
                report
                    .unsupported_actions
                    .iter()
                    .any(|candidate| candidate == action),
                "missing unsupported {action}: {report:?}"
            );
            assert!(
                !report
                    .supported_actions
                    .iter()
                    .any(|candidate| candidate == action),
                "falsely supported {action}: {report:?}"
            );
        }
    }

    #[test]
    fn native_system_capability_report_accepts_partition_materialization() {
        let overlay = PackOverlay {
            pack_id: "test/native-system".to_string(),
            partition_roles: vec![PackPartitionRole {
                source: "app".to_string(),
                mount: "/system".to_string(),
                materialization: Some("staged-copy".to_string()),
            }],
            network_mode: Some("dhcp".to_string()),
            network_interface: Some("eth0".to_string()),
            skip_flags: vec!["repair:skip-module:vendor-*.ko".to_string()],
            ..PackOverlay::default()
        };
        let mut plan =
            fat_emulate::EmulationPlan::new("native", "qemu-direct", vec![]).expect("plan");
        plan.strategy.selected.backend_id = "qemu-direct".to_string();
        plan.strategy.selected.substrate = fat_core::runs::SubstrateKind::NativeHost;
        plan.rehosting_recipe.selected_substrate = LogicalSubstrateKind::System;

        let report = final_pack_capability_report(&overlay, &plan);

        assert!(report
            .supported_actions
            .iter()
            .any(|action| action == "partition:app:/system"));
        assert!(!report
            .unsupported_actions
            .iter()
            .any(|action| action == "partition:app:/system"));
        assert!(report
            .supported_actions
            .iter()
            .any(|action| action == "repair:skip-module:vendor-*.ko"));
        assert!(report
            .supported_actions
            .iter()
            .any(|action| action == "network-configuration"));
        assert!(report.degraded_actions.is_empty(), "{report:?}");
    }
}

fn render_native_system_launch_script(
    spec: &fat_emulate::system_runner::SystemLaunchSpec,
) -> String {
    let mut command_parts = Vec::with_capacity(spec.args.len() + 3);
    command_parts.push(spec.qemu_binary.clone());
    command_parts.extend(spec.args.iter().cloned());
    if let Some(instrumentation) = spec.instrumentation.as_ref() {
        let trace_log = Path::new(&spec.serial_log)
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("instrument-trace.jsonl");
        command_parts.push("-plugin".to_string());
        command_parts.push(instrumentation.plugin_arg(trace_log.to_string_lossy().as_ref()));
    }
    let command = command_parts
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");
    format!("#!/bin/sh\nexec {command}\n")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn reset_directory(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&src_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &dst_path)?;
            #[cfg(not(unix))]
            fs::copy(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn mark_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn build_ext2_rootfs_image(
    guest_root: &Path,
    rootfs_image: &Path,
    probe: &impl CommandProbe,
) -> Result<(), String> {
    // On macOS, mke2fs -d doesn't preserve symlinks or Unix permissions. A
    // prebuilt, digest-pinned builder may be configured explicitly. It must
    // already contain e2fsprogs; this path never installs packages at runtime.
    if cfg!(target_os = "macos") {
        if let (Some(docker), Some(builder_image)) = (
            probe.command_path("docker"),
            ext2_builder_image_from_env().transpose()?,
        ) {
            return build_ext2_via_docker(&docker, guest_root, rootfs_image, &builder_image);
        }
    }

    // On Linux or if Docker is unavailable, use native mke2fs + debugfs permission fix
    let mke2fs = probe
        .command_path("mke2fs")
        .ok_or("missing mke2fs on PATH")?;
    let output = Command::new(&mke2fs)
        .arg("-d")
        .arg(guest_root)
        .arg("-t")
        .arg("ext2")
        .arg("-F")
        .arg(rootfs_image)
        .arg(NATIVE_SYSTEM_ROOTFS_BLOCKS)
        .output()
        .map_err(|err| format!("failed to execute mke2fs: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "mke2fs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    fix_ext2_permissions(rootfs_image, guest_root, probe)
}

fn build_ext2_via_docker(
    docker: &Path,
    guest_root: &Path,
    rootfs_image: &Path,
    builder_image: &str,
) -> Result<(), String> {
    let output_dir = rootfs_image
        .parent()
        .ok_or("rootfs image has no parent directory")?;
    let image_name = rootfs_image
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rootfs.ext2");

    let script = format!(
        r#"set -e
# Copy without preserving permissions, then set them explicitly
mkdir -p /build
cp -r --no-preserve=mode,ownership /source/. /build/ 2>/dev/null || cp -rL /source/. /build/ || cp -r /source/. /build/
# Set all regular files to 0644, all directories to 0755
find /build -type f -exec chmod 0644 {{}} \;
find /build -type d -exec chmod 0755 {{}} \;
# Mark executables
find /build/bin /build/sbin -type f -exec chmod 0755 {{}} \; 2>/dev/null || true
find /build/usr/bin /build/usr/sbin -type f -exec chmod 0755 {{}} \; 2>/dev/null || true
find /build/lib -type f \( -name '*.so*' -o -name 'ld-*' \) -exec chmod 0755 {{}} \; 2>/dev/null || true
find /build -name '*.sh' -exec chmod 0755 {{}} \; 2>/dev/null || true
find /build \( -name 'rcS' -o -name 'rc.local' -o -name 'preinit*' \) -exec chmod 0755 {{}} \; 2>/dev/null || true
# Build ext2
mke2fs -d /build -t ext2 -F /output/{image_name} {NATIVE_SYSTEM_ROOTFS_BLOCKS} >/dev/null 2>&1
"#,
    );

    let args = docker_ext2_args(guest_root, output_dir, builder_image, &script)?;
    let output = Command::new(docker)
        .args(args)
        .output()
        .map_err(|err| format!("failed to run Docker ext2 builder: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "Docker ext2 builder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    if !rootfs_image.is_file() {
        return Err("Docker ext2 builder did not produce rootfs image".to_string());
    }

    Ok(())
}

fn ext2_builder_image_from_env() -> Option<Result<String, String>> {
    std::env::var(EXT2_BUILDER_IMAGE_ENV)
        .ok()
        .map(|image| validate_ext2_builder_image(&image).map(|_| image))
}

fn validate_ext2_builder_image(image: &str) -> Result<(), String> {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return Err(format!(
            "{EXT2_BUILDER_IMAGE_ENV} must reference a prebuilt image pinned by @sha256:<64 hex>"
        ));
    };
    if name.trim().is_empty()
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "{EXT2_BUILDER_IMAGE_ENV} must reference a prebuilt image pinned by @sha256:<64 hex>"
        ));
    }
    Ok(())
}

fn docker_ext2_args(
    guest_root: &Path,
    output_dir: &Path,
    builder_image: &str,
    script: &str,
) -> Result<Vec<String>, String> {
    validate_ext2_builder_image(builder_image)?;
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--pull".to_string(),
        "never".to_string(),
        "--cap-drop".to_string(),
        "ALL".to_string(),
    ];
    for capability in ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"] {
        args.push("--cap-add".to_string());
        args.push(capability.to_string());
    }
    args.extend([
        "--security-opt".to_string(),
        "no-new-privileges:true".to_string(),
        "--mount".to_string(),
        format!(
            "type=bind,src={},dst=/source,readonly",
            guest_root.display()
        ),
        "--mount".to_string(),
        format!("type=bind,src={},dst=/output", output_dir.display()),
        "--network".to_string(),
        "none".to_string(),
        builder_image.to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        script.to_string(),
    ]);
    Ok(args)
}

fn fix_ext2_permissions(
    image_path: &Path,
    guest_root: &Path,
    probe: &impl CommandProbe,
) -> Result<(), String> {
    let Some(debugfs) = probe.command_path("debugfs") else {
        // Try common Homebrew e2fsprogs path
        let homebrew_debugfs = PathBuf::from("/opt/homebrew/Cellar/e2fsprogs")
            .read_dir()
            .ok()
            .and_then(|mut entries| entries.next())
            .and_then(|entry| entry.ok())
            .map(|entry| entry.path().join("sbin").join("debugfs"));
        let debugfs_path = homebrew_debugfs
            .filter(|path| path.is_file())
            .ok_or("debugfs not found on PATH or in Homebrew e2fsprogs")?;
        return fix_ext2_permissions_with_debugfs(&debugfs_path, image_path, guest_root);
    };
    fix_ext2_permissions_with_debugfs(&debugfs, image_path, guest_root)
}

fn fix_ext2_permissions_with_debugfs(
    debugfs: &Path,
    image_path: &Path,
    guest_root: &Path,
) -> Result<(), String> {
    let exec_dirs = ["bin", "sbin", "usr/bin", "usr/sbin"];
    let lib_dirs = ["lib"];
    let mut commands = Vec::new();

    // Fix executables in standard directories
    for dir in &exec_dirs {
        let host_dir = guest_root.join(dir);
        if !host_dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&host_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    let name = entry.file_name();
                    commands.push(format!(
                        "set_inode_field /{}/{} mode 0100755",
                        dir,
                        name.to_string_lossy()
                    ));
                }
            }
        }
    }

    // Fix shared libraries
    for dir in &lib_dirs {
        let host_dir = guest_root.join(dir);
        if !host_dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&host_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false)
                    && (name_str.contains(".so") || name_str.starts_with("ld-"))
                {
                    commands.push(format!("set_inode_field /{dir}/{name_str} mode 0100755"));
                }
            }
        }
    }

    // Fix shell scripts and init files
    for pattern_dir in ["etc", "etc_ro", "fat", "sbin"] {
        let host_dir = guest_root.join(pattern_dir);
        if !host_dir.is_dir() {
            continue;
        }
        fix_scripts_recursive(&host_dir, pattern_dir, &mut commands);
    }

    if commands.is_empty() {
        return Ok(());
    }

    let input = commands.join("\n") + "\n";
    let output = Command::new(debugfs)
        .arg("-w")
        .arg(image_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|err| format!("failed to run debugfs: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("error") {
            return Err(format!("debugfs reported errors: {stderr}"));
        }
    }

    Ok(())
}

fn fix_scripts_recursive(dir: &Path, relative: &str, commands: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let child_relative = format!("{relative}/{name_str}");
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            fix_scripts_recursive(&entry.path(), &child_relative, commands);
        } else if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            let is_script = name_str.ends_with(".sh")
                || name_str == "rcS"
                || name_str == "rc.local"
                || name_str == "preinit.sh";
            if is_script {
                commands.push(format!("set_inode_field /{child_relative} mode 0100755"));
            }
        }
    }
}

fn classify_native_system_launch_failure(diagnostic: DiagnosticRecord) -> DiagnosticRecord {
    let summary = diagnostic.summary.as_str();
    let (class, phase) = if summary.contains("failed to prepare stdout capture file")
        || summary.contains("failed to prepare stderr capture file")
        || summary.contains("did not expose stdout")
        || summary.contains("did not expose stderr")
        || summary.contains("failed while capturing launch output")
        || summary.contains("failed while joining capture thread")
        || summary.contains("failed while probing native-host system launch state")
    {
        (
            DiagnosticClass::PreparationFailed,
            DiagnosticPhase::Preparation,
        )
    } else if summary.contains("failed to spawn native-host system launch")
        || summary.contains("no such file or directory")
        || summary.contains("permission denied")
    {
        (
            DiagnosticClass::SubstrateUnavailable,
            DiagnosticPhase::Launch,
        )
    } else {
        (diagnostic.class, diagnostic.phase)
    };

    DiagnosticRecord::new(
        diagnostic.run_id.clone(),
        phase,
        diagnostic.owner,
        class,
        diagnostic.subclass.clone(),
        diagnostic.severity,
        diagnostic.confidence,
        diagnostic.actionability,
        diagnostic.summary.clone(),
        diagnostic.evidence_artifact_ids.clone(),
        diagnostic.contradicted_artifact_ids.clone(),
        diagnostic.suggested_next_actions.clone(),
    )
}

fn launch_qemu_direct_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    family_id: &str,
    target_signals: &[String],
    docker_binary: PathBuf,
    _mapped_ports: Vec<u16>,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
    probe: &impl CommandProbe,
) -> DynResult<()> {
    let readiness_goals = plan.readiness_goals.clone();
    let Some(qemu_binary) = find_first_command(probe, qemu_candidates_for_family(family_id)) else {
        let run_id = plan.run.record.run_id.clone();
        return persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            missing_qemu_runtime_diagnostic(&run_id, family_id),
        );
    };

    let substrate = match plan.strategy.selected.substrate {
        fat_core::runs::SubstrateKind::NativeHost => BackendSubstrateKind::NativeHost,
        fat_core::runs::SubstrateKind::DockerEngine => BackendSubstrateKind::DockerEngine,
        fat_core::runs::SubstrateKind::ManagedLinuxVm => unreachable!("qemu-direct substrate"),
    };
    let target_id = derive_target_id(&project_record.name, &project_record.firmware_name);
    let driver = QemuDirectDriver::new();
    let request = QemuDirectRequest::new(
        project_record.name.clone(),
        target_id,
        family_id.to_string(),
        "emulate firmware",
        architecture_for_signals(target_signals),
        qemu_binary,
        docker_binary,
        project_dir.join("work").join("runtime"),
    )
    .with_preferred_substrate(substrate);

    let prepared = match driver.prepare(request) {
        Ok(prepared) => prepared,
        Err(diagnostic) => {
            return persist_failed_launch(project_dir, store, &recipe, plan.launch(), diagnostic);
        }
    };
    let launch_result = match driver.launch(&prepared, substrate) {
        Ok(result) => result,
        Err(diagnostic) => {
            return persist_failed_launch(project_dir, store, &recipe, plan.launch(), diagnostic);
        }
    };

    let mut active = plan
        .launch()
        .into_active_run()
        .preparing_at(current_timestamp_string())
        .launching_at(current_timestamp_string())
        .running_at(current_timestamp_string())
        .with_supervision(
            fat_core::runs::SupervisionMode::ProbeOnStatus,
            fat_core::runs::HealthState::Unknown,
            None,
        );
    for endpoint in launch_result.endpoints {
        active = active.reattach_endpoint(endpoint);
    }

    store.write_recipe(active.session().session_id(), &recipe)?;
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    store.write_readiness_report(&build_readiness_report(
        project_record,
        &derive_target_id(&project_record.name, &project_record.firmware_name),
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &readiness_goals,
        active.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Ready,
        "launch completed with ready surfaces",
    ))?;

    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "launch-stdout",
        "launch stdout",
        &launch_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "launch-stderr",
        "launch stderr",
        &launch_result.stderr,
    )?;
    promote_runtime_validation_state(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
    )?;
    let view = load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
        .expect("runtime view");
    print!(
        "{}",
        render_launch_output(
            store,
            &recipe.recipe_id,
            &active.session().mapped_ports(),
            &view,
        )?
    );
    Ok(())
}

fn prepare_managed_linux_vm_session(
    project_dir: &Path,
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    recipe: fat_core::recipes::RecipeRecord,
    plan: fat_emulate::EmulationPlan,
) -> DynResult<()> {
    let run_id = plan.run.record.run_id.clone();
    let backend_id = plan.strategy.selected.backend_id.clone();
    let substrate = plan.strategy.selected.substrate;
    let readiness_goals = plan.readiness_goals.clone();
    let Some(bundle_dir) = managed_linux_vm_bundle_dir_from_env() else {
        return persist_failed_launch(
            project_dir,
            store,
            &recipe,
            plan.launch(),
            unsupported_runtime_diagnostic(&run_id, &backend_id, substrate),
        );
    };
    let manager = ManagedLinuxVmManager::new();
    let prepared = match manager.prepare(
        ManagedLinuxVmRequest::new(
            backend_id.clone(),
            managed_linux_vm_bundle_version_from_env(),
            bundle_dir,
            managed_linux_vm_workspace_root(project_dir, plan.session.session_id.as_str()),
        )
        .with_run_id(run_id.clone())
        .with_mapped_ports(plan.clone().launch().mapped_ports()),
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                DiagnosticRecord::new(
                    run_id,
                    DiagnosticPhase::SubstrateProvisioning,
                    DiagnosticOwner::Substrate,
                    DiagnosticClass::SubstrateUnavailable,
                    Some("managed-linux-vm".to_string()),
                    DiagnosticSeverity::High,
                    DiagnosticConfidence::High,
                    DiagnosticActionability::RequiresSubstrateFix,
                    err.contract.health.detail,
                    Vec::new(),
                    Vec::new(),
                    vec!["repair the managed-linux-vm bundle inputs".to_string()],
                ),
            );
        }
    };

    // Held for the launch artifact, which must record the brand actually used
    // and its source rather than a FAT-invented default.
    let mut upstream_brand: Option<String> = None;
    let upstream_launch_result = if backend_id == "firmae" {
        let Some(upstream_dir) = firmae_upstream_dir_from_env() else {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                firmae_upstream_recipe_unavailable_diagnostic(
                    &run_id,
                    format!(
                        "missing {}",
                        fat_backend::managed_linux_vm::FIRMAE_UPSTREAM_DIR_ENV
                    ),
                ),
            );
        };
        let Some(host_python) = firmae_host_python_from_env() else {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                firmae_upstream_recipe_unavailable_diagnostic(
                    &run_id,
                    format!(
                        "missing {}",
                        fat_backend::managed_linux_vm::FIRMAE_HOST_PYTHON_ENV
                    ),
                ),
            );
        };
        let brand = match fat_backend::managed_linux_vm::firmae_upstream_brand_from_env() {
            Some(Ok(brand)) => brand,
            Some(Err(detail)) => {
                return persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    plan.launch(),
                    firmae_upstream_recipe_unavailable_diagnostic(&run_id, detail),
                );
            }
            None => {
                return persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    plan.launch(),
                    firmae_upstream_recipe_unavailable_diagnostic(
                        &run_id,
                        format!(
                            "missing {}",
                            fat_backend::managed_linux_vm::FIRMAE_UPSTREAM_BRAND_ENV
                        ),
                    ),
                );
            }
        };
        upstream_brand = Some(brand.clone());
        Some(
            manager.launch_firmae_upstream(
                &prepared,
                &ManagedLinuxVmUpstreamLaunchRequest::new(
                    upstream_dir,
                    host_python,
                    project_dir
                        .join("input")
                        .join(&project_record.firmware_name),
                    brand,
                ),
            ),
        )
    } else {
        None
    };

    let upstream_launch_result = match upstream_launch_result {
        Some(Ok(upstream_launch_result)) => Some(upstream_launch_result),
        Some(Err(err)) => {
            return persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.launch(),
                err.diagnostic,
            );
        }
        None => None,
    };

    let launch_result = if let Some(upstream_launch_result) = upstream_launch_result.as_ref() {
        ManagedLinuxVmLaunchResult {
            substrate: fat_backend::BackendSubstrateKind::ManagedLinuxVm,
            exit_code: upstream_launch_result.exit_code,
            stdout: upstream_launch_result.stdout.clone(),
            stderr: upstream_launch_result.stderr.clone(),
            endpoints: Vec::new(),
            launch_manifest: None,
        }
    } else {
        match manager.launch(&prepared) {
            Ok(launch_result) => launch_result,
            Err(diagnostic) => {
                return persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    plan.launch(),
                    diagnostic,
                );
            }
        }
    };

    let launched_at = current_timestamp_string();
    let launch_state = prepared.launch_state(&launch_result);
    let launch_state_json = serde_json::to_string_pretty(&launch_state)?;
    let mut runtime_status = prepared.runtime_status_from_launch_state(&launch_state);
    let probe = PathCommandProbe;
    let initial_probe = if upstream_launch_result.is_none() {
        match manager.probe(&prepared) {
            Ok(result) => Some(result),
            Err(error) => {
                let cleanup_error = manager.stop(&prepared).err();
                persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    plan.clone().launch(),
                    error.diagnostic,
                )?;
                if let Some(cleanup_error) = cleanup_error {
                    persist_managed_spawn_cleanup_failure(
                        store,
                        plan.session.session_id.as_str(),
                        &cleanup_error.diagnostic,
                    )?;
                    return Err(format!(
                        "managed runtime launcher returned success but the initial runtime probe failed; cleanup also failed: {}",
                        cleanup_error.diagnostic.summary
                    )
                    .into());
                }
                return Err(
                    "managed runtime launcher returned success but the initial runtime probe failed"
                        .into(),
                );
            }
        }
    } else {
        None
    };
    if backend_id == "firmae"
        && launch_result
            .endpoints
            .iter()
            .all(|endpoint| endpoint.kind != fat_core::runs::RuntimeEndpointKind::Service)
    {
        runtime_status.runtime_outcome =
            Some(ManagedLinuxVmRuntimeOutcome::BootedServicesUnreachable);
    }
    let mut active = plan
        .clone()
        .launch()
        .into_active_run()
        .preparing_at(launched_at.clone())
        .launching_at(launched_at.clone())
        .with_supervision(
            if upstream_launch_result.is_some() {
                fat_core::runs::SupervisionMode::None
            } else {
                fat_core::runs::SupervisionMode::BackgroundSupervisor
            },
            if initial_probe.is_some() {
                fat_core::runs::HealthState::Healthy
            } else {
                fat_core::runs::HealthState::Unknown
            },
            None,
        );
    for endpoint in &launch_result.endpoints {
        active = active.reattach_endpoint(endpoint.clone());
    }
    if let Some(upstream_launch_result) = upstream_launch_result.as_ref() {
        persist_firmae_upstream_launch_artifacts(
            store,
            project_record,
            active.session_record().session_id.as_str(),
            active.run_record().run_id.as_str(),
            &active.run_record().backend_driver,
            active.run_record().substrate_kind,
            &project_dir
                .join("input")
                .join(&project_record.firmware_name),
            upstream_brand.as_deref().unwrap_or_default(),
            upstream_launch_result,
        )?;
        let upstream_dir = firmae_upstream_dir_from_env()
            .ok_or("managed upstream observation requires FAT_FIRMAE_UPSTREAM_DIR")?;
        let observation_result = match ManagedLinuxVmManager::new().observe_firmae_upstream(
            &prepared,
            upstream_launch_result,
            &ManagedLinuxVmUpstreamObservationRequest::new(upstream_dir, None),
            &probe,
        ) {
            Ok(observation_result) => observation_result,
            Err(diagnostic) => {
                return persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    plan.clone().launch(),
                    diagnostic,
                );
            }
        };
        let upstream_endpoints = observation_result.runtime_status.endpoints.clone();
        for endpoint in &upstream_endpoints {
            active = active.reattach_endpoint(endpoint.clone());
        }
        active = active.with_supervision(
            fat_core::runs::SupervisionMode::None,
            managed_runtime_health_state(&observation_result.runtime_status),
            None,
        );
        persist_firmae_upstream_observation_artifact(
            store,
            project_record,
            active.session_record().session_id.as_str(),
            active.run_record().run_id.as_str(),
            &active.run_record().backend_driver,
            active.run_record().substrate_kind,
            &observation_result,
        )?;
        runtime_status = observation_result.runtime_status.clone();
        if observation_result.container_name.is_none() || !observation_result.container_running {
            let diagnostic = firmae_upstream_runtime_missing_diagnostic(
                active.run_record().run_id.as_str(),
                observation_result.container_name.as_deref(),
                observation_result.container_running,
            );
            persist_failed_launch(
                project_dir,
                store,
                &recipe,
                plan.clone().launch(),
                diagnostic,
            )?;
            return Err(
                "FirmAE launch helper returned success but no running container was observed"
                    .into(),
            );
        }
    } else if let Some(probe_result) = initial_probe.as_ref() {
        let probe_state = prepared.probe_state(
            ManagedLinuxVmProbeSource::ProbeOnStatus,
            ManagedLinuxVmProbeOutcome::Healthy,
            true,
            &probe_result.stdout,
            &probe_result.stderr,
        );
        runtime_status =
            runtime_status.with_probe_state(&probe_state, ManagedLinuxVmRuntimePhase::ProbeHealthy);
        write_runtime_state_artifact(
            store,
            project_record,
            active.session_record().session_id.as_str(),
            active.run_record().run_id.as_str(),
            &active.run_record().backend_driver,
            active.run_record().substrate_kind,
            "managed-linux-vm-probe-state",
            "managed linux vm initial probe state",
            &serde_json::to_string_pretty(&probe_state)?,
        )?;
    }
    if upstream_launch_result.is_none() {
        persist_managed_pre_supervisor_state(store, &recipe, &active)?;
    } else {
        active = active.running_at(launched_at.clone());
        store.write_recipe(active.session().session_id(), &recipe)?;
        store.write_session(active.session_record())?;
        store.write_run(active.run_record())?;
    }
    let preparation_log = format!(
        "managed-linux-vm prepared for backend {}\nbundle version: {}\nworkspace: {}\nbase image: {}\nguest agent: {}\n",
        prepared.request.backend_id,
        prepared.bundle.bundle_version,
        prepared.workspace_dir.display(),
        prepared.bundle.base_image.display(),
        prepared.bundle.guest_agent.display(),
    );
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "managed-linux-vm-preparation",
        "managed linux vm preparation",
        &preparation_log,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "managed-linux-vm-launch-stdout",
        "managed linux vm launch stdout",
        &launch_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "managed-linux-vm-launch-stderr",
        "managed linux vm launch stderr",
        &launch_result.stderr,
    )?;
    if let Some(launch_manifest) = &launch_result.launch_manifest {
        write_runtime_state_artifact(
            store,
            project_record,
            active.session_record().session_id.as_str(),
            active.run_record().run_id.as_str(),
            &active.run_record().backend_driver,
            active.run_record().substrate_kind,
            "managed-linux-vm-launch-manifest",
            "managed linux vm launch manifest",
            &serde_json::to_string_pretty(launch_manifest)?,
        )?;
    }
    write_runtime_state_artifact(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "managed-linux-vm-launch-state",
        "managed linux vm launch state",
        &launch_state_json,
    )?;
    write_managed_runtime_status_artifacts(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        &runtime_status,
    )?;
    if upstream_launch_result.is_none() {
        let supervisor = match spawn_managed_linux_vm_supervisor(
            project_dir,
            active.session_record().session_id.as_str(),
        ) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                let cleanup_error = manager.stop(&prepared).err();
                let diagnostic = managed_supervisor_spawn_diagnostic(
                    active.run_record().run_id.as_str(),
                    error.to_string(),
                );
                persist_failed_launch(
                    project_dir,
                    store,
                    &recipe,
                    active.session().clone(),
                    diagnostic,
                )?;
                if let Some(cleanup_error) = cleanup_error {
                    persist_managed_spawn_cleanup_failure(
                        store,
                        active.session_record().session_id.as_str(),
                        &cleanup_error.diagnostic,
                    )?;
                    return Err(format!(
                        "failed to start managed runtime supervisor: {error}; cleanup also failed: {}",
                        cleanup_error.diagnostic.summary
                    )
                    .into());
                }
                return Err(format!("failed to start managed runtime supervisor: {error}").into());
            }
        };
        // The supervisor shares this process's group, so only its own pid is
        // guarded: signalling the group would reach the CLI itself.
        crate::launch_guard::arm_process(supervisor);
        active = active.with_supervisor_runtime(Some(supervisor), None, None);
        if let Err(error) = store.write_run(active.run_record()) {
            crate::launch_guard::terminate_and_disarm();
            return Err(error.into());
        }
        crate::launch_guard::disarm();
        active = active.running_at(launched_at);
        persist_managed_supervised_running_state(store, &active)?;
    }
    store.write_readiness_report(&build_readiness_report(
        project_record,
        &derive_target_id(&project_record.name, &project_record.firmware_name),
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &readiness_goals,
        active.run_record().active_endpoints.as_slice(),
        SurfaceReadiness::Ready,
        "launch completed with ready surfaces",
    ))?;
    promote_runtime_validation_state(
        store,
        project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
    )?;
    let view = load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
        .expect("runtime view");
    print!(
        "{}",
        render_launch_output(
            store,
            &recipe.recipe_id,
            &active.session().mapped_ports(),
            &view,
        )?
    );
    Ok(())
}

/// Write the records that make a native launch's supervisor pid durable.
fn persist_native_launch_records(
    store: &RuntimeStore,
    recipe: &fat_core::recipes::RecipeRecord,
    active: &fat_emulate::ActiveRun,
) -> DynResult<()> {
    store.write_recipe(active.session().session_id(), recipe)?;
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    Ok(())
}

fn persist_managed_pre_supervisor_state(
    store: &RuntimeStore,
    recipe: &fat_core::recipes::RecipeRecord,
    launching: &fat_emulate::ActiveRun,
) -> DynResult<()> {
    if launching.run_record().status != fat_core::runs::RunStatus::Launching
        || launching.run_record().supervisor_pid.is_some()
    {
        return Err(
            "managed pre-supervisor state must be Launching without a supervisor PID".into(),
        );
    }
    store.write_recipe(launching.session().session_id(), recipe)?;
    store.write_session(launching.session_record())?;
    store.write_run(launching.run_record())?;
    Ok(())
}

fn persist_managed_supervised_running_state(
    store: &RuntimeStore,
    running: &fat_emulate::ActiveRun,
) -> DynResult<()> {
    if running.run_record().status != fat_core::runs::RunStatus::Running
        || running.run_record().supervisor_pid.is_none()
    {
        return Err("managed Running state requires a durable supervisor PID".into());
    }
    store.write_session(running.session_record())?;
    store.write_run(running.run_record())?;
    Ok(())
}

fn persist_managed_spawn_cleanup_failure(
    store: &RuntimeStore,
    session_id: &str,
    diagnostic: &DiagnosticRecord,
) -> DynResult<()> {
    store.write_diagnostic(session_id, diagnostic)?;
    store.append_diagnostic_index(diagnostic)?;
    Ok(())
}

fn stop_managed_linux_vm_session(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<()> {
    let Some(bundle_dir) = managed_linux_vm_bundle_dir_from_env() else {
        return Err("managed-linux-vm bundle dir is not configured".into());
    };
    terminate_managed_supervisor(view.run.supervisor_pid);
    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .resume(
            ManagedLinuxVmRequest::new(
                view.run.backend_driver.clone(),
                managed_linux_vm_bundle_version_from_env(),
                bundle_dir,
                managed_linux_vm_workspace_root(project_dir, &view.session.session_id),
            )
            .with_run_id(view.run.run_id.clone())
            .with_mapped_ports(
                view.run
                    .active_endpoints
                    .iter()
                    .filter_map(|endpoint| endpoint.target_port)
                    .collect(),
            ),
        )
        .map_err(|err| err.contract.health.detail)?;
    let upstream_stop = view.run.backend_driver == "firmae";
    let stop_result = match if upstream_stop {
        let observation = current_firmae_upstream_observation(
            store,
            view.session.session_id.as_str(),
            view.run.run_id.as_str(),
        )?
        .ok_or("missing firmae-upstream-observation runtime state for upstream stop")?;
        let container_name = observation
            .container_name
            .ok_or("missing firmae-upstream-observation container_name for upstream stop")?;
        manager
            .stop_firmae_upstream(
                &prepared,
                &ManagedLinuxVmUpstreamStopRequest::new(container_name),
                &PathCommandProbe,
            )
            .map(|result| (result.exit_code, result.stdout, result.stderr))
    } else {
        manager
            .stop(&prepared)
            .map(|result| (result.exit_code, result.stdout, result.stderr))
    } {
        Ok(stop_result) => stop_result,
        Err(stop_error) => {
            let updated_at = current_timestamp_string();
            let session = fat_emulate::EmulationSession::new(
                view.session.session_id.clone(),
                view.session,
                fat_emulate::EmulationRun::new(view.run),
            );
            let degraded = session
                .into_active_run()
                .degraded_running_at(updated_at, stop_error.diagnostic.clone())
                .with_supervisor_runtime(None, None, None);
            let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
            write_stop_artifacts(
                store,
                &project_record,
                degraded.session_record().session_id.as_str(),
                degraded.run_record().run_id.as_str(),
                &degraded.run_record().backend_driver,
                degraded.run_record().substrate_kind,
                upstream_stop,
                &stop_error.stdout,
                &stop_error.stderr,
            )?;
            let stop_state = if upstream_stop {
                prepared.upstream_stop_state(
                    stop_error.exit_code,
                    false,
                    false,
                    &stop_error.stdout,
                    &stop_error.stderr,
                )
            } else {
                prepared.stop_state(
                    stop_error.exit_code,
                    false,
                    false,
                    &stop_error.stdout,
                    &stop_error.stderr,
                )
            };
            write_runtime_state_artifact(
                store,
                &project_record,
                degraded.session_record().session_id.as_str(),
                degraded.run_record().run_id.as_str(),
                &degraded.run_record().backend_driver,
                degraded.run_record().substrate_kind,
                "managed-linux-vm-stop-state",
                "managed linux vm stop state",
                &serde_json::to_string_pretty(&stop_state)?,
            )?;
            let runtime_status = current_managed_runtime_status(
                store,
                degraded.session_record().session_id.as_str(),
                degraded.run_record().run_id.as_str(),
            )?
            .unwrap_or_else(|| {
                prepared.runtime_status(degraded.run_record().active_endpoints.clone(), false)
            })
            .with_stop_state(&stop_state, ManagedLinuxVmRuntimePhase::StopFailed);
            write_managed_runtime_status_artifacts(
                store,
                &project_record,
                degraded.session_record().session_id.as_str(),
                degraded.run_record().run_id.as_str(),
                &degraded.run_record().backend_driver,
                degraded.run_record().substrate_kind,
                &runtime_status,
            )?;
            store.write_diagnostic(
                degraded.session_record().session_id.as_str(),
                &stop_error.diagnostic,
            )?;
            store.append_diagnostic_index(&stop_error.diagnostic)?;
            store.write_session(degraded.session_record())?;
            store.write_run(degraded.run_record())?;
            print!(
                "{}",
                render_runtime_view(
                    "",
                    &load_runtime_view(store, Some(degraded.session_record().session_id.as_str()))?
                        .expect("runtime view"),
                )
            );
            return Err(stop_error.diagnostic.summary.into());
        }
    };

    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let active = session
        .into_active_run()
        .completed_at(current_timestamp_string())
        .with_supervisor_runtime(None, None, None);
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
    write_stop_artifacts(
        store,
        &project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        upstream_stop,
        &stop_result.1,
        &stop_result.2,
    )?;
    let stop_state = if upstream_stop {
        prepared.upstream_stop_state(
            stop_result.0,
            !prepared.workspace_dir.exists(),
            true,
            &stop_result.1,
            &stop_result.2,
        )
    } else {
        prepared.stop_state(
            stop_result.0,
            !prepared.workspace_dir.exists(),
            true,
            &stop_result.1,
            &stop_result.2,
        )
    };
    write_runtime_state_artifact(
        store,
        &project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        "managed-linux-vm-stop-state",
        "managed linux vm stop state",
        &serde_json::to_string_pretty(&stop_state)?,
    )?;
    let runtime_status = current_managed_runtime_status(
        store,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
    )?
    .unwrap_or_else(|| prepared.runtime_status(active.run_record().active_endpoints.clone(), false))
    .with_stop_state(&stop_state, ManagedLinuxVmRuntimePhase::StopComplete);
    write_managed_runtime_status_artifacts(
        store,
        &project_record,
        active.session_record().session_id.as_str(),
        active.run_record().run_id.as_str(),
        &active.run_record().backend_driver,
        active.run_record().substrate_kind,
        &runtime_status,
    )?;
    fat_plugin_host::dispatch_run_analysis(
        project_dir,
        AnalysisTrigger::RunCompleted,
        &active.session_record().session_id,
        &active.run_record().run_id,
    )?;
    print!(
        "{}",
        render_runtime_view(
            "",
            &load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
                .expect("runtime view"),
        )
    );
    Ok(())
}

fn stop_native_system_session(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<()> {
    let was_running = view.run.status == fat_core::runs::RunStatus::Running;
    let supervisor_pid = view.run.supervisor_pid;
    terminate_native_system_supervisor(supervisor_pid)?;
    let process_running = supervisor_pid.is_some_and(process_is_running);
    if process_running {
        return Err(format!(
            "native-host system process {} is still running after stop",
            supervisor_pid.unwrap_or_default()
        )
        .into());
    }
    let removed_sockets = cleanup_native_system_sockets(&view)?;
    let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
    write_runtime_state_artifact(
        store,
        &project_record,
        view.session.session_id.as_str(),
        view.run.run_id.as_str(),
        view.run.backend_driver.as_str(),
        view.run.substrate_kind,
        "native-system-stop-state",
        "native-host system stop verification",
        &serde_json::to_string_pretty(&serde_json::json!({
            "supervisor_pid": supervisor_pid,
            "termination_requested": supervisor_pid.is_some(),
            "process_running": process_running,
            "removed_sockets": removed_sockets,
            "verified_at": current_timestamp_string(),
        }))?,
    )?;
    if was_running {
        complete_supervised_session_stop(project_dir, store, view)
    } else {
        print!("{}", render_runtime_view("", &view));
        Ok(())
    }
}

fn cleanup_native_system_sockets(view: &crate::run_cmd::RuntimeView) -> DynResult<Vec<String>> {
    let mut removed = Vec::new();
    for endpoint in &view.run.active_endpoints {
        let Some(uri) = endpoint.uri.as_deref() else {
            continue;
        };
        let Some(raw_path) = uri.strip_prefix("unix://") else {
            continue;
        };
        let path = Path::new(raw_path);
        let safe_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("fat-") && name.ends_with(".sock"));
        if path.parent() != Some(Path::new("/tmp")) || !safe_name {
            return Err(format!(
                "refusing to remove unowned native-system socket path: {}",
                path.display()
            )
            .into());
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(
                    format!("inspect native-system socket {}: {error}", path.display()).into(),
                )
            }
        };
        #[cfg(unix)]
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "refusing to remove non-socket native-system path: {}",
                path.display()
            )
            .into());
        }
        #[cfg(not(unix))]
        let _ = metadata;
        fs::remove_file(path)
            .map_err(|error| format!("remove native-system socket {}: {error}", path.display()))?;
        removed.push(path.display().to_string());
    }
    Ok(removed)
}

fn stop_emux_session(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<()> {
    let supervisor_result = terminate_emux_supervisor(view.run.supervisor_pid);
    let container_result = remove_emux_container_if_present();
    match (supervisor_result, container_result) {
        (Ok(()), Ok(())) => {}
        (Err(supervisor), Ok(())) => return Err(supervisor),
        (Ok(()), Err(container)) => return Err(container.into()),
        (Err(supervisor), Err(container)) => {
            return Err(format!(
                "failed to stop EMUX supervisor: {supervisor}; additionally failed to remove EMUX container: {container}"
            )
            .into())
        }
    }
    complete_supervised_session_stop(project_dir, store, view)
}

fn complete_supervised_session_stop(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<()> {
    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let active = session
        .into_active_run()
        .completed_at(current_timestamp_string())
        .with_supervisor_runtime(None, None, None);
    store.write_session(active.session_record())?;
    store.write_run(active.run_record())?;
    fat_plugin_host::dispatch_run_analysis(
        project_dir,
        AnalysisTrigger::RunCompleted,
        &active.session_record().session_id,
        &active.run_record().run_id,
    )?;
    print!(
        "{}",
        render_runtime_view(
            "",
            &load_runtime_view(store, Some(active.session_record().session_id.as_str()))?
                .expect("runtime view"),
        )
    );
    Ok(())
}

fn emux_dir_from_env() -> Option<PathBuf> {
    std::env::var(EMUX_DIR_ENV).ok().map(PathBuf::from)
}

fn emux_reference_device_from_env() -> Option<String> {
    std::env::var(EMUX_REFERENCE_DEVICE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn unsupported_runtime_diagnostic(
    run_id: &str,
    backend_id: &str,
    substrate: fat_core::runs::SubstrateKind,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some(format!("{backend_id}-{}", substrate.as_str())),
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresBackendFix,
        format!(
            "CLI runtime path does not yet implement backend {} on substrate {}",
            backend_id,
            substrate.as_str()
        ),
        Vec::new(),
        Vec::new(),
        vec![format!(
            "add CLI/runtime-manager support for backend {} on {}",
            backend_id,
            substrate.as_str()
        )],
    )
}

fn emux_reference_recipe_unavailable_diagnostic(run_id: &str, detail: String) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::BackendProvisioning,
        DiagnosticOwner::BackendTool,
        DiagnosticClass::BackendUnavailable,
        Some("emux-reference-recipe-unavailable".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("EMUX reference recipe unavailable: {detail}"),
        Vec::new(),
        Vec::new(),
        vec![
            "configure FAT_EMUX_DIR with a valid EMUX checkout".to_string(),
            "set FAT_EMUX_REFERENCE_DEVICE to a bundled reference device".to_string(),
        ],
    )
}

fn write_runtime_log_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    subkind: &str,
    provenance: &str,
    contents: &str,
) -> DynResult<()> {
    let artifacts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&artifacts_dir)?;
    let path = artifacts_dir.join(format!("{subkind}.log"));
    fs::write(&path, contents)?;
    let artifact = ArtifactRecord::new(
        project_record.name.clone(),
        derive_target_id(&project_record.name, &project_record.firmware_name),
        session_id.to_string(),
        run_id.to_string(),
        ArtifactKind::RuntimeLog,
        subkind.to_string(),
        "fat",
        "fat emulate",
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        "text/plain",
        contents.len() as u64,
        None,
        provenance.to_string(),
        ArtifactRetentionPolicy::Session,
    )
    .with_phase("launch")
    .with_backend_driver(backend.to_string())
    .with_substrate_kind(substrate_kind)
    .with_tool_version(env!("CARGO_PKG_VERSION"));
    store.write_artifact(&artifact)?;
    store.append_artifact_index(&artifact)?;
    Ok(())
}

fn write_runtime_state_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    subkind: &str,
    provenance: &str,
    contents: &str,
) -> DynResult<()> {
    let artifacts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&artifacts_dir)?;
    let path = artifacts_dir.join(format!("{subkind}.json"));
    fs::write(&path, contents)?;
    let artifact = ArtifactRecord::new(
        project_record.name.clone(),
        derive_target_id(&project_record.name, &project_record.firmware_name),
        session_id.to_string(),
        run_id.to_string(),
        ArtifactKind::RuntimeState,
        subkind.to_string(),
        "fat",
        "fat emulate",
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        "application/json",
        contents.len() as u64,
        None,
        provenance.to_string(),
        ArtifactRetentionPolicy::Session,
    )
    .with_phase("launch")
    .with_backend_driver(backend.to_string())
    .with_substrate_kind(substrate_kind)
    .with_tool_version(env!("CARGO_PKG_VERSION"));
    store.write_artifact(&artifact)?;
    store.append_artifact_index(&artifact)?;
    Ok(())
}

fn write_runtime_capture_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    subkind: &str,
    provenance: &str,
    contents: &str,
) -> DynResult<()> {
    let artifacts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&artifacts_dir)?;
    let path = artifacts_dir.join(format!("{subkind}.json"));
    fs::write(&path, contents)?;
    let artifact = ArtifactRecord::new(
        project_record.name.clone(),
        derive_target_id(&project_record.name, &project_record.firmware_name),
        session_id.to_string(),
        run_id.to_string(),
        ArtifactKind::RuntimeCapture,
        subkind.to_string(),
        "fat",
        "fat emulate",
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        "application/json",
        contents.len() as u64,
        None,
        provenance.to_string(),
        ArtifactRetentionPolicy::Session,
    )
    .with_phase("launch")
    .with_backend_driver(backend.to_string())
    .with_substrate_kind(substrate_kind)
    .with_tool_version(env!("CARGO_PKG_VERSION"));
    store.write_artifact(&artifact)?;
    store.append_artifact_index(&artifact)?;
    Ok(())
}

fn write_managed_runtime_status_artifacts(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    runtime_status: &ManagedLinuxVmRuntimeStatus,
) -> DynResult<()> {
    let runtime_status_json = serde_json::to_string_pretty(runtime_status)?;
    write_runtime_state_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "managed-runtime-status",
        "managed runtime status",
        &runtime_status_json,
    )?;
    if let Some(summary) = managed_runtime_summary_from_runtime_status_json(&runtime_status_json) {
        write_runtime_state_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "managed-runtime-summary",
            "managed runtime summary",
            &serde_json::to_string_pretty(&summary)?,
        )?;
    }
    Ok(())
}

fn current_managed_runtime_status(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<ManagedLinuxVmRuntimeStatus>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    if let Some(status) = read_latest_typed_runtime_state_from_artifacts::<
        ManagedLinuxVmRuntimeStatus,
    >(&artifacts, "managed-runtime-status")?
    {
        return Ok(Some(status));
    }

    Ok(
        read_latest_typed_runtime_state_from_artifacts::<ManagedLinuxVmLaunchState>(
            &artifacts,
            "managed-linux-vm-launch-state",
        )?
        .map(|launch_state| ManagedLinuxVmRuntimeStatus::from_launch_state(&launch_state)),
    )
}

#[derive(Debug, Deserialize)]
struct FirmaeUpstreamObservationArtifact {
    container_name: Option<String>,
}

fn current_firmae_upstream_observation(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<FirmaeUpstreamObservationArtifact>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    read_latest_typed_runtime_state_from_artifacts::<FirmaeUpstreamObservationArtifact>(
        &artifacts,
        "firmae-upstream-observation",
    )
}

fn persist_service_user_mode_manifest(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    active: &fat_emulate::ActiveRun,
    manifest: &ServiceUserModeLaunchManifest,
) -> DynResult<()> {
    let session_id = active.session_record().session_id.as_str();
    let run_id = active.run_record().run_id.as_str();
    let backend = active.run_record().backend_driver.as_str();
    let substrate_kind = active.run_record().substrate_kind;

    write_runtime_state_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "service-launch-manifest",
        "service qemu-user launch manifest",
        &serde_json::to_string_pretty(manifest)?,
    )?;

    if !manifest.processes.is_empty() {
        let snapshot = ObservedProcessSnapshot {
            session_id: session_id.to_string(),
            run_id: run_id.to_string(),
            backend_id: backend.to_string(),
            processes: manifest.processes.clone(),
        };
        write_runtime_capture_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "process-snapshot",
            "service qemu-user observed processes",
            &serde_json::to_string_pretty(&snapshot)?,
        )?;
    }

    if !manifest.services.is_empty() {
        let snapshot = ObservedServiceSnapshot {
            session_id: session_id.to_string(),
            run_id: run_id.to_string(),
            backend_id: backend.to_string(),
            services: manifest.services.clone(),
        };
        write_runtime_capture_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "service-snapshot",
            "service qemu-user observed services",
            &serde_json::to_string_pretty(&snapshot)?,
        )?;
    }

    let network_endpoints: Vec<_> = manifest
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.kind == fat_core::runs::RuntimeEndpointKind::Service)
        .map(|endpoint| {
            let mut entry = ObservedNetworkEntry::new(
                DebugSurfaceKind::Service,
                endpoint.name.clone(),
                endpoint.host.clone(),
                endpoint.port,
            );
            if let Some(target_port) = endpoint.target_port {
                entry = entry.with_target_port(target_port);
            }
            if let Some(uri) = endpoint.uri.clone() {
                entry = entry.with_uri(uri);
            }
            entry
        })
        .collect();
    if !network_endpoints.is_empty() {
        let snapshot = ObservedNetworkSnapshot {
            session_id: session_id.to_string(),
            run_id: run_id.to_string(),
            backend_id: backend.to_string(),
            substrate_kind,
            endpoints: network_endpoints,
        };
        write_runtime_capture_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "network-snapshot",
            "service qemu-user observed network endpoints",
            &serde_json::to_string_pretty(&snapshot)?,
        )?;
    }

    Ok(())
}

fn managed_runtime_summary_for_view(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<fat_core::services::ManagedRuntimeSummary>> {
    let artifacts = store.read_run_artifacts(session_id, run_id)?;
    for artifact in artifacts.iter().rev() {
        if artifact.kind != ArtifactKind::RuntimeState {
            continue;
        }
        if artifact.subkind == "managed-runtime-summary" {
            let content = fs::read_to_string(&artifact.path)?;
            if let Some(summary) = managed_runtime_summary_from_summary_json(&content) {
                return Ok(Some(summary));
            }
        }
        if artifact.subkind == "managed-runtime-status" {
            let content = fs::read_to_string(&artifact.path)?;
            if let Some(summary) = managed_runtime_summary_from_runtime_status_json(&content) {
                return Ok(Some(summary));
            }
        }
    }
    Ok(None)
}

fn managed_runtime_health_state(
    runtime_status: &ManagedLinuxVmRuntimeStatus,
) -> fat_core::runs::HealthState {
    match runtime_status.runtime_outcome {
        Some(ManagedLinuxVmRuntimeOutcome::GuestUnreachable) => {
            fat_core::runs::HealthState::GuestUnreachable
        }
        Some(ManagedLinuxVmRuntimeOutcome::BootedServicesUnreachable) => {
            fat_core::runs::HealthState::BootedServicesUnreachable
        }
        Some(ManagedLinuxVmRuntimeOutcome::BootedServicesReachable) => {
            fat_core::runs::HealthState::BootedServicesReachable
        }
        None => fat_core::runs::HealthState::Unreachable,
    }
}

fn render_runtime_output(
    store: &RuntimeStore,
    prefix: &str,
    view: &crate::run_cmd::RuntimeView,
) -> DynResult<String> {
    let mut output = render_runtime_view(prefix, view);
    if let Some(summary) = managed_runtime_summary_for_view(
        store,
        view.session.session_id.as_str(),
        view.run.run_id.as_str(),
    )? {
        output.push_str(&format!(
            "{}: {}\n",
            prefixed_runtime_key(prefix, "managed runtime phase"),
            summary.runtime_phase
        ));
        if let Some(runtime_outcome) = summary.runtime_outcome {
            output.push_str(&format!(
                "{}: {}\n",
                prefixed_runtime_key(prefix, "managed runtime outcome"),
                runtime_outcome
            ));
        }
    }
    Ok(output)
}

fn prefixed_runtime_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}{key}")
    }
}

fn read_latest_typed_runtime_state_from_artifacts<T: DeserializeOwned>(
    artifacts: &[ArtifactRecord],
    subkind: &str,
) -> DynResult<Option<T>> {
    for artifact in artifacts.iter().rev() {
        if artifact.kind != ArtifactKind::RuntimeState || artifact.subkind != subkind {
            continue;
        }
        let content = fs::read_to_string(&artifact.path)?;
        return Ok(Some(serde_json::from_str::<T>(&content)?));
    }
    Ok(None)
}

fn read_latest_typed_runtime_capture_from_artifacts<T: DeserializeOwned>(
    artifacts: &[ArtifactRecord],
    subkind: &str,
) -> DynResult<Option<T>> {
    for artifact in artifacts.iter().rev() {
        if artifact.kind != ArtifactKind::RuntimeCapture || artifact.subkind != subkind {
            continue;
        }
        let content = fs::read_to_string(&artifact.path)?;
        return Ok(Some(serde_json::from_str::<T>(&content)?));
    }
    Ok(None)
}

fn write_stop_artifacts(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    upstream_stop: bool,
    stdout: &str,
    stderr: &str,
) -> DynResult<()> {
    let stdout_subkind = if upstream_stop {
        "firmae-upstream-stop-stdout"
    } else {
        "managed-linux-vm-stop-stdout"
    };
    let stderr_subkind = if upstream_stop {
        "firmae-upstream-stop-stderr"
    } else {
        "managed-linux-vm-stop-stderr"
    };
    let stdout_label = if upstream_stop {
        "firmae upstream stop stdout"
    } else {
        "managed linux vm stop stdout"
    };
    let stderr_label = if upstream_stop {
        "firmae upstream stop stderr"
    } else {
        "managed linux vm stop stderr"
    };
    write_runtime_log_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        stdout_subkind,
        stdout_label,
        stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        stderr_subkind,
        stderr_label,
        stderr,
    )?;
    if upstream_stop {
        let command = format!(
            "docker stop {}",
            current_firmae_upstream_observation(store, session_id, run_id)?
                .and_then(|observation| observation.container_name)
                .unwrap_or_else(|| "<missing-container-name>".to_string())
        );
        write_runtime_log_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            "firmae-upstream-stop-command",
            "firmae upstream stop command",
            &command,
        )?;
    }
    Ok(())
}

fn firmae_upstream_recipe_unavailable_diagnostic(run_id: &str, detail: String) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::BackendProvisioning,
        DiagnosticOwner::BackendTool,
        DiagnosticClass::BackendUnavailable,
        Some("firmae-upstream-recipe-unavailable".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("FirmAE upstream recipe unavailable: {detail}"),
        Vec::new(),
        Vec::new(),
        vec![
            "run fat doctor to validate the upstream FirmAE recipe".to_string(),
            "configure the upstream checkout and host helper inputs before retrying firmae"
                .to_string(),
            // The brand is an operator input like the others, and it is the
            // one most likely to be missing from a previously working setup,
            // since it was formerly defaulted. Name it explicitly: it is not
            // derivable from firmware evidence, so no amount of re-running
            // will supply it.
            format!(
                "set {} to the brand upstream FirmAE should use; FAT does not infer it from the firmware",
                fat_backend::managed_linux_vm::FIRMAE_UPSTREAM_BRAND_ENV
            ),
        ],
    )
}

fn firmae_upstream_runtime_missing_diagnostic(
    run_id: &str,
    container_name: Option<&str>,
    container_running: bool,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendTool,
        DiagnosticClass::LaunchFailed,
        Some("firmae-upstream-runtime-not-observed".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!(
            "FirmAE launch completed without an observable running container (container_name={}, container_running={container_running})",
            container_name.unwrap_or("none")
        ),
        Vec::new(),
        Vec::new(),
        vec![
            "inspect the FirmAE helper stderr and PostgreSQL/container prerequisites".to_string(),
            "retry only after `fat doctor` reports the FirmAE recipe ready".to_string(),
        ],
    )
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

fn architecture_for_signals(signals: &[String]) -> String {
    for signal in signals {
        if let Some(architecture) = signal.strip_prefix("arch:") {
            return architecture.to_string();
        }
    }
    "unknown".to_string()
}

fn qemu_candidates_for_family(family_id: &str) -> &'static [&'static str] {
    match family_id {
        "linux-router-arm" | "linux-medical-appliance-arm" => {
            &["qemu-system-arm", "qemu-system-aarch64"]
        }
        "linux-gateway-arm64" => &["qemu-system-aarch64", "qemu-system-arm"],
        "linux-router-mips" | "linux-camera-mips" => &[
            "qemu-system-mipsel",
            "qemu-system-mips",
            "qemu-system-mipseb",
        ],
        _ => &[
            "qemu-system-arm",
            "qemu-system-aarch64",
            "qemu-system-mipsel",
        ],
    }
}

fn qemu_user_candidates_for_arch(architecture: &str) -> &'static [&'static str] {
    match architecture {
        "armel" | "armhf" | "arm" => &["qemu-arm"],
        "aarch64" | "arm64" => &["qemu-aarch64", "qemu-arm"],
        "mipsel" => &["qemu-mipsel", "qemu-mips"],
        "mips" | "mipseb" => &["qemu-mips", "qemu-mipseb"],
        "x86_64" => &["qemu-x86_64"],
        _ => &["qemu-arm", "qemu-aarch64", "qemu-mipsel", "qemu-mips"],
    }
}

fn find_first_command(probe: &impl CommandProbe, commands: &[&str]) -> Option<PathBuf> {
    commands
        .iter()
        .find_map(|command| probe.command_path(command))
}

fn missing_service_candidate_diagnostic(run_id: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Preparation,
        DiagnosticOwner::RuntimeSynthesizer,
        DiagnosticClass::PreparationFailed,
        Some("service-executable-missing".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::FallbackRecommended,
        "service-runner: no executable service candidate was synthesized for the selected target",
        Vec::new(),
        Vec::new(),
        vec![
            "promote an explicit service:/absolute/path signal into the TargetModel".to_string(),
            "fallback to system-runner when only init-level evidence exists".to_string(),
        ],
    )
}

pub fn current_timestamp_string() -> String {
    let millis = current_timestamp_millis();
    format!("unix-ms:{millis}")
}

pub fn current_timestamp_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis()
}

fn short_runtime_path_key(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn timestamp_from_millis(millis: u128) -> String {
    format!("unix-ms:{millis}")
}

fn managed_linux_vm_workspace_root(project_dir: &Path, session_id: &str) -> PathBuf {
    project_dir.join("work").join("runtime").join(session_id)
}

fn managed_linux_vm_supervisor_interval_ms() -> u64 {
    std::env::var(MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1_000)
}

fn managed_linux_vm_supervisor_max_ticks() -> Option<u32> {
    std::env::var(MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
}

pub fn resolve_data_root() -> Option<std::path::PathBuf> {
    if let Ok(data) = std::env::var("FAT_DATA_DIR") {
        let path = std::path::PathBuf::from(data);
        if path.is_dir() {
            return Some(path);
        }
    }
    fat_core::data_dir::DataResolver::for_current_process(None)
        .resolve_required("profiles")
        .ok()
        .map(|resolved| resolved.root)
}

fn attempt_idle_stop(
    store: &RuntimeStore,
    project_dir: &Path,
    manager: &ManagedLinuxVmManager,
    session_id: &str,
) {
    let Ok(Some(view)) = load_runtime_view(store, Some(session_id)) else {
        return;
    };
    let backend = view.run.backend_driver.as_str();
    let Some(bundle_dir) = managed_linux_vm_bundle_dir_from_env() else {
        return;
    };
    let prepared = match manager.resume(
        ManagedLinuxVmRequest::new(
            backend.to_string(),
            managed_linux_vm_bundle_version_from_env(),
            bundle_dir,
            managed_linux_vm_workspace_root(project_dir, &view.session.session_id),
        )
        .with_run_id(view.run.run_id.clone()),
    ) {
        Ok(prepared) => prepared,
        Err(_) => return,
    };

    let stopped_at = current_timestamp_string();
    let stop_result = match backend {
        "firmae" if view.run.supervisor_pid.is_some() => {
            // The supervisor pid tracked in the run record is the firmae
            // process group. terminate_native_system_supervisor handles
            // SIGTERM + SIGKILL, and the managed-vm stop contract cleans
            // up the Docker container.
            terminate_native_system_supervisor(view.run.supervisor_pid).ok();
            Ok(())
        }
        _ => manager.stop(&prepared).map(|_| ()).map_err(|err| {
            format!(
                "failed to stop managed vm session {}: {}",
                session_id, err.diagnostic.summary
            )
        }),
    };

    let outcome = match &stop_result {
        Ok(()) => "idle-timeout-stop",
        Err(_) => "idle-timeout-stop-failed",
    };
    let run_id = view.run.run_id.clone();
    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let completed = session.into_active_run().completed_at(stopped_at.clone());
    let _ = store.write_session(completed.session_record());
    let _ = store.write_run(completed.run_record());
    let _ = store.append_diagnostic_index(&DiagnosticRecord::new(
        run_id,
        DiagnosticPhase::SteadyState,
        DiagnosticOwner::Policy,
        DiagnosticClass::SubstrateUnhealthy,
        Some("lifecycle-idle-timeout".to_string()),
        DiagnosticSeverity::Low,
        DiagnosticConfidence::High,
        DiagnosticActionability::TerminalForThisStrategy,
        format!("emulation stopped by lifecycle idle timeout; outcome: {outcome}"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
}

fn spawn_managed_linux_vm_supervisor(project_dir: &Path, session_id: &str) -> DynResult<u32> {
    let executable = match std::env::var_os(MANAGED_LINUX_VM_SUPERVISOR_EXECUTABLE_ENV) {
        Some(executable) => PathBuf::from(executable),
        None => std::env::current_exe()?,
    };
    let child = Command::new(executable)
        .arg("supervise-managed-vm")
        .arg("--project")
        .arg(project_dir)
        .arg("--session-id")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child.id())
}

/// Ask the managed supervisor to exit.
///
/// Only that pid is signalled, never its group: the managed supervisor shares
/// this process's group, so a group signal would reach the CLI itself. This
/// stays a single best-effort SIGTERM with no escalation — the supervisor owns
/// the managed runtime's own teardown, which `stop_managed_linux_vm_session`
/// drives separately.
fn terminate_managed_supervisor(supervisor_pid: Option<u32>) {
    let Some(supervisor_pid) = supervisor_pid else {
        return;
    };
    let _ = signal_process(supervisor_pid, terminate_signal());
}

pub fn terminate_native_system_supervisor(supervisor_pid: Option<u32>) -> DynResult<()> {
    let Some(supervisor_pid) = supervisor_pid else {
        return Ok(());
    };
    terminate_process_group(
        supervisor_pid,
        "native-host system",
        Duration::from_secs(5),
        Duration::from_secs(2),
    )
}

pub fn terminate_emux_supervisor(supervisor_pid: Option<u32>) -> DynResult<()> {
    let Some(supervisor_pid) = supervisor_pid else {
        return Ok(());
    };
    terminate_process_group(
        supervisor_pid,
        "EmuX",
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

/// Stop a process group by escalation: SIGTERM, wait for it to leave, then
/// SIGKILL, then wait again. `label` names the backend in error messages, and
/// the two grace periods are per-backend because how long a runtime needs to
/// shut down cleanly is a property of that runtime.
///
/// A group that is already gone is success: stopping is idempotent, and a
/// supervisor that exited on its own is the outcome the caller asked for.
fn terminate_process_group(
    process_group_id: u32,
    label: &str,
    terminate_grace: Duration,
    kill_grace: Duration,
) -> DynResult<()> {
    if let Err(err) = signal_process_group(process_group_id, terminate_signal()) {
        if !matches!(err.raw_os_error(), Some(code) if code == no_such_process_code()) {
            return Err(format!(
                "failed to send {label} termination signal to process group {process_group_id}: {err}"
            )
            .into());
        }
        return Ok(());
    }
    if wait_for_process_group_exit(process_group_id, terminate_grace) {
        return Ok(());
    }

    if let Err(err) = signal_process_group(process_group_id, kill_signal()) {
        if !matches!(err.raw_os_error(), Some(code) if code == no_such_process_code()) {
            return Err(format!(
                "failed to send {label} kill signal to process group {process_group_id}: {err}"
            )
            .into());
        }
    }
    if wait_for_process_group_exit(process_group_id, kill_grace) {
        return Ok(());
    }

    Err(format!("{label} process group {process_group_id} did not exit after termination").into())
}

/// Poll until the group is gone or `grace` elapses. Returns whether it left.
fn wait_for_process_group_exit(process_group_id: u32, grace: Duration) -> bool {
    let deadline = std::time::Instant::now() + grace;
    while std::time::Instant::now() < deadline {
        if !process_group_is_running(process_group_id) {
            return true;
        }
        sleep(Duration::from_millis(50));
    }
    !process_group_is_running(process_group_id)
}

fn process_group_is_running(process_group_id: u32) -> bool {
    match signal_process_group(process_group_id, probe_signal()) {
        Ok(()) => true,
        Err(err) if err.raw_os_error() == Some(permission_denied_code()) => true,
        Err(err) if err.raw_os_error() == Some(no_such_process_code()) => false,
        Err(_) => true,
    }
}

#[cfg(unix)]
fn signal_process_group(process_group_id: u32, signal: i32) -> io::Result<()> {
    let process_group_id = i32::try_from(process_group_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process group id overflow"))?;
    let result = unsafe { libc::kill(-process_group_id, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_process_group(process_group_id: u32, signal: i32) -> io::Result<()> {
    signal_process(process_group_id, signal)
}

pub(crate) fn process_is_running(pid: u32) -> bool {
    match signal_process(pid, probe_signal()) {
        Ok(()) => true,
        Err(err) => matches!(err.raw_os_error(), Some(code) if code == permission_denied_code()),
    }
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: i32) -> io::Result<()> {
    let result = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_process(pid: u32, signal: i32) -> io::Result<()> {
    let mut command = Command::new("/bin/kill");
    if signal != 0 {
        command.arg(format!("-{signal}"));
    } else {
        command.arg("-0");
    }
    let status = command.arg(pid.to_string()).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("kill returned status {status}"),
        ))
    }
}

#[cfg(unix)]
const fn terminate_signal() -> i32 {
    libc::SIGTERM
}

#[cfg(not(unix))]
const fn terminate_signal() -> i32 {
    15
}

#[cfg(unix)]
const fn kill_signal() -> i32 {
    libc::SIGKILL
}

#[cfg(not(unix))]
const fn kill_signal() -> i32 {
    9
}

const fn probe_signal() -> i32 {
    0
}

#[cfg(unix)]
const fn no_such_process_code() -> i32 {
    libc::ESRCH
}

#[cfg(not(unix))]
const fn no_such_process_code() -> i32 {
    3
}

#[cfg(unix)]
const fn permission_denied_code() -> i32 {
    libc::EPERM
}

#[cfg(not(unix))]
const fn permission_denied_code() -> i32 {
    1
}

pub fn run_managed_supervisor(project_dir: PathBuf, session_id: String) -> DynResult<()> {
    let store = RuntimeStore::open(&project_dir)?;
    let interval_ms = managed_linux_vm_supervisor_interval_ms();
    let max_ticks = managed_linux_vm_supervisor_max_ticks();
    let manager = ManagedLinuxVmManager::new();
    let config = crate::emulate_config::load_config(&project_dir, resolve_data_root().as_deref());
    let idle_timeout_ms = config.lifecycle.idle_timeout_secs.saturating_mul(1_000);
    let idle_tick_limit = if idle_timeout_ms > 0 {
        Some(idle_timeout_ms / interval_ms)
    } else {
        None
    };
    let mut ticks = 0u32;
    let mut last_healthy_tick: Option<u32> = None;

    loop {
        if max_ticks.map(|max| ticks >= max).unwrap_or(false) {
            return Ok(());
        }

        // Idle timeout: no healthy probe within the configured window.
        if let Some(tick_limit) = idle_tick_limit {
            if let Some(last_healthy) = last_healthy_tick {
                if ticks.saturating_sub(last_healthy) >= tick_limit as u32 {
                    attempt_idle_stop(&store, &project_dir, &manager, &session_id);
                    return Ok(());
                }
            }
        }

        let Some(view) = load_runtime_view(&store, Some(&session_id))? else {
            return Ok(());
        };
        if view.run.substrate_kind != fat_core::runs::SubstrateKind::ManagedLinuxVm
            || !matches!(view.run.backend_driver.as_str(), "firmae" | "firmadyne")
            || view.run.supervision_mode != fat_core::runs::SupervisionMode::BackgroundSupervisor
        {
            return Ok(());
        }
        if let Some(supervisor_pid) = view.run.supervisor_pid {
            if supervisor_pid != std::process::id() {
                return Ok(());
            }
        }
        if view.run.status == fat_core::runs::RunStatus::Launching {
            sleep(Duration::from_millis(interval_ms));
            continue;
        }
        if view.run.status != fat_core::runs::RunStatus::Running {
            return Ok(());
        }

        let Some(bundle_dir) = managed_linux_vm_bundle_dir_from_env() else {
            return Ok(());
        };
        let prepared = match manager.resume(
            ManagedLinuxVmRequest::new(
                view.run.backend_driver.clone(),
                managed_linux_vm_bundle_version_from_env(),
                bundle_dir,
                managed_linux_vm_workspace_root(&project_dir, &view.session.session_id),
            )
            .with_run_id(view.run.run_id.clone())
            .with_mapped_ports(
                view.run
                    .active_endpoints
                    .iter()
                    .filter_map(|endpoint| endpoint.target_port)
                    .collect(),
            ),
        ) {
            Ok(prepared) => prepared,
            Err(_) => return Ok(()),
        };

        let heartbeat_at = current_timestamp_string();
        let lease_expires_at =
            timestamp_from_millis(current_timestamp_millis() + u128::from(interval_ms) * 2);
        match manager.probe(&prepared) {
            Ok(probe_result) => {
                let session = fat_emulate::EmulationSession::new(
                    view.session.session_id.clone(),
                    view.session,
                    fat_emulate::EmulationRun::new(view.run),
                )
                .with_lifecycle(
                    fat_core::sessions::SessionStatus::Active,
                    fat_core::sessions::GoalProgress::Substantial,
                    heartbeat_at.clone(),
                );
                let active = session
                    .into_active_run()
                    .with_supervision(
                        fat_core::runs::SupervisionMode::BackgroundSupervisor,
                        fat_core::runs::HealthState::Healthy,
                        Some(heartbeat_at.clone()),
                    )
                    .with_supervisor_runtime(
                        Some(std::process::id()),
                        Some(heartbeat_at),
                        Some(lease_expires_at),
                    );
                let project_record = load_project(&ProjectDb::open(&project_dir)?, &project_dir)?;
                let probe_state = prepared.probe_state(
                    ManagedLinuxVmProbeSource::BackgroundSupervisor,
                    ManagedLinuxVmProbeOutcome::Healthy,
                    true,
                    &probe_result.stdout,
                    &probe_result.stderr,
                );
                write_runtime_state_artifact(
                    &store,
                    &project_record,
                    active.session_record().session_id.as_str(),
                    active.run_record().run_id.as_str(),
                    &active.run_record().backend_driver,
                    active.run_record().substrate_kind,
                    "managed-linux-vm-probe-state",
                    "managed linux vm probe state",
                    &serde_json::to_string_pretty(&probe_state)?,
                )?;
                let runtime_status = current_managed_runtime_status(
                    &store,
                    active.session_record().session_id.as_str(),
                    active.run_record().run_id.as_str(),
                )?
                .unwrap_or_else(|| {
                    prepared.runtime_status(active.run_record().active_endpoints.clone(), false)
                })
                .with_probe_state(&probe_state, ManagedLinuxVmRuntimePhase::ProbeHealthy);
                write_managed_runtime_status_artifacts(
                    &store,
                    &project_record,
                    active.session_record().session_id.as_str(),
                    active.run_record().run_id.as_str(),
                    &active.run_record().backend_driver,
                    active.run_record().substrate_kind,
                    &runtime_status,
                )?;
                store.write_session(active.session_record())?;
                store.write_run(active.run_record())?;
                last_healthy_tick = Some(ticks);
            }
            Err(probe_error) => {
                let session = fat_emulate::EmulationSession::new(
                    view.session.session_id.clone(),
                    view.session,
                    fat_emulate::EmulationRun::new(view.run),
                );
                let degraded_session = session
                    .into_active_run()
                    .degraded_running_at(heartbeat_at.clone(), probe_error.diagnostic.clone());
                let project_record = load_project(&ProjectDb::open(&project_dir)?, &project_dir)?;
                write_runtime_log_artifact(
                    &store,
                    &project_record,
                    degraded_session.session_record().session_id.as_str(),
                    degraded_session.run_record().run_id.as_str(),
                    &degraded_session.run_record().backend_driver,
                    degraded_session.run_record().substrate_kind,
                    "managed-linux-vm-probe-stdout",
                    "managed linux vm probe stdout",
                    &probe_error.stdout,
                )?;
                write_runtime_log_artifact(
                    &store,
                    &project_record,
                    degraded_session.session_record().session_id.as_str(),
                    degraded_session.run_record().run_id.as_str(),
                    &degraded_session.run_record().backend_driver,
                    degraded_session.run_record().substrate_kind,
                    "managed-linux-vm-probe-stderr",
                    "managed linux vm probe stderr",
                    &probe_error.stderr,
                )?;
                let probe_state = prepared.probe_state(
                    ManagedLinuxVmProbeSource::BackgroundSupervisor,
                    ManagedLinuxVmProbeOutcome::Unreachable,
                    false,
                    &probe_error.stdout,
                    &probe_error.stderr,
                );
                write_runtime_state_artifact(
                    &store,
                    &project_record,
                    degraded_session.session_record().session_id.as_str(),
                    degraded_session.run_record().run_id.as_str(),
                    &degraded_session.run_record().backend_driver,
                    degraded_session.run_record().substrate_kind,
                    "managed-linux-vm-probe-state",
                    "managed linux vm probe state",
                    &serde_json::to_string_pretty(&probe_state)?,
                )?;
                let runtime_status = current_managed_runtime_status(
                    &store,
                    degraded_session.session_record().session_id.as_str(),
                    degraded_session.run_record().run_id.as_str(),
                )?
                .unwrap_or_else(|| {
                    prepared.runtime_status(
                        degraded_session.run_record().active_endpoints.clone(),
                        false,
                    )
                })
                .with_probe_state(&probe_state, ManagedLinuxVmRuntimePhase::ProbeUnreachable);
                let degraded = degraded_session
                    .with_supervision(
                        fat_core::runs::SupervisionMode::BackgroundSupervisor,
                        managed_runtime_health_state(&runtime_status),
                        Some(heartbeat_at.clone()),
                    )
                    .with_supervisor_runtime(
                        None,
                        Some(heartbeat_at.clone()),
                        Some(lease_expires_at),
                    );
                write_managed_runtime_status_artifacts(
                    &store,
                    &project_record,
                    degraded.session_record().session_id.as_str(),
                    degraded.run_record().run_id.as_str(),
                    &degraded.run_record().backend_driver,
                    degraded.run_record().substrate_kind,
                    &runtime_status,
                )?;
                store.write_diagnostic(
                    degraded.session_record().session_id.as_str(),
                    &probe_error.diagnostic,
                )?;
                store.append_diagnostic_index(&probe_error.diagnostic)?;
                store.write_session(degraded.session_record())?;
                store.write_run(degraded.run_record())?;
                return Ok(());
            }
        }

        ticks += 1;
        sleep(Duration::from_millis(interval_ms));
    }
}

fn refresh_managed_linux_vm_status(
    project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<crate::run_cmd::RuntimeView> {
    let Some(bundle_dir) = managed_linux_vm_bundle_dir_from_env() else {
        return Ok(view);
    };
    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .resume(
            ManagedLinuxVmRequest::new(
                view.run.backend_driver.clone(),
                managed_linux_vm_bundle_version_from_env(),
                bundle_dir,
                managed_linux_vm_workspace_root(project_dir, &view.session.session_id),
            )
            .with_run_id(view.run.run_id.clone())
            .with_mapped_ports(
                view.run
                    .active_endpoints
                    .iter()
                    .filter_map(|endpoint| endpoint.target_port)
                    .collect(),
            ),
        )
        .map_err(|err| err.contract.health.detail)?;

    match manager.probe(&prepared) {
        Ok(probe_result) => {
            let checked_at = current_timestamp_string();
            let session = fat_emulate::EmulationSession::new(
                view.session.session_id.clone(),
                view.session,
                fat_emulate::EmulationRun::new(view.run),
            );
            let refreshed = session
                .with_lifecycle(
                    fat_core::sessions::SessionStatus::Active,
                    fat_core::sessions::GoalProgress::Substantial,
                    checked_at.clone(),
                )
                .into_active_run()
                .with_supervision(
                    fat_core::runs::SupervisionMode::ProbeOnStatus,
                    fat_core::runs::HealthState::Healthy,
                    Some(checked_at.clone()),
                );
            store.write_session(refreshed.session_record())?;
            store.write_run(refreshed.run_record())?;
            let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
            let probe_state = prepared.probe_state(
                ManagedLinuxVmProbeSource::ProbeOnStatus,
                ManagedLinuxVmProbeOutcome::Healthy,
                true,
                &probe_result.stdout,
                &probe_result.stderr,
            );
            write_runtime_state_artifact(
                store,
                &project_record,
                refreshed.session_record().session_id.as_str(),
                refreshed.run_record().run_id.as_str(),
                &refreshed.run_record().backend_driver,
                refreshed.run_record().substrate_kind,
                "managed-linux-vm-probe-state",
                "managed linux vm probe state",
                &serde_json::to_string_pretty(&probe_state)?,
            )?;
            let runtime_status = current_managed_runtime_status(
                store,
                refreshed.session_record().session_id.as_str(),
                refreshed.run_record().run_id.as_str(),
            )?
            .unwrap_or_else(|| {
                prepared.runtime_status(refreshed.run_record().active_endpoints.clone(), false)
            })
            .with_probe_state(&probe_state, ManagedLinuxVmRuntimePhase::ProbeHealthy);
            write_managed_runtime_status_artifacts(
                store,
                &project_record,
                refreshed.session_record().session_id.as_str(),
                refreshed.run_record().run_id.as_str(),
                &refreshed.run_record().backend_driver,
                refreshed.run_record().substrate_kind,
                &runtime_status,
            )?;
            Ok(crate::run_cmd::RuntimeView {
                session: refreshed.session_record().clone(),
                run: refreshed.run_record().clone(),
                diagnostics: Vec::new(),
            })
        }
        Err(probe_error) => {
            let checked_at = current_timestamp_string();
            let session = fat_emulate::EmulationSession::new(
                view.session.session_id.clone(),
                view.session,
                fat_emulate::EmulationRun::new(view.run),
            );
            let degraded_session = session
                .into_active_run()
                .degraded_running_at(checked_at.clone(), probe_error.diagnostic.clone());
            let project_record = load_project(&ProjectDb::open(project_dir)?, project_dir)?;
            write_runtime_log_artifact(
                store,
                &project_record,
                degraded_session.session_record().session_id.as_str(),
                degraded_session.run_record().run_id.as_str(),
                &degraded_session.run_record().backend_driver,
                degraded_session.run_record().substrate_kind,
                "managed-linux-vm-probe-stdout",
                "managed linux vm probe stdout",
                &probe_error.stdout,
            )?;
            write_runtime_log_artifact(
                store,
                &project_record,
                degraded_session.session_record().session_id.as_str(),
                degraded_session.run_record().run_id.as_str(),
                &degraded_session.run_record().backend_driver,
                degraded_session.run_record().substrate_kind,
                "managed-linux-vm-probe-stderr",
                "managed linux vm probe stderr",
                &probe_error.stderr,
            )?;
            let probe_state = prepared.probe_state(
                ManagedLinuxVmProbeSource::ProbeOnStatus,
                ManagedLinuxVmProbeOutcome::Unreachable,
                false,
                &probe_error.stdout,
                &probe_error.stderr,
            );
            write_runtime_state_artifact(
                store,
                &project_record,
                degraded_session.session_record().session_id.as_str(),
                degraded_session.run_record().run_id.as_str(),
                &degraded_session.run_record().backend_driver,
                degraded_session.run_record().substrate_kind,
                "managed-linux-vm-probe-state",
                "managed linux vm probe state",
                &serde_json::to_string_pretty(&probe_state)?,
            )?;
            let runtime_status = current_managed_runtime_status(
                store,
                degraded_session.session_record().session_id.as_str(),
                degraded_session.run_record().run_id.as_str(),
            )?
            .unwrap_or_else(|| {
                prepared.runtime_status(
                    degraded_session.run_record().active_endpoints.clone(),
                    false,
                )
            })
            .with_probe_state(&probe_state, ManagedLinuxVmRuntimePhase::ProbeUnreachable);
            let degraded = degraded_session.with_supervision(
                fat_core::runs::SupervisionMode::ProbeOnStatus,
                managed_runtime_health_state(&runtime_status),
                Some(checked_at),
            );
            write_managed_runtime_status_artifacts(
                store,
                &project_record,
                degraded.session_record().session_id.as_str(),
                degraded.run_record().run_id.as_str(),
                &degraded.run_record().backend_driver,
                degraded.run_record().substrate_kind,
                &runtime_status,
            )?;
            store.write_diagnostic(
                degraded.session_record().session_id.as_str(),
                &probe_error.diagnostic,
            )?;
            store.append_diagnostic_index(&probe_error.diagnostic)?;
            store.write_session(degraded.session_record())?;
            store.write_run(degraded.run_record())?;
            Ok(crate::run_cmd::RuntimeView {
                session: degraded.session_record().clone(),
                run: degraded.run_record().clone(),
                diagnostics: vec![probe_error.diagnostic],
            })
        }
    }
}

fn refresh_managed_linux_vm_background_supervision(
    _project_dir: &Path,
    store: &RuntimeStore,
    view: crate::run_cmd::RuntimeView,
) -> DynResult<crate::run_cmd::RuntimeView> {
    if !managed_supervision_lease_expired(view.run.supervision_lease_expires_at.as_deref()) {
        return Ok(view);
    }

    let checked_at = current_timestamp_string();
    let diagnostic = managed_supervision_stale_diagnostic(&view.run.run_id);
    let session = fat_emulate::EmulationSession::new(
        view.session.session_id.clone(),
        view.session,
        fat_emulate::EmulationRun::new(view.run),
    );
    let degraded = session
        .into_active_run()
        .degraded_running_at(checked_at.clone(), diagnostic.clone())
        .with_supervision(
            fat_core::runs::SupervisionMode::BackgroundSupervisor,
            fat_core::runs::HealthState::Stale,
            Some(checked_at.clone()),
        )
        .with_supervisor_runtime(None, None, None);
    store.write_diagnostic(degraded.session_record().session_id.as_str(), &diagnostic)?;
    store.append_diagnostic_index(&diagnostic)?;
    store.write_session(degraded.session_record())?;
    store.write_run(degraded.run_record())?;

    Ok(crate::run_cmd::RuntimeView {
        session: degraded.session_record().clone(),
        run: degraded.run_record().clone(),
        diagnostics: store.read_run_diagnostics(
            degraded.session_record().session_id.as_str(),
            degraded.run_record().run_id.as_str(),
        )?,
    })
}

fn managed_supervision_lease_expired(lease_expires_at: Option<&str>) -> bool {
    lease_expires_at
        .map(parse_unix_ms)
        .is_some_and(|lease| current_timestamp_millis() > lease)
}

fn managed_supervision_stale_diagnostic(run_id: &str) -> DiagnosticRecord {
    DiagnosticRecord::new(
        run_id.to_string(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::Policy,
        DiagnosticClass::SubstrateUnhealthy,
        Some("managed-linux-vm-supervision-lease-expired".to_string()),
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        "background supervisor lease expired before a fresh managed-linux-vm heartbeat arrived",
        Vec::new(),
        Vec::new(),
        vec![
            "run fat emulate --status again after relaunching the managed runtime".to_string(),
            "inspect the managed supervisor process if the guest should still be alive".to_string(),
        ],
    )
}

/// Read back a timestamp written by [`current_timestamp_string`]. Anything that
/// is not a `unix-ms:` stamp reads as 0, which dates it to the epoch and so
/// treats it as arbitrarily old.
pub(crate) fn parse_unix_ms(value: &str) -> u128 {
    value
        .strip_prefix("unix-ms:")
        .and_then(|millis| millis.parse::<u128>().ok())
        .unwrap_or(0)
}

fn persist_firmae_upstream_launch_artifacts(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    firmware_path: &Path,
    brand: &str,
    launch_result: &ManagedLinuxVmUpstreamLaunchResult,
) -> DynResult<()> {
    // Record the brand actually passed upstream and where it came from. FAT
    // does not derive this value, so the artifact must not read as a FAT
    // assertion about the target.
    let command = format!(
        "docker-helper.py -ec {brand} {}\nbrand-source: {}",
        firmware_path.display(),
        fat_backend::managed_linux_vm::FIRMAE_UPSTREAM_BRAND_ENV
    );
    write_runtime_log_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "firmae-upstream-launch-command",
        "firmae upstream launch command",
        &command,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "firmae-upstream-launch-stdout",
        "firmae upstream launch stdout",
        &launch_result.stdout,
    )?;
    write_runtime_log_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "firmae-upstream-launch-stderr",
        "firmae upstream launch stderr",
        &launch_result.stderr,
    )?;
    for artifact_path in &launch_result.declared_artifact_paths {
        let Some(name) = upstream_artifact_output_name(artifact_path) else {
            continue;
        };
        let contents = fs::read(artifact_path)?;
        let contents = String::from_utf8_lossy(&contents);
        write_runtime_log_artifact(
            store,
            project_record,
            session_id,
            run_id,
            backend,
            substrate_kind,
            name.as_str(),
            &format!("firmae upstream {name}"),
            contents.as_ref(),
        )?;
    }
    Ok(())
}

fn persist_firmae_upstream_observation_artifact(
    store: &RuntimeStore,
    project_record: &fat_core::project::Project,
    session_id: &str,
    run_id: &str,
    backend: &str,
    substrate_kind: fat_core::runs::SubstrateKind,
    observation: &fat_backend::managed_linux_vm::ManagedLinuxVmUpstreamObservationResult,
) -> DynResult<()> {
    let observation_json = serde_json::json!({
        "observation_source": "bounded-live-inspection",
        "observation_timestamp": current_timestamp_string(),
        "container_name": observation.container_name,
        "container_running": observation.container_running,
        "scratch_artifacts_present": observation.scratch_artifacts_present,
        "observed_artifact_paths": observation
            .observed_artifact_paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        "guest_ip": observation.guest_ip,
        "guest_reachable": observation.guest_reachable,
        "port_80_reachable": observation.port_80_reachable,
        "port_31337_reachable": observation.port_31337_reachable,
        "port_31338_reachable": observation.port_31338_reachable,
        "runtime_status": observation.runtime_status,
    });
    write_runtime_state_artifact(
        store,
        project_record,
        session_id,
        run_id,
        backend,
        substrate_kind,
        "firmae-upstream-observation",
        "firmae upstream observation",
        &serde_json::to_string_pretty(&observation_json)?,
    )?;
    Ok(())
}

fn upstream_artifact_output_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".log").unwrap_or(name);
    let output_name = match stem {
        "qemu.initial.serial" => "firmae-upstream-initial-serial".to_string(),
        "qemu.final.serial" => "firmae-upstream-final-serial".to_string(),
        "makeNetwork" => "firmae-upstream-network-log".to_string(),
        other => format!("firmae-upstream-{other}"),
    };
    Some(output_name)
}

fn render_launch_output(
    store: &RuntimeStore,
    recipe_id: &str,
    mapped_ports: &[u16],
    view: &crate::run_cmd::RuntimeView,
) -> DynResult<String> {
    let mut output = String::new();
    output.push_str(&format!("recipe: {recipe_id}\n"));
    output.push_str(&format!("ports: {mapped_ports:?}\n"));
    output.push_str(&format!("status: {}\n", view.session.status.as_str()));
    output.push_str(&render_runtime_output(store, "", view)?);
    Ok(output)
}

/// Build a typed InstrumentationConfig from a hooks config file path.
///
/// Supports both YAML (line-oriented parser) and JSON (serde_json).
/// Resolves the plugin .so from well-known locations:
///   1. FAT_HOOK_PLUGIN_PATH env var
///   2. scripts/fat-hook.so relative to the repo root
///   3. fat-hook.so in the same directory as the config file
fn build_instrumentation_config(
    config_path: &Path,
) -> DynResult<fat_core::rehosting_recipe::InstrumentationConfig> {
    use fat_core::rehosting_recipe::InstrumentationConfig;

    if !config_path.exists() {
        return Err(format!(
            "instrumentation config not found: {}",
            config_path.display()
        )
        .into());
    }

    let content = fs::read_to_string(config_path)?;
    let hooks = if config_path.extension().and_then(|e| e.to_str()) == Some("json") {
        parse_hooks_json(&content)?
    } else {
        parse_hooks_yaml(&content)?
    };

    if hooks.is_empty() {
        return Err("instrumentation config contains no hooks".into());
    }

    let plugin_path = resolve_plugin_path(config_path)?;

    Ok(InstrumentationConfig {
        plugin_path,
        hooks,
        json_output: true,
    })
}

fn parse_hooks_json(content: &str) -> DynResult<Vec<fat_core::rehosting_recipe::HookSpec>> {
    let parsed: serde_json::Value = serde_json::from_str(content)?;
    let hooks_array = parsed
        .get("hooks")
        .and_then(|v| v.as_array())
        .ok_or("JSON config missing 'hooks' array")?;

    let mut hooks = Vec::new();
    for entry in hooks_array {
        let address_str = entry
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or("hook entry missing 'address'")?;
        let address =
            u64::from_str_radix(address_str.strip_prefix("0x").unwrap_or(address_str), 16)?;
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("hook entry missing 'name'")?
            .to_string();
        let string_args = entry
            .get("string_args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        hooks.push(fat_core::rehosting_recipe::HookSpec {
            address,
            name,
            string_args,
        });
    }
    Ok(hooks)
}

/// Minimal line-oriented YAML parser for hooks config files.
/// Handles the format generated by `fat instrument-hooks`.
fn parse_hooks_yaml(content: &str) -> DynResult<Vec<fat_core::rehosting_recipe::HookSpec>> {
    let mut hooks = Vec::new();
    let mut current_address: Option<u64> = None;
    let mut current_name: Option<String> = None;
    let mut current_string_args: Vec<String> = Vec::new();

    let flush = |hooks: &mut Vec<fat_core::rehosting_recipe::HookSpec>,
                 addr: &mut Option<u64>,
                 name: &mut Option<String>,
                 sargs: &mut Vec<String>| {
        if let (Some(a), Some(n)) = (addr.take(), name.take()) {
            hooks.push(fat_core::rehosting_recipe::HookSpec {
                address: a,
                name: n,
                string_args: std::mem::take(sargs),
            });
        } else {
            sargs.clear();
        }
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // New hook entry: "- address: 0x..."
        if trimmed.starts_with("- address:") {
            flush(
                &mut hooks,
                &mut current_address,
                &mut current_name,
                &mut current_string_args,
            );
            let val = trimmed.strip_prefix("- address:").unwrap().trim();
            current_address = Some(u64::from_str_radix(
                val.strip_prefix("0x")
                    .or_else(|| val.strip_prefix("0X"))
                    .unwrap_or(val),
                16,
            )?);
            continue;
        }

        if trimmed.starts_with("name:") {
            current_name = Some(trimmed.strip_prefix("name:").unwrap().trim().to_string());
            continue;
        }

        if trimmed.starts_with("string_args:") {
            let val = trimmed.strip_prefix("string_args:").unwrap().trim();
            // Parse "[a0, a1]" style
            let inner = val.trim_start_matches('[').trim_end_matches(']');
            current_string_args = inner
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            continue;
        }
    }

    // Flush last entry
    flush(
        &mut hooks,
        &mut current_address,
        &mut current_name,
        &mut current_string_args,
    );

    Ok(hooks)
}

/// Resolve the fat-hook.so plugin path from well-known locations.
fn resolve_plugin_path(config_path: &Path) -> DynResult<PathBuf> {
    // 1. Environment variable override
    if let Ok(env_path) = std::env::var("FAT_HOOK_PLUGIN_PATH") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("FAT_HOOK_PLUGIN_PATH={env_path} does not exist").into());
    }

    // 2. scripts/fat-hook.so relative to the binary's location
    if let Ok(exe) = std::env::current_exe() {
        // Walk up from the binary to find the repo root
        for ancestor in exe.ancestors().skip(1) {
            let candidate = ancestor.join("scripts").join("fat-hook.so");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // 3. Same directory as the config file
    if let Some(config_dir) = config_path.parent() {
        let candidate = config_dir.join("fat-hook.so");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 4. Current working directory
    let cwd_candidate = PathBuf::from("fat-hook.so");
    if cwd_candidate.exists() {
        return Ok(cwd_candidate.canonicalize()?);
    }

    Err(
        "cannot locate fat-hook.so plugin — set FAT_HOOK_PLUGIN_PATH or \
         build it with: cc -shared -fPIC -o fat-hook.so scripts/fat-hook-plugin.c \
         $(pkg-config --cflags glib-2.0) -I$(brew --prefix)/include -undefined dynamic_lookup"
            .into(),
    )
}

#[cfg(test)]
mod instrumentation_tests {
    use super::*;
    use fat_core::rehosting_recipe::{HookSpec, InstrumentationConfig};
    use tempfile::tempdir;

    // -- YAML parser tests --

    #[test]
    fn parse_hooks_yaml_basic() {
        let yaml = "\
hooks:
  - address: 0x00412345
    name: system
    string_args: [a0]
  - address: 0x0043a070
    name: hardware_reg
";
        let hooks = parse_hooks_yaml(yaml).unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].address, 0x00412345);
        assert_eq!(hooks[0].name, "system");
        assert_eq!(hooks[0].string_args, vec!["a0"]);
        assert_eq!(hooks[1].address, 0x0043a070);
        assert_eq!(hooks[1].name, "hardware_reg");
        assert!(hooks[1].string_args.is_empty());
    }

    #[test]
    fn parse_hooks_yaml_multiple_string_args() {
        let yaml = "\
hooks:
  - address: 0x00400000
    name: popen
    string_args: [a0, a1]
";
        let hooks = parse_hooks_yaml(yaml).unwrap();
        assert_eq!(hooks[0].string_args, vec!["a0", "a1"]);
    }

    #[test]
    fn parse_hooks_yaml_comments_and_empty_lines() {
        let yaml = "\
# This is a comment
hooks:

  - address: 0x100
    name: test
    # category: command-exec
";
        let hooks = parse_hooks_yaml(yaml).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].address, 0x100);
    }

    #[test]
    fn parse_hooks_yaml_empty() {
        let hooks = parse_hooks_yaml("hooks:\n").unwrap();
        assert!(hooks.is_empty());
    }

    // -- JSON parser tests --

    #[test]
    fn parse_hooks_json_basic() {
        let json = r#"{"hooks": [
            {"address": "0x00412345", "name": "system", "string_args": ["a0"]},
            {"address": "0x0043a070", "name": "hw_reg"}
        ]}"#;
        let hooks = parse_hooks_json(json).unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].address, 0x00412345);
        assert_eq!(hooks[0].name, "system");
        assert_eq!(hooks[0].string_args, vec!["a0"]);
        assert_eq!(hooks[1].name, "hw_reg");
        assert!(hooks[1].string_args.is_empty());
    }

    #[test]
    fn parse_hooks_json_noncontiguous_string_args() {
        let json = r#"{"hooks": [
            {"address": "0x100", "name": "custom", "string_args": ["a0", "a2"]}
        ]}"#;
        let hooks = parse_hooks_json(json).unwrap();
        assert_eq!(hooks[0].string_args, vec!["a0", "a2"]);
    }

    // -- Recipe projection tests --

    #[test]
    fn project_rehosting_recipe_preserves_instrumentation() {
        let instrumentation = InstrumentationConfig {
            plugin_path: std::path::PathBuf::from("/path/to/fat-hook.so"),
            hooks: vec![HookSpec {
                address: 0x00412345,
                name: "system".to_string(),
                string_args: vec!["a0".to_string()],
            }],
            json_output: true,
        };

        let source = RehostingRecipe::new(
            "target-1",
            "model-1",
            "run-1",
            "boot-firmware",
            fat_core::rehosting_policy::SubstratePreference::Auto,
            fat_core::rehosting_policy::SubstrateKind::System,
        )
        .with_instrumentation(instrumentation.clone());

        let target_model = TargetModel::new("proj-1", "target-1", None, None, vec![]);
        let projected =
            project_rehosting_recipe_for_plan("target-1", "run-2", &target_model, &source);

        assert!(
            projected.instrumentation.is_some(),
            "instrumentation must survive recipe projection"
        );
        let projected_inst = projected.instrumentation.unwrap();
        assert_eq!(projected_inst.hooks.len(), 1);
        assert_eq!(projected_inst.hooks[0].name, "system");
        assert_eq!(projected_inst.hooks[0].address, 0x00412345);
        assert_eq!(
            projected_inst.plugin_path.to_str().unwrap(),
            "/path/to/fat-hook.so"
        );
    }

    #[test]
    fn project_rehosting_recipe_preserves_none_instrumentation() {
        let source = RehostingRecipe::new(
            "target-1",
            "model-1",
            "run-1",
            "boot-firmware",
            fat_core::rehosting_policy::SubstratePreference::Auto,
            fat_core::rehosting_policy::SubstrateKind::System,
        );

        let target_model = TargetModel::new("proj-1", "target-1", None, None, vec![]);
        let projected =
            project_rehosting_recipe_for_plan("target-1", "run-2", &target_model, &source);

        assert!(projected.instrumentation.is_none());
    }

    #[test]
    fn instrumented_launch_biases_auto_preference_to_system_first() {
        let effective = effective_substrate_preference(SubstratePreference::Auto, false, true);

        assert_eq!(effective, SubstratePreference::SystemFirst);
    }

    #[test]
    fn instrumented_launch_preserves_explicit_preference() {
        let effective =
            effective_substrate_preference(SubstratePreference::ServiceFirst, true, true);

        assert_eq!(effective, SubstratePreference::ServiceFirst);
    }

    #[test]
    fn instrumented_launch_defaults_backend_to_qemu_direct() {
        let backend = effective_instrument_backend(None, true);

        assert_eq!(backend.as_deref(), Some("qemu-direct"));
    }

    #[test]
    fn instrumented_launch_preserves_explicit_backend() {
        let backend = effective_instrument_backend(Some("firmae".to_string()), true);

        assert_eq!(backend.as_deref(), Some("firmae"));
    }

    // -- Substrate fallback gate tests --

    #[test]
    fn should_attempt_substrate_fallback_allows_when_no_constraints() {
        assert!(should_attempt_substrate_fallback(false, false));
    }

    #[test]
    fn should_attempt_substrate_fallback_blocks_on_explicit_backend() {
        assert!(!should_attempt_substrate_fallback(true, false));
    }

    #[test]
    fn should_attempt_substrate_fallback_blocks_on_instrumentation() {
        assert!(!should_attempt_substrate_fallback(false, true));
    }

    #[test]
    fn should_attempt_substrate_fallback_blocks_on_both() {
        assert!(!should_attempt_substrate_fallback(true, true));
    }

    #[test]
    fn instrumented_plan_does_not_silently_fallback_to_unsupported_substrate() {
        // Regression test: an instrumented plan falling back to an
        // unsupported substrate must not silently proceed with
        // instrumentation: None.  The fallback candidate produced by
        // exact_plan_for_logical_substrate() lacks instrumentation
        // because EmulationBundleRequest has no instrumentation field.
        // The gate at the fallback selection point must prevent this.

        let instrumentation = InstrumentationConfig {
            plugin_path: std::path::PathBuf::from("/tmp/fat-hook.so"),
            hooks: vec![HookSpec {
                address: 0x00448784,
                name: "system".to_string(),
                string_args: vec!["a0".to_string()],
            }],
            json_output: true,
        };

        // Simulate a plan that just failed on system substrate with
        // instrumentation active.
        let mut recipe = RehostingRecipe::new(
            "target-1",
            "model-1",
            "run-1",
            "boot-firmware",
            fat_core::rehosting_policy::SubstratePreference::Auto,
            fat_core::rehosting_policy::SubstrateKind::System,
        )
        .with_instrumentation(instrumentation);

        // The gate checks these two conditions:
        let backend_explicit = false; // user did not pass --backend
        let instrumentation_present = recipe.instrumentation.is_some();

        // Fallback must be blocked
        assert!(
            !should_attempt_substrate_fallback(backend_explicit, instrumentation_present),
            "substrate fallback must be blocked when instrumentation is active; \
             otherwise the fallback candidate will silently drop instrumentation"
        );

        // Verify the inverse: if instrumentation is removed (simulating
        // the bug where a fresh candidate has instrumentation: None),
        // the gate would allow fallback — which is exactly what we
        // prevent by checking the *original* plan's instrumentation
        // before entering the fallback loop.
        recipe.instrumentation = None;
        assert!(
            should_attempt_substrate_fallback(false, recipe.instrumentation.is_some()),
            "fallback is allowed when there is no instrumentation to lose"
        );
    }

    #[test]
    fn instrumentation_gate_reports_logical_substrate_and_guidance() {
        let temp = tempdir().unwrap();
        let store = RuntimeStore::open(temp.path()).unwrap();
        let project = fat_core::project::Project::new("proj".to_string(), "fw".to_string());
        let recipe = fat_core::recipes::RecipeRecord::new(
            "target",
            "strategy",
            "goal",
            "qemu-direct",
            "native-host",
        );
        let probe = PathCommandProbe;
        let mut plan = fat_emulate::EmulationPlan::new("instr-gate", "qemu-direct", vec![])
            .expect("qemu-direct plan should be buildable");
        plan.strategy.selected.backend_id = "qemu-direct".to_string();
        plan.strategy.selected.substrate = fat_core::runs::SubstrateKind::NativeHost;
        plan.rehosting_recipe.selected_substrate = LogicalSubstrateKind::Service;
        plan.rehosting_recipe.instrumentation = Some(InstrumentationConfig {
            plugin_path: std::path::PathBuf::from("/tmp/fat-hook.so"),
            hooks: vec![HookSpec {
                address: 0x1000,
                name: "system".to_string(),
                string_args: vec!["a0".to_string()],
            }],
            json_output: true,
        });

        let err = dispatch_emulation_plan(
            temp.path(),
            &store,
            &project,
            "family",
            &[],
            std::path::PathBuf::from("/usr/bin/docker"),
            recipe,
            plan,
            &probe,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("logical_substrate=service"));
        assert!(err.contains("--substrate-policy system-first"));
    }

    #[test]
    fn native_system_launch_script_includes_plugin_args() {
        let spec = fat_emulate::system_runner::SystemLaunchSpec {
            kernel_profile_id: None,
            machine: "malta".to_string(),
            qemu_binary: "qemu-system-mipsel".to_string(),
            required_qemu_version: None,
            args: vec!["-M".to_string(), "malta".to_string()],
            kernel_path: "/tmp/vmlinux".to_string(),
            rootfs_image: "/tmp/rootfs.ext2".to_string(),
            preinit_path: "/tmp/preinit.sh".to_string(),
            boot_args: "root=/dev/sda".to_string(),
            serial_log: "/tmp/boot/serial.log".to_string(),
            serial_socket: "/tmp/boot/serial.sock".to_string(),
            monitor_socket: "/tmp/boot/monitor.sock".to_string(),
            gdb_address: "127.0.0.1:1234".to_string(),
            boot_artifacts: vec![],
            registered_surfaces: vec![],
            host_forwards: vec![],
            instrumentation: Some(InstrumentationConfig {
                plugin_path: std::path::PathBuf::from("/tmp/fat-hook.so"),
                hooks: vec![HookSpec {
                    address: 0x00448784,
                    name: "system".to_string(),
                    string_args: vec!["a1".to_string()],
                }],
                json_output: true,
            }),
        };

        let script = render_native_system_launch_script(&spec);

        assert!(script.contains("'-plugin'"));
        assert!(script.contains("fat-hook.so,hook=0x00448784:system:m2"));
        assert!(script.contains("instrument-trace.jsonl"));
    }

    #[test]
    fn degraded_automatic_rehosting_requires_explicit_acceptance() {
        let report = fat_core::rehosting_recipe::RehostingCapabilityReport {
            pack_id: "vendor/device".into(),
            degraded_actions: vec!["network fidelity is experimental".into()],
            ..Default::default()
        };

        let error = ensure_pack_capability(&report, false).unwrap_err();

        assert!(error.to_string().contains("--accept-degraded-rehosting"));
        assert!(ensure_pack_capability(&report, true).is_ok());
    }
}

#[cfg(test)]
mod termination_tests {
    use super::*;

    /// Start a process group this process does not parent.
    ///
    /// The shell is spawned as its own group leader, backgrounds a `sleep`, and
    /// exits; reaping it leaves the `sleep` in that group, re-parented away.
    /// That matches production, where `--stop` and `--gc` run in a different
    /// process than the launcher. A child of *this* process would linger as a
    /// zombie after being signalled, and a zombie still answers `kill(pgid, 0)`.
    fn spawn_detached_group() -> u32 {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 60 &");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut shell = command.spawn().expect("spawn a stand-in supervisor group");
        let group = shell.id();
        shell.wait().expect("the shell exits immediately");
        group
    }

    #[test]
    fn terminating_a_group_reaps_it() {
        let group = spawn_detached_group();
        assert!(process_group_is_running(group));

        terminate_process_group(
            group,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("group should terminate");

        assert!(!process_group_is_running(group));
    }

    #[test]
    fn terminating_a_group_that_is_already_gone_succeeds() {
        let group = spawn_detached_group();
        terminate_process_group(
            group,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("first stop terminates the group");

        // Stopping is idempotent: a supervisor that is already gone is the
        // outcome the caller wanted, not an error.
        terminate_process_group(
            group,
            "test",
            Duration::from_millis(200),
            Duration::from_millis(200),
        )
        .expect("an absent group is not a failure");
    }

    #[test]
    fn a_process_we_may_not_signal_counts_as_running() {
        // pid 1 exists on every unix host and is not ours to signal, so the
        // permission error must read as alive. Reporting it dead is what would
        // let a gc sweep mark a live session stale.
        assert!(process_is_running(1));
    }
}
