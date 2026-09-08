use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;

use fat_query::adapters::traits::ExecutionMode;
use fat_query::discovery::{CandidateStatus, DiscoveryLead, TriggerRecipeStep};
use fat_query::state_machines::{
    build_machine_snapshots_for_lead, build_machines_for_lead, registered_machine_ids,
    MachineTransitionSelection, StateMachineSnapshot,
};
use fat_query::state_queries::{
    find_counterfactual_transition_matches, find_event_path_matches, find_ghost_state_matches,
    find_invalidation_paths, find_lifetime_coexistence_candidates, find_locality_policy_candidates,
    find_state_condition_matches, CoexistenceMatch, CounterfactualTransitionMatch, EventPathMatch,
    GhostStateMatch, InvalidationPathMatch, StateConditionMatch,
};
use fat_query::target_lanes::{
    load_target_lane_manifest, LaneAdapter, TargetLaneManifest, TargetLaneRecord,
};
use serde::{Deserialize, Serialize};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
pub struct LeadSource<'a> {
    pub leads_file: Option<&'a Path>,
    pub fixture: Option<&'a Path>,
    pub repo: Option<&'a Path>,
    pub manifest: Option<&'a Path>,
    pub family: Option<&'a str>,
    pub top_k: usize,
    pub mode: ExecutionMode,
    pub debug_bundle_dir: Option<&'a Path>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeriveRecord {
    lead_id: String,
    symbol: String,
    family: String,
    blocked_by_locality: bool,
    #[serde(default)]
    trigger_recipe: Vec<TriggerRecipeStep>,
    #[serde(default)]
    expected_proof_classes: Vec<String>,
    machine_count: usize,
    machines: Vec<StateMachineSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeriveOutput {
    lead_count: usize,
    records: Vec<DeriveRecord>,
}

#[derive(Debug, Serialize)]
struct HsmPlanRecord {
    lead_id: String,
    symbol: String,
    family: String,
    lane_id: String,
    source_root: String,
    build_dir: String,
    adapter_kind: Option<String>,
    artifact_dir: String,
    sanitizer_mode: String,
    launcher_command: Vec<String>,
    expected_proof_classes: Vec<String>,
    trigger_recipe: Vec<TriggerRecipeStep>,
    state_hypothesis_id: String,
    machine_id: String,
    transition_id: String,
    event_id: String,
    source_state: String,
    target_state: String,
    required_states: Vec<String>,
    expected_proof_class: Option<String>,
    attempted_transition_summary: String,
}

#[derive(Debug, Serialize)]
struct HsmPlanOutput {
    plan_count: usize,
    records: Vec<HsmPlanRecord>,
}

pub fn run_registry(json: bool) -> DynResult<()> {
    let ids = registered_machine_ids();
    if json {
        println!("{}", serde_json::to_string_pretty(&ids)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        println!("{}", palette.heading("HSM Registry"));
        println!("{}", palette.kv("family_count", ids.len().to_string()));
        for id in ids {
            println!("{}", palette.kv("machine", id));
        }
        return Ok(());
    }

    let mut lines = vec![format!(
        "{} {} registered machine families",
        palette.check_glyph(true),
        palette.good(ids.len().to_string())
    )];
    for id in &ids {
        lines.push(format!("{} {}", palette.dot_ok(), id));
    }
    println!("{}", palette.panel("HSM Registry", &lines));
    println!(
        "{}",
        palette.next_hint("fat hsm derive --leads-file <leads.json> to instantiate machines")
    );
    Ok(())
}

pub fn run_derive(
    source: LeadSource<'_>,
    out_file: Option<&Path>,
    lead_id: Option<&str>,
    json: bool,
) -> DynResult<()> {
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    let records = filtered
        .iter()
        .map(|lead| DeriveRecord {
            lead_id: lead.lead_id.clone(),
            symbol: lead.symbol.clone(),
            family: lead.family.as_str().to_string(),
            blocked_by_locality: matches!(
                lead.candidate_status,
                CandidateStatus::BlockedByLocality
            ),
            trigger_recipe: lead.suggested_trigger_recipe.clone(),
            expected_proof_classes: lead
                .expected_proof_signal
                .iter()
                .map(|signal| signal.kind.clone())
                .collect(),
            machine_count: build_machines_for_lead(lead).len(),
            machines: build_machine_snapshots_for_lead(lead),
        })
        .collect::<Vec<_>>();
    let output = DeriveOutput {
        lead_count: filtered.len(),
        records,
    };

    if let Some(path) = out_file {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(&output)?)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        println!("{}", palette.heading("HSM Derive"));
        println!(
            "{}",
            palette.kv("lead_count", output.lead_count.to_string())
        );
        if let Some(path) = out_file {
            println!(
                "{}",
                palette.kv("snapshot_file", path.display().to_string())
            );
        }
        for record in output.records {
            println!();
            println!("{}", palette.kv("lead", &record.lead_id));
            println!("{}", palette.kv("symbol", &record.symbol));
            println!("{}", palette.kv("family", &record.family));
            println!(
                "{}",
                palette.kv("machine_count", record.machine_count.to_string())
            );
            for snapshot in record.machines {
                println!("{}", palette.kv("hypothesis", &snapshot.hypothesis_id));
                println!("{}", palette.kv("machine", &snapshot.machine.machine_id));
                println!(
                    "{}",
                    palette.kv("regions", snapshot.machine.regions.len().to_string())
                );
                println!(
                    "{}",
                    palette.kv("events", snapshot.machine.events.len().to_string())
                );
                println!(
                    "{}",
                    palette.kv(
                        "transitions",
                        snapshot.machine.transitions.len().to_string()
                    )
                );
            }
        }
        return Ok(());
    }

    let mut lines = vec![format!(
        "{} {} derived from leads",
        palette.check_glyph(output.lead_count > 0),
        palette.good(format!("{} machines", output.lead_count))
    )];
    if let Some(path) = out_file {
        lines.push(palette.muted(format!("snapshot: {}", path.display())));
    }
    for record in output.records {
        let dot = if record.blocked_by_locality {
            palette.dot_warn()
        } else {
            palette.dot_ok()
        };
        lines.push(format!(
            "{} {}  {}",
            dot,
            palette.key(&record.lead_id),
            palette.muted(format!("symbol {}", record.symbol))
        ));
        lines.push(format!(
            "· {}  {}  {}",
            palette.muted(format!("family: {}", record.family)),
            palette.muted(format!("machines: {}", record.machine_count)),
            palette.muted(format!(
                "proof: {}",
                if record.expected_proof_classes.is_empty() {
                    "-".to_string()
                } else {
                    record.expected_proof_classes.join(", ")
                }
            ))
        ));
        for step in &record.trigger_recipe {
            lines.push(format!(
                "· {}",
                palette.muted(format!("trigger: {} ({})", step.kind, step.detail))
            ));
        }
        for snapshot in record.machines {
            lines.push(format!(
                "· {}  {}",
                palette.code(&snapshot.machine.machine_id),
                palette.muted(format!(
                    "hypothesis {} · regions {} · events {} · transitions {}",
                    snapshot.hypothesis_id,
                    snapshot.machine.regions.len(),
                    snapshot.machine.events.len(),
                    snapshot.machine.transitions.len()
                ))
            ));
        }
    }
    println!("{}", palette.panel("HSM Derive", &lines));
    println!(
        "{}",
        palette.next_hint("fat hsm plan --machines-file <snapshot.json> --manifest <lanes.json>")
    );
    Ok(())
}

pub fn run_query_event_path(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    event_id: &str,
    json: bool,
) -> DynResult<()> {
    ensure_machine_registered(machine_id)?;
    if let Some(path) = machines_file {
        return render_query_result(
            "HSM Event Path",
            json,
            &find_event_path_matches_in_snapshot(
                &load_machine_snapshot(path)?,
                machine_id,
                event_id,
            ),
        );
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM Event Path",
        json,
        &find_event_path_matches(&filtered, machine_id, event_id),
    )
}

pub fn run_query_invalidation_path(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    json: bool,
) -> DynResult<()> {
    ensure_machine_registered(machine_id)?;
    if let Some(path) = machines_file {
        return render_query_result(
            "HSM Invalidation Path",
            json,
            &find_invalidation_paths_in_snapshot(&load_machine_snapshot(path)?, machine_id),
        );
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM Invalidation Path",
        json,
        &find_invalidation_paths(&filtered, machine_id),
    )
}

pub fn run_query_coexistence(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    json: bool,
) -> DynResult<()> {
    if let Some(path) = machines_file {
        return match machine_id {
            "lifetime-reentrancy" => render_query_result(
                "HSM Coexistence",
                json,
                &find_coexistence_in_snapshot(&load_machine_snapshot(path)?, machine_id),
            ),
            _ => Err(format!("unsupported machine id for coexistence query: {machine_id}").into()),
        };
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    match machine_id {
        "lifetime-reentrancy" => render_query_result(
            "HSM Coexistence",
            json,
            &find_lifetime_coexistence_candidates(&filtered),
        ),
        _ => Err(format!("unsupported machine id for coexistence query: {machine_id}").into()),
    }
}

pub fn run_query_ghost_state(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    json: bool,
) -> DynResult<()> {
    ensure_machine_registered(machine_id)?;
    if let Some(path) = machines_file {
        return render_query_result(
            "HSM Ghost State",
            json,
            &find_ghost_states_in_snapshot(&load_machine_snapshot(path)?, machine_id),
        );
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM Ghost State",
        json,
        &find_ghost_state_matches(&filtered, machine_id),
    )
}

pub fn run_query_state_condition(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    required_state: &str,
    json: bool,
) -> DynResult<()> {
    ensure_machine_registered(machine_id)?;
    if let Some(path) = machines_file {
        return render_query_result(
            "HSM State Condition",
            json,
            &find_state_condition_matches_in_snapshot(
                &load_machine_snapshot(path)?,
                machine_id,
                required_state,
            ),
        );
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM State Condition",
        json,
        &find_state_condition_matches(&filtered, machine_id, required_state),
    )
}

pub fn run_query_counterfactual(
    machines_file: Option<&Path>,
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    machine_id: &str,
    guard_id: Option<&str>,
    json: bool,
) -> DynResult<()> {
    ensure_machine_registered(machine_id)?;
    if let Some(path) = machines_file {
        return render_query_result(
            "HSM Counterfactual",
            json,
            &find_counterfactual_matches_in_snapshot(
                &load_machine_snapshot(path)?,
                machine_id,
                guard_id,
            ),
        );
    }
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM Counterfactual",
        json,
        &find_counterfactual_transition_matches(&filtered, machine_id, guard_id),
    )
}

pub fn run_query_locality_policy(
    source: LeadSource<'_>,
    lead_id: Option<&str>,
    json: bool,
) -> DynResult<()> {
    let leads = load_leads(source)?;
    let filtered = filter_leads(&leads, lead_id);
    render_query_result(
        "HSM Locality Policy",
        json,
        &find_locality_policy_candidates(&filtered),
    )
}

pub fn run_plan(
    machines_file: &Path,
    manifest_path: &Path,
    lead_id: Option<&str>,
    machine_id: Option<&str>,
    transition_id: Option<&str>,
    json: bool,
) -> DynResult<()> {
    let snapshot = load_machine_snapshot(machines_file)?;
    let manifest = load_target_lane_manifest(manifest_path)
        .map_err(|e| format!("failed to load target lanes: {e}"))?;
    let records = snapshot
        .records
        .iter()
        .filter(|record| lead_id.map(|value| record.lead_id == value).unwrap_or(true))
        .filter(|record| {
            machine_id
                .map(|value| record.family == value)
                .unwrap_or(true)
        })
        .filter(|record| !record.blocked_by_locality)
        .filter_map(|record| {
            let lane = resolve_lane_for_record(&manifest, record)?;
            let selected = select_transition_from_snapshot_record(record, transition_id)?;
            Some(HsmPlanRecord {
                lead_id: record.lead_id.clone(),
                symbol: record.symbol.clone(),
                family: record.family.clone(),
                lane_id: lane.lane_id.clone(),
                source_root: lane.source_root.clone(),
                build_dir: lane.build_dir.clone(),
                adapter_kind: lane.adapter.as_ref().map(adapter_kind_name),
                artifact_dir: lane.artifact_dir.clone(),
                sanitizer_mode: lane.sanitizer_mode.clone(),
                launcher_command: lane.launcher_command.clone(),
                expected_proof_classes: record.expected_proof_classes.clone(),
                trigger_recipe: record.trigger_recipe.clone(),
                state_hypothesis_id: selected.hypothesis_id.clone(),
                machine_id: selected.machine_id.clone(),
                transition_id: selected.transition_id.clone(),
                event_id: selected.event_id.clone(),
                source_state: selected.source_state.clone(),
                target_state: selected.target_state.clone(),
                required_states: selected.required_states.clone(),
                expected_proof_class: selected.expected_proof_class.clone(),
                attempted_transition_summary: selected.attempted_transition_summary(),
            })
        })
        .collect::<Vec<_>>();

    let output = HsmPlanOutput {
        plan_count: records.len(),
        records,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        println!("{}", palette.heading("HSM Plan"));
        println!(
            "{}",
            palette.kv("plan_count", output.plan_count.to_string())
        );
        for record in output.records {
            println!();
            println!("{}", palette.kv("lead", &record.lead_id));
            println!("{}", palette.kv("symbol", &record.symbol));
            println!("{}", palette.kv("family", &record.family));
            println!("{}", palette.kv("lane", &record.lane_id));
            println!("{}", palette.kv("transition", &record.transition_id));
            println!(
                "{}",
                palette.kv("attempt", &record.attempted_transition_summary)
            );
        }
        return Ok(());
    }

    let mut lines = vec![format!(
        "{} {}",
        palette.check_glyph(output.plan_count > 0),
        palette.good(format!("{} harness plans", output.plan_count))
    )];
    for record in output.records {
        lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            palette.key(&record.lead_id),
            palette.muted(format!("symbol {}", record.symbol))
        ));
        lines.push(format!(
            "· {}  {}  {}",
            palette.muted(format!("family: {}", record.family)),
            palette.muted(format!("lane: {}", record.lane_id)),
            palette.muted(format!("transition: {}", record.transition_id))
        ));
        lines.push(format!(
            "· {}",
            palette.muted(format!("attempt: {}", record.attempted_transition_summary))
        ));
    }
    println!("{}", palette.panel("HSM Plan", &lines));
    if output.plan_count == 0 {
        println!(
            "{}",
            palette.muted("no plans — widen the lead filter or check lane family allowlists")
        );
    } else {
        println!(
            "{}",
            palette.next_hint("fat discover run --manifest <lanes.json> to execute the plans")
        );
    }
    Ok(())
}

fn render_query_result<T: Serialize>(title: &str, json: bool, matches: &T) -> DynResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(matches)?);
        return Ok(());
    }
    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading(title));
    println!("{}", serde_json::to_string_pretty(matches)?);
    Ok(())
}

fn load_leads(source: LeadSource<'_>) -> DynResult<Vec<DiscoveryLead>> {
    if let Some(path) = source.leads_file {
        return load_leads_from_file(path);
    }
    crate::discover_cmd::collect_leads(
        source.fixture,
        source.repo,
        source.manifest,
        source.family,
        source.top_k,
        source.mode,
        source.debug_bundle_dir,
    )
}

fn load_leads_from_file(path: &Path) -> DynResult<Vec<DiscoveryLead>> {
    let text = fs::read_to_string(path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid leads json: {e}"))?;
    if value.is_array() {
        return Ok(serde_json::from_value(value)?);
    }
    if let Some(leads) = value.get("leads") {
        return Ok(serde_json::from_value(leads.clone())?);
    }
    Err("expected a JSON array of discovery leads or an object with a `leads` field".into())
}

fn load_machine_snapshot(path: &Path) -> DynResult<DeriveOutput> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text).map_err(|e| format!("invalid machines json: {e}"))?)
}

fn filter_leads(leads: &[DiscoveryLead], lead_id: Option<&str>) -> Vec<DiscoveryLead> {
    let filtered = match lead_id {
        Some(lead_id) => leads
            .iter()
            .filter(|lead| lead.lead_id == lead_id)
            .cloned()
            .collect(),
        None => leads.to_vec(),
    };
    dedupe_leads(filtered)
}

fn ensure_machine_registered(machine_id: &str) -> DynResult<()> {
    if registered_machine_ids()
        .into_iter()
        .any(|id| id == machine_id)
    {
        return Ok(());
    }
    Err(format!("unsupported machine id: {machine_id}").into())
}

fn resolve_lane_for_record<'a>(
    manifest: &'a TargetLaneManifest,
    record: &DeriveRecord,
) -> Option<&'a TargetLaneRecord> {
    manifest
        .resolve_family(&record.family)
        .into_iter()
        .find(|lane| {
            record.expected_proof_classes.is_empty()
                || record.expected_proof_classes.iter().any(|proof| {
                    lane.proof_class_allowlist
                        .iter()
                        .any(|allowed| allowed == proof)
                })
        })
}

fn select_transition_from_snapshot_record(
    record: &DeriveRecord,
    transition_id: Option<&str>,
) -> Option<MachineTransitionSelection> {
    let build = |snapshot: &StateMachineSnapshot,
                 transition: &fat_query::state_machines::StateMachineTransition| {
        MachineTransitionSelection {
            machine_id: snapshot.machine.machine_id.clone(),
            hypothesis_id: snapshot.hypothesis_id.clone(),
            transition_id: transition.transition_id.clone(),
            event_id: transition.event_id.clone(),
            source_state: snapshot.machine.describe_state(&transition.source_state),
            target_state: snapshot.machine.describe_state(&transition.target_state),
            required_states: transition
                .required_states
                .iter()
                .map(|state| snapshot.machine.describe_state(state))
                .collect(),
            expected_proof_class: transition.expected_proof_class.clone(),
            rationale: transition.rationale.clone(),
        }
    };

    record
        .machines
        .iter()
        .flat_map(|snapshot| {
            snapshot
                .machine
                .transitions
                .iter()
                .filter(|transition| transition.forbidden)
                .filter(|transition| {
                    transition_id.is_none_or(|target| transition.transition_id == target)
                })
                .map(move |transition| build(snapshot, transition))
        })
        .find(|selection| {
            record.expected_proof_classes.is_empty()
                || selection
                    .expected_proof_class
                    .as_ref()
                    .is_some_and(|expected| {
                        record
                            .expected_proof_classes
                            .iter()
                            .any(|value| value == expected)
                    })
        })
        .or_else(|| {
            record
                .machines
                .iter()
                .flat_map(|snapshot| {
                    snapshot
                        .machine
                        .transitions
                        .iter()
                        .filter(|transition| transition.forbidden)
                        .filter(|transition| {
                            transition_id.is_none_or(|target| transition.transition_id == target)
                        })
                        .map(move |transition| build(snapshot, transition))
                })
                .next()
        })
}

fn adapter_kind_name(adapter: &LaneAdapter) -> String {
    match adapter {
        LaneAdapter::BrowserLifetimeWebtest { .. } => "browser-lifetime-webtest".into(),
        LaneAdapter::DirectCliSize { .. } => "direct-cli-size".into(),
        LaneAdapter::StderrProofProtocol { .. } => "stderr-proof-protocol".into(),
        LaneAdapter::StderrProofValidation { .. } => "stderr-proof-validation".into(),
        LaneAdapter::AndroidAdbIcc { .. } => "android-adb-icc".into(),
        LaneAdapter::AndroidInstrumentationWebview { .. } => {
            "android-instrumentation-webview".into()
        }
        LaneAdapter::AndroidAdbProvider { .. } => "android-adb-provider".into(),
        LaneAdapter::AndroidInstrumentationNative { .. } => "android-instrumentation-native".into(),
    }
}

fn find_event_path_matches_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
    event_id: &str,
) -> Vec<EventPathMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .transitions
                .iter()
                .filter(|transition| transition.forbidden && transition.event_id == event_id)
                .map(|transition| EventPathMatch {
                    lead_id: record.lead_id.clone(),
                    symbol: record.symbol.clone(),
                    machine_id: snapshot.machine.machine_id.clone(),
                    hypothesis_id: snapshot.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    source_state: transition.source_state.clone(),
                    target_state: transition.target_state.clone(),
                    event_id: transition.event_id.clone(),
                    expected_proof_class: transition.expected_proof_class.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn find_invalidation_paths_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
) -> Vec<InvalidationPathMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .invalidation_edges
                .iter()
                .map(|edge| InvalidationPathMatch {
                    lead_id: record.lead_id.clone(),
                    symbol: record.symbol.clone(),
                    machine_id: snapshot.machine.machine_id.clone(),
                    hypothesis_id: snapshot.hypothesis_id.clone(),
                    source_actor: edge.source_actor.clone(),
                    source_state: edge.source_state.clone(),
                    event_id: edge.event_id.clone(),
                    target_actor: edge.target_actor.clone(),
                    invalidated_state: edge.invalidated_state.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn find_coexistence_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
) -> Vec<CoexistenceMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .transitions
                .iter()
                .filter(|transition| {
                    transition.forbidden
                        && transition.target_state == "OwnerDestroyed"
                        && !transition.required_states.is_empty()
                })
                .map(|transition| CoexistenceMatch {
                    lead_id: record.lead_id.clone(),
                    symbol: record.symbol.clone(),
                    machine_id: snapshot.machine.machine_id.clone(),
                    hypothesis_id: snapshot.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    conflict_states: transition.required_states.clone(),
                    event_id: transition.event_id.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn find_ghost_states_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
) -> Vec<GhostStateMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .nodes
                .iter()
                .filter(|node| node.region_id == "ghost-states")
                .map(|node| GhostStateMatch {
                    lead_id: record.lead_id.clone(),
                    symbol: record.symbol.clone(),
                    machine_id: snapshot.machine.machine_id.clone(),
                    hypothesis_id: snapshot.hypothesis_id.clone(),
                    state_id: node.state_id.clone(),
                    path: snapshot.machine.describe_state(&node.state_id),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn find_state_condition_matches_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
    required_state: &str,
) -> Vec<StateConditionMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .transitions
                .iter()
                .filter(|transition| {
                    transition
                        .required_states
                        .iter()
                        .any(|state| state == required_state)
                })
                .map(|transition| StateConditionMatch {
                    lead_id: record.lead_id.clone(),
                    symbol: record.symbol.clone(),
                    machine_id: snapshot.machine.machine_id.clone(),
                    hypothesis_id: snapshot.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    required_state: required_state.to_string(),
                    event_id: transition.event_id.clone(),
                    target_state: transition.target_state.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn find_counterfactual_matches_in_snapshot(
    snapshot: &DeriveOutput,
    machine_id: &str,
    guard_id: Option<&str>,
) -> Vec<CounterfactualTransitionMatch> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            record.machines.iter().filter_map(move |snapshot| {
                if snapshot.machine.machine_id != machine_id {
                    return None;
                }
                Some((record, snapshot))
            })
        })
        .flat_map(|(record, snapshot)| {
            snapshot
                .machine
                .transitions
                .iter()
                .filter(|transition| transition.forbidden)
                .flat_map(|transition| {
                    transition
                        .required_guards
                        .iter()
                        .filter(|guard| guard_id.map(|value| *guard == value).unwrap_or(true))
                        .map(|guard| CounterfactualTransitionMatch {
                            lead_id: record.lead_id.clone(),
                            symbol: record.symbol.clone(),
                            machine_id: snapshot.machine.machine_id.clone(),
                            hypothesis_id: snapshot.hypothesis_id.clone(),
                            transition_id: transition.transition_id.clone(),
                            absent_guard: guard.clone(),
                            event_id: transition.event_id.clone(),
                            target_state: transition.target_state.clone(),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn dedupe_leads(leads: Vec<DiscoveryLead>) -> Vec<DiscoveryLead> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for lead in leads {
        if seen.insert(lead.lead_id.clone()) {
            deduped.push(lead);
        }
    }
    deduped
}
