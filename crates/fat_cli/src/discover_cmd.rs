use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fat_core::discovery::{HarnessAttemptRecord, TriageRecord};
use fat_query::adapters::source_clang_facts::{
    maybe_analyze_codeql_database_with_options, maybe_analyze_source_tree_with_options,
    SourceAnalysisOptions,
};
use fat_query::adapters::traits::{ExecutionMode, QueryKind};
use fat_query::attempt_generation::generate_attempt_bindings;
use fat_query::derived::derive_from_fused_source;
use fat_query::discovery::{
    build_discovery_leads, filter_leads_by_family, populate_sibling_candidates, BugFamily,
    DiscoveryLead,
};
use fat_query::discovery_runtime::{execute_harness_plan, execute_harness_plan_with_binding};
use fat_query::discovery_triage::{normalize_triage, TriageInput};
use fat_query::fusion::fuse_source_analysis;
use fat_query::harnesses::{generate_harness_plans, HarnessPlan};
use fat_query::harvesters::{harvest_family_candidates, HarvestReport};
use fat_query::planner::build_source_analysis_plan;
use fat_query::result::{DerivedAnalysis, FusedSourceEvidence, RollResolution};
use fat_query::roll_resolver::resolve_roll_locality;
use fat_query::slice_expander::{evaluate_slice_expansion, repair_source_analysis};
use fat_query::target_lanes::{
    load_target_lane_manifest, preflight_target_lane_manifest, TargetLaneManifest, TargetLaneRecord,
};
use serde::Serialize;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone)]
struct DiscoveryContext {
    target: PathBuf,
    fused: FusedSourceEvidence,
    derived: DerivedAnalysis,
    locality: RollResolution,
    leads: Vec<DiscoveryLead>,
}

#[derive(Debug, Serialize)]
struct DiscoverOutput {
    target: String,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family_filter: Option<String>,
    lead_count: usize,
    leads: Vec<DiscoveryLead>,
}

#[derive(Debug, Serialize)]
struct HarvestOutput {
    manifest: String,
    lane_id: String,
    target: String,
    family: String,
    lead_count: usize,
    leads: Vec<DiscoveryLead>,
    harvest: HarvestReport,
}

#[derive(Debug, Serialize)]
struct RunOutput {
    manifest: String,
    lane_id: String,
    target: String,
    family: String,
    lead_count: usize,
    harness_plan_count: usize,
    plans: Vec<HarnessPlan>,
    attempts: Vec<HarnessAttemptRecord>,
    triage: Vec<TriageRecord>,
}

pub fn run_legacy(
    fixture: Option<&Path>,
    repo: Option<&Path>,
    family: Option<&str>,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    run_leads(fixture, repo, family, top_k, mode, debug_bundle_dir, json)
}

pub fn run_leads(
    fixture: Option<&Path>,
    repo: Option<&Path>,
    family: Option<&str>,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let target = fixture
        .or(repo)
        .ok_or("discover leads requires --fixture or --repo")?;
    let family_filter = family.and_then(BugFamily::parse);
    let context = analyze_target(target, family_filter.clone(), top_k, mode, debug_bundle_dir)?;

    if json {
        let output = DiscoverOutput {
            target: context.target.display().to_string(),
            mode: mode.as_str().into(),
            family_filter: family_filter.map(|value| value.as_str().to_string()),
            lead_count: context.leads.len(),
            leads: context.leads,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Discover Leads"));
    println!(
        "{}",
        palette.kv("target", context.target.display().to_string())
    );
    println!("{}", palette.kv("mode", mode.as_str()));
    if let Some(family_filter) = family_filter {
        println!("{}", palette.kv("family", family_filter.as_str()));
    }
    println!(
        "{}",
        palette.kv("lead_count", context.leads.len().to_string())
    );

    for lead in context.leads.iter().take(top_k) {
        println!();
        println!("{}", palette.kv("lead", &lead.symbol));
        println!("{}", palette.kv("family", lead.family.as_str()));
        println!(
            "{}",
            palette.kv("confidence", format!("{:.2}", lead.family_confidence))
        );
        println!("{}", palette.kv("locality", format!("{:?}", lead.locality)));
        if let Some(trigger) = lead.suggested_trigger_recipe.first() {
            println!("{}", palette.kv("trigger", &trigger.kind));
        }
        if let Some(signal) = lead.expected_proof_signal.first() {
            println!("{}", palette.kv("proof", &signal.kind));
        }
    }

    Ok(())
}

pub fn collect_leads(
    fixture: Option<&Path>,
    repo: Option<&Path>,
    manifest: Option<&Path>,
    family: Option<&str>,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
) -> DynResult<Vec<DiscoveryLead>> {
    if let Some(manifest_path) = manifest {
        return collect_leads_from_manifest(
            manifest_path,
            family.ok_or("discover leads with --manifest requires --family")?,
            top_k,
            mode,
            debug_bundle_dir,
        );
    }
    let target = fixture
        .or(repo)
        .ok_or("discover leads requires --fixture or --repo")?;
    let family_filter = family.and_then(BugFamily::parse);
    let context = analyze_target(target, family_filter, top_k, mode, debug_bundle_dir)?;
    Ok(context.leads)
}

pub fn collect_leads_from_manifest(
    manifest_path: &Path,
    family: &str,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
) -> DynResult<Vec<DiscoveryLead>> {
    let manifest = load_target_lane_manifest(manifest_path)
        .map_err(|e| format!("failed to load target lanes: {e}"))?;
    let family = parse_family_required(family)?;
    let mut leads = Vec::new();
    for lane in manifest.resolve_family(family.as_str()) {
        let context = analyze_target(
            Path::new(&lane.source_root),
            Some(family.clone()),
            top_k,
            mode,
            debug_bundle_dir,
        )?;
        leads.extend(context.leads);
    }
    Ok(leads)
}

pub fn run_preflight(manifest_path: &Path, json: bool) -> DynResult<()> {
    let manifest = load_target_lane_manifest(manifest_path)
        .map_err(|e| format!("failed to load target lanes: {e}"))?;
    let report = preflight_target_lane_manifest(&manifest);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Discover Preflight"));
    println!(
        "{}",
        palette.kv("manifest", manifest_path.display().to_string())
    );
    println!("{}", palette.kv("ok", report.ok.to_string()));
    for lane in report.lanes {
        println!();
        println!("{}", palette.kv("lane", lane.lane_id));
        println!("{}", palette.kv("ok", lane.ok.to_string()));
        for check in lane.checks {
            let label = format!("check:{}", check.check_id);
            println!(
                "{}",
                palette.kv(
                    label.as_str(),
                    format!("{} ({})", check.passed, check.detail)
                )
            );
        }
    }
    Ok(())
}

pub fn run_harvest(
    manifest_path: &Path,
    family: &str,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let manifest = load_target_lane_manifest(manifest_path)
        .map_err(|e| format!("failed to load target lanes: {e}"))?;
    let family = parse_family_required(family)?;
    let lane = resolve_primary_lane(&manifest, family.clone())?;
    let context = analyze_target(
        Path::new(&lane.source_root),
        Some(family.clone()),
        top_k,
        mode,
        debug_bundle_dir,
    )?;
    let harvest = harvest_family_candidates(
        family.clone(),
        &context.fused,
        &context.derived,
        &context.locality,
    );

    if json {
        let output = HarvestOutput {
            manifest: manifest_path.display().to_string(),
            lane_id: lane.lane_id.clone(),
            target: context.target.display().to_string(),
            family: family.as_str().to_string(),
            lead_count: context.leads.len(),
            leads: context.leads,
            harvest,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Discover Harvest"));
    println!(
        "{}",
        palette.kv("manifest", manifest_path.display().to_string())
    );
    println!("{}", palette.kv("lane", &lane.lane_id));
    println!("{}", palette.kv("family", family.as_str()));
    println!(
        "{}",
        palette.kv("target", context.target.display().to_string())
    );
    println!(
        "{}",
        palette.kv("emitted", harvest.emitted.len().to_string())
    );
    println!(
        "{}",
        palette.kv("suppressed", harvest.suppressed.len().to_string())
    );
    Ok(())
}

pub fn run_execute(
    manifest_path: &Path,
    family: &str,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let manifest = load_target_lane_manifest(manifest_path)
        .map_err(|e| format!("failed to load target lanes: {e}"))?;
    let family = parse_family_required(family)?;
    let lane = resolve_primary_lane(&manifest, family.clone())?;
    let context = analyze_target(
        Path::new(&lane.source_root),
        Some(family.clone()),
        top_k,
        mode,
        debug_bundle_dir,
    )?;

    let plans = context
        .leads
        .iter()
        .take(top_k)
        .flat_map(|lead| generate_harness_plans(lead, &manifest))
        .collect::<Vec<_>>();

    let mut attempts = Vec::new();
    let mut triage = Vec::new();
    for plan in &plans {
        let generated_attempts = generate_attempt_bindings(plan);
        if generated_attempts.is_empty() {
            let execution = execute_harness_plan(plan, 0)
                .map_err(|e| format!("failed to execute harness {}: {}", plan.harness_id, e))?;
            triage.push(normalize_triage(
                &execution.attempt,
                TriageInput::CapturedOutput {
                    stdout: execution.stdout,
                    stderr: execution.stderr,
                    exit_code: execution.exit_code,
                },
            ));
            attempts.push(execution.attempt);
            continue;
        }

        for generated in &generated_attempts {
            let execution = execute_harness_plan_with_binding(plan, generated, 0).map_err(|e| {
                format!(
                    "failed to execute harness {} binding {}: {}",
                    plan.harness_id, generated.binding_id, e
                )
            })?;
            triage.push(normalize_triage(
                &execution.attempt,
                TriageInput::CapturedOutput {
                    stdout: execution.stdout,
                    stderr: execution.stderr,
                    exit_code: execution.exit_code,
                },
            ));
            attempts.push(execution.attempt);
        }
    }

    if json {
        let output = RunOutput {
            manifest: manifest_path.display().to_string(),
            lane_id: lane.lane_id.clone(),
            target: context.target.display().to_string(),
            family: family.as_str().to_string(),
            lead_count: context.leads.len(),
            harness_plan_count: plans.len(),
            plans,
            attempts,
            triage,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Discover Run"));
    println!(
        "{}",
        palette.kv("manifest", manifest_path.display().to_string())
    );
    println!("{}", palette.kv("lane", &lane.lane_id));
    println!("{}", palette.kv("family", family.as_str()));
    println!("{}", palette.kv("plans", plans.len().to_string()));
    println!("{}", palette.kv("attempts", attempts.len().to_string()));
    println!("{}", palette.kv("triage", triage.len().to_string()));
    Ok(())
}

pub fn run_triage(attempt_record: &Path, json: bool) -> DynResult<()> {
    let attempt: HarnessAttemptRecord = serde_json::from_str(&fs::read_to_string(attempt_record)?)
        .map_err(|e| format!("invalid harness attempt record: {e}"))?;
    let stdout = read_capture_file(Path::new(&attempt.artifact_root).join("stdout.txt"))?;
    let stderr = read_capture_file(Path::new(&attempt.artifact_root).join("stderr.txt"))?;
    let triage = normalize_triage(
        &attempt,
        TriageInput::CapturedOutput {
            stdout,
            stderr,
            exit_code: None,
        },
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&triage)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Discover Triage"));
    println!("{}", palette.kv("attempt", &attempt.harness_attempt_id));
    if let Some(outcome) = triage.outcome {
        println!("{}", palette.kv("outcome", outcome.as_str()));
    }
    println!("{}", palette.kv("summary", &triage.summary));
    Ok(())
}

fn analyze_target(
    target: &Path,
    family_filter: Option<BugFamily>,
    top_k: usize,
    mode: ExecutionMode,
    debug_bundle_dir: Option<&Path>,
) -> DynResult<DiscoveryContext> {
    let source_plan = build_source_analysis_plan(target, QueryKind::Invariant, mode)
        .map_err(|e| format!("source planning failed: {e}"))?;
    let source_options = SourceAnalysisOptions {
        mode,
        debug_bundle_dir: debug_bundle_dir.map(PathBuf::from),
        budgets: Some(source_plan.budgets.clone()),
    };
    let analysis_root = source_plan.analysis_root.clone();
    let mut source_analysis = if let Some(codeql_db_root) = source_plan.codeql_db_root.as_ref() {
        maybe_analyze_codeql_database_with_options(&analysis_root, codeql_db_root, &source_options)
            .map_err(|e| format!("source analysis failed: {e}"))?
    } else {
        maybe_analyze_source_tree_with_options(&analysis_root, &source_options)
            .map_err(|e| format!("source analysis failed: {e}"))?
    };
    if let Some(summary) = source_analysis.as_mut() {
        repair_source_analysis(&analysis_root, summary, &source_plan.budgets)
            .map_err(|e| format!("slice repair failed: {e}"))?;
    }
    let fused = fuse_source_analysis(source_analysis.as_ref());
    let derived = derive_from_fused_source(&fused);
    let _slice_expansion = evaluate_slice_expansion(source_analysis.as_ref(), &derived);
    let locality = resolve_roll_locality(&analysis_root)
        .map_err(|e| format!("roll resolution failed: {e}"))?;
    let mut leads = filter_leads_by_family(
        build_discovery_leads(&fused, &derived, &locality),
        family_filter,
    );
    populate_sibling_candidates(&mut leads, &fused, &derived, &locality, top_k);
    Ok(DiscoveryContext {
        target: analysis_root,
        fused,
        derived,
        locality,
        leads,
    })
}

fn parse_family_required(value: &str) -> DynResult<BugFamily> {
    BugFamily::parse(value).ok_or_else(|| format!("unsupported discovery family {value}").into())
}

fn resolve_primary_lane(
    manifest: &TargetLaneManifest,
    family: BugFamily,
) -> DynResult<&TargetLaneRecord> {
    manifest
        .resolve_family(family.as_str())
        .into_iter()
        .next()
        .ok_or_else(|| format!("no target lane configured for family {}", family.as_str()).into())
}

fn read_capture_file(path: PathBuf) -> DynResult<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(path)?)
}
