use crate::adapters::source;
use crate::adapters::source_clang_facts::{
    maybe_analyze_source_tree_with_options, SourceAnalysisOptions,
};
use crate::adapters::traits::{ExecutionMode, QueryKind};
use crate::attempt_generation::generate_attempt_bindings;
use crate::derived::derive_from_fused_source;
use crate::discovery::filter_leads_by_family;
use crate::discovery::{build_discovery_leads, populate_sibling_candidates, BugFamily};
use crate::discovery_runtime::{execute_harness_plan, execute_harness_plan_with_binding};
use crate::discovery_triage::{normalize_triage, TriageInput};
use crate::fusion::fuse_source_analysis;
use crate::harnesses::generate_harness_plans;
use crate::harvesters::harvest_family_candidates;
use crate::planner::{build_source_analysis_plan, ResourceBudgets};
use crate::replay::rank_replay_candidates;
use crate::result::{ParseStatus, ReplayAnalysis, SourceAnalysisSummary};
use crate::roll_resolver::resolve_roll_locality;
use crate::target_lanes::{TargetLaneManifest, TargetLaneRecord};
use crate::variant_hunter::hunt_variants;
use fat_core::discovery::{
    DiscoveryLeadRecord, DiscoveryLifecycleStatus, DiscoveryOutcomeClass,
    DiscoveryProofSignalRecord, DiscoveryStateHypothesisRecord, DiscoveryTriggerRecipeStepRecord,
    ForbiddenTransitionRecord, HarnessAttemptRecord, HarvesterExpansionRecord,
};
use fat_core::runtime_store::RuntimeStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayBenchmarkManifest {
    pub family: String,
    pub top_k: usize,
    pub cases: Vec<ReplayBenchmarkManifestCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayBenchmarkManifestCase {
    pub id: String,
    pub fixture: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayBenchmarkCase {
    pub id: String,
    pub kind: String,
    pub family: Option<String>,
    pub language: String,
    pub file_name: String,
    pub compile_args: Vec<String>,
    pub source: String,
    pub reference_symbols: Vec<String>,
    pub surface_candidate: String,
    pub variant_candidate: Option<String>,
    #[serde(default)]
    pub baseline_candidates: Vec<String>,
    #[serde(default)]
    pub variant_baseline_candidates: Vec<String>,
    #[serde(default)]
    pub roll_metadata: Option<ReplayBenchmarkRollMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkRollMetadata {
    #[serde(default)]
    pub likely_upstream_repo: Option<String>,
    #[serde(default)]
    pub vendored_nearby_path: Option<String>,
    #[serde(default)]
    pub local_patch_touching_vendored_code: bool,
    #[serde(default)]
    pub no_local_vulnerable_source_likely: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkCaseResult {
    pub id: String,
    pub kind: String,
    pub family: String,
    pub language: String,
    pub parse_success: bool,
    /// Why the parse failed, when it did. The adapter records the backend's own
    /// error; dropping it here is what made a host-specific parse failure
    /// impossible to diagnose from a benchmark run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_diagnostic: Option<String>,
    pub tu_resolution_success: bool,
    pub replay_rank: usize,
    pub replay_score: i32,
    pub replay_top1: bool,
    pub replay_top3: bool,
    pub scanner_rank: usize,
    pub scanner_top1: bool,
    pub scanner_top3: bool,
    pub variant_rank: usize,
    pub variant_score: i32,
    pub variant_top1: bool,
    pub variant_top3: bool,
    pub discovery_lead_count: usize,
    #[serde(default)]
    pub discovery_top_family: Option<String>,
    pub lead_family_match: bool,
    pub sibling_rank: usize,
    pub sibling_top1: bool,
    pub sibling_top3: bool,
    pub queued_leads: usize,
    pub harvester_expansions: usize,
    pub harness_attempts: usize,
    pub unique_attempt_count: usize,
    pub effective_unique_attempt_count: usize,
    pub unique_resolved_command_count: usize,
    pub unique_shape_count: usize,
    pub binding_compression_rate: f64,
    pub harness_attempt_valid: bool,
    pub proof_yield: bool,
    #[serde(default)]
    pub proof_outcome: Option<String>,
    #[serde(default)]
    pub first_signal_attempt_rank: Option<usize>,
    pub no_signal_attempts: usize,
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub generator_id: Option<String>,
    pub locality_blocked_correct: bool,
    pub trigger_recipe_coverage: bool,
    pub proof_signal_family_correctness: bool,
    pub locality_correct: bool,
    pub locality: String,
    pub allow_vendored_scan: bool,
    pub vendored_lead_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkMetrics {
    pub parse_success: f64,
    pub tu_resolution_success: f64,
    pub replay_top1: f64,
    pub replay_top3: f64,
    pub scanner_top3: f64,
    pub precision_at_3: f64,
    pub variant_top1: f64,
    pub variant_top3: f64,
    pub variant_precision_at_3: f64,
    pub sibling_top1: f64,
    pub sibling_top3: f64,
    pub lead_queue_rate: f64,
    pub harvester_expansion_rate: f64,
    pub harness_attempt_validity: f64,
    pub attempt_generation_rate: f64,
    pub average_unique_attempt_count: f64,
    pub average_effective_unique_attempt_count: f64,
    pub average_unique_resolved_command_count: f64,
    pub average_unique_shape_count: f64,
    pub binding_compression_rate: f64,
    pub no_signal_rate: f64,
    pub first_signal_attempt_rank: f64,
    pub proof_yield: f64,
    pub locality_blocked_correctness: f64,
    pub family_match_rate: f64,
    pub hard_negative_precision: f64,
    pub vendored_locality_accuracy: f64,
    pub trigger_recipe_coverage: f64,
    pub proof_signal_family_correctness: f64,
    pub proof_yield_per_lane: BTreeMap<String, f64>,
    pub proof_yield_per_generator: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkFamilyMetrics {
    pub positive_cases: usize,
    pub negative_cases: usize,
    pub replay_top1: f64,
    pub replay_top3: f64,
    pub scanner_top3: f64,
    pub precision_at_3: f64,
    pub variant_top1: f64,
    pub variant_top3: f64,
    pub variant_precision_at_3: f64,
    pub sibling_top1: f64,
    pub sibling_top3: f64,
    pub lead_queue_rate: f64,
    pub harvester_expansion_rate: f64,
    pub harness_attempt_validity: f64,
    pub proof_yield: f64,
    pub family_match_rate: f64,
    pub hard_negative_precision: f64,
    pub trigger_recipe_coverage: f64,
    pub proof_signal_family_correctness: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkSummary {
    pub family: String,
    pub top_k: usize,
    pub metrics: ReplayBenchmarkMetrics,
    pub ablations: BTreeMap<String, ReplayBenchmarkStageMetrics>,
    pub family_metrics: BTreeMap<String, ReplayBenchmarkFamilyMetrics>,
    pub cases: Vec<ReplayBenchmarkCaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkStageMetrics {
    pub positive_cases: usize,
    pub negative_cases: usize,
    pub top1: f64,
    pub top3: f64,
    pub precision_at_3: f64,
}

pub fn run_replay_benchmark(manifest_path: &Path) -> Result<ReplayBenchmarkSummary, String> {
    let manifest = load_manifest(manifest_path)?;
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| format!("manifest has no parent: {}", manifest_path.display()))?;
    let mut evaluations = Vec::new();
    for manifest_case in &manifest.cases {
        let case_path = manifest_dir.join(&manifest_case.fixture);
        let case = load_case(&case_path)?;
        if case.id != manifest_case.id {
            return Err(format!(
                "manifest/case id mismatch: manifest={} fixture={}",
                manifest_case.id, case.id
            ));
        }
        evaluations.push(run_case(&case, manifest.top_k)?);
    }

    let metrics = aggregate_metrics(&evaluations, manifest.top_k);
    let ablations = aggregate_ablation_metrics(&evaluations, manifest.top_k);
    let family_metrics = aggregate_family_metrics(&evaluations, manifest.top_k);
    Ok(ReplayBenchmarkSummary {
        family: manifest.family,
        top_k: manifest.top_k,
        metrics,
        ablations,
        family_metrics,
        cases: evaluations,
    })
}

fn run_case(case: &ReplayBenchmarkCase, top_k: usize) -> Result<ReplayBenchmarkCaseResult, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let source_path = dir.path().join(&case.file_name);
    fs::write(&source_path, &case.source)
        .map_err(|e| format!("write {} failed: {}", source_path.display(), e))?;
    fs::write(
        dir.path().join("compile_commands.json"),
        serde_json::to_string_pretty(&vec![serde_json::json!({
            "directory": dir.path(),
            "file": source_path,
            "arguments": case
                .compile_args
                .iter()
                .cloned()
                .chain([source_path.display().to_string()])
                .collect::<Vec<_>>(),
        })])
        .map_err(|e| format!("serialize compile_commands.json failed: {e}"))?,
    )
    .map_err(|e| format!("write compile_commands.json failed: {e}"))?;
    if let Some(roll_metadata) = &case.roll_metadata {
        fs::write(
            dir.path().join("fat-roll-metadata.json"),
            serde_json::to_string_pretty(roll_metadata)
                .map_err(|e| format!("serialize roll metadata failed: {e}"))?,
        )
        .map_err(|e| format!("write fat-roll-metadata.json failed: {e}"))?;
    }

    let plan =
        build_source_analysis_plan(dir.path(), QueryKind::PatchInvariant, ExecutionMode::Deep)
            .map_err(|e| format!("build source analysis plan failed: {e}"))?;
    let summary = maybe_analyze_source_tree_with_options(
        dir.path(),
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: None,
            budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
        },
    )?;
    let fused = fuse_source_analysis(summary.as_ref());
    let derived = derive_from_fused_source(&fused);
    let replay = rank_replay_candidates(
        &case.reference_symbols,
        &fused,
        &derived,
        &case.baseline_candidates,
    );
    let scanner_rank = scanner_rank_for_surface(dir.path(), &case.surface_candidate)?;
    let scanner_top1 = scanner_rank == 1;
    let replay_rank = rank_for_symbol(&replay, &case.surface_candidate);
    let replay_score = replay_score(&replay, &case.surface_candidate);
    let locality = resolve_roll_locality(dir.path())
        .map_err(|e| format!("resolve roll locality failed: {e}"))?;
    let variant_baseline_candidates = if case.variant_baseline_candidates.is_empty() {
        &case.baseline_candidates
    } else {
        &case.variant_baseline_candidates
    };
    let variant_leads = hunt_variants(
        &replay,
        &fused,
        &derived,
        &locality,
        variant_baseline_candidates,
        1,
    );
    let benchmark_family = case.family.clone().unwrap_or_else(|| "unspecified".into());
    let mut discovery_leads = build_discovery_leads(&fused, &derived, &locality);
    populate_sibling_candidates(&mut discovery_leads, &fused, &derived, &locality, top_k);
    let promoted_family = case.family.as_deref().and_then(BugFamily::parse);
    let proof_loop = run_discovery_proof_loop(
        case,
        dir.path(),
        promoted_family.clone(),
        &fused,
        &derived,
        &locality,
        &discovery_leads,
        top_k,
    )?;
    let variant_rank = variant_rank_for_case(case, &variant_leads);
    let variant_score = variant_score_for_case(case, &variant_leads);
    let vendored_lead_present = variant_leads
        .iter()
        .any(|lead| lead.symbol.starts_with("vendored-neighborhood:"));
    let discovery_top_family = discovery_leads
        .first()
        .map(|lead| lead.family.as_str().to_string());
    let lead_family_match = discovery_leads
        .first()
        .map(|lead| lead.family.benchmark_family() == benchmark_family.as_str())
        .unwrap_or(false);
    let sibling_rank = discovery_sibling_rank_for_case(case, &discovery_leads);
    let trigger_recipe_coverage = discovery_leads
        .first()
        .is_some_and(|lead| !lead.suggested_trigger_recipe.is_empty());
    let proof_signal_family_correctness = discovery_leads.first().is_some_and(|lead| {
        proof_signal_matches_family(lead.family.clone(), case.family.as_deref())
    });
    let locality_correct = locality_matches_expectation(case.roll_metadata.as_ref(), &locality);

    let parse_success = summary.as_ref().is_some_and(|summary| {
        !summary.reports.is_empty()
            && summary
                .reports
                .iter()
                .all(|report| report.diagnostics.parse != ParseStatus::Failed)
    });
    let parse_diagnostic = if parse_success {
        None
    } else {
        Some(describe_parse_failure(summary.as_ref()))
    };
    let tu_resolution_success = summary.is_some() && !plan.adapter_ids.is_empty();
    let variant_top3 = case.variant_candidate.is_some() && variant_rank <= top_k;
    let sibling_top3 = sibling_rank <= top_k;

    Ok(ReplayBenchmarkCaseResult {
        id: case.id.clone(),
        kind: case.kind.clone(),
        family: benchmark_family,
        language: case.language.clone(),
        parse_success,
        parse_diagnostic,
        tu_resolution_success,
        replay_rank,
        replay_score,
        replay_top1: replay_rank == 1,
        replay_top3: replay_rank <= top_k,
        scanner_rank,
        scanner_top1,
        scanner_top3: scanner_rank <= top_k,
        variant_rank,
        variant_score,
        variant_top1: case.variant_candidate.is_some() && variant_rank == 1,
        variant_top3,
        discovery_lead_count: discovery_leads.len(),
        discovery_top_family,
        lead_family_match,
        sibling_rank,
        sibling_top1: sibling_rank == 1,
        sibling_top3,
        queued_leads: proof_loop.queued_leads,
        harvester_expansions: proof_loop.harvester_expansions,
        harness_attempts: proof_loop.harness_attempts,
        unique_attempt_count: proof_loop.unique_attempt_count,
        effective_unique_attempt_count: proof_loop.effective_unique_attempt_count,
        unique_resolved_command_count: proof_loop.unique_resolved_command_count,
        unique_shape_count: proof_loop.unique_shape_count,
        binding_compression_rate: proof_loop.binding_compression_rate,
        harness_attempt_valid: proof_loop.harness_attempt_valid,
        proof_yield: proof_loop.proof_yield,
        proof_outcome: proof_loop.proof_outcome,
        first_signal_attempt_rank: proof_loop.first_signal_attempt_rank,
        no_signal_attempts: proof_loop.no_signal_attempts,
        lane_id: proof_loop.lane_id,
        generator_id: proof_loop.generator_id,
        locality_blocked_correct: proof_loop.locality_blocked_correct,
        trigger_recipe_coverage,
        proof_signal_family_correctness,
        locality_correct,
        locality: format!("{:?}", locality.locality),
        allow_vendored_scan: locality.allow_vendored_scan,
        vendored_lead_present,
    })
}

#[derive(Debug, Default)]
struct DiscoveryProofLoopResult {
    queued_leads: usize,
    harvester_expansions: usize,
    harness_attempts: usize,
    unique_attempt_count: usize,
    effective_unique_attempt_count: usize,
    unique_resolved_command_count: usize,
    unique_shape_count: usize,
    binding_compression_rate: f64,
    harness_attempt_valid: bool,
    proof_yield: bool,
    proof_outcome: Option<String>,
    first_signal_attempt_rank: Option<usize>,
    no_signal_attempts: usize,
    lane_id: Option<String>,
    generator_id: Option<String>,
    locality_blocked_correct: bool,
}

fn run_discovery_proof_loop(
    case: &ReplayBenchmarkCase,
    root: &Path,
    promoted_family: Option<BugFamily>,
    fused: &crate::result::FusedSourceEvidence,
    derived: &crate::result::DerivedAnalysis,
    locality: &crate::result::RollResolution,
    discovery_leads: &[crate::discovery::DiscoveryLead],
    top_k: usize,
) -> Result<DiscoveryProofLoopResult, String> {
    let Some(promoted_family) = promoted_family else {
        return Ok(DiscoveryProofLoopResult::default());
    };

    let store = RuntimeStore::open(root.join("benchmark-runtime-store"))
        .map_err(|e| format!("open benchmark runtime store failed: {e}"))?;
    let promoted_leads =
        filter_leads_by_family(discovery_leads.to_vec(), Some(promoted_family.clone()));
    for lead in &promoted_leads {
        store
            .write_discovery_lead(&DiscoveryLeadRecord {
                discovery_lead_id: lead.lead_id.clone(),
                lifecycle: DiscoveryLifecycleStatus::Queued,
                family: lead.family.as_str().into(),
                symbol: lead.symbol.clone(),
                family_confidence: lead.family_confidence,
                family_pack_version: lead.family_pack_version.clone(),
                analysis_scope: format!("{:?}", lead.analysis_scope),
                candidate_status: format!("{:?}", lead.candidate_status),
                locality: format!("{:?}", lead.locality),
                trigger_recipe: lead
                    .suggested_trigger_recipe
                    .iter()
                    .map(|step| DiscoveryTriggerRecipeStepRecord {
                        kind: step.kind.clone(),
                        detail: step.detail.clone(),
                    })
                    .collect(),
                expected_proof_signals: lead
                    .expected_proof_signal
                    .iter()
                    .map(|signal| DiscoveryProofSignalRecord {
                        kind: signal.kind.clone(),
                        detail: signal.detail.clone(),
                    })
                    .collect(),
                state_hypotheses: lead
                    .state_hypotheses
                    .iter()
                    .map(|hypothesis| DiscoveryStateHypothesisRecord {
                        hypothesis_id: hypothesis.hypothesis_id.clone(),
                        machine_id: hypothesis.machine_id.clone(),
                        actors: hypothesis.actors.clone(),
                        active_regions: hypothesis.active_regions.clone(),
                        key_states: hypothesis.key_states.clone(),
                        ghost_states: hypothesis.ghost_states.clone(),
                        invalidating_events: hypothesis.invalidating_events.clone(),
                        required_guards: hypothesis.required_guards.clone(),
                        forbidden_transitions: hypothesis
                            .forbidden_transitions
                            .iter()
                            .map(|transition| ForbiddenTransitionRecord {
                                transition_id: transition.transition_id.clone(),
                                expected_proof_class: transition.expected_proof_class.clone(),
                                rationale: transition.rationale.clone(),
                            })
                            .collect(),
                        confidence: hypothesis.confidence,
                    })
                    .collect(),
                summary: lead
                    .why_matched
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "benchmark discovery lead".into()),
            })
            .map_err(|e| format!("write discovery lead failed: {e}"))?;
    }

    let harvest = harvest_family_candidates(promoted_family.clone(), fused, derived, locality);
    for (index, candidate) in harvest.emitted.iter().enumerate() {
        store
            .write_harvester_expansion(&HarvesterExpansionRecord {
                harvester_expansion_id: format!("{}::{}", case.id, index),
                lead_id: promoted_leads
                    .first()
                    .map(|lead| lead.lead_id.clone())
                    .unwrap_or_else(|| format!("{}::no-lead", case.id)),
                lifecycle: DiscoveryLifecycleStatus::Ready,
                attempt_plan_hash: candidate.fingerprint.clone(),
                artifact_root: root
                    .join("benchmark-artifacts")
                    .join(&candidate.fingerprint)
                    .display()
                    .to_string(),
                retry_count: 0,
                sibling_fingerprint: Some(candidate.fingerprint.clone()),
                family_overlap: candidate.family_overlap.clone(),
                role_overlap: candidate.role_overlap.clone(),
                locality_notes: candidate.locality_notes.clone(),
                suppression_reasons: candidate.suppression_reasons.clone(),
            })
            .map_err(|e| format!("write harvester expansion failed: {e}"))?;
    }

    let manifest = synthetic_manifest_for_case(case, root, &promoted_family);
    let plans = promoted_leads
        .iter()
        .take(top_k)
        .flat_map(|lead| generate_harness_plans(lead, &manifest))
        .collect::<Vec<_>>();
    let locality_blocked_expected =
        locality.no_local_vulnerable_source_likely && !locality.allow_vendored_scan;
    let locality_blocked_correct = if locality_blocked_expected {
        plans.is_empty()
    } else {
        true
    };

    let mut triage_records = Vec::new();
    let mut valid_attempts = 0usize;
    let mut harness_attempts = 0usize;
    let mut resolved_runtime_attempts = BTreeSet::new();
    let mut unique_shapes = BTreeSet::new();
    let mut first_signal_attempt_rank = None;
    let mut no_signal_attempts = 0usize;
    let lane_id = plans.first().map(|plan| plan.lane_id.clone());
    let generator_id = plans.first().map(|plan| format!("{:?}", plan.kind));
    for plan in &plans {
        let generated_attempts = generate_attempt_bindings(plan);
        if generated_attempts.is_empty() {
            let execution = execute_harness_plan(plan, 0)
                .map_err(|e| format!("execute benchmark harness failed: {e}"))?;
            harness_attempts += 1;
            if execution.attempt.lifecycle == DiscoveryLifecycleStatus::Completed {
                valid_attempts += 1;
            }
            resolved_runtime_attempts.insert(resolved_runtime_fingerprint(&execution.attempt));
            unique_shapes.insert(shape_fingerprint(&execution.attempt));
            store
                .write_harness_attempt(&execution.attempt)
                .map_err(|e| format!("write harness attempt failed: {e}"))?;
            let triage = normalize_triage(
                &execution.attempt,
                TriageInput::CapturedOutput {
                    stdout: execution.stdout,
                    stderr: execution.stderr,
                    exit_code: execution.exit_code,
                },
            );
            if triage.outcome == Some(DiscoveryOutcomeClass::NoSignal) {
                no_signal_attempts += 1;
            }
            if first_signal_attempt_rank.is_none()
                && triage
                    .outcome
                    .is_some_and(|outcome| matches_proof_family(outcome, &promoted_family))
            {
                first_signal_attempt_rank = Some(harness_attempts);
            }
            store
                .write_triage(&triage)
                .map_err(|e| format!("write triage failed: {e}"))?;
            triage_records.push(triage);
            continue;
        }

        for generated in &generated_attempts {
            let execution = execute_harness_plan_with_binding(plan, generated, 0)
                .map_err(|e| format!("execute benchmark harness failed: {e}"))?;
            harness_attempts += 1;
            if execution.attempt.lifecycle == DiscoveryLifecycleStatus::Completed {
                valid_attempts += 1;
            }
            resolved_runtime_attempts.insert(resolved_runtime_fingerprint(&execution.attempt));
            unique_shapes.insert(shape_fingerprint(&execution.attempt));
            store
                .write_harness_attempt(&execution.attempt)
                .map_err(|e| format!("write harness attempt failed: {e}"))?;
            let triage = normalize_triage(
                &execution.attempt,
                TriageInput::CapturedOutput {
                    stdout: execution.stdout,
                    stderr: execution.stderr,
                    exit_code: execution.exit_code,
                },
            );
            if triage.outcome == Some(DiscoveryOutcomeClass::NoSignal) {
                no_signal_attempts += 1;
            }
            if first_signal_attempt_rank.is_none()
                && triage
                    .outcome
                    .is_some_and(|outcome| matches_proof_family(outcome, &promoted_family))
            {
                first_signal_attempt_rank = Some(harness_attempts);
            }
            store
                .write_triage(&triage)
                .map_err(|e| format!("write triage failed: {e}"))?;
            triage_records.push(triage);
        }
    }

    let proof_outcome = triage_records
        .iter()
        .filter_map(|record| record.outcome)
        .find(|outcome| matches_proof_family(*outcome, &promoted_family))
        .map(|outcome| outcome.as_str().to_string())
        .or_else(|| {
            triage_records
                .iter()
                .find_map(|record| record.outcome.map(|outcome| outcome.as_str().to_string()))
        });
    let proof_yield = case.kind == "positive"
        && triage_records
            .iter()
            .filter_map(|record| record.outcome)
            .any(|outcome| matches_proof_family(outcome, &promoted_family));
    let unique_resolved_command_count = resolved_runtime_attempts.len();
    let unique_shape_count = unique_shapes.len();
    let effective_unique_attempt_count = unique_resolved_command_count;
    let binding_compression_rate = if harness_attempts == 0 {
        0.0
    } else {
        1.0 - (effective_unique_attempt_count as f64 / harness_attempts as f64)
    };

    Ok(DiscoveryProofLoopResult {
        queued_leads: promoted_leads.len(),
        harvester_expansions: harvest.emitted.len(),
        harness_attempts,
        unique_attempt_count: harness_attempts,
        effective_unique_attempt_count,
        unique_resolved_command_count,
        unique_shape_count,
        binding_compression_rate,
        harness_attempt_valid: harness_attempts > 0 && valid_attempts == harness_attempts,
        proof_yield,
        proof_outcome,
        first_signal_attempt_rank,
        no_signal_attempts,
        lane_id,
        generator_id,
        locality_blocked_correct,
    })
}

fn synthetic_manifest_for_case(
    case: &ReplayBenchmarkCase,
    root: &Path,
    family: &BugFamily,
) -> TargetLaneManifest {
    let proof_class = match (family, case.kind.as_str()) {
        (BugFamily::LifetimeReentrancy, "positive") => "asan-use-after-free",
        (BugFamily::SizeStrideArithmetic, "positive") => "asan-heap-buffer-overflow",
        (BugFamily::GpuProtocolOrderLifecycle, "positive") => "guard-trip",
        (BugFamily::ValidationTrustBoundary, "positive") => "bad-message",
        (_, _) => "no-signal",
    };
    let command = match proof_class {
        "asan-use-after-free" => "printf 'ERROR: AddressSanitizer: heap-use-after-free' 1>&2",
        "asan-heap-buffer-overflow" => {
            "printf 'ERROR: AddressSanitizer: heap-buffer-overflow' 1>&2"
        }
        "guard-trip" => "printf 'CHECK failed: device lost ordering invariant' 1>&2",
        "bad-message" => "printf 'Received bad user message: malformed payload' 1>&2",
        _ => "printf 'benchmark-no-signal'",
    };
    let artifact_dir = root.join("benchmark-artifacts");
    let mut required_env = BTreeMap::new();
    required_env.insert("ASAN_OPTIONS".into(), "symbolize=1:detect_leaks=0".into());

    TargetLaneManifest {
        schema_version: crate::target_lanes::TARGET_LANE_SCHEMA_VERSION.into(),
        local_manifest_path_hint: None,
        lanes: vec![TargetLaneRecord {
            lane_id: format!("benchmark-{}", family.as_str()),
            family_allowlist: vec![family.as_str().into()],
            source_root: root.display().to_string(),
            build_dir: root.display().to_string(),
            binary_or_driver: "/bin/sh".into(),
            launcher_command: vec!["/bin/sh".into(), "-lc".into(), command.into()],
            required_env,
            adapter: None,
            timeout_ms: 1_000,
            artifact_dir: artifact_dir.display().to_string(),
            sanitizer_mode: "asan".into(),
            proof_class_allowlist: vec![
                "asan-use-after-free".into(),
                "asan-heap-buffer-overflow".into(),
                "bad-message".into(),
                "guard-trip".into(),
                "no-signal".into(),
            ],
            runtime_capabilities: synthetic_runtime_capabilities_for_family(family),
            preflight_checks: vec![],
        }],
    }
}

fn synthetic_runtime_capabilities_for_family(
    family: &BugFamily,
) -> crate::target_lanes::RuntimeCapabilities {
    match family {
        BugFamily::LifetimeReentrancy => crate::target_lanes::RuntimeCapabilities {
            accepts_callback_count: true,
            accepts_teardown_mode: true,
            accepts_cancellation_mode: true,
            accepts_observer_mutation_mode: true,
            accepts_navigation_mode: true,
            ..Default::default()
        },
        BugFamily::SizeStrideArithmetic => crate::target_lanes::RuntimeCapabilities {
            accepts_arg_size: true,
            accepts_width: true,
            accepts_height: true,
            accepts_row_pitch: true,
            accepts_depth_pitch: true,
            accepts_payload_bytes: true,
            requires_vk_icd: true,
            requires_gpu_backend: true,
            ..Default::default()
        },
        _ => Default::default(),
    }
}

fn matches_proof_family(outcome: DiscoveryOutcomeClass, family: &BugFamily) -> bool {
    matches!(
        (family, outcome),
        (
            BugFamily::LifetimeReentrancy,
            DiscoveryOutcomeClass::AsanUseAfterFree
        ) | (
            BugFamily::SizeStrideArithmetic,
            DiscoveryOutcomeClass::AsanHeapBufferOverflow
        ) | (
            BugFamily::SizeStrideArithmetic,
            DiscoveryOutcomeClass::UbsanIntegerOverflow
        ) | (
            BugFamily::GpuProtocolOrderLifecycle,
            DiscoveryOutcomeClass::GuardTrip
        ) | (
            BugFamily::GpuProtocolOrderLifecycle,
            DiscoveryOutcomeClass::AsanUseAfterFree
        ) | (
            BugFamily::ValidationTrustBoundary,
            DiscoveryOutcomeClass::BadMessage
        ) | (
            BugFamily::ValidationTrustBoundary,
            DiscoveryOutcomeClass::GuardTrip
        )
    )
}

fn aggregate_ablation_metrics(
    evaluations: &[ReplayBenchmarkCaseResult],
    _top_k: usize,
) -> BTreeMap<String, ReplayBenchmarkStageMetrics> {
    let mut stages = BTreeMap::new();
    stages.insert(
        "scanner".into(),
        stage_metrics(
            evaluations,
            |case| case.scanner_top1,
            |case| case.scanner_top3,
        ),
    );
    stages.insert(
        "replay".into(),
        stage_metrics(
            evaluations,
            |case| case.replay_rank == 1,
            |case| case.replay_top3,
        ),
    );
    stages.insert(
        "variant".into(),
        stage_metrics(
            evaluations,
            |case| case.variant_rank == 1 && case.variant_rank != usize::MAX,
            |case| case.variant_top3,
        ),
    );
    stages.insert(
        "discovery_siblings".into(),
        stage_metrics(
            evaluations,
            |case| case.sibling_top1,
            |case| case.sibling_top3,
        ),
    );
    stages.insert(
        "vendored_expansion".into(),
        stage_metrics(
            evaluations,
            |case| case.allow_vendored_scan && case.vendored_lead_present,
            |case| case.allow_vendored_scan && case.vendored_lead_present,
        ),
    );
    stages
}

fn stage_metrics(
    evaluations: &[ReplayBenchmarkCaseResult],
    top1_predicate: impl Fn(&ReplayBenchmarkCaseResult) -> bool,
    top3_predicate: impl Fn(&ReplayBenchmarkCaseResult) -> bool,
) -> ReplayBenchmarkStageMetrics {
    let positives = evaluations
        .iter()
        .filter(|case| case.kind == "positive")
        .collect::<Vec<_>>();
    let negatives = evaluations
        .iter()
        .filter(|case| case.kind != "positive")
        .collect::<Vec<_>>();
    let positive_denominator = positives.len().max(1) as f64;
    let top3_true = positives.iter().filter(|case| top3_predicate(case)).count() as f64;
    ReplayBenchmarkStageMetrics {
        positive_cases: positives.len(),
        negative_cases: negatives.len(),
        top1: positives.iter().filter(|case| top1_predicate(case)).count() as f64
            / positive_denominator,
        top3: top3_true / positive_denominator,
        precision_at_3: top3_true
            / (top3_true + negatives.iter().filter(|case| top3_predicate(case)).count() as f64)
                .max(1.0),
    }
}

/// Explain a parse failure in one line, using the backend's own error text.
///
/// `AdapterDiagnostics::inferred` is where `failed_report` puts the backend
/// error, and `observed` names which backend gave up. A missing summary means no
/// translation unit was resolved at all, which is a different failure and worth
/// saying so.
fn describe_parse_failure(summary: Option<&SourceAnalysisSummary>) -> String {
    let Some(summary) = summary else {
        return "no translation unit was resolved for the case source".to_string();
    };
    if summary.reports.is_empty() {
        return "the source analysis produced no adapter reports".to_string();
    }
    let reasons: Vec<String> = summary
        .reports
        .iter()
        .filter(|report| report.diagnostics.parse == ParseStatus::Failed)
        .map(|report| {
            let detail = report
                .diagnostics
                .inferred
                .iter()
                .chain(report.diagnostics.observed.iter())
                .next()
                .cloned()
                .unwrap_or_else(|| "no detail recorded".to_string());
            format!("{} ({detail})", report.backend.as_str())
        })
        .collect();
    if reasons.is_empty() {
        return "a report failed to parse without recording a backend".to_string();
    }
    reasons.join("; ")
}

fn aggregate_metrics(
    evaluations: &[ReplayBenchmarkCaseResult],
    _top_k: usize,
) -> ReplayBenchmarkMetrics {
    let total = evaluations.len() as f64;
    let positives = evaluations
        .iter()
        .filter(|case| case.kind == "positive")
        .collect::<Vec<_>>();
    let negatives = evaluations
        .iter()
        .filter(|case| case.kind != "positive")
        .collect::<Vec<_>>();
    let variant_positive_denominator = positives
        .iter()
        .filter(|case| case.variant_rank != usize::MAX)
        .count()
        .max(1) as f64;
    let variant_false_positive_top3 =
        negatives.iter().filter(|case| case.variant_top3).count() as f64;
    let replay_true_top3 = positives.iter().filter(|case| case.replay_top3).count() as f64;
    let variant_true_top3 = positives.iter().filter(|case| case.variant_top3).count() as f64;
    let discovery_supported_positives = positives
        .iter()
        .filter(|case| supports_discovery_family(&case.family))
        .collect::<Vec<_>>();
    let discovery_supported_negatives = negatives
        .iter()
        .filter(|case| supports_discovery_family(&case.family))
        .collect::<Vec<_>>();
    let discovery_positive_denominator = discovery_supported_positives.len().max(1) as f64;
    let discovery_negative_denominator = discovery_supported_negatives.len().max(1) as f64;
    let roll_cases = evaluations
        .iter()
        .filter(|case| case.family == "dependency-roll-upstream-hidden")
        .count()
        .max(1) as f64;
    let locality_blocked_cases = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .filter(|case| case.locality_blocked_correct)
        .count() as f64;
    let locality_blocked_denominator =
        (discovery_supported_positives.len() + discovery_supported_negatives.len()).max(1) as f64;
    let generated_cases = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .filter(|case| case.unique_attempt_count > 1)
        .count() as f64;
    let discovery_case_denominator =
        (discovery_supported_positives.len() + discovery_supported_negatives.len()).max(1) as f64;
    let attempt_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.harness_attempts)
        .sum::<usize>()
        .max(1) as f64;
    let unique_attempt_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.unique_attempt_count)
        .sum::<usize>() as f64;
    let effective_unique_attempt_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.effective_unique_attempt_count)
        .sum::<usize>() as f64;
    let unique_resolved_command_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.unique_resolved_command_count)
        .sum::<usize>() as f64;
    let unique_shape_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.unique_shape_count)
        .sum::<usize>() as f64;
    let compression_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.binding_compression_rate)
        .sum::<f64>();
    let no_signal_total = discovery_supported_positives
        .iter()
        .chain(discovery_supported_negatives.iter())
        .map(|case| case.no_signal_attempts)
        .sum::<usize>() as f64;
    let first_signal_rank_cases = discovery_supported_positives
        .iter()
        .filter_map(|case| case.first_signal_attempt_rank)
        .collect::<Vec<_>>();

    ReplayBenchmarkMetrics {
        parse_success: evaluations.iter().filter(|case| case.parse_success).count() as f64 / total,
        tu_resolution_success: evaluations
            .iter()
            .filter(|case| case.tu_resolution_success)
            .count() as f64
            / total,
        replay_top1: positives.iter().filter(|case| case.replay_top1).count() as f64
            / positives.len().max(1) as f64,
        replay_top3: replay_true_top3 / positives.len().max(1) as f64,
        scanner_top3: positives.iter().filter(|case| case.scanner_top3).count() as f64
            / positives.len().max(1) as f64,
        precision_at_3: replay_true_top3
            / (replay_true_top3 + negatives.iter().filter(|case| case.replay_top3).count() as f64)
                .max(1.0),
        variant_top1: positives.iter().filter(|case| case.variant_top1).count() as f64
            / variant_positive_denominator,
        variant_top3: variant_true_top3 / variant_positive_denominator,
        variant_precision_at_3: variant_true_top3
            / (variant_true_top3 + variant_false_positive_top3).max(1.0),
        sibling_top1: discovery_supported_positives
            .iter()
            .filter(|case| case.sibling_top1)
            .count() as f64
            / discovery_positive_denominator,
        sibling_top3: discovery_supported_positives
            .iter()
            .filter(|case| case.sibling_top3)
            .count() as f64
            / discovery_positive_denominator,
        lead_queue_rate: discovery_supported_positives
            .iter()
            .filter(|case| case.queued_leads > 0)
            .count() as f64
            / discovery_positive_denominator,
        harvester_expansion_rate: discovery_supported_positives
            .iter()
            .filter(|case| case.harvester_expansions > 0)
            .count() as f64
            / discovery_positive_denominator,
        harness_attempt_validity: discovery_supported_positives
            .iter()
            .filter(|case| case.harness_attempt_valid)
            .count() as f64
            / discovery_positive_denominator,
        attempt_generation_rate: generated_cases / discovery_case_denominator,
        average_unique_attempt_count: unique_attempt_total / discovery_case_denominator,
        average_effective_unique_attempt_count: effective_unique_attempt_total
            / discovery_case_denominator,
        average_unique_resolved_command_count: unique_resolved_command_total
            / discovery_case_denominator,
        average_unique_shape_count: unique_shape_total / discovery_case_denominator,
        binding_compression_rate: compression_total / discovery_case_denominator,
        no_signal_rate: no_signal_total / attempt_total,
        first_signal_attempt_rank: first_signal_rank_cases.iter().sum::<usize>() as f64
            / first_signal_rank_cases.len().max(1) as f64,
        proof_yield: discovery_supported_positives
            .iter()
            .filter(|case| case.proof_yield)
            .count() as f64
            / discovery_positive_denominator,
        locality_blocked_correctness: locality_blocked_cases / locality_blocked_denominator,
        family_match_rate: discovery_supported_positives
            .iter()
            .filter(|case| case.lead_family_match)
            .count() as f64
            / discovery_positive_denominator,
        hard_negative_precision: discovery_supported_negatives
            .iter()
            .filter(|case| !case.sibling_top3)
            .count() as f64
            / discovery_negative_denominator,
        vendored_locality_accuracy: evaluations
            .iter()
            .filter(|case| {
                case.family == "dependency-roll-upstream-hidden" && case.locality_correct
            })
            .count() as f64
            / roll_cases,
        trigger_recipe_coverage: discovery_supported_positives
            .iter()
            .filter(|case| case.trigger_recipe_coverage)
            .count() as f64
            / discovery_positive_denominator,
        proof_signal_family_correctness: discovery_supported_positives
            .iter()
            .filter(|case| case.proof_signal_family_correctness)
            .count() as f64
            / discovery_positive_denominator,
        proof_yield_per_lane: aggregate_proof_yield_by_key(evaluations, |case| {
            case.lane_id.as_deref()
        }),
        proof_yield_per_generator: aggregate_proof_yield_by_key(evaluations, |case| {
            case.generator_id.as_deref()
        }),
    }
}

fn aggregate_proof_yield_by_key(
    evaluations: &[ReplayBenchmarkCaseResult],
    key_fn: impl Fn(&ReplayBenchmarkCaseResult) -> Option<&str>,
) -> BTreeMap<String, f64> {
    let mut totals = BTreeMap::<String, (usize, usize)>::new();
    for case in evaluations
        .iter()
        .filter(|case| case.kind == "positive" && supports_discovery_family(&case.family))
    {
        if let Some(key) = key_fn(case) {
            let entry = totals.entry(key.to_string()).or_insert((0, 0));
            entry.0 += 1;
            if case.proof_yield {
                entry.1 += 1;
            }
        }
    }
    totals
        .into_iter()
        .map(|(key, (total, yielded))| (key, yielded as f64 / total.max(1) as f64))
        .collect()
}

fn resolved_runtime_fingerprint(attempt: &HarnessAttemptRecord) -> String {
    serde_json::to_string(&(
        &attempt.resolved_argv,
        &attempt.resolved_env,
        &attempt.resolved_cwd,
        attempt.timeout_ms,
    ))
    .unwrap_or_else(|_| {
        format!(
            "{:?}|{:?}|{}|{}",
            attempt.resolved_argv, attempt.resolved_env, attempt.resolved_cwd, attempt.timeout_ms
        )
    })
}

fn shape_fingerprint(attempt: &HarnessAttemptRecord) -> String {
    serde_json::to_string(&attempt.generated_input_bindings)
        .unwrap_or_else(|_| format!("{:?}", attempt.generated_input_bindings))
}

fn aggregate_family_metrics(
    evaluations: &[ReplayBenchmarkCaseResult],
    _top_k: usize,
) -> BTreeMap<String, ReplayBenchmarkFamilyMetrics> {
    let mut metrics = BTreeMap::new();
    let mut families = evaluations
        .iter()
        .map(|case| case.family.clone())
        .collect::<Vec<_>>();
    families.sort();
    families.dedup();

    for family in families {
        let family_cases = evaluations
            .iter()
            .filter(|case| case.family == family)
            .collect::<Vec<_>>();
        let positives = family_cases
            .iter()
            .filter(|case| case.kind == "positive")
            .collect::<Vec<_>>();
        let negatives = family_cases
            .iter()
            .filter(|case| case.kind != "positive")
            .collect::<Vec<_>>();
        let variant_positive_denominator = positives
            .iter()
            .filter(|case| case.variant_rank != usize::MAX)
            .count()
            .max(1) as f64;
        let replay_true_top3 = positives.iter().filter(|case| case.replay_top3).count() as f64;
        let variant_true_top3 = positives.iter().filter(|case| case.variant_top3).count() as f64;
        let discovery_positive_denominator = positives
            .iter()
            .filter(|case| supports_discovery_family(&case.family))
            .count()
            .max(1) as f64;
        let discovery_negatives = negatives
            .iter()
            .filter(|case| supports_discovery_family(&case.family))
            .collect::<Vec<_>>();
        let discovery_negative_denominator = discovery_negatives.len().max(1) as f64;

        metrics.insert(
            family.clone(),
            ReplayBenchmarkFamilyMetrics {
                positive_cases: positives.len(),
                negative_cases: negatives.len(),
                replay_top1: positives.iter().filter(|case| case.replay_top1).count() as f64
                    / positives.len().max(1) as f64,
                replay_top3: replay_true_top3 / positives.len().max(1) as f64,
                scanner_top3: positives.iter().filter(|case| case.scanner_top3).count() as f64
                    / positives.len().max(1) as f64,
                precision_at_3: replay_true_top3
                    / (replay_true_top3
                        + negatives.iter().filter(|case| case.replay_top3).count() as f64)
                        .max(1.0),
                variant_top1: positives.iter().filter(|case| case.variant_top1).count() as f64
                    / variant_positive_denominator,
                variant_top3: variant_true_top3 / variant_positive_denominator,
                variant_precision_at_3: variant_true_top3
                    / (variant_true_top3
                        + negatives.iter().filter(|case| case.variant_top3).count() as f64)
                        .max(1.0),
                sibling_top1: positives.iter().filter(|case| case.sibling_top1).count() as f64
                    / discovery_positive_denominator,
                sibling_top3: positives.iter().filter(|case| case.sibling_top3).count() as f64
                    / discovery_positive_denominator,
                lead_queue_rate: positives
                    .iter()
                    .filter(|case| case.queued_leads > 0)
                    .count() as f64
                    / discovery_positive_denominator,
                harvester_expansion_rate: positives
                    .iter()
                    .filter(|case| case.harvester_expansions > 0)
                    .count() as f64
                    / discovery_positive_denominator,
                harness_attempt_validity: positives
                    .iter()
                    .filter(|case| case.harness_attempt_valid)
                    .count() as f64
                    / discovery_positive_denominator,
                proof_yield: positives.iter().filter(|case| case.proof_yield).count() as f64
                    / discovery_positive_denominator,
                family_match_rate: positives
                    .iter()
                    .filter(|case| case.lead_family_match)
                    .count() as f64
                    / discovery_positive_denominator,
                hard_negative_precision: discovery_negatives
                    .iter()
                    .filter(|case| !case.sibling_top3)
                    .count() as f64
                    / discovery_negative_denominator,
                trigger_recipe_coverage: positives
                    .iter()
                    .filter(|case| case.trigger_recipe_coverage)
                    .count() as f64
                    / discovery_positive_denominator,
                proof_signal_family_correctness: positives
                    .iter()
                    .filter(|case| case.proof_signal_family_correctness)
                    .count() as f64
                    / discovery_positive_denominator,
            },
        );
    }

    metrics
}

fn discovery_sibling_rank_for_case(
    case: &ReplayBenchmarkCase,
    leads: &[crate::discovery::DiscoveryLead],
) -> usize {
    let target = if case.kind == "positive" {
        case.variant_candidate
            .as_deref()
            .unwrap_or(case.surface_candidate.as_str())
    } else {
        case.surface_candidate.as_str()
    };
    leads
        .first()
        .and_then(|lead| {
            lead.sibling_candidates
                .iter()
                .position(|candidate| candidate.symbol == target)
                .map(|index| index + 1)
        })
        .unwrap_or(usize::MAX)
}

fn proof_signal_matches_family(family: BugFamily, case_family: Option<&str>) -> bool {
    matches!(
        (family, case_family),
        (BugFamily::LifetimeReentrancy, Some("lifetime-ownership"))
            | (
                BugFamily::SizeStrideArithmetic,
                Some("bounds-size-arithmetic")
            )
            | (
                BugFamily::GpuProtocolOrderLifecycle,
                Some("gpu-protocol-order-lifecycle")
            )
            | (
                BugFamily::ValidationTrustBoundary,
                Some("validation-policy")
            )
    )
}

fn locality_matches_expectation(
    metadata: Option<&ReplayBenchmarkRollMetadata>,
    locality: &crate::result::RollResolution,
) -> bool {
    let Some(metadata) = metadata else {
        return true;
    };
    if metadata.vendored_nearby_path.is_some() {
        locality.allow_vendored_scan
    } else if metadata.no_local_vulnerable_source_likely {
        !locality.allow_vendored_scan
    } else {
        true
    }
}

fn supports_discovery_family(family: &str) -> bool {
    matches!(
        family,
        "lifetime-ownership"
            | "bounds-size-arithmetic"
            | "gpu-protocol-order-lifecycle"
            | "validation-policy"
    )
}

fn rank_for_symbol(replay: &ReplayAnalysis, symbol: &str) -> usize {
    replay
        .candidates
        .iter()
        .position(|candidate| candidate.symbol == symbol)
        .map(|index| index + 1)
        .unwrap_or(usize::MAX)
}

fn replay_score(replay: &ReplayAnalysis, symbol: &str) -> i32 {
    replay
        .candidates
        .iter()
        .find(|candidate| candidate.symbol == symbol)
        .map(|candidate| candidate.score)
        .unwrap_or(i32::MIN)
}

fn variant_rank_for_case(
    case: &ReplayBenchmarkCase,
    leads: &[crate::result::VariantLead],
) -> usize {
    let Some(target) = &case.variant_candidate else {
        return usize::MAX;
    };
    leads
        .iter()
        .position(|lead| &lead.symbol == target)
        .map(|index| index + 1)
        .unwrap_or(usize::MAX)
}

fn variant_score_for_case(case: &ReplayBenchmarkCase, leads: &[crate::result::VariantLead]) -> i32 {
    let Some(target) = &case.variant_candidate else {
        return if leads.is_empty() {
            i32::MIN
        } else {
            leads[0].score
        };
    };
    leads
        .iter()
        .find(|lead| &lead.symbol == target)
        .map(|lead| lead.score)
        .unwrap_or(i32::MIN)
}

fn scanner_rank_for_surface(root: &Path, surface_candidate: &str) -> Result<usize, String> {
    let graph = source::index_repo_fixture(root)?;
    Ok(graph
        .nodes()
        .iter()
        .filter(|node| node.kind == crate::ir::NodeKind::Function)
        .map(|node| node.label.clone())
        .position(|label| label == surface_candidate)
        .map(|index| index + 1)
        .unwrap_or(usize::MAX))
}

fn load_manifest(path: &Path) -> Result<ReplayBenchmarkManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
}

fn load_case(path: &Path) -> Result<ReplayBenchmarkCase, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::{load_case, run_case};
    use crate::adapters::source_clang_facts::{
        maybe_analyze_source_tree_with_options, SourceAnalysisOptions,
    };
    use crate::adapters::traits::{ExecutionMode, QueryKind};
    use crate::derived::derive_from_fused_source;
    use crate::fusion::fuse_source_analysis;
    use crate::planner::{build_source_analysis_plan, ResourceBudgets};
    use crate::replay::rank_replay_candidates;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_root() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        loop {
            let candidate = dir.join("tests").join("fixtures").join("benchmarks");
            if candidate.exists() {
                return candidate;
            }
            if !dir.pop() {
                panic!(
                    "could not locate benchmark fixtures from {}",
                    env!("CARGO_MANIFEST_DIR")
                );
            }
        }
    }

    fn ranked_symbols_for_case(case_relpath: &str, baseline_candidates: &[String]) -> Vec<String> {
        let root = fixture_root();
        let case = load_case(&root.join("fat-replay-family").join(case_relpath)).expect("case");
        let dir = tempfile::tempdir().expect("tempdir");
        let source_path = dir.path().join(&case.file_name);
        fs::write(&source_path, &case.source).expect("write source");
        fs::write(
            dir.path().join("compile_commands.json"),
            serde_json::to_string_pretty(&vec![serde_json::json!({
                "directory": dir.path(),
                "file": source_path,
                "arguments": case
                    .compile_args
                    .iter()
                    .cloned()
                    .chain([source_path.display().to_string()])
                    .collect::<Vec<_>>(),
            })])
            .expect("serialize compile commands"),
        )
        .expect("write compile commands");
        let plan =
            build_source_analysis_plan(dir.path(), QueryKind::PatchInvariant, ExecutionMode::Deep)
                .expect("build analysis plan");
        let summary = maybe_analyze_source_tree_with_options(
            dir.path(),
            &SourceAnalysisOptions {
                mode: ExecutionMode::Deep,
                debug_bundle_dir: None,
                budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
            },
        )
        .expect("analyze source");
        let fused = fuse_source_analysis(summary.as_ref());
        let derived = derive_from_fused_source(&fused);
        assert!(
            !plan.adapter_ids.is_empty(),
            "analysis plan should resolve adapters"
        );
        rank_replay_candidates(
            &case.reference_symbols,
            &fused,
            &derived,
            baseline_candidates,
        )
        .candidates
        .into_iter()
        .map(|candidate| candidate.symbol)
        .collect()
    }

    #[test]
    fn validation_negative_replay_target_stays_outside_top3() {
        let root = fixture_root();
        let case = load_case(
            &root
                .join("fat-replay-family")
                .join("validation-negative.json"),
        )
        .expect("validation negative case");
        let result = run_case(&case, 3).expect("run case");
        let ranked = ranked_symbols_for_case("validation-negative.json", &case.baseline_candidates);
        assert!(
            !result.replay_top3,
            "validation-negative unexpectedly ranked in replay top3: rank={} score={} ranked={:?}",
            result.replay_rank, result.replay_score, ranked
        );
    }
}
