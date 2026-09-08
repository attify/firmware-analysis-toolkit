use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use fat_core::artifacts::ArtifactKind;
use fat_core::benchmark::{
    score_fat_native_run, BenchmarkComparator, BenchmarkEvidenceGrade, BenchmarkOutcomeClass,
    BenchmarkOutcomeRecord, BenchmarkRunMode, BenchmarkRunRecord, BenchmarkStageScore,
    BenchmarkStageStatus, BenchmarkStageVector, BenchmarkTarget, ComparatorKind,
};
use fat_core::database::ProjectDb;
use fat_core::debug::{
    DebugGdbTranscript, DebugShellTranscript, ObservedNetworkSnapshot, ObservedProcessSnapshot,
    ObservedServiceSnapshot,
};
use fat_core::readiness::ConfidenceReport;
use fat_core::rehosting::{ReadinessReport, SurfaceReadiness};
use fat_core::rehosting_policy::{
    SelectionTrace, SubstrateAttemptState, SubstrateKind as LogicalSubstrateKind,
};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runs::{RunRecord, RuntimeEndpoint, RuntimeEndpointKind};
use fat_core::runtime_store::RuntimeStore;
use fat_core::services::{managed_runtime_summary_from_runtime_state_json, ManagedRuntimeSummary};
use fat_query::replay_benchmark::run_replay_benchmark;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

use fat_core::finding::FindingSeverity;
use fat_taint::proof::angr;
use fat_taint::{FindingStatus, TaintFinding};

use crate::debug_cmd::load_latest_readiness_report;
use crate::run_cmd;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// Score and report FAT benchmark records.
#[derive(Debug, Clone, Subcommand)]
pub enum BenchmarkCommand {
    /// Run the replay/variant benchmark corpus and report family metrics.
    Replay {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Summarize taint findings across a benchmark manifest.
    Taint {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Score a FAT-native benchmark outcome from persisted runtime state.
    Score {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        comparator: Option<String>,
        #[arg(long = "run-mode")]
        run_mode: Option<String>,
    },
    /// Import a comparator benchmark report into the runtime store.
    Import {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    /// Report stored benchmark comparisons for a project.
    Report {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

pub fn run(subject: BenchmarkCommand) -> DynResult<()> {
    match subject {
        BenchmarkCommand::Replay { manifest, json } => replay(manifest, json),
        BenchmarkCommand::Taint { dataset, json } => taint(dataset, json),
        BenchmarkCommand::Score {
            project,
            session_id,
            run_id,
            comparator,
            run_mode,
        } => score(project, session_id, run_id, comparator, run_mode),
        BenchmarkCommand::Import { project, report } => import(project, report),
        BenchmarkCommand::Report { project, json } => report(project, json),
    }
}

fn replay(manifest: PathBuf, json: bool) -> DynResult<()> {
    let summary = run_replay_benchmark(&manifest)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_replay_panel(&palette, &summary);
        return Ok(());
    }
    println!("{}", palette.heading("Replay Benchmark"));
    println!("{}", palette.kv("family", &summary.family));
    println!("{}", palette.kv("top-k", summary.top_k.to_string()));
    println!("{}", palette.kv("cases", summary.cases.len().to_string()));
    println!();
    println!("{}", palette.heading("Metrics"));
    println!(
        "{}",
        palette.kv(
            "parse success",
            format!("{:.3}", summary.metrics.parse_success)
        )
    );
    println!(
        "{}",
        palette.kv(
            "tu resolution success",
            format!("{:.3}", summary.metrics.tu_resolution_success)
        )
    );
    println!(
        "{}",
        palette.kv("replay top1", format!("{:.3}", summary.metrics.replay_top1))
    );
    println!(
        "{}",
        palette.kv("replay top3", format!("{:.3}", summary.metrics.replay_top3))
    );
    println!(
        "{}",
        palette.kv(
            "scanner top3",
            format!("{:.3}", summary.metrics.scanner_top3)
        )
    );
    println!(
        "{}",
        palette.kv(
            "precision@3",
            format!("{:.3}", summary.metrics.precision_at_3)
        )
    );
    println!(
        "{}",
        palette.kv(
            "variant top1",
            format!("{:.3}", summary.metrics.variant_top1)
        )
    );
    println!(
        "{}",
        palette.kv(
            "variant top3",
            format!("{:.3}", summary.metrics.variant_top3)
        )
    );
    println!(
        "{}",
        palette.kv(
            "variant precision@3",
            format!("{:.3}", summary.metrics.variant_precision_at_3)
        )
    );
    println!(
        "{}",
        palette.kv(
            "sibling top1",
            format!("{:.3}", summary.metrics.sibling_top1)
        )
    );
    println!(
        "{}",
        palette.kv(
            "sibling top3",
            format!("{:.3}", summary.metrics.sibling_top3)
        )
    );
    println!(
        "{}",
        palette.kv(
            "lead queue rate",
            format!("{:.3}", summary.metrics.lead_queue_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "harvester expansion rate",
            format!("{:.3}", summary.metrics.harvester_expansion_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "harness attempt validity",
            format!("{:.3}", summary.metrics.harness_attempt_validity)
        )
    );
    println!(
        "{}",
        palette.kv(
            "attempt generation rate",
            format!("{:.3}", summary.metrics.attempt_generation_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "average unique attempts",
            format!("{:.3}", summary.metrics.average_unique_attempt_count)
        )
    );
    println!(
        "{}",
        palette.kv(
            "average effective unique attempts",
            format!(
                "{:.3}",
                summary.metrics.average_effective_unique_attempt_count
            )
        )
    );
    println!(
        "{}",
        palette.kv(
            "average unique resolved commands",
            format!(
                "{:.3}",
                summary.metrics.average_unique_resolved_command_count
            )
        )
    );
    println!(
        "{}",
        palette.kv(
            "average unique shapes",
            format!("{:.3}", summary.metrics.average_unique_shape_count)
        )
    );
    println!(
        "{}",
        palette.kv(
            "binding compression rate",
            format!("{:.3}", summary.metrics.binding_compression_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "no signal rate",
            format!("{:.3}", summary.metrics.no_signal_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "first signal attempt rank",
            format!("{:.3}", summary.metrics.first_signal_attempt_rank)
        )
    );
    println!(
        "{}",
        palette.kv("proof yield", format!("{:.3}", summary.metrics.proof_yield))
    );
    println!(
        "{}",
        palette.kv(
            "family match rate",
            format!("{:.3}", summary.metrics.family_match_rate)
        )
    );
    println!(
        "{}",
        palette.kv(
            "hard negative precision",
            format!("{:.3}", summary.metrics.hard_negative_precision)
        )
    );
    println!(
        "{}",
        palette.kv(
            "vendored locality accuracy",
            format!("{:.3}", summary.metrics.vendored_locality_accuracy)
        )
    );
    println!(
        "{}",
        palette.kv(
            "locality blocked correctness",
            format!("{:.3}", summary.metrics.locality_blocked_correctness)
        )
    );
    println!(
        "{}",
        palette.kv(
            "trigger recipe coverage",
            format!("{:.3}", summary.metrics.trigger_recipe_coverage)
        )
    );
    println!(
        "{}",
        palette.kv(
            "proof signal family correctness",
            format!("{:.3}", summary.metrics.proof_signal_family_correctness)
        )
    );
    for (lane, value) in &summary.metrics.proof_yield_per_lane {
        let key = format!("proof yield per lane {lane}");
        println!("{}", palette.kv(key.as_str(), format!("{value:.3}")));
    }
    for (generator, value) in &summary.metrics.proof_yield_per_generator {
        let key = format!("proof yield per generator {generator}");
        println!("{}", palette.kv(key.as_str(), format!("{value:.3}")));
    }

    if !summary.family_metrics.is_empty() {
        println!();
        println!("{}", palette.heading("Family Metrics"));
        for (family, metrics) in &summary.family_metrics {
            println!(
                "{}",
                palette.kv(
                    family,
                    format!(
                        "pos={} neg={} replay_top3={:.3} variant_top3={:.3} sibling_top3={:.3} queue={:.3} harvest={:.3} proof={:.3} family_match={:.3} precision@3={:.3}",
                        metrics.positive_cases,
                        metrics.negative_cases,
                        metrics.replay_top3,
                        metrics.variant_top3,
                        metrics.sibling_top3,
                        metrics.lead_queue_rate,
                        metrics.harvester_expansion_rate,
                        metrics.proof_yield,
                        metrics.family_match_rate,
                        metrics.precision_at_3
                    )
                )
            );
        }
    }

    if !summary.ablations.is_empty() {
        println!();
        println!("{}", palette.heading("Ablations"));
        for (stage, metrics) in &summary.ablations {
            println!(
                "{}",
                palette.kv(
                    stage,
                    format!(
                        "pos={} neg={} top1={:.3} top3={:.3} precision@3={:.3}",
                        metrics.positive_cases,
                        metrics.negative_cases,
                        metrics.top1,
                        metrics.top3,
                        metrics.precision_at_3
                    )
                )
            );
        }
    }

    println!();
    println!("{}", palette.heading("Cases"));
    for case in &summary.cases {
        println!(
            "{}",
            palette.kv(
                &case.id,
                format!(
                    "family={} kind={} locality={} vendored_scan={} vendored_lead={} replay_rank={} variant_rank={} replay_score={} variant_score={}",
                    case.family,
                    case.kind,
                    case.locality,
                    case.allow_vendored_scan,
                    case.vendored_lead_present,
                    case.replay_rank,
                    case.variant_rank,
                    case.replay_score,
                    case.variant_score
                )
            )
        );
    }

    Ok(())
}

fn render_replay_panel(
    palette: &crate::style::Palette,
    summary: &fat_query::replay_benchmark::ReplayBenchmarkSummary,
) {
    let metrics = &summary.metrics;
    let mut lines = vec![
        palette.kv("family", &summary.family),
        palette.kv("top-k", summary.top_k.to_string()),
        palette.kv("cases", summary.cases.len().to_string()),
        String::new(),
        palette.heading("Metrics"),
    ];
    for (name, value, with_bar) in [
        ("parse success", metrics.parse_success, true),
        ("tu resolution success", metrics.tu_resolution_success, true),
        ("replay top1", metrics.replay_top1, true),
        ("replay top3", metrics.replay_top3, true),
        ("scanner top3", metrics.scanner_top3, true),
        ("precision@3", metrics.precision_at_3, true),
        ("variant top1", metrics.variant_top1, true),
        ("variant top3", metrics.variant_top3, true),
        ("variant precision@3", metrics.variant_precision_at_3, true),
        ("sibling top1", metrics.sibling_top1, true),
        ("sibling top3", metrics.sibling_top3, true),
        ("lead queue rate", metrics.lead_queue_rate, true),
        (
            "harvester expansion rate",
            metrics.harvester_expansion_rate,
            true,
        ),
        (
            "harness attempt validity",
            metrics.harness_attempt_validity,
            true,
        ),
        (
            "attempt generation rate",
            metrics.attempt_generation_rate,
            true,
        ),
        (
            "average unique attempts",
            metrics.average_unique_attempt_count,
            false,
        ),
        (
            "average effective unique attempts",
            metrics.average_effective_unique_attempt_count,
            false,
        ),
        (
            "average unique resolved commands",
            metrics.average_unique_resolved_command_count,
            false,
        ),
        (
            "average unique shapes",
            metrics.average_unique_shape_count,
            false,
        ),
        (
            "binding compression rate",
            metrics.binding_compression_rate,
            true,
        ),
        ("no signal rate", metrics.no_signal_rate, true),
        (
            "first signal attempt rank",
            metrics.first_signal_attempt_rank,
            false,
        ),
        ("proof yield", metrics.proof_yield, true),
        ("family match rate", metrics.family_match_rate, true),
        (
            "hard negative precision",
            metrics.hard_negative_precision,
            true,
        ),
        (
            "vendored locality accuracy",
            metrics.vendored_locality_accuracy,
            true,
        ),
        (
            "locality blocked correctness",
            metrics.locality_blocked_correctness,
            true,
        ),
        (
            "trigger recipe coverage",
            metrics.trigger_recipe_coverage,
            true,
        ),
        (
            "proof signal family correctness",
            metrics.proof_signal_family_correctness,
            true,
        ),
    ] {
        lines.push(replay_metric_row(palette, name, value, with_bar));
    }
    for (lane, value) in &metrics.proof_yield_per_lane {
        lines.push(replay_metric_row(
            palette,
            &format!("proof yield per lane {lane}"),
            *value,
            true,
        ));
    }
    for (generator, value) in &metrics.proof_yield_per_generator {
        lines.push(replay_metric_row(
            palette,
            &format!("proof yield per generator {generator}"),
            *value,
            true,
        ));
    }

    if !summary.family_metrics.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Family Metrics"));
        for (family, family_metrics) in &summary.family_metrics {
            lines.push(format!(
                "{} {}  {}",
                palette.dot_ok(),
                family,
                palette.muted(format!(
                    "pos={} neg={} replay_top3={:.3} variant_top3={:.3} sibling_top3={:.3} queue={:.3} harvest={:.3} proof={:.3} family_match={:.3} precision@3={:.3}",
                    family_metrics.positive_cases,
                    family_metrics.negative_cases,
                    family_metrics.replay_top3,
                    family_metrics.variant_top3,
                    family_metrics.sibling_top3,
                    family_metrics.lead_queue_rate,
                    family_metrics.harvester_expansion_rate,
                    family_metrics.proof_yield,
                    family_metrics.family_match_rate,
                    family_metrics.precision_at_3
                ))
            ));
        }
    }

    if !summary.ablations.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Ablations"));
        for (stage, ablation) in &summary.ablations {
            let dot = if ablation.positive_cases > 0 {
                palette.dot_ok()
            } else {
                palette.dot_muted()
            };
            lines.push(format!(
                "{dot} {stage}  {}",
                palette.muted(format!(
                    "pos={} neg={} top1={:.3} top3={:.3} precision@3={:.3}",
                    ablation.positive_cases,
                    ablation.negative_cases,
                    ablation.top1,
                    ablation.top3,
                    ablation.precision_at_3
                ))
            ));
        }
    }

    lines.push(String::new());
    lines.push(palette.heading("Cases"));
    for case in &summary.cases {
        let dot = match case.kind.as_str() {
            "positive" => palette.dot_ok(),
            "negative" => palette.dot_bad(),
            _ => palette.dot_muted(),
        };
        lines.push(format!(
            "{dot} {}  {}",
            case.id,
            palette.muted(format!(
                "family={} kind={} locality={} vendored_scan={} vendored_lead={} replay_rank={} variant_rank={} replay_score={} variant_score={}",
                case.family,
                case.kind,
                case.locality,
                case.allow_vendored_scan,
                case.vendored_lead_present,
                case.replay_rank,
                case.variant_rank,
                case.replay_score,
                case.variant_score
            ))
        ));
    }

    println!("{}", palette.panel("Replay Benchmark", &lines));
    println!(
        "{}",
        palette.next_hint("fat benchmark score --project <project>")
    );
}

fn replay_metric_row(
    palette: &crate::style::Palette,
    name: &str,
    value: f64,
    with_bar: bool,
) -> String {
    let mut row = palette.kv(name, format!("{value:.3}"));
    if with_bar {
        row.push(' ');
        row.push_str(&palette.bar(value as f32, 8));
    }
    row
}

#[derive(Debug, Deserialize)]
struct TaintBenchmarkManifest {
    dataset: String,
    cases: Vec<TaintBenchmarkCase>,
}

#[derive(Debug, Deserialize)]
struct TaintBenchmarkCase {
    id: String,
    findings_fixture: Option<PathBuf>,
    file: Option<PathBuf>,
    arch: Option<String>,
    base: Option<String>,
    duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TaintBenchmarkSummary {
    dataset: String,
    cases: usize,
    total_findings: usize,
    total_duration_ms: u64,
    by_severity: BTreeMap<String, usize>,
    by_status: BTreeMap<String, usize>,
    case_summaries: Vec<TaintBenchmarkCaseSummary>,
}

#[derive(Debug, Serialize)]
struct TaintBenchmarkCaseSummary {
    id: String,
    findings: usize,
    duration_ms: u64,
}

fn taint(dataset: PathBuf, json: bool) -> DynResult<()> {
    let manifest_text = fs::read_to_string(&dataset)?;
    let manifest: TaintBenchmarkManifest = serde_json::from_str(&manifest_text)?;
    let dataset_dir = dataset
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut by_severity = BTreeMap::new();
    let mut by_status = BTreeMap::new();
    let mut total_findings = 0usize;
    let mut total_duration_ms = 0u64;
    let mut case_summaries = Vec::new();

    for case in manifest.cases {
        let (findings, duration_ms) = load_benchmark_case(&dataset_dir, &case)?;
        total_findings += findings.len();
        total_duration_ms += duration_ms;

        for finding in &findings {
            *by_severity
                .entry(severity_key(finding.severity))
                .or_insert(0) += 1;
            *by_status.entry(status_key(finding.status)).or_insert(0) += 1;
        }

        case_summaries.push(TaintBenchmarkCaseSummary {
            id: case.id,
            findings: findings.len(),
            duration_ms,
        });
    }

    let summary = TaintBenchmarkSummary {
        dataset: manifest.dataset,
        cases: case_summaries.len(),
        total_findings,
        total_duration_ms,
        by_severity,
        by_status,
        case_summaries,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        let palette = crate::style::Palette::stdout();
        if palette.enabled() {
            render_taint_panel(&palette, &summary);
            return Ok(());
        }
        println!("{}", palette.heading("Taint Benchmark"));
        println!(
            "{}",
            palette.kv(
                "dataset",
                format!("{} ({} cases)", summary.dataset, summary.cases)
            )
        );
        println!(
            "{}",
            palette.kv(
                "total findings",
                palette.info(summary.total_findings.to_string())
            )
        );
        println!(
            "{}",
            palette.kv(
                "total duration",
                format!("{} ms", summary.total_duration_ms)
            )
        );
        if !summary.by_severity.is_empty() {
            println!();
            println!("{}", palette.heading("By Severity"));
            for (key, value) in &summary.by_severity {
                let styled_key = match key.as_str() {
                    "critical" | "high" => palette.bad(key),
                    "medium" => palette.warn(key),
                    "low" => palette.info(key),
                    _ => palette.muted(key),
                };
                println!("  {styled_key}: {value}");
            }
        }
        if !summary.by_status.is_empty() {
            println!();
            println!("{}", palette.heading("By Status"));
            for (key, value) in &summary.by_status {
                println!("  {}: {}", palette.status_word(key), value);
            }
        }
    }

    Ok(())
}

fn render_taint_panel(palette: &crate::style::Palette, summary: &TaintBenchmarkSummary) {
    let mut lines = vec![
        palette.kv(
            "dataset",
            format!("{} ({} cases)", summary.dataset, summary.cases),
        ),
        palette.kv(
            "total findings",
            palette.info(summary.total_findings.to_string()),
        ),
        palette.kv(
            "total duration",
            format!("{} ms", summary.total_duration_ms),
        ),
    ];

    if !summary.by_severity.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("By Severity"));
        for (key, value) in &summary.by_severity {
            let styled_key = match key.as_str() {
                "critical" | "high" => palette.bad(key),
                "medium" => palette.warn(key),
                "low" => palette.info(key),
                _ => palette.muted(key),
            };
            let dot = match key.as_str() {
                "critical" | "high" => palette.dot_bad(),
                "medium" => palette.dot_warn(),
                "low" => palette.dot_ok(),
                _ => palette.dot_muted(),
            };
            lines.push(format!(
                "{dot} {styled_key}: {}",
                palette.muted(value.to_string())
            ));
        }
    }

    if !summary.by_status.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("By Status"));
        for (key, value) in &summary.by_status {
            let dot = match key.as_str() {
                "proven" | "attested" | "confirmed" | "satisfying" => palette.dot_ok(),
                "candidate" | "warning" | "violating" | "unknown" | "partial" => palette.dot_warn(),
                "fail" | "unavailable" | "rejected" | "error" => palette.dot_bad(),
                _ => palette.dot_muted(),
            };
            lines.push(format!(
                "{dot} {}: {}",
                palette.status_word(key),
                palette.muted(value.to_string())
            ));
        }
    }

    println!("{}", palette.panel("Taint Benchmark", &lines));
}

fn load_benchmark_case(
    dataset_dir: &Path,
    case: &TaintBenchmarkCase,
) -> DynResult<(Vec<TaintFinding>, u64)> {
    if let Some(findings_fixture) = &case.findings_fixture {
        let fixture_path = resolve_manifest_path(dataset_dir, findings_fixture);
        let findings_text = fs::read_to_string(fixture_path)?;
        let findings: Vec<TaintFinding> = serde_json::from_str(&findings_text)?;
        return Ok((findings, case.duration_ms.unwrap_or(0)));
    }

    let file = case.file.as_ref().ok_or_else(|| {
        format!(
            "benchmark case '{}' missing file or findings_fixture",
            case.id
        )
    })?;
    let file = resolve_manifest_path(dataset_dir, file);
    let start = Instant::now();
    let findings =
        angr::analyze_binary_with_opts(&file, case.arch.as_deref(), case.base.as_deref())
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let duration_ms = case
        .duration_ms
        .unwrap_or_else(|| start.elapsed().as_millis() as u64);
    Ok((findings, duration_ms))
}

fn resolve_manifest_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn severity_key(severity: FindingSeverity) -> String {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Low => "low",
        FindingSeverity::Medium => "medium",
        FindingSeverity::High => "high",
        FindingSeverity::Critical => "critical",
    }
    .to_string()
}

fn status_key(status: FindingStatus) -> String {
    match status {
        FindingStatus::Proven => "proven",
        FindingStatus::Attested => "attested",
        FindingStatus::Candidate => "candidate",
        FindingStatus::DynamicallyConfirmed => "confirmed",
        FindingStatus::Rejected => "rejected",
    }
    .to_string()
}

fn score(
    project_dir: PathBuf,
    requested_session_id: Option<String>,
    requested_run_id: Option<String>,
    requested_comparator: Option<String>,
    requested_run_mode: Option<String>,
) -> DynResult<()> {
    let project_dir = crate::normalize_project_dir(&project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let project = crate::load_project(&db, &project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let target = crate::ensure_target_record(&store, &project)?;
    let benchmark_target = benchmark_target_from_project(&project_dir, &target);
    let benchmark_comparator = resolve_benchmark_comparator(
        requested_comparator.as_deref(),
        requested_run_mode.as_deref(),
    )?;

    if benchmark_comparator.comparator_id == "emux"
        && benchmark_comparator.run_mode == BenchmarkRunMode::ComparatorTuned
    {
        crate::emulate_cmd::run(
            Some(project_dir.clone()),
            Some("emux".to_string()),
            None,
            requested_session_id.clone(),
            Vec::new(),
            false,
            false,
            false,
            false,
            false,
            None,
            None,
            false,
            false,
            None,
        )?;
    }

    let mut view = select_runtime_view(
        &store,
        requested_session_id.as_deref(),
        requested_run_id.as_deref(),
    )?
    .ok_or_else(|| format!("no runtime session found for {}", project_dir.display()))?;
    let mut scored_run = view.run.clone();
    augment_run_with_persisted_service_evidence(
        &store,
        &project_dir,
        &view.session.session_id,
        &mut scored_run,
    )?;
    if benchmark_comparator.comparator_id == "emux"
        && benchmark_comparator.run_mode == BenchmarkRunMode::ComparatorTuned
    {
        collect_emux_comparator_evidence(&project_dir, &view.session.session_id)?;
        scored_run = augment_run_with_emux_comparator_evidence(
            &store,
            &project_dir,
            &view.session.session_id,
            &view.run,
        )?;
        view = select_runtime_view(
            &store,
            Some(view.session.session_id.as_str()),
            Some(view.run.run_id.as_str()),
        )?
        .ok_or_else(|| format!("no runtime session found for {}", project_dir.display()))?;
    }
    let runtime_summary = load_managed_runtime_summary(
        &store,
        &project_dir,
        &view.session.session_id,
        &view.run.run_id,
    )?;
    let findings = store.read_run_findings(&view.session.session_id, &view.run.run_id)?;
    let readiness_report =
        load_latest_readiness_report(&store, &view.session.session_id, &view.run.run_id)?;
    let confidence_report =
        load_latest_confidence_report(&store, &view.session.session_id, &view.run.run_id)?;
    let mut outcome = score_fat_native_run(
        &target,
        &scored_run,
        runtime_summary.as_ref(),
        readiness_report.as_ref(),
        confidence_report.as_ref(),
        &findings,
        &view.diagnostics,
    );
    let rehosting_recipe =
        load_latest_rehosting_recipe(&store, &view.session.session_id, &view.run.run_id)?;
    let selection_trace =
        load_latest_selection_trace(&store, &view.session.session_id, &view.run.run_id)?;
    apply_readiness_report(
        &mut outcome,
        readiness_report.as_ref(),
        rehosting_recipe.as_ref(),
        selection_trace.as_ref(),
    );
    let benchmark_run = BenchmarkRunRecord::try_new(
        benchmark_target.target_id.clone(),
        benchmark_comparator,
        local_host_profile(),
        view.run.run_id.clone(),
    )?;
    outcome.benchmark_run_id = benchmark_run.benchmark_run_id.clone();

    store.write_benchmark_target(&benchmark_target)?;
    store.write_benchmark_run(&benchmark_run)?;
    store.write_benchmark_outcome(&outcome)?;

    print_scored_run_for_target(&benchmark_run, &outcome);
    Ok(())
}

fn load_latest_confidence_report(
    store: &RuntimeStore,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<ConfidenceReport>> {
    let confidence_dir = store
        .run_path(session_id, run_id)
        .parent()
        .ok_or("run path missing parent")?
        .join("rehosting")
        .join("confidence");
    if !confidence_dir.exists() {
        return Ok(None);
    }

    let mut records: Vec<ConfidenceReport> = fs::read_dir(&confidence_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<ConfidenceReport>(&bytes).ok())
        .collect();
    records.sort_by(|left, right| left.confidence_report_id.cmp(&right.confidence_report_id));
    Ok(records.pop())
}

fn apply_readiness_report(
    outcome: &mut BenchmarkOutcomeRecord,
    readiness_report: Option<&ReadinessReport>,
    rehosting_recipe: Option<&RehostingRecipe>,
    selection_trace: Option<&SelectionTrace>,
) {
    let Some(report) = readiness_report else {
        return;
    };

    let has_operator_surface = report.surfaces.iter().any(|surface| {
        matches!(surface.kind.as_str(), "shell" | "debugger" | "monitor")
            && matches!(
                surface.readiness,
                SurfaceReadiness::Ready | SurfaceReadiness::Validated
            )
    });
    let has_reachable_surface = report.surfaces.iter().any(|surface| {
        matches!(surface.kind.as_str(), "service" | "port-forward")
            && matches!(
                surface.readiness,
                SurfaceReadiness::Ready | SurfaceReadiness::Validated
            )
    });
    let has_validated_service = report.surfaces.iter().any(|surface| {
        surface.kind == "service" && surface.readiness == SurfaceReadiness::Validated
    });
    let has_readiness_signal = has_operator_surface
        || has_reachable_surface
        || has_validated_service
        || !report.validated_goals.is_empty();

    if has_operator_surface {
        outcome.stage_vector.operator_access = BenchmarkStageScore::reached();
    }
    if has_reachable_surface {
        outcome.stage_vector.reachability = BenchmarkStageScore::reached();
    }
    if has_validated_service {
        outcome.stage_vector.exploit_readiness = BenchmarkStageScore::reached();
    }
    if has_readiness_signal {
        outcome.stage_vector.research_utility = BenchmarkStageScore::reached();
    }

    let logical_substrate = rehosting_recipe
        .map(|recipe| recipe.selected_substrate)
        .or_else(|| selected_logical_substrate_from_trace(selection_trace));
    if logical_substrate == Some(LogicalSubstrateKind::Reference) && !has_validated_service {
        outcome.stage_vector.reachability = if has_operator_surface || has_readiness_signal {
            BenchmarkStageScore::partial()
        } else {
            BenchmarkStageScore::not_reached()
        };
        outcome.stage_vector.exploit_readiness = BenchmarkStageScore::not_reached();
    }
    outcome.outcome_class = classify_stage_vector_for_cli(&outcome.stage_vector, logical_substrate);
    outcome.evidence_grade =
        evidence_grade_for_stage_vector_for_cli(&outcome.stage_vector, logical_substrate);
}

fn selected_logical_substrate_from_trace(
    selection_trace: Option<&SelectionTrace>,
) -> Option<LogicalSubstrateKind> {
    selection_trace.and_then(|trace| {
        trace
            .attempts
            .iter()
            .find(|attempt| attempt.state == SubstrateAttemptState::Selected)
            .map(|attempt| attempt.substrate)
            .or_else(|| trace.attempts.first().map(|attempt| attempt.substrate))
    })
}

fn classify_stage_vector_for_cli(
    stage_vector: &BenchmarkStageVector,
    logical_substrate: Option<LogicalSubstrateKind>,
) -> BenchmarkOutcomeClass {
    let boot_required = logical_substrate != Some(LogicalSubstrateKind::Service);
    let reference_without_target_reachability = logical_substrate
        == Some(LogicalSubstrateKind::Reference)
        && stage_vector.reachability.status != BenchmarkStageStatus::Reached
        && stage_vector.exploit_readiness.status != BenchmarkStageStatus::Reached;
    if boot_required && stage_vector.boot.status != BenchmarkStageStatus::Reached {
        BenchmarkOutcomeClass::Failed
    } else if reference_without_target_reachability {
        BenchmarkOutcomeClass::Partial
    } else if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        && stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        && stage_vector.reachability.status == BenchmarkStageStatus::Reached
        && stage_vector.operator_access.status == BenchmarkStageStatus::Reached
    {
        BenchmarkOutcomeClass::Strong
    } else if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        || stage_vector.reachability.status == BenchmarkStageStatus::Reached
        || stage_vector.operator_access.status == BenchmarkStageStatus::Reached
    {
        BenchmarkOutcomeClass::Useful
    } else if stage_vector.intake.status == BenchmarkStageStatus::Reached
        || stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        || stage_vector.reachability.status == BenchmarkStageStatus::Partial
    {
        BenchmarkOutcomeClass::Partial
    } else {
        BenchmarkOutcomeClass::Failed
    }
}

fn evidence_grade_for_stage_vector_for_cli(
    stage_vector: &BenchmarkStageVector,
    logical_substrate: Option<LogicalSubstrateKind>,
) -> BenchmarkEvidenceGrade {
    let boot_required = logical_substrate != Some(LogicalSubstrateKind::Service);
    let reference_without_target_reachability = logical_substrate
        == Some(LogicalSubstrateKind::Reference)
        && stage_vector.reachability.status != BenchmarkStageStatus::Reached;
    if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        && stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        && (stage_vector.reachability.status == BenchmarkStageStatus::Reached
            || stage_vector.operator_access.status == BenchmarkStageStatus::Reached)
        && !reference_without_target_reachability
    {
        BenchmarkEvidenceGrade::Rich
    } else if (reference_without_target_reachability
        && (stage_vector.operator_access.status == BenchmarkStageStatus::Reached
            || stage_vector.research_utility.status == BenchmarkStageStatus::Reached))
        || ((!boot_required || stage_vector.boot.status == BenchmarkStageStatus::Reached)
            && (stage_vector.research_utility.status == BenchmarkStageStatus::Reached
                || stage_vector.reachability.status != BenchmarkStageStatus::NotReached))
    {
        BenchmarkEvidenceGrade::Moderate
    } else {
        BenchmarkEvidenceGrade::Minimal
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

fn augment_run_with_persisted_service_evidence(
    store: &RuntimeStore,
    project_dir: &Path,
    session_id: &str,
    scored_run: &mut RunRecord,
) -> DynResult<()> {
    let service_snapshots = load_runtime_artifact_jsons::<ObservedServiceSnapshot>(
        store,
        project_dir,
        session_id,
        &scored_run.run_id,
        "service-snapshot",
    )?;
    if service_snapshots.is_empty() {
        return Ok(());
    }
    let network_snapshots = load_runtime_artifact_jsons::<ObservedNetworkSnapshot>(
        store,
        project_dir,
        session_id,
        &scored_run.run_id,
        "network-snapshot",
    )?;
    if network_snapshots.is_empty() {
        return Ok(());
    }

    for snapshot in service_snapshots {
        for service in snapshot.services {
            if let Some(endpoint) = service.endpoint {
                push_unique_endpoint(
                    &mut scored_run.active_endpoints,
                    RuntimeEndpoint::new(
                        RuntimeEndpointKind::Service,
                        service.name,
                        "127.0.0.1",
                        0,
                    )
                    .with_uri(endpoint),
                );
            }
        }
    }
    Ok(())
}

fn collect_emux_comparator_evidence(project_dir: &Path, session_id: &str) -> DynResult<()> {
    let _ = crate::debug_cmd::run_surfaces(project_dir, Some(session_id), false);
    let _ = crate::observe_cmd::run_ps(project_dir, Some(session_id), false);
    let _ = crate::observe_cmd::run_net(project_dir, Some(session_id), false);
    let _ = crate::debug_cmd::run_shell(project_dir, Some(session_id), Some("id"));
    let _ = crate::debug_cmd::run_monitor(project_dir, Some(session_id), Some("info version"));
    if crate::debug_cmd::run_gdb(
        project_dir,
        Some(session_id),
        Some("dropbear"),
        Some("info threads"),
    )
    .is_err()
    {
        let _ = crate::debug_cmd::run_gdb(
            project_dir,
            Some(session_id),
            Some("uhttpd"),
            Some("info threads"),
        );
    }
    Ok(())
}

fn augment_run_with_emux_comparator_evidence(
    store: &RuntimeStore,
    project_dir: &Path,
    session_id: &str,
    run: &RunRecord,
) -> DynResult<RunRecord> {
    let mut scored_run = run.clone();
    augment_run_with_persisted_service_evidence(store, project_dir, session_id, &mut scored_run)?;
    if let Some(transcript) = load_runtime_artifact_json::<DebugShellTranscript>(
        store,
        project_dir,
        session_id,
        &run.run_id,
        "debug-shell-transcript",
    )? {
        if transcript.exit_code == 0 {
            push_unique_endpoint(
                &mut scored_run.active_endpoints,
                RuntimeEndpoint::new(
                    RuntimeEndpointKind::Shell,
                    "emux-userspace",
                    "127.0.0.1",
                    22222,
                )
                .with_uri(transcript.shell_uri),
            );
        }
    }
    if let Some(transcript) = load_runtime_artifact_json::<DebugGdbTranscript>(
        store,
        project_dir,
        session_id,
        &run.run_id,
        "debug-gdb-transcript",
    )? {
        if transcript.exit_code == 0 {
            push_unique_endpoint(
                &mut scored_run.active_endpoints,
                RuntimeEndpoint::new(RuntimeEndpointKind::Debugger, "emux-gdb", "127.0.0.1", 0)
                    .with_uri(transcript.debugger_uri),
            );
        }
    }
    if load_runtime_artifact_json::<ObservedProcessSnapshot>(
        store,
        project_dir,
        session_id,
        &run.run_id,
        "process-snapshot",
    )?
    .is_some()
        && scored_run.active_endpoints.is_empty()
    {
        push_unique_endpoint(
            &mut scored_run.active_endpoints,
            RuntimeEndpoint::new(
                RuntimeEndpointKind::Shell,
                "emux-userspace",
                "127.0.0.1",
                22222,
            )
            .with_uri("emux://userspace"),
        );
    }
    Ok(scored_run)
}

fn push_unique_endpoint(endpoints: &mut Vec<RuntimeEndpoint>, candidate: RuntimeEndpoint) {
    if endpoints.iter().any(|endpoint| {
        endpoint.kind == candidate.kind
            && endpoint.name == candidate.name
            && endpoint.host == candidate.host
            && endpoint.port == candidate.port
            && endpoint.target_port == candidate.target_port
            && endpoint.uri == candidate.uri
    }) {
        return;
    }
    endpoints.push(candidate);
}

fn load_runtime_artifact_json<T: DeserializeOwned>(
    store: &RuntimeStore,
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
    subkind: &str,
) -> DynResult<Option<T>> {
    let mut artifacts = store.read_run_artifacts(session_id, run_id)?;
    artifacts.retain(|artifact| {
        artifact.kind == ArtifactKind::RuntimeCapture || artifact.kind == ArtifactKind::RuntimeDebug
    });
    artifacts.retain(|artifact| artifact.subkind == subkind);
    artifacts.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    let Some(artifact) = artifacts.into_iter().last() else {
        return Ok(None);
    };
    let text = fs::read_to_string(resolve_artifact_path(project_dir, &artifact.path))?;
    Ok(Some(serde_json::from_str(&text)?))
}

fn load_runtime_artifact_jsons<T: DeserializeOwned>(
    store: &RuntimeStore,
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
    subkind: &str,
) -> DynResult<Vec<T>> {
    let mut artifacts = store.read_run_artifacts(session_id, run_id)?;
    artifacts.retain(|artifact| {
        artifact.kind == ArtifactKind::RuntimeCapture || artifact.kind == ArtifactKind::RuntimeDebug
    });
    artifacts.retain(|artifact| artifact.subkind == subkind);
    artifacts.sort_by(|left, right| left.created_at.cmp(&right.created_at));

    let mut records = Vec::new();
    for artifact in artifacts {
        let text = fs::read_to_string(resolve_artifact_path(project_dir, &artifact.path))?;
        records.push(serde_json::from_str(&text)?);
    }
    Ok(records)
}

fn resolve_benchmark_comparator(
    requested_comparator: Option<&str>,
    requested_run_mode: Option<&str>,
) -> DynResult<BenchmarkComparator> {
    match (requested_comparator, requested_run_mode) {
        (None, None) => Ok(BenchmarkComparator::new(
            "fat",
            ComparatorKind::Internal,
            BenchmarkRunMode::FatNative,
        )),
        (Some("emux"), Some("comparator-tuned")) => Ok(BenchmarkComparator::new(
            "emux",
            ComparatorKind::External,
            BenchmarkRunMode::ComparatorTuned,
        )),
        (Some(comparator), Some(run_mode)) => Err(format!(
            "unsupported benchmark comparator execution: {comparator} [{run_mode}]"
        )
        .into()),
        (Some(_), None) | (None, Some(_)) => {
            Err("benchmark comparator execution requires both --comparator and --run-mode".into())
        }
    }
}

fn import(project_dir: PathBuf, report_path: PathBuf) -> DynResult<()> {
    let project_dir = crate::normalize_project_dir(&project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let project = crate::load_project(&db, &project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let target = crate::ensure_target_record(&store, &project)?;
    let benchmark_target = benchmark_target_from_project(&project_dir, &target);
    let report_bytes = fs::read(&report_path)?;
    let report: ImportedBenchmarkReport = serde_json::from_slice(&report_bytes)?;

    let benchmark_run = BenchmarkRunRecord::try_new(
        benchmark_target.target_id.clone(),
        BenchmarkComparator::new(
            report.comparator_id.clone(),
            ComparatorKind::External,
            report.run_mode,
        ),
        report.host_profile.clone(),
        format!("import-sha256:{:x}", Sha256::digest(&report_bytes)),
    )?;
    let outcome = BenchmarkOutcomeRecord::new(
        benchmark_run.benchmark_run_id.clone(),
        report.outcome_class,
        report.evidence_grade,
        report.stage_vector,
    );

    store.write_benchmark_target(&benchmark_target)?;
    store.write_benchmark_run(&benchmark_run)?;
    store.write_benchmark_outcome(&outcome)?;

    print_scored_run(&benchmark_run, &outcome);
    Ok(())
}

fn report(project_dir: PathBuf, json: bool) -> DynResult<()> {
    let project_dir = crate::normalize_project_dir(&project_dir)?;
    let store = RuntimeStore::open(&project_dir)?;
    let targets = store.read_benchmark_targets()?;
    let runs = store.read_benchmark_runs()?;
    let outcomes = store.read_benchmark_outcomes()?;

    let run_index: BTreeMap<_, _> = runs
        .into_iter()
        .map(|run| (run.benchmark_run_id.clone(), run))
        .collect();
    let outcome_index: BTreeMap<_, _> = outcomes
        .into_iter()
        .map(|outcome| (outcome.benchmark_run_id.clone(), outcome))
        .collect();

    let mut report_targets = Vec::new();
    for target in targets {
        let mut comparisons = Vec::new();
        for run in run_index
            .values()
            .filter(|run| run.target_id == target.target_id)
        {
            let outcome = outcome_index.get(&run.benchmark_run_id).ok_or_else(|| {
                format!("missing benchmark outcome for run {}", run.benchmark_run_id)
            })?;
            comparisons.push(report_row_from_run(run, outcome));
        }
        comparisons.sort_by(|left, right| {
            left.comparator_id
                .cmp(&right.comparator_id)
                .then(left.run_mode.cmp(&right.run_mode))
                .then(left.benchmark_run_id.cmp(&right.benchmark_run_id))
        });
        if !comparisons.is_empty() {
            report_targets.push(ReportTarget {
                target_id: target.target_id,
                display_name: target.display_name,
                architecture: target.architecture,
                packaging: target.packaging,
                comparisons,
            });
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&BenchmarkReport {
                targets: report_targets
            })?
        );
        return Ok(());
    }

    for target in report_targets {
        let palette = crate::style::Palette::stdout();
        println!("{}", palette.heading("Benchmark Target"));
        println!("{}", palette.kv("target", &target.display_name));
        println!("{}", palette.kv("architecture", &target.architecture));
        println!("{}", palette.kv("packaging", &target.packaging));
        for comparison in target.comparisons {
            println!(
                "{}",
                palette.kv("benchmark run", &comparison.benchmark_run_id)
            );
            println!(
                "{}",
                palette.kv(
                    "comparator",
                    format!("{} [{}]", comparison.comparator_id, comparison.run_mode)
                )
            );
            println!("{}", palette.kv("host profile", &comparison.host_profile));
            println!(
                "{}",
                palette.kv(
                    "outcome class",
                    palette.status_word(&comparison.outcome_class)
                )
            );
            println!(
                "{}",
                palette.kv("evidence grade", palette.info(&comparison.evidence_grade))
            );
            println!("{}", palette.kv("stages", &comparison.stage_summary));
        }
        println!();
    }
    Ok(())
}

fn benchmark_target_from_project(
    project_dir: &Path,
    target: &fat_core::targets::TargetRecord,
) -> BenchmarkTarget {
    BenchmarkTarget::new(
        target.target_id.clone(),
        target.display_name.clone(),
        project_architecture(project_dir),
        "vendor-firmware-blob",
    )
}

fn project_architecture(project_dir: &Path) -> String {
    let Ok(content) = fs::read_to_string(crate::project_signals_path(project_dir)) else {
        return "unknown".to_string();
    };

    content
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("arch:"))
        .map(str::trim)
        .filter(|arch| !arch.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn load_managed_runtime_summary(
    store: &RuntimeStore,
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
) -> DynResult<Option<ManagedRuntimeSummary>> {
    let mut artifacts = store.read_run_artifacts(session_id, run_id)?;
    artifacts.retain(|artifact| {
        artifact.kind == ArtifactKind::RuntimeState
            && matches!(
                artifact.subkind.as_str(),
                "managed-runtime-summary"
                    | "managed-runtime-status"
                    | "firmae-upstream-observation"
            )
            && artifact.content_type == "application/json"
    });
    artifacts.sort_by(|left, right| left.created_at.cmp(&right.created_at));

    let Some(artifact) = artifacts.into_iter().last() else {
        return Ok(None);
    };

    let text = fs::read_to_string(resolve_artifact_path(project_dir, &artifact.path))?;
    let summary = managed_runtime_summary_from_runtime_state_json(&artifact.subkind, &text)
        .ok_or_else(|| {
            format!(
                "failed to parse {} artifact {}",
                artifact.subkind, artifact.path
            )
        })?;
    Ok(Some(summary))
}

fn resolve_artifact_path(project_dir: &Path, artifact_path: &str) -> PathBuf {
    let artifact_path = Path::new(artifact_path);
    if artifact_path.is_absolute() {
        artifact_path.to_path_buf()
    } else {
        project_dir.join(artifact_path)
    }
}

fn local_host_profile() -> String {
    format!("local-{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn select_runtime_view(
    store: &RuntimeStore,
    requested_session_id: Option<&str>,
    requested_run_id: Option<&str>,
) -> DynResult<Option<run_cmd::RuntimeView>> {
    match requested_run_id {
        Some(run_id) => select_runtime_view_by_run_id(store, requested_session_id, run_id),
        None => run_cmd::load_runtime_view(store, requested_session_id),
    }
}

fn select_runtime_view_by_run_id(
    store: &RuntimeStore,
    requested_session_id: Option<&str>,
    requested_run_id: &str,
) -> DynResult<Option<run_cmd::RuntimeView>> {
    let session = match requested_session_id {
        Some(session_id) => resolve_session_by_id_or_alias(store, session_id)?,
        None => find_session_for_run_id(store, requested_run_id)?,
    };
    let Some(session) = session else {
        return Ok(None);
    };
    let run = match store.read_run(&session.session_id, requested_run_id) {
        Ok(run) => run,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let diagnostics = store.read_run_diagnostics(&session.session_id, requested_run_id)?;
    Ok(Some(run_cmd::RuntimeView {
        session,
        run,
        diagnostics,
    }))
}

fn resolve_session_by_id_or_alias(
    store: &RuntimeStore,
    session_id_or_alias: &str,
) -> DynResult<Option<fat_core::sessions::SessionRecord>> {
    match store.read_session(session_id_or_alias) {
        Ok(session) => Ok(Some(session)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut sessions = store.read_sessions()?;
            sessions.sort_by(|left, right| left.updated_at.cmp(&right.updated_at));
            Ok(sessions.into_iter().rev().find(|session| {
                session.requested_session_id.as_deref() == Some(session_id_or_alias)
            }))
        }
        Err(err) => Err(err.into()),
    }
}

fn find_session_for_run_id(
    store: &RuntimeStore,
    requested_run_id: &str,
) -> DynResult<Option<fat_core::sessions::SessionRecord>> {
    let mut matches = Vec::new();
    for session in store.read_sessions()? {
        let has_run = if session
            .run_ids
            .iter()
            .any(|run_id| run_id == requested_run_id)
        {
            true
        } else {
            store
                .read_runs(&session.session_id)?
                .into_iter()
                .any(|run| run.run_id == requested_run_id)
        };
        if has_run {
            matches.push(session);
        }
    }
    matches.sort_by(|left, right| left.updated_at.cmp(&right.updated_at));
    if matches.len() > 1 {
        return Err(format!("multiple sessions matched run {requested_run_id}").into());
    }
    Ok(matches.pop())
}

fn print_scored_run(run: &BenchmarkRunRecord, outcome: &BenchmarkOutcomeRecord) {
    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Benchmark Score"));
    println!("{}", palette.kv("benchmark run", &run.benchmark_run_id));
    println!("{}", palette.kv("target", &run.target_id));
    println!(
        "{}",
        palette.kv("comparator", &run.comparator.comparator_id)
    );
    println!(
        "{}",
        palette.kv("run mode", run.comparator.run_mode.as_str())
    );
    println!("{}", palette.kv("host profile", &run.host_profile));
    println!(
        "{}",
        palette.kv(
            "outcome class",
            palette.status_word(outcome_class_label(outcome.outcome_class))
        )
    );
    println!(
        "{}",
        palette.kv(
            "evidence grade",
            palette.info(evidence_grade_label(outcome.evidence_grade))
        )
    );
    println!(
        "{}",
        palette.kv("stages", stage_summary(&outcome.stage_vector))
    );
}

/// `benchmark score` entry point: panel mode when styling is on, otherwise the
/// flat card. `import` keeps calling the flat renderer directly.
fn print_scored_run_for_target(run: &BenchmarkRunRecord, outcome: &BenchmarkOutcomeRecord) {
    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        print_scored_run_panel(&palette, run, outcome);
        return;
    }
    print_scored_run(run, outcome);
}
fn print_scored_run_panel(
    palette: &crate::style::Palette,
    run: &BenchmarkRunRecord,
    outcome: &BenchmarkOutcomeRecord,
) {
    let lines = vec![
        palette.kv("benchmark run", &run.benchmark_run_id),
        palette.kv("target", &run.target_id),
        palette.kv("comparator", &run.comparator.comparator_id),
        palette.kv("run mode", run.comparator.run_mode.as_str()),
        palette.kv("host profile", &run.host_profile),
        palette.kv(
            "outcome class",
            palette.status_word(outcome_class_label(outcome.outcome_class)),
        ),
        palette.kv(
            "evidence grade",
            palette.info(evidence_grade_label(outcome.evidence_grade)),
        ),
        palette.kv("stages", stage_summary(&outcome.stage_vector)),
    ];
    println!("{}", palette.panel("Benchmark Score", &lines));
}

fn report_row_from_run(run: &BenchmarkRunRecord, outcome: &BenchmarkOutcomeRecord) -> ReportRow {
    ReportRow {
        benchmark_run_id: run.benchmark_run_id.clone(),
        comparator_id: run.comparator.comparator_id.clone(),
        comparator_kind: run.comparator.kind.as_str().to_string(),
        run_mode: run.comparator.run_mode.as_str().to_string(),
        host_profile: run.host_profile.clone(),
        outcome_class: outcome_class_label(outcome.outcome_class).to_string(),
        evidence_grade: evidence_grade_label(outcome.evidence_grade).to_string(),
        stage_summary: stage_summary(&outcome.stage_vector),
        stage_vector: ReportStageVector::from(&outcome.stage_vector),
    }
}

fn outcome_class_label(outcome_class: BenchmarkOutcomeClass) -> &'static str {
    match outcome_class {
        BenchmarkOutcomeClass::Failed => "failed",
        BenchmarkOutcomeClass::Partial => "partial",
        BenchmarkOutcomeClass::Useful => "useful",
        BenchmarkOutcomeClass::Strong => "strong",
    }
}

fn evidence_grade_label(evidence_grade: BenchmarkEvidenceGrade) -> &'static str {
    match evidence_grade {
        BenchmarkEvidenceGrade::Minimal => "minimal",
        BenchmarkEvidenceGrade::Moderate => "moderate",
        BenchmarkEvidenceGrade::Rich => "rich",
    }
}

#[derive(Debug, Deserialize)]
struct ImportedBenchmarkReport {
    comparator_id: String,
    run_mode: BenchmarkRunMode,
    host_profile: String,
    outcome_class: BenchmarkOutcomeClass,
    evidence_grade: BenchmarkEvidenceGrade,
    stage_vector: BenchmarkStageVector,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    targets: Vec<ReportTarget>,
}

#[derive(Debug, Clone, Serialize)]
struct ReportTarget {
    target_id: String,
    display_name: String,
    architecture: String,
    packaging: String,
    comparisons: Vec<ReportRow>,
}

#[derive(Debug, Clone, Serialize)]
struct ReportRow {
    benchmark_run_id: String,
    comparator_id: String,
    comparator_kind: String,
    run_mode: String,
    host_profile: String,
    outcome_class: String,
    evidence_grade: String,
    stage_summary: String,
    stage_vector: ReportStageVector,
}

#[derive(Debug, Clone, Serialize)]
struct ReportStageVector {
    intake: String,
    boot: String,
    reachability: String,
    operator_access: String,
    research_utility: String,
    exploit_readiness: String,
}

impl From<&BenchmarkStageVector> for ReportStageVector {
    fn from(stage_vector: &BenchmarkStageVector) -> Self {
        Self {
            intake: stage_status_label(stage_vector.intake.status).to_string(),
            boot: stage_status_label(stage_vector.boot.status).to_string(),
            reachability: stage_status_label(stage_vector.reachability.status).to_string(),
            operator_access: stage_status_label(stage_vector.operator_access.status).to_string(),
            research_utility: stage_status_label(stage_vector.research_utility.status).to_string(),
            exploit_readiness: stage_status_label(stage_vector.exploit_readiness.status)
                .to_string(),
        }
    }
}

fn stage_summary(stage_vector: &BenchmarkStageVector) -> String {
    format!(
        "intake={} boot={} reachability={} operator-access={} research-utility={} exploit-readiness={}",
        stage_status_label(stage_vector.intake.status),
        stage_status_label(stage_vector.boot.status),
        stage_status_label(stage_vector.reachability.status),
        stage_status_label(stage_vector.operator_access.status),
        stage_status_label(stage_vector.research_utility.status),
        stage_status_label(stage_vector.exploit_readiness.status),
    )
}

fn stage_status_label(status: BenchmarkStageStatus) -> &'static str {
    match status {
        BenchmarkStageStatus::NotReached => "not-reached",
        BenchmarkStageStatus::Partial => "partial",
        BenchmarkStageStatus::Reached => "reached",
    }
}
