use clap::{Args, Subcommand};
use fat_query::android::benchmark::{
    run_android_discovery_benchmark, AndroidDiscoveryBenchmarkSummary,
};
use fat_query::android::chains::{build_android_chain_report, AndroidChainReport};
use fat_query::android::discovery::{
    build_discover_report, build_locality_report, build_semantic_explain_report, inventory_apks,
    load_semantic_bundle, AndroidDiscoverReport, AndroidInventoryReport, AndroidLocalityReport,
    AndroidSemanticExplainReport, AndroidSemanticExplainRevelation, AndroidSemanticExplainSurface,
};
use fat_query::android::extractor::{
    derive_semantic_bundle_from_jadx_root_with_progress, merge_semantic_layers, run_jadx,
    AndroidProgressPhase, AndroidProgressSink, AndroidProgressSnapshot, AndroidSemanticMode,
};
use fat_query::android::flutter_runtime::derive_flutter_runtime_semantics;
use fat_query::android::handoff::{build_runtime_manifest, write_runtime_manifest};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;
use zip::ZipArchive;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Args)]
pub struct AndroidInventoryArgs {
    /// Path to the base APK.
    #[arg(long)]
    apk: PathBuf,
    /// Optional split APKs that should be analyzed with the base APK.
    #[arg(long = "splits", num_args = 1.., value_delimiter = ',')]
    splits: Vec<PathBuf>,
    /// Output as JSON instead of structured text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AndroidDiscoverArgs {
    /// Path to the base APK.
    #[arg(long)]
    apk: PathBuf,
    /// Optional split APKs that should be analyzed with the base APK.
    #[arg(long = "splits", num_args = 1.., value_delimiter = ',')]
    splits: Vec<PathBuf>,
    /// Optional semantic bundle emitted by the Android extractor pipeline.
    #[arg(long = "semantic-bundle")]
    semantic_bundle: Option<PathBuf>,
    /// Optional JADX decompiled tree to synthesize a semantic bundle from.
    #[arg(long = "jadx-root")]
    jadx_root: Option<PathBuf>,
    /// Optional output path for a derived semantic bundle.
    #[arg(long = "semantic-bundle-out")]
    semantic_bundle_out: Option<PathBuf>,
    /// Semantic bundle density for derived extraction.
    #[arg(long = "semantic-mode", default_value = "default")]
    semantic_mode: String,
    /// Optional family selector such as remote-router-gadget.
    #[arg(long)]
    family: Option<String>,
    /// Limit the number of returned leads.
    #[arg(long, default_value_t = 10)]
    top_k: usize,
    /// Label recorded in the discovery report; does not change analysis depth or execution.
    #[arg(long, default_value = "deep")]
    mode: String,
    /// Progress output mode.
    #[arg(long, default_value = "human")]
    progress: String,
    /// Output as JSON instead of structured text.
    #[arg(long)]
    json: bool,
    /// Optional path to write a target-lane runtime manifest for the discovered leads.
    #[arg(long = "runtime-manifest-out")]
    runtime_manifest_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct AndroidChainsArgs {
    /// Path to the base APK.
    #[arg(long)]
    apk: PathBuf,
    /// Optional split APKs that should be analyzed with the base APK.
    #[arg(long = "splits", num_args = 1.., value_delimiter = ',')]
    splits: Vec<PathBuf>,
    /// Optional semantic bundle emitted by the Android extractor pipeline.
    #[arg(long = "semantic-bundle")]
    semantic_bundle: Option<PathBuf>,
    /// Optional JADX decompiled tree to synthesize a semantic bundle from.
    #[arg(long = "jadx-root")]
    jadx_root: Option<PathBuf>,
    /// Semantic bundle density for derived extraction.
    #[arg(long = "semantic-mode", default_value = "default")]
    semantic_mode: String,
    /// Progress output mode.
    #[arg(long, default_value = "human")]
    progress: String,
    /// Entry surface, runtime role, package, endpoint, or revelation to search from.
    #[arg(long)]
    entry: String,
    /// Sink surface, runtime role, package, endpoint, or command object to search toward.
    #[arg(long)]
    sink: String,
    /// Output as JSON instead of structured text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AndroidLocalityArgs {
    /// Path to the base APK.
    #[arg(long)]
    apk: PathBuf,
    /// Optional split APKs that should be analyzed with the base APK.
    #[arg(long = "splits", num_args = 1.., value_delimiter = ',')]
    splits: Vec<PathBuf>,
    /// Output as JSON instead of structured text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AndroidExplainArgs {
    /// Path to a semantic bundle emitted by the Android extractor pipeline.
    #[arg(long = "semantic-bundle")]
    semantic_bundle: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct AndroidBenchmarkArgs {
    /// Benchmark manifest path.
    #[arg(long)]
    manifest: PathBuf,
    /// Output as JSON instead of structured text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum AndroidCommand {
    /// Inventory Android APK structure, manifest surface, and split metadata.
    Inventory(AndroidInventoryArgs),
    /// Emit Android discovery leads for the requested family.
    Discover(AndroidDiscoverArgs),
    /// Query Android capability chains between an entry and sink surface.
    #[command(
        long_about = "Query Android semantic chains between an entry and a sink.\n\n\
Chains prefer strong semantic edges such as runtime role clusters, explicit control surfaces, and narrow subsystems. \
Broad runtime overlap alone is not enough: informational endpoints and weak runtime-only connections are rejected as no-path.\n\n\
Examples:\n  \
fat android chains --apk app.apk --semantic-bundle app.semantic.json --entry bluetooth --sink main.lua --json\n  \
fat android chains --apk app.apk --semantic-bundle app.semantic.json --entry login --sink signout --json"
    )]
    Chains(AndroidChainsArgs),
    /// Summarize Android locality classifications for app and bundled logic.
    Locality(AndroidLocalityArgs),
    /// Explain a semantic bundle in compact, human-readable form.
    Explain(AndroidExplainArgs),
    /// Run Android discovery benchmark evaluation from a manifest.
    Benchmark(AndroidBenchmarkArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AndroidProgressMode {
    Human,
    Jsonl,
    Quiet,
}

impl FromStr for AndroidProgressMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "jsonl" => Ok(Self::Jsonl),
            "quiet" => Ok(Self::Quiet),
            other => Err(format!("unsupported android progress mode: {other}")),
        }
    }
}

struct CliAndroidProgressSink {
    mode: AndroidProgressMode,
    wrote_header: bool,
}

impl CliAndroidProgressSink {
    fn new(mode: AndroidProgressMode) -> Self {
        Self {
            mode,
            wrote_header: false,
        }
    }

    fn ensure_header(&mut self) {
        if self.mode != AndroidProgressMode::Human || self.wrote_header {
            return;
        }
        let _ = writeln!(io::stderr(), "Android Discover Progress");
        self.wrote_header = true;
    }

    fn emit_human(
        &mut self,
        phase: AndroidProgressPhase,
        prefix: &str,
        snapshot: &AndroidProgressSnapshot,
    ) {
        self.ensure_header();
        let _ = writeln!(io::stderr(), "{prefix} {}", phase.label());
        if let (Some(completed), Some(total)) = (snapshot.completed, snapshot.total) {
            let _ = writeln!(io::stderr(), "  scanned {completed}/{total} files");
        }
        if let Some(facts) = snapshot.facts {
            let symbols = snapshot.symbols.unwrap_or_default();
            let controls = snapshot.controls.unwrap_or_default();
            let _ = writeln!(
                io::stderr(),
                "  facts={facts} symbols={symbols} controls={controls}"
            );
        }
        if let Some(subsystems) = snapshot.subsystems {
            let _ = writeln!(io::stderr(), "  subsystems={subsystems}");
        }
        if let Some(revelations) = snapshot.revelations {
            let _ = writeln!(io::stderr(), "  revelations={revelations}");
        }
        if let Some(message) = &snapshot.message {
            let _ = writeln!(io::stderr(), "  {message}");
        }
    }

    fn emit_jsonl(
        &mut self,
        event: &str,
        phase: AndroidProgressPhase,
        snapshot: &AndroidProgressSnapshot,
    ) {
        #[derive(Serialize)]
        struct ProgressEvent<'a> {
            event: &'a str,
            phase: AndroidProgressPhase,
            #[serde(flatten)]
            snapshot: &'a AndroidProgressSnapshot,
        }
        let payload = ProgressEvent {
            event,
            phase,
            snapshot,
        };
        let _ = writeln!(
            io::stderr(),
            "{}",
            serde_json::to_string(&payload)
                .unwrap_or_else(|_| "{\"event\":\"serialization_error\"}".into())
        );
    }
}

impl AndroidProgressSink for CliAndroidProgressSink {
    fn phase_started(&mut self, phase: AndroidProgressPhase, snapshot: &AndroidProgressSnapshot) {
        match self.mode {
            AndroidProgressMode::Human => self.emit_human(phase, "[start]", snapshot),
            AndroidProgressMode::Jsonl => self.emit_jsonl("phase_started", phase, snapshot),
            AndroidProgressMode::Quiet => {}
        }
    }

    fn phase_progress(&mut self, phase: AndroidProgressPhase, snapshot: &AndroidProgressSnapshot) {
        match self.mode {
            AndroidProgressMode::Human => self.emit_human(phase, "[progress]", snapshot),
            AndroidProgressMode::Jsonl => self.emit_jsonl("phase_progress", phase, snapshot),
            AndroidProgressMode::Quiet => {}
        }
    }

    fn phase_completed(&mut self, phase: AndroidProgressPhase, snapshot: &AndroidProgressSnapshot) {
        match self.mode {
            AndroidProgressMode::Human => self.emit_human(phase, "[done]", snapshot),
            AndroidProgressMode::Jsonl => self.emit_jsonl("phase_completed", phase, snapshot),
            AndroidProgressMode::Quiet => {}
        }
    }
}

pub fn run(subject: AndroidCommand) -> DynResult<()> {
    match subject {
        AndroidCommand::Inventory(args) => run_inventory(args),
        AndroidCommand::Discover(args) => run_discover(args),
        AndroidCommand::Chains(args) => run_chains(args),
        AndroidCommand::Locality(args) => run_locality(args),
        AndroidCommand::Explain(args) => run_explain(args),
        AndroidCommand::Benchmark(args) => run_benchmark(args),
    }
}

fn run_inventory(args: AndroidInventoryArgs) -> DynResult<()> {
    reject_xapk_input(&args.apk, "inventory")?;
    let report = inventory_apks(&args.apk, &args.splits)
        .map_err(|message| format!("android inventory failed: {message}"))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_inventory_panel(&palette, &report);
    } else {
        render_inventory_plain(&palette, &report);
    }
    Ok(())
}

fn render_inventory_plain(palette: &crate::style::Palette, report: &AndroidInventoryReport) {
    println!("{}", palette.heading("Android Inventory"));
    println!("{}", palette.kv("apk", &report.base_apk));
    println!(
        "{}",
        palette.kv("containers", report.summary.container_count.to_string())
    );
    println!(
        "{}",
        palette.kv("dex_files", report.summary.dex_file_count.to_string())
    );
    println!(
        "{}",
        palette.kv("native_libs", report.summary.native_lib_count.to_string())
    );
    println!(
        "{}",
        palette.kv("components", report.summary.component_count.to_string())
    );
    println!(
        "{}",
        palette.kv("graph_nodes", report.graph_summary.node_count.to_string())
    );
}

fn render_inventory_panel(palette: &crate::style::Palette, report: &AndroidInventoryReport) {
    let mut lines = vec![format!(
        "{} {} containers · {} dex files · {} native libs",
        palette.dot_ok(),
        report.summary.container_count,
        report.summary.dex_file_count,
        report.summary.native_lib_count
    )];
    lines.push(String::new());
    lines.push(palette.heading("Summary"));
    lines.push(palette.kv("apk", &report.base_apk));
    lines.push(palette.kv("containers", report.summary.container_count.to_string()));
    lines.push(palette.kv("dex_files", report.summary.dex_file_count.to_string()));
    lines.push(palette.kv("native_libs", report.summary.native_lib_count.to_string()));
    lines.push(palette.kv("components", report.summary.component_count.to_string()));
    lines.push(palette.kv("graph_nodes", report.graph_summary.node_count.to_string()));
    println!("{}", palette.panel("Android Inventory", &lines));
    println!(
        "{}",
        palette.next_hint(&format!("fat android discover --apk {}", report.base_apk))
    );
}

fn run_locality(args: AndroidLocalityArgs) -> DynResult<()> {
    reject_xapk_input(&args.apk, "locality")?;
    let report = build_locality_report(&args.apk, &args.splits)
        .map_err(|message| format!("android locality failed: {message}"))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_locality_panel(&palette, &report);
    } else {
        render_locality_plain(&palette, &report);
    }
    Ok(())
}

fn render_locality_plain(palette: &crate::style::Palette, report: &AndroidLocalityReport) {
    println!("{}", palette.heading("Android Locality"));
    println!("{}", palette.kv("apk", &report.base_apk));
    println!(
        "{}",
        palette.kv("app_local", report.summary.app_local.to_string())
    );
    println!(
        "{}",
        palette.kv(
            "split_feature_local",
            report.summary.split_feature_local.to_string()
        )
    );
    println!(
        "{}",
        palette.kv(
            "bundled_native_lib",
            report.summary.bundled_native_lib.to_string()
        )
    );
    println!(
        "{}",
        palette.kv("unknown", report.summary.unknown.to_string())
    );
}

fn render_locality_panel(palette: &crate::style::Palette, report: &AndroidLocalityReport) {
    let mut lines = vec![format!(
        "{} {} app-local · {} split-feature-local · {} bundled native libs",
        palette.dot_ok(),
        report.summary.app_local,
        report.summary.split_feature_local,
        report.summary.bundled_native_lib
    )];
    lines.push(String::new());
    lines.push(palette.heading("Summary"));
    lines.push(palette.kv("apk", &report.base_apk));
    lines.push(palette.kv("app_local", report.summary.app_local.to_string()));
    lines.push(palette.kv(
        "split_feature_local",
        report.summary.split_feature_local.to_string(),
    ));
    lines.push(palette.kv(
        "bundled_native_lib",
        report.summary.bundled_native_lib.to_string(),
    ));
    lines.push(palette.kv("unknown", report.summary.unknown.to_string()));
    println!("{}", palette.panel("Android Locality", &lines));
    println!(
        "{}",
        palette.next_hint(&format!(
            "fat android chains --apk {} --entry <entry> --sink <sink>",
            report.base_apk
        ))
    );
}

fn run_chains(args: AndroidChainsArgs) -> DynResult<()> {
    reject_xapk_input(&args.apk, "chains")?;
    let progress_mode = args
        .progress
        .parse::<AndroidProgressMode>()
        .map_err(|message| format!("android chains failed: {message}"))?;
    let mut progress = CliAndroidProgressSink::new(progress_mode);
    let semantic_bundle_path = resolve_chains_semantic_bundle_path(&args, &mut progress)?;
    let Some(semantic_bundle_path) = semantic_bundle_path else {
        return Err("android chains failed: no semantic bundle available".into());
    };
    let bundle = load_semantic_bundle(&semantic_bundle_path)
        .map_err(|message| format!("android chains failed: {message}"))?;
    let report = build_android_chain_report(&bundle, &args.entry, &args.sink);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_chains_panel(&palette, &report);
    } else {
        render_chains_plain(&palette, &report);
    }
    Ok(())
}

fn render_chains_plain(palette: &crate::style::Palette, report: &AndroidChainReport) {
    println!("{}", palette.heading("Android Chains"));
    println!("{}", palette.kv("entry", &report.entry));
    println!("{}", palette.kv("sink", &report.sink));
    println!(
        "{}",
        palette.kv("path_found", report.path_found.to_string())
    );
    for step in &report.steps {
        println!("{} {}", palette.bullet("-"), palette.code(&step.label));
    }
    for warning in &report.warnings {
        println!("{} {}", palette.warn("warning:"), warning);
    }
    println!("{}", palette.muted(&report.message));
}

fn render_chains_panel(palette: &crate::style::Palette, report: &AndroidChainReport) {
    let mut lines = vec![
        palette.kv("entry", &report.entry),
        palette.kv("sink", &report.sink),
        palette.kv("path_found", report.path_found.to_string()),
    ];
    lines.push(String::new());
    let step_dot = if report.path_found {
        palette.dot_ok()
    } else {
        palette.dot_warn()
    };
    for step in &report.steps {
        lines.push(format!("{} {}", step_dot, palette.code(&step.label)));
    }
    if !report.warnings.is_empty() {
        lines.push(String::new());
        for warning in &report.warnings {
            lines.push(format!("{} {}", palette.dot_warn(), warning));
        }
    }
    lines.push(String::new());
    lines.push(palette.muted(&report.message));
    println!("{}", palette.panel("Android Chains", &lines));
}

fn run_discover(args: AndroidDiscoverArgs) -> DynResult<()> {
    reject_xapk_input(&args.apk, "discover")?;
    let progress_mode = args
        .progress
        .parse::<AndroidProgressMode>()
        .map_err(|message| format!("android discover failed: {message}"))?;
    let mut progress = CliAndroidProgressSink::new(progress_mode);
    let semantic_bundle_path = resolve_semantic_bundle_path(&args, &mut progress)?;
    progress.phase_started(
        AndroidProgressPhase::RankDiscoveryLeads,
        &AndroidProgressSnapshot::default(),
    );
    let mut report = build_discover_report(
        &args.apk,
        &args.splits,
        semantic_bundle_path.as_deref(),
        args.family.as_deref(),
        args.top_k,
        &args.mode,
    )
    .map_err(|message| format!("android discover failed: {message}"))?;
    let top_lead_message = report
        .leads
        .first()
        .map(|lead| format!("provisional top lead: {} -> {}", lead.family, lead.symbol));
    progress.phase_completed(
        AndroidProgressPhase::RankDiscoveryLeads,
        &AndroidProgressSnapshot {
            completed: Some(report.lead_count),
            total: Some(report.top_k),
            message: top_lead_message,
            ..AndroidProgressSnapshot::default()
        },
    );
    if let Some(output_path) = args.runtime_manifest_out.as_deref() {
        if report.lead_count == 0 {
            report.warnings.push(
                "no leads available for runtime handoff; runtime manifest was skipped".into(),
            );
        } else {
            let package_name = report
                .manifest_package_name
                .as_deref()
                .or(report
                    .semantic
                    .as_ref()
                    .map(|semantic| semantic.target_package_name.as_str()))
                .ok_or("android discover could not resolve a package name for runtime handoff")?;
            let (manifest, _handoffs) = build_runtime_manifest(&report, package_name, output_path)
                .map_err(|message| format!("android runtime handoff failed: {message}"))?;
            write_runtime_manifest(&manifest, output_path)
                .map_err(|message| format!("android runtime handoff failed: {message}"))?;
        }
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_discover_panel(&palette, &report);
    } else {
        render_discover_plain(&palette, &report);
    }
    Ok(())
}

fn render_discover_plain(palette: &crate::style::Palette, report: &AndroidDiscoverReport) {
    println!("{}", palette.heading("Android Discover"));
    println!("{}", palette.kv("apk", &report.base_apk));
    if !report.split_apks.is_empty() {
        println!(
            "{}",
            palette.kv("split_apks", report.split_apks.len().to_string())
        );
    }
    if let Some(family) = &report.family_filter {
        println!("{}", palette.kv("family", family));
    }
    println!("{}", palette.kv("status", &report.status));
    println!(
        "{}",
        palette.kv(
            "containers",
            report.inventory_summary.container_count.to_string()
        )
    );
    println!(
        "{}",
        palette.kv("graph_nodes", report.graph_summary.node_count.to_string())
    );
    if let Some(semantic) = &report.semantic {
        println!(
            "{}",
            palette.kv("semantic_bundle", &semantic.bundle_version)
        );
        println!(
            "{}",
            palette.kv("semantic_facts", semantic.fact_count.to_string())
        );
        println!(
            "{}",
            palette.kv(
                "semantic_observed",
                semantic.observed_fact_count.to_string()
            )
        );
        println!(
            "{}",
            palette.kv(
                "semantic_inferred",
                semantic.inferred_fact_count.to_string()
            )
        );
    }
    println!(
        "{}",
        palette.kv("lead_count", report.lead_count.to_string())
    );
    println!("{}", palette.muted(&report.message));
    for warning in &report.warnings {
        println!("{} {}", palette.warn("warning:"), warning);
    }
}

fn render_discover_panel(palette: &crate::style::Palette, report: &AndroidDiscoverReport) {
    let mut lines = vec![palette.kv("apk", &report.base_apk)];
    if !report.split_apks.is_empty() {
        lines.push(palette.kv("split_apks", report.split_apks.len().to_string()));
    }
    if let Some(family) = &report.family_filter {
        lines.push(palette.kv("family", family));
    }
    lines.push(palette.kv("status", &report.status));
    lines.push(String::new());
    lines.push(palette.heading("Inventory"));
    lines.push(palette.kv(
        "containers",
        report.inventory_summary.container_count.to_string(),
    ));
    lines.push(palette.kv("graph_nodes", report.graph_summary.node_count.to_string()));
    if let Some(semantic) = &report.semantic {
        lines.push(String::new());
        lines.push(palette.heading("Semantic"));
        lines.push(palette.kv("semantic_bundle", &semantic.bundle_version));
        lines.push(palette.kv("semantic_facts", semantic.fact_count.to_string()));
        lines.push(palette.kv(
            "semantic_observed",
            semantic.observed_fact_count.to_string(),
        ));
        lines.push(palette.kv(
            "semantic_inferred",
            semantic.inferred_fact_count.to_string(),
        ));
    }
    lines.push(String::new());
    lines.push(palette.heading("Leads"));
    lines.push(palette.kv("lead_count", report.lead_count.to_string()));
    lines.push(palette.muted(&report.message));
    for warning in &report.warnings {
        lines.push(format!("{} {}", palette.dot_warn(), warning));
    }
    println!("{}", palette.panel("Android Discover", &lines));
}

fn run_explain(args: AndroidExplainArgs) -> DynResult<()> {
    let report = build_semantic_explain_report(&args.semantic_bundle)
        .map_err(|message| format!("android explain failed: {message}"))?;

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_explain_panel(&palette, &report);
    } else {
        render_explain_plain(&palette, &report);
    }
    Ok(())
}

fn render_explain_plain(palette: &crate::style::Palette, report: &AndroidSemanticExplainReport) {
    println!("{}", palette.heading("Android Explain"));
    println!("{}", palette.kv("bundle_version", &report.bundle_version));
    println!("{}", palette.kv("package", &report.target_package_name));
    println!(
        "{}",
        palette.kv("revelations", report.revelations.len().to_string())
    );
    for revelation in &report.revelations {
        println!("{} {}", palette.bullet("-"), palette.code(&revelation.name));
        println!(
            "{}",
            palette.kv(
                "support",
                palette.status_word(&format!("{:?}", revelation.support_level))
            )
        );
        println!(
            "{}",
            palette.kv("rationale", palette.muted(&revelation.rationale))
        );
        if !revelation.subsystem_ids.is_empty() {
            println!(
                "{}",
                palette.kv(
                    "subsystems",
                    palette.info(revelation.subsystem_ids.join(", "))
                )
            );
        }
        if !revelation.evidence.is_empty() || !revelation.members.is_empty() {
            let mut context = Vec::new();
            if !revelation.evidence.is_empty() {
                context.push(format!("evidence={}", revelation.evidence.join("; ")));
            }
            if !revelation.members.is_empty() {
                let mut members = revelation.evidence.clone();
                if members.is_empty() {
                    members = revelation.members.iter().take(3).cloned().collect();
                }
                let mut member_context = format!("members={}", members.join(", "));
                if let Some(summary) = &revelation.member_summary {
                    member_context.push_str(&format!("; {summary}"));
                }
                context.push(member_context);
            }
            println!(
                "{}",
                palette.kv("context", palette.info(context.join("; ")))
            );
        }
    }
    if !report.javascript_interface_methods.is_empty() {
        println!(
            "{}",
            palette.kv(
                "javascript_interface_methods",
                report.javascript_interface_methods.len().to_string()
            )
        );
        for method in &report.javascript_interface_methods {
            println!("{} {}", palette.bullet("-"), palette.code(&method.trigger));
            if !method.notes.is_empty() {
                println!(
                    "{}",
                    palette.kv("notes", palette.info(method.notes.join(", ")))
                );
            }
        }
    }
    if !report.runtime_dart_packages.is_empty() {
        println!(
            "{}",
            palette.kv(
                "runtime_dart_packages",
                report.runtime_dart_packages.len().to_string()
            )
        );
        for item in &report.runtime_dart_packages {
            println!("{} {}", palette.bullet("-"), palette.code(&item.trigger));
            if !item.notes.is_empty() {
                println!(
                    "{}",
                    palette.kv("notes", palette.info(item.notes.join(", ")))
                );
            }
        }
    }
    if !report.runtime_plugins.is_empty() {
        println!(
            "{}",
            palette.kv("runtime_plugins", report.runtime_plugins.len().to_string())
        );
        for item in &report.runtime_plugins {
            println!("{} {}", palette.bullet("-"), palette.code(&item.trigger));
            if !item.notes.is_empty() {
                println!(
                    "{}",
                    palette.kv("notes", palette.info(item.notes.join(", ")))
                );
            }
        }
    }
    if !report.runtime_http_endpoints.is_empty() {
        println!(
            "{}",
            palette.kv(
                "runtime_http_endpoints",
                report.runtime_http_endpoints.len().to_string()
            )
        );
        for item in &report.runtime_http_endpoints {
            println!("{} {}", palette.bullet("-"), palette.code(&item.trigger));
            if !item.notes.is_empty() {
                println!(
                    "{}",
                    palette.kv("notes", palette.info(item.notes.join(", ")))
                );
            }
        }
    }
    if !report.runtime_chains.is_empty() {
        println!(
            "{}",
            palette.kv("runtime_chains", report.runtime_chains.len().to_string())
        );
        for chain in &report.runtime_chains {
            println!("{} {}", palette.bullet("-"), palette.code(&chain.trigger));
            if !chain.notes.is_empty() {
                println!(
                    "{}",
                    palette.kv("members", palette.info(chain.notes.join(" -> ")))
                );
            }
        }
    }
    for warning in &report.warnings {
        println!("{} {}", palette.warn("warning:"), warning);
    }
}

fn render_explain_panel(palette: &crate::style::Palette, report: &AndroidSemanticExplainReport) {
    let mut lines = vec![
        palette.kv("bundle_version", &report.bundle_version),
        palette.kv("package", &report.target_package_name),
    ];
    if !report.revelations.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Revelations"));
        for revelation in &report.revelations {
            lines.push(palette.code(&revelation.name));
            lines.push(palette.muted(format!(
                "support {} · rationale {}",
                format!("{:?}", revelation.support_level).to_lowercase(),
                revelation.rationale
            )));
            if !revelation.subsystem_ids.is_empty() {
                lines.push(palette.muted(format!(
                    "subsystems: {}",
                    revelation.subsystem_ids.join(", ")
                )));
            }
            let context = revelation_panel_context(revelation);
            if !context.is_empty() {
                lines.push(palette.muted(context));
            }
        }
    }
    let surface_sections: [(&str, &[AndroidSemanticExplainSurface], &str); 5] = [
        (
            "JavaScript Interface Methods",
            &report.javascript_interface_methods,
            ", ",
        ),
        ("Runtime Dart Packages", &report.runtime_dart_packages, ", "),
        ("Runtime Plugins", &report.runtime_plugins, ", "),
        (
            "Runtime HTTP Endpoints",
            &report.runtime_http_endpoints,
            ", ",
        ),
        ("Runtime Chains", &report.runtime_chains, " -> "),
    ];
    for (section, items, notes_separator) in surface_sections {
        if items.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(palette.heading(section));
        for item in items {
            lines.push(palette.code(&item.trigger));
            if !item.notes.is_empty() {
                lines.push(palette.muted(item.notes.join(notes_separator)));
            }
        }
    }
    for warning in &report.warnings {
        lines.push(format!("{} {}", palette.dot_warn(), warning));
    }
    println!("{}", palette.panel("Android Explain", &lines));
}

/// Mirrors the `context` row of the plain explain renderer (evidence, members
/// fallback, member summary) as a dimmed panel line.
fn revelation_panel_context(revelation: &AndroidSemanticExplainRevelation) -> String {
    let mut context = Vec::new();
    if !revelation.evidence.is_empty() {
        context.push(format!("evidence={}", revelation.evidence.join("; ")));
    }
    if !revelation.members.is_empty() {
        let mut members = revelation.evidence.clone();
        if members.is_empty() {
            members = revelation.members.iter().take(3).cloned().collect();
        }
        let mut member_context = format!("members={}", members.join(", "));
        if let Some(summary) = &revelation.member_summary {
            member_context.push_str(&format!("; {summary}"));
        }
        context.push(member_context);
    }
    context.join("; ")
}

fn resolve_semantic_bundle_path(
    args: &AndroidDiscoverArgs,
    progress: &mut dyn AndroidProgressSink,
) -> DynResult<Option<PathBuf>> {
    if let Some(path) = &args.semantic_bundle {
        return Ok(Some(path.clone()));
    }
    if args.jadx_root.is_none() && args.semantic_bundle_out.is_none() {
        return Ok(None);
    }

    progress.phase_started(
        AndroidProgressPhase::InventoryApks,
        &AndroidProgressSnapshot::default(),
    );
    let inventory = inventory_apks(&args.apk, &args.splits)
        .map_err(|message| format!("android semantic preparation failed: {message}"))?;
    progress.phase_completed(
        AndroidProgressPhase::InventoryApks,
        &AndroidProgressSnapshot {
            completed: Some(inventory.containers.len()),
            total: Some(inventory.containers.len()),
            message: Some(format!("base + {} split APKs", inventory.split_apks.len())),
            ..AndroidProgressSnapshot::default()
        },
    );
    let package_name = inventory
        .containers
        .iter()
        .find_map(|container| container.manifest.package_name.clone())
        .unwrap_or_else(|| "android-app".into());

    let semantic_mode = args
        .semantic_mode
        .parse::<AndroidSemanticMode>()
        .map_err(|message| format!("android semantic preparation failed: {message}"))?;

    let source_bundle = if let Some(jadx_root) = &args.jadx_root {
        derive_semantic_bundle_from_jadx_root_with_progress(
            jadx_root,
            inventory.containers.first().map(|c| &c.manifest),
            &package_name,
            semantic_mode,
            progress,
        )
        .map_err(|message| format!("android semantic extraction failed: {message}"))?
    } else {
        let temp = tempfile::tempdir()
            .map_err(|e| format!("android semantic preparation tempdir failed: {e}"))?;
        let root = temp.keep();
        progress.phase_started(
            AndroidProgressPhase::RunJadx,
            &AndroidProgressSnapshot::default(),
        );
        run_jadx(&args.apk, &root)
            .map_err(|message| format!("android semantic extraction failed: {message}"))?;
        progress.phase_completed(
            AndroidProgressPhase::RunJadx,
            &AndroidProgressSnapshot {
                message: Some(format!("output={}", root.display())),
                ..AndroidProgressSnapshot::default()
            },
        );
        derive_semantic_bundle_from_jadx_root_with_progress(
            &root,
            inventory.containers.first().map(|c| &c.manifest),
            &package_name,
            semantic_mode,
            progress,
        )
        .map_err(|message| format!("android semantic extraction failed: {message}"))?
    };
    let runtime_bundle =
        derive_flutter_runtime_semantics(&args.apk, &args.splits, semantic_mode)
            .map_err(|message| format!("android runtime semantic extraction failed: {message}"))?;
    let derived_bundle = merge_semantic_layers(source_bundle, runtime_bundle);

    let output_path = if let Some(path) = &args.semantic_bundle_out {
        path.clone()
    } else {
        let temp = tempfile::NamedTempFile::new()
            .map_err(|e| format!("android semantic output temp file failed: {e}"))?;
        temp.into_temp_path()
            .keep()
            .map_err(|e| format!("android semantic output temp file persistence failed: {e}"))?
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "android semantic output parent creation failed {}: {e}",
                parent.display()
            )
        })?;
    }
    fs::write(
        &output_path,
        serde_json::to_vec_pretty(&derived_bundle)
            .map_err(|e| format!("android semantic bundle serialization failed: {e}"))?,
    )
    .map_err(|e| {
        format!(
            "android semantic bundle write failed {}: {e}",
            output_path.display()
        )
    })?;
    Ok(Some(output_path))
}

fn resolve_chains_semantic_bundle_path(
    args: &AndroidChainsArgs,
    progress: &mut dyn AndroidProgressSink,
) -> DynResult<Option<PathBuf>> {
    if let Some(path) = &args.semantic_bundle {
        return Ok(Some(path.clone()));
    }

    progress.phase_started(
        AndroidProgressPhase::InventoryApks,
        &AndroidProgressSnapshot::default(),
    );
    let inventory = inventory_apks(&args.apk, &args.splits)
        .map_err(|message| format!("android semantic preparation failed: {message}"))?;
    progress.phase_completed(
        AndroidProgressPhase::InventoryApks,
        &AndroidProgressSnapshot {
            completed: Some(inventory.containers.len()),
            total: Some(inventory.containers.len()),
            message: Some(format!("base + {} split APKs", inventory.split_apks.len())),
            ..AndroidProgressSnapshot::default()
        },
    );
    let package_name = inventory
        .containers
        .iter()
        .find_map(|container| container.manifest.package_name.clone())
        .unwrap_or_else(|| "android-app".into());
    let semantic_mode = args
        .semantic_mode
        .parse::<AndroidSemanticMode>()
        .map_err(|message| format!("android semantic preparation failed: {message}"))?;

    let source_bundle = if let Some(jadx_root) = &args.jadx_root {
        derive_semantic_bundle_from_jadx_root_with_progress(
            jadx_root,
            inventory.containers.first().map(|c| &c.manifest),
            &package_name,
            semantic_mode,
            progress,
        )
        .map_err(|message| format!("android semantic extraction failed: {message}"))?
    } else {
        let temp = tempfile::tempdir()
            .map_err(|e| format!("android semantic preparation tempdir failed: {e}"))?;
        let root = temp.keep();
        progress.phase_started(
            AndroidProgressPhase::RunJadx,
            &AndroidProgressSnapshot::default(),
        );
        run_jadx(&args.apk, &root)
            .map_err(|message| format!("android semantic extraction failed: {message}"))?;
        progress.phase_completed(
            AndroidProgressPhase::RunJadx,
            &AndroidProgressSnapshot {
                message: Some(format!("output={}", root.display())),
                ..AndroidProgressSnapshot::default()
            },
        );
        derive_semantic_bundle_from_jadx_root_with_progress(
            &root,
            inventory.containers.first().map(|c| &c.manifest),
            &package_name,
            semantic_mode,
            progress,
        )
        .map_err(|message| format!("android semantic extraction failed: {message}"))?
    };
    let runtime_bundle =
        derive_flutter_runtime_semantics(&args.apk, &args.splits, semantic_mode)
            .map_err(|message| format!("android runtime semantic extraction failed: {message}"))?;
    let derived_bundle = merge_semantic_layers(source_bundle, runtime_bundle);

    let temp = tempfile::NamedTempFile::new()
        .map_err(|e| format!("android semantic output temp file failed: {e}"))?;
    let output_path = temp
        .into_temp_path()
        .keep()
        .map_err(|e| format!("android semantic output temp file persistence failed: {e}"))?;
    fs::write(
        &output_path,
        serde_json::to_vec_pretty(&derived_bundle)
            .map_err(|e| format!("android semantic bundle serialization failed: {e}"))?,
    )
    .map_err(|e| {
        format!(
            "android semantic bundle write failed {}: {e}",
            output_path.display()
        )
    })?;
    Ok(Some(output_path))
}

fn reject_xapk_input(path: &std::path::Path, command: &str) -> DynResult<()> {
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("xapk"))
    {
        return Err(format!(
            "android {command} does not accept .xapk directly; extract the XAPK and rerun with --apk <base.apk> plus any --splits <split.apk ...>"
        )
        .into());
    }
    if looks_like_embedded_apk_bundle(path)? {
        return Err(format!(
            "android {command} does not accept embedded APK bundle containers directly; extract the bundle and rerun with --apk <base.apk> plus any --splits <split.apk ...>"
        )
        .into());
    }
    Ok(())
}

fn looks_like_embedded_apk_bundle(path: &std::path::Path) -> DynResult<bool> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };
    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(_) => return Ok(false),
    };
    let mut has_manifest = false;
    let mut has_embedded_apk = false;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|e| {
            format!(
                "failed to read zip entry {} from {}: {}",
                index,
                path.display(),
                e
            )
        })?;
        let name = entry.name();
        if name == "AndroidManifest.xml" {
            has_manifest = true;
        }
        if name.ends_with(".apk") {
            has_embedded_apk = true;
        }
    }
    Ok(has_embedded_apk && !has_manifest)
}

fn run_benchmark(args: AndroidBenchmarkArgs) -> DynResult<()> {
    let summary = run_android_discovery_benchmark(&args.manifest)
        .map_err(|message| format!("android benchmark failed: {message}"))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        render_benchmark_panel(&palette, &summary);
    } else {
        render_benchmark_plain(&palette, &summary);
    }
    Ok(())
}

fn render_benchmark_plain(
    palette: &crate::style::Palette,
    summary: &AndroidDiscoveryBenchmarkSummary,
) {
    println!("{}", palette.heading("Android Benchmark"));
    println!("{}", palette.kv("suite", &summary.suite));
    println!("{}", palette.kv("top_k", summary.top_k.to_string()));
    println!("{}", palette.kv("cases", summary.cases.len().to_string()));
    println!("{}", palette.kv("passes", summary.pass_count.to_string()));
    println!(
        "{}",
        palette.kv("family_hit_rate", format!("{:.2}", summary.family_hit_rate))
    );
    println!(
        "{}",
        palette.kv(
            "positive_precision",
            format!("{:.2}", summary.positive_precision)
        )
    );
}

fn render_benchmark_panel(
    palette: &crate::style::Palette,
    summary: &AndroidDiscoveryBenchmarkSummary,
) {
    let mut lines = vec![format!(
        "{} {} of {} cases pass",
        palette.dot_ok(),
        summary.pass_count,
        summary.cases.len()
    )];
    lines.push(String::new());
    lines.push(palette.heading("Summary"));
    lines.push(palette.kv("suite", &summary.suite));
    lines.push(palette.kv("top_k", summary.top_k.to_string()));
    lines.push(palette.kv("cases", summary.cases.len().to_string()));
    lines.push(palette.kv("passes", summary.pass_count.to_string()));
    lines.push(format!(
        "{}  {}",
        palette.kv("family_hit_rate", format!("{:.2}", summary.family_hit_rate)),
        palette.bar(summary.family_hit_rate as f32, 8)
    ));
    lines.push(format!(
        "{}  {}",
        palette.kv(
            "positive_precision",
            format!("{:.2}", summary.positive_precision)
        ),
        palette.bar(summary.positive_precision as f32, 8)
    ));
    println!("{}", palette.panel("Android Benchmark", &lines));
}
