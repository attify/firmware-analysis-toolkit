use clap::{ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use fat_analyze::bootloader::{
    analyze_firmware_path as analyze_bootloader_firmware, analyze_text as analyze_bootloader_text,
    merge_snapshots as merge_bootloader_snapshots,
};
use fat_analyze::firmware_formats::scan as scan_firmware_formats;
use fat_bootloader::{
    assist_boot, discover_boot_artifacts, evaluate_true_boot_chain, launch_in_tmux,
    materialize_workspace, prepare_launch, stop_all_tmux_sessions, stop_tmux_session,
    BootArtifactDiscovery,
};
use fat_core::artifacts::{ArtifactKind, ArtifactRetentionPolicy};
use fat_core::bootloader::{BootEnvVariable, BootloaderSnapshot};
use fat_core::database::ProjectDb;
use fat_core::fingerprint::FirmwareFingerprint;
use fat_core::inventory::{AnalysisSnapshot, Architecture, BinaryRecord};
use fat_core::project::{Project, ProjectStatus};
use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::{derive_target_id, TargetArtifactRecord, TargetRecord};
use fat_emulate::preflight::PreflightReport;
use fat_extract::evidence::{file_count, squashfs_candidates, CarvedEvidence};
use fat_extract::extractors::{
    run_extraction_strategy, ExternalExtractor, ExternalExtractorOptions, ExtractStatus,
    ExtractionOutcome, ExtractionRequest, Extractor, ExtractorRegistry, ExtractorSelection,
    StrategyContext, Sufficiency,
};
use fat_extract::manifest::{EngineReport, EngineStatus, ExtractionManifest};
use fat_extract::native::{extract_gzip_member, GzipExtractionOptions};
use fat_extract::rootfs::{find_all_trees, find_rootfs};
use fat_extract::{cramfs::extract_cramfs, cramfs::CramfsLimits};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::IsTerminal;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

mod adapter_routing;
mod android_cmd;
mod benchmark_cmd;
mod bootloader_handoff_cmd;
mod bundle_reality_cmd;
mod carve_cmd;
mod chain_query_cmd;
mod crypto_census_cmd;
mod crypto_cmd;
mod data_cmd;
mod debug_cmd;
mod decompile_cmd;
mod diff_cmd;
mod discover_cmd;
mod doctor_cmd;
mod edge_ai_cmd;
mod elf_addr;
mod elf_inspect;
mod emulate_cmd;
mod emulate_config;
mod emulate_gc;
mod emulate_list;
mod envelope_cmd;
mod experiment_cmd;
mod extract_payload_cmd;
mod fat_graph_cmd;
mod firmware_diff_cmd;
mod handler_table_cmd;
mod handoff_evidence;
mod helptext;
mod hsm_cmd;
mod identify_cmd;
mod identify_launcher_cmd;
mod info_cmd;
mod inspect_cmd;
mod inspect_handoff_cmd;
mod instrument_hooks_cmd;
mod invariant_query_cmd;
mod kernel_cmd;
mod known_container;
mod launch_guard;
mod list_cmd;
mod observe_cmd;
mod patch_check_cmd;
mod probe_cmd;
mod r2_triage_cmd;
mod raw_cortex_m;
mod raw_mips_pic;
mod rehost_cmd;
mod rehosting_trace_cmd;
mod run_cmd;
mod runtime_augment;
mod runtime_plane_cmd;
mod schema_versions;
mod sdk_trace_cmd;
mod search_cmd;
mod semantic_profile;
mod signature_fit_cmd;
mod sink_discovery_cmd;
mod source_map_cmd;
mod startup_map_cmd;
mod style;
mod taint_cmd;
mod taint_cross_cmd;
mod taint_query_cmd;
mod trace_ingest_cmd;
mod trust_boundary_cmd;
mod verify_cmd;
mod xref_search_cmd;

const DEFAULT_PROJECTS_DIR: &str = ".fat-projects";
const EDGE_AI_LONG_ABOUT: &str = "Scan extracted firmware roots for Edge AI models.\n\n\
Rust-only scanner path for MAGIK/JZDL, TFLite, ONNX, and Qualcomm DLC evidence.\n\
Use `fat edge-ai scan` outside a FAT project; `fat analyze` runs the same built-in analyzers inside a project.\n\n\
Examples:\n  \
fat edge-ai scan --rootfs ./rootfs\n  \
fat edge-ai scan --rootfs ./rootfs --format magik,tflite --json\n  \
fat edge-ai scan --rootfs ./rootfs --format onnx";

#[derive(Debug, Parser)]
#[command(name = "fat", about = "Firmware Analysis Toolkit", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Args)]
struct DiscoverLeadArgs {
    #[arg(long)]
    fixture: Option<PathBuf>,
    #[arg(long)]
    repo: Option<PathBuf>,
    #[arg(long)]
    family: Option<String>,
    #[arg(long, default_value_t = 10)]
    top_k: usize,
    #[arg(long, default_value = "deep")]
    mode: String,
    #[arg(long = "debug-bundle-dir")]
    debug_bundle_dir: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
struct DiscoverManifestArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    family: String,
    #[arg(long, default_value_t = 10)]
    top_k: usize,
    #[arg(long, default_value = "deep")]
    mode: String,
    #[arg(long = "debug-bundle-dir")]
    debug_bundle_dir: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
struct DiscoverPreflightArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
struct DiscoverTriageArgs {
    #[arg(long = "attempt-record")]
    attempt_record: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Subcommand)]
enum DiscoverCommand {
    Leads(DiscoverLeadArgs),
    Preflight(DiscoverPreflightArgs),
    Harvest(DiscoverManifestArgs),
    Run(DiscoverManifestArgs),
    Triage(DiscoverTriageArgs),
}

#[derive(Debug, Clone, Subcommand)]
enum HsmQueryCommand {
    #[command(
        about = "Find transitions triggered by a specific event in a derived machine family."
    )]
    EventPath {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a fixture path directly instead of reading an intermediate leads file."
        )]
        fixture: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a repository path directly instead of reading an intermediate leads file."
        )]
        repo: Option<PathBuf>,
        #[arg(
            long,
            help = "Resolve a target lane manifest directly instead of reading an intermediate leads file."
        )]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional discovery family filter when using --fixture or --repo."
        )]
        family: Option<String>,
        #[arg(
            long,
            default_value_t = 10,
            help = "Maximum sibling/lead expansion budget when using --fixture or --repo."
        )]
        top_k: usize,
        #[arg(
            long,
            default_value = "deep",
            help = "Discovery execution mode when using --fixture or --repo."
        )]
        mode: String,
        #[arg(
            long = "debug-bundle-dir",
            help = "Optional debug bundle output directory when using --fixture or --repo."
        )]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(
            long = "lead-id",
            help = "Optional lead id filter applied before HSM derivation."
        )]
        lead_id: Option<String>,
        #[arg(
            long = "machine-id",
            help = "Registered machine family id, for example `size-stride-arithmetic`."
        )]
        machine_id: String,
        #[arg(
            long = "event",
            help = "Family event id to match, for example `CopyWithMismatchedPitch`."
        )]
        event_id: String,
        #[arg(long, help = "Emit machine query results as JSON.")]
        json: bool,
    },
    #[command(about = "Find invalidation edges in a derived machine family.")]
    InvalidationPath {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a fixture path directly instead of reading an intermediate leads file."
        )]
        fixture: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a repository path directly instead of reading an intermediate leads file."
        )]
        repo: Option<PathBuf>,
        #[arg(
            long,
            help = "Resolve a target lane manifest directly instead of reading an intermediate leads file."
        )]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional discovery family filter when using --fixture or --repo."
        )]
        family: Option<String>,
        #[arg(
            long,
            default_value_t = 10,
            help = "Maximum sibling/lead expansion budget when using --fixture or --repo."
        )]
        top_k: usize,
        #[arg(
            long,
            default_value = "deep",
            help = "Discovery execution mode when using --fixture or --repo."
        )]
        mode: String,
        #[arg(
            long = "debug-bundle-dir",
            help = "Optional debug bundle output directory when using --fixture or --repo."
        )]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(
            long = "lead-id",
            help = "Optional lead id filter applied before HSM derivation."
        )]
        lead_id: Option<String>,
        #[arg(
            long = "machine-id",
            help = "Registered machine family id, for example `validation-trust-boundary`."
        )]
        machine_id: String,
        #[arg(long, help = "Emit machine query results as JSON.")]
        json: bool,
    },
    #[command(
        about = "Find forbidden coexistence candidates for machine families that support it."
    )]
    Coexistence {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a fixture path directly instead of reading an intermediate leads file."
        )]
        fixture: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a repository path directly instead of reading an intermediate leads file."
        )]
        repo: Option<PathBuf>,
        #[arg(
            long,
            help = "Resolve a target lane manifest directly instead of reading an intermediate leads file."
        )]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional discovery family filter when using --fixture or --repo."
        )]
        family: Option<String>,
        #[arg(
            long,
            default_value_t = 10,
            help = "Maximum sibling/lead expansion budget when using --fixture or --repo."
        )]
        top_k: usize,
        #[arg(
            long,
            default_value = "deep",
            help = "Discovery execution mode when using --fixture or --repo."
        )]
        mode: String,
        #[arg(
            long = "debug-bundle-dir",
            help = "Optional debug bundle output directory when using --fixture or --repo."
        )]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(
            long = "lead-id",
            help = "Optional lead id filter applied before HSM derivation."
        )]
        lead_id: Option<String>,
        #[arg(
            long = "machine-id",
            help = "Registered machine family id. Currently only `lifetime-reentrancy` is supported."
        )]
        machine_id: String,
        #[arg(long, help = "Emit machine query results as JSON.")]
        json: bool,
    },
    #[command(about = "List ghost states that were synthesized into the derived machine graph.")]
    GhostState {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a fixture path directly instead of reading an intermediate leads file."
        )]
        fixture: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a repository path directly instead of reading an intermediate leads file."
        )]
        repo: Option<PathBuf>,
        #[arg(
            long,
            help = "Resolve a target lane manifest directly instead of reading an intermediate leads file."
        )]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional discovery family filter when using --fixture or --repo."
        )]
        family: Option<String>,
        #[arg(
            long,
            default_value_t = 10,
            help = "Maximum sibling/lead expansion budget when using --fixture or --repo."
        )]
        top_k: usize,
        #[arg(
            long,
            default_value = "deep",
            help = "Discovery execution mode when using --fixture or --repo."
        )]
        mode: String,
        #[arg(
            long = "debug-bundle-dir",
            help = "Optional debug bundle output directory when using --fixture or --repo."
        )]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(
            long = "lead-id",
            help = "Optional lead id filter applied before HSM derivation."
        )]
        lead_id: Option<String>,
        #[arg(long = "machine-id", help = "Registered machine family id.")]
        machine_id: String,
        #[arg(long, help = "Emit machine query results as JSON.")]
        json: bool,
    },
    #[command(about = "List forbidden transitions gated on a specific required state.")]
    StateCondition {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[arg(long, default_value = "deep")]
        mode: String,
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(long = "lead-id")]
        lead_id: Option<String>,
        #[arg(long = "machine-id")]
        machine_id: String,
        #[arg(long = "state")]
        state_id: String,
        #[arg(long)]
        json: bool,
    },
    #[command(
        about = "List forbidden transitions under the counterfactual where a required guard is absent."
    )]
    Counterfactual {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`; avoids rebuilding machines from leads."
        )]
        machines_file: Option<PathBuf>,
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[arg(long, default_value = "deep")]
        mode: String,
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(long = "lead-id")]
        lead_id: Option<String>,
        #[arg(long = "machine-id")]
        machine_id: String,
        #[arg(long = "guard")]
        guard_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "List leads blocked by locality policy before widening or expansion.")]
    LocalityPolicy {
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[arg(long, default_value = "deep")]
        mode: String,
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(long = "lead-id")]
        lead_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum HsmCommand {
    #[command(
        about = "List the registered HSM machine families available for derive and query flows."
    )]
    Registry {
        #[arg(long, help = "Emit registry output as JSON.")]
        json: bool,
    },
    #[command(about = "Derive generic HSM machine instances from discovery leads JSON.")]
    Derive {
        #[arg(
            long = "leads-file",
            help = "Path to JSON produced by `fat discover leads --json`."
        )]
        leads_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a fixture path directly instead of reading an intermediate leads file."
        )]
        fixture: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyze a repository path directly instead of reading an intermediate leads file."
        )]
        repo: Option<PathBuf>,
        #[arg(
            long,
            help = "Resolve a target lane manifest directly instead of reading an intermediate leads file."
        )]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional discovery family filter when using --fixture or --repo."
        )]
        family: Option<String>,
        #[arg(
            long,
            default_value_t = 10,
            help = "Maximum sibling/lead expansion budget when using --fixture or --repo."
        )]
        top_k: usize,
        #[arg(
            long,
            default_value = "deep",
            help = "Discovery execution mode when using --fixture or --repo."
        )]
        mode: String,
        #[arg(
            long = "debug-bundle-dir",
            help = "Optional debug bundle output directory when using --fixture or --repo."
        )]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(
            long = "out-file",
            help = "Optional JSON path where derived machine snapshots should be persisted for reuse/history."
        )]
        out_file: Option<PathBuf>,
        #[arg(
            long = "lead-id",
            help = "Optional lead id filter applied before HSM derivation."
        )]
        lead_id: Option<String>,
        #[arg(long, help = "Emit derived machines as JSON.")]
        json: bool,
    },
    #[command(
        about = "Resolve persisted machine snapshots against a target lane manifest and emit machine-backed planning summaries."
    )]
    Plan {
        #[arg(
            long = "machines-file",
            help = "Path to JSON emitted by `fat hsm derive --out-file ...`."
        )]
        machines_file: PathBuf,
        #[arg(
            long = "manifest",
            help = "Target lane manifest used to resolve the destination lane for each persisted machine."
        )]
        manifest: PathBuf,
        #[arg(long = "lead-id", help = "Optional lead id filter.")]
        lead_id: Option<String>,
        #[arg(long = "machine-id", help = "Optional machine family filter.")]
        machine_id: Option<String>,
        #[arg(
            long = "transition-id",
            help = "Optional transition id filter; emits plans only for this forbidden transition."
        )]
        transition_id: Option<String>,
        #[arg(long, help = "Emit planning summaries as JSON.")]
        json: bool,
    },
    #[command(
        about = "Run HSM queries over derived machine instances built from discovery leads."
    )]
    Query {
        #[command(subcommand)]
        command: HsmQueryCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    Android {
        #[command(subcommand)]
        subject: android_cmd::AndroidCommand,
    },
    New {
        firmware: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = DEFAULT_PROJECTS_DIR)]
        projects_dir: PathBuf,
    },
    /// List FAT projects under the projects root.
    ///
    /// Examples:
    ///   fat list
    ///   fat list --projects-dir ~/fat-projects --json
    List {
        /// Projects root to enumerate.
        #[arg(long, default_value = DEFAULT_PROJECTS_DIR)]
        projects_dir: PathBuf,
        /// Output as JSON instead of structured text.
        #[arg(long)]
        json: bool,
    },
    /// Delete a FAT project (by directory path or bare name under the projects root).
    ///
    /// Examples:
    ///   fat delete demo             # prints what would be removed
    ///   fat delete demo --yes       # actually removes .fat-projects/demo
    Delete {
        /// Project directory path, or a bare project name under --projects-dir.
        project: PathBuf,
        /// Projects root used to resolve a bare project name.
        #[arg(long, default_value = DEFAULT_PROJECTS_DIR)]
        projects_dir: PathBuf,
        /// Actually remove the project directory (otherwise a dry run).
        #[arg(long)]
        yes: bool,
    },
    /// Identify a file or directory and recommend the next FAT command.
    ///
    /// Examples:
    ///   fat identify --file firmware.bin
    ///   fat identify firmware.bin
    ///   fat identify firmware.bin --json
    Identify {
        /// Path to the file or directory to identify.
        path: Option<PathBuf>,
        /// Path to the file or directory to identify.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Output as JSON instead of structured text.
        #[arg(long)]
        json: bool,
    },
    Extract {
        /// Project directory (positional).
        project: Option<PathBuf>,
        /// Project directory (alias for the positional argument).
        #[arg(long = "project")]
        project_flag: Option<PathBuf>,
        /// Re-run extraction and overwrite existing extraction artifacts
        #[arg(long)]
        force: bool,
        /// Seconds before a stalled binwalk/unblob run is killed (0 disables;
        /// defaults to FAT_EXTRACT_TIMEOUT or 1800)
        #[arg(long = "extract-timeout", value_name = "SECS")]
        extract_timeout: Option<u64>,
        /// Which extraction engines to use: auto (priority chain), all (run
        /// every engine, no skipping), or one of native, binwalk, unblob
        #[arg(long = "extractor", value_name = "ENGINE")]
        extractor: Option<String>,
        /// Worker processes for unblob (forwarded only when set)
        #[arg(long = "unblob-processes", value_name = "N")]
        unblob_processes: Option<u32>,
        /// Recursion depth for unblob (forwarded only when set)
        #[arg(long = "unblob-depth", value_name = "N")]
        unblob_depth: Option<u32>,
        /// Emit one machine-readable JSON object on stdout instead of the
        /// human summary; progress goes to stderr
        #[arg(long)]
        json: bool,
    },
    ExtractPayload {
        project: Option<PathBuf>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        offset: String,
        #[arg(long)]
        format: String,
    },
    Carve {
        project: Option<PathBuf>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        offset: String,
        #[arg(long)]
        size: Option<String>,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Analyze {
        /// Project directory (positional).
        project: Option<PathBuf>,
        /// Project directory (alias for the positional argument).
        #[arg(long = "project")]
        project_flag: Option<PathBuf>,
        /// Emit one machine-readable JSON object on stdout instead of the
        /// human summary
        #[arg(long)]
        json: bool,
    },
    #[command(
        name = "edge-ai",
        about = "Scan extracted firmware roots for Edge AI models.",
        long_about = EDGE_AI_LONG_ABOUT
    )]
    EdgeAi {
        #[command(subcommand)]
        command: edge_ai_cmd::EdgeAiCommand,
    },
    Preflight {
        project: Option<PathBuf>,
        #[arg(long = "signal")]
        signals: Vec<String>,
        /// Emit one machine-readable JSON object on stdout instead of the
        /// human report
        #[arg(long)]
        json: bool,
    },
    Info {
        /// Project directory (positional).
        project: Option<PathBuf>,
        /// Project directory (alias for the positional argument).
        #[arg(long = "project")]
        project_flag: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "rehosting-trace")]
    RehostingTrace {
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "rehost", about = "Inspect and validate rehosting packs.")]
    Rehost {
        #[command(subcommand)]
        command: rehost_cmd::RehostCommand,
    },
    #[command(
        name = "experiment",
        about = "Validate and inspect rehosting experiments."
    )]
    Experiment {
        #[command(subcommand)]
        command: experiment_cmd::ExperimentCommand,
    },
    #[command(
        name = "kernel",
        about = "Build, verify, install, and inspect FAT-maintained kernels."
    )]
    Kernel {
        #[command(subcommand)]
        command: kernel_cmd::KernelCommand,
    },
    #[command(name = "data", about = "Install and verify FAT runtime data.")]
    Data {
        #[command(subcommand)]
        command: data_cmd::DataCommand,
    },
    #[command(
        name = "sink-discovery",
        about = "Inspect sink discovery profiles and validation helpers."
    )]
    SinkDiscovery(#[command(flatten)] sink_discovery_cmd::SinkDiscoveryArgs),
    Doctor {
        /// Exit non-zero when a core workflow prerequisite is missing.
        #[arg(long)]
        strict: bool,
        /// Emit machine-readable JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    Debug {
        #[command(subcommand)]
        subject: DebugCommand,
    },
    Observe {
        #[command(subcommand)]
        subject: ObserveCommand,
    },
    Benchmark {
        #[command(subcommand)]
        subject: benchmark_cmd::BenchmarkCommand,
    },
    Discover {
        #[command(subcommand)]
        subject: Option<DiscoverCommand>,
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[arg(long, default_value = "deep")]
        mode: String,
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    #[command(
        about = "Inspect and query generic hierarchical state machine models derived from discovery leads.",
        long_about = "Inspect and query generic hierarchical state machine models derived from discovery leads.\n\nTypical workflows:\n  1. File-backed:\n     fat discover leads --repo <path> --json > /tmp/leads.json\n     fat hsm derive --leads-file /tmp/leads.json --out-file /tmp/machines.json --json\n     fat hsm query event-path --machines-file /tmp/machines.json --machine-id size-stride-arithmetic --event CopyWithMismatchedPitch --json\n  2. Direct:\n     fat hsm derive --repo <path> --family size --mode deep --out-file /tmp/machines.json --json\n  3. Manifest-backed planning:\n     fat hsm derive --manifest <lanes.json> --family validation --mode deep --out-file /tmp/machines.json --json\n     fat hsm plan --machines-file /tmp/machines.json --manifest <lanes.json> --json\n\nThe HSM layer currently supports machine families such as lifetime-reentrancy, size-stride-arithmetic, validation-trust-boundary, and gpu-protocol-order-lifecycle."
    )]
    Hsm {
        #[command(subcommand)]
        command: HsmCommand,
    },
    /// Discover frontend input surfaces and rank likely backend consumers.
    ///
    /// Backend source hints come from the specified models only. Pass
    /// --source-profile to add a target's own request-parameter getters; FAT
    /// ships none and never selects one on its own.
    #[command(name = "source-map")]
    SourceMap {
        #[arg(long)]
        rootfs: PathBuf,
        /// Path to a taint source profile whose source names are also reported
        /// as backend source hints.
        #[arg(long)]
        source_profile: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Map rootfs startup metadata to concrete binaries and profile evidence.
    #[command(name = "startup-map")]
    StartupMap {
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long, value_parser = ["cloud-tls", "curl", "dns", "web", "update"])]
        profile: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        binary: Option<String>,
        #[arg(long)]
        api: Option<String>,
        #[arg(long)]
        library: Option<String>,
        #[arg(long, default_value_t = 50)]
        max: usize,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        explain: bool,
        #[arg(long = "emit-actions")]
        emit_actions: bool,
        #[arg(long = "all-scripts")]
        all_scripts: bool,
        #[arg(long = "no-r2")]
        no_r2: bool,
    },
    /// Search firmware strings in extracted rootfs binaries or all files.
    #[command(name = "search")]
    Search {
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(short = 'i', long = "include")]
        include: Option<String>,
        #[arg(long = "profile", action = ArgAction::Append)]
        profiles: Vec<String>,
        #[arg(short = 'I', long = "case-insensitive")]
        case_insensitive: bool,
        #[arg(short = 'e', long = "exclude", action = ArgAction::Append)]
        exclude: Vec<String>,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        max: usize,
        #[arg(long)]
        all_files: bool,
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        #[arg(long, default_value_t = 0)]
        context: usize,
        #[arg(long)]
        unique: bool,
        #[arg(long = "no-discover-rootfs")]
        no_discover_rootfs: bool,
        #[arg(long)]
        show_empty: bool,
        #[arg(long, default_value = "weak", value_parser = ["weak", "medium", "strong"])]
        min_strength: String,
        #[arg(long, default_value = "boilerplate", value_parser = ["none", "boilerplate"])]
        context_filter: String,
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        summary: bool,
        #[arg(long, default_value = "text", value_parser = ["text", "anchor"])]
        format: String,
        #[arg(long, value_parser = ["auto", "always", "never"])]
        color: Option<String>,
        #[arg(
            long,
            default_value = "never",
            value_parser = ["never", "human"],
            help = "Emit realtime search progress to stderr without changing stdout"
        )]
        progress: String,
        #[arg(long)]
        json: bool,
    },
    /// Search an ELF or raw blob for pointer/code references to an address or matching strings.
    #[command(name = "xref-search")]
    XrefSearch {
        /// Path to the ELF binary or raw firmware blob.
        #[arg(long)]
        file: PathBuf,
        /// Virtual address to search for, e.g. 0x0046a5b0.
        #[arg(long)]
        vaddr: Option<String>,
        /// Search for pointers to all strings containing this pattern.
        #[arg(long, alias = "string", conflicts_with = "vaddr")]
        string_pattern: Option<String>,
        /// Treat input as a raw firmware blob instead of an ELF.
        #[arg(long)]
        raw: bool,
        /// Architecture hint for raw blobs, for example cortex-m or mips-pic.
        #[arg(long)]
        arch: Option<String>,
        /// Base address for raw blobs, decimal or 0x-prefixed hex.
        #[arg(long)]
        base: Option<String>,
        /// Scan filter: non-executable, writable-only, or all.
        #[arg(long, default_value = "non-executable")]
        scan: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Discover URL/command handler dispatch tables in an ELF binary.
    #[command(name = "handler-table")]
    HandlerTable {
        /// Path to the ELF binary to scan.
        #[arg(long)]
        file: PathBuf,
        /// URL/command prefix patterns to search for, comma-separated.
        #[arg(long)]
        patterns: Option<String>,
        /// Override entry size detection in bytes.
        #[arg(long)]
        entry_size: Option<usize>,
        /// Scan filter: non-executable, writable-only, or all.
        #[arg(long, default_value = "non-executable")]
        scan: String,
        /// Cross-reference with source-map JSON.
        #[arg(long)]
        source_map: Option<PathBuf>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Emulate firmware in a QEMU-based environment.
    ///
    /// Supports native-host system emulation, service-mode user-mode,
    /// Docker-based reference emulation, and managed Linux VM substrates.
    ///
    /// When --instrument is provided, loads the FAT QEMU TCG plugin to
    /// intercept function calls at specified addresses and log register
    /// state and string arguments. Automatically biases toward the
    /// native-host system substrate (required for TCG plugin support).
    ///
    /// Generate a hooks config with `fat instrument-hooks --file <binary>`.
    ///
    /// Examples:
    ///   fat emulate --project ./camera-project
    ///   fat emulate --project ./camera-project --instrument hooks.yaml
    ///   fat emulate --project ./camera-project --instrument hooks.yaml --backend qemu-direct
    Emulate {
        /// Project directory (positional alias for --project).
        project_arg: Option<PathBuf>,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long = "substrate-policy")]
        substrate_policy: Option<String>,
        #[arg(long = "port")]
        ports: Vec<u16>,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        status: bool,
        /// List recorded emulation sessions with live process and resource
        /// state. Also accepted as `fat emulate list`.
        #[arg(long, conflicts_with_all = ["status", "stop"])]
        list: bool,
        /// Emit the list view as JSON (requires --list).
        #[arg(long, requires = "list")]
        list_json: bool,
        /// Sweep stale sessions and staging directories.
        /// Terminates emulations past their configured idle timeout,
        /// marks dead-process sessions as stale, and removes orphaned
        /// staging directories.  Requires --project.
        #[arg(long)]
        gc: bool,
        #[arg(long)]
        stop: bool,
        /// Path to a hooks.yaml config for QEMU TCG plugin instrumentation.
        /// Generate with: fat instrument-hooks --file <binary> --output hooks.yaml
        #[arg(long)]
        instrument: Option<PathBuf>,
        /// Rehosting pack to apply (a YAML path or a pack id). Overrides the
        /// QEMU machine, init repairs, validators, and caveats. See `fat rehost match`.
        #[arg(long)]
        pack: Option<String>,
        /// EXPERIMENTAL: allow FAT to automatically apply a matching rehosting pack.
        #[arg(long)]
        experimental_rehosting: bool,
        /// Accept capability gaps reported for an automatically selected experimental pack.
        #[arg(long, requires = "experimental_rehosting")]
        accept_degraded_rehosting: bool,
        /// Assert a measured maintained-kernel compatibility class for this run.
        #[arg(
            long,
            value_parser = [
                "mips32-o32-le-r1-page4k",
                "mips32-o32-be-r1-page4k",
                "arm32-eabi-le-v7-page4k"
            ]
        )]
        kernel_class: Option<String>,
    },
    #[command(hide = true, name = "supervise-managed-vm")]
    SuperviseManagedVm {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: String,
    },
    Diff {
        #[command(subcommand)]
        subject: DiffCommand,
    },
    /// Export FAT analysis facts as reusable graph data.
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },
    /// Scan firmware labels and emit label/evidence graphs.
    Label {
        #[command(subcommand)]
        command: LabelCommand,
    },
    /// Explain evidence-backed labels for one firmware path.
    Labels {
        #[command(subcommand)]
        command: LabelsCommand,
    },
    /// Render an ls-like firmware view with neutral inventory or evidence-backed tags.
    Ls {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Research profile to show. Use `inventory` for neutral file facts or
        /// `update-authority` with `--tags` for evidence-backed update labels.
        #[arg(long)]
        profile: Option<String>,
        /// Show evidence-backed tags
        #[arg(long)]
        tags: bool,
        /// Emit the same view as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Render a directory summary view with inventory counts or label rollups.
    Tree {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Research profile to summarize. Use `inventory` for neutral file-kind
        /// counts or `update-authority` with `--tags` for label rollups.
        #[arg(long)]
        profile: Option<String>,
        /// Include evidence-backed tags
        #[arg(long)]
        tags: bool,
        /// Summarize labels by directory
        #[arg(long)]
        summary: bool,
        /// Emit the same view as JSON.
        #[arg(long)]
        json: bool,
    },
    Bootloader {
        #[command(subcommand)]
        command: BootloaderCommand,
    },
    Inspect {
        #[command(subcommand)]
        subject: InspectCommand,
    },
    /// Map trust-bearing binaries with a stronger updater-path summary.
    #[command(name = "trust-map", alias = "update-path")]
    TrustMap {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Detect opaque wrapper behavior for a firmware blob.
    #[command(name = "detect-encryption")]
    DetectEncryption {
        /// Path to the encrypted firmware blob
        #[arg(long)]
        file: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Compare an encrypted blob against a reference image to infer shared boundaries.
    #[command(name = "compare")]
    Compare {
        /// Path to the encrypted firmware blob under investigation
        #[arg(long)]
        encrypted: PathBuf,
        /// Reference blob for shared-prefix/structure comparison
        #[arg(long)]
        reference: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Census a rootfs for reused crypto artifacts and governing-path hits.
    #[command(name = "crypto-census")]
    CryptoCensus {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Filter artifacts by a comma-separated token list such as rsa or blob
        #[arg(long)]
        only: Option<String>,
        /// Group artifacts by this mode. Initial support: fingerprint
        #[arg(long, default_value = "fingerprint")]
        group_by: String,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Inspect likely downstream implementation artifacts for a binary.
    ///
    /// Reuses linked-library and entrypoint evidence to rank likely downstream
    /// targets and inspect whether they exist as normal on-disk files or only
    /// through packaged/runtime-backed reality.
    #[command(name = "inspect-handoff")]
    InspectHandoff {
        /// Path to a binary or shared library
        #[arg(long)]
        file: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Compare linked framework metadata with visible filesystem reality.
    ///
    /// Highlights cases where a bundle declares an executable but the expected
    /// file is not present plainly on disk, suggesting packaged or runtime-backed
    /// implementations.
    #[command(name = "bundle-reality")]
    BundleReality {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Summarize the likely runtime-backed object plane around a binary.
    ///
    /// Uses linked-library, bundle, and entrypoint evidence to identify the
    /// deeper implementation objects that likely govern behavior beyond the
    /// visible launcher or shallow daemon.
    #[command(name = "runtime-plane")]
    RuntimePlane {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Binary audit triage via radare2 — profile, exports, imports, strings, complexity ranking.
    ///
    /// Drives rabin2 and r2pipe to extract binary metadata, then produces a
    /// structured report highlighting dangerous imports, security-relevant
    /// exports, classified strings, crypto libraries, and top audit targets
    /// ranked by cyclomatic complexity.
    ///
    /// Examples:
    ///   fat r2-triage --file quick.cgi
    ///   fat r2-triage --file quick.cgi --json
    ///   fat r2-triage --file STM32.bin --arch cortex-m --base 0x08000000 --json
    #[command(name = "r2-triage")]
    R2Triage {
        /// Path to an ELF binary or raw firmware blob
        #[arg(long)]
        file: PathBuf,
        /// Architecture hint for raw blobs, for example `cortex-m`
        #[arg(long)]
        arch: Option<String>,
        /// Base address for raw blobs, decimal or 0x-prefixed hex
        #[arg(long)]
        base: Option<String>,
        /// Family hint for raw blobs, for example `STM32H7`
        #[arg(long)]
        family: Option<String>,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
        /// Show the full uncapped report instead of the compact panel
        #[arg(long)]
        full: bool,
    },
    /// Auto-discover hookable sinks in a firmware binary and generate
    /// a hooks config for the FAT QEMU TCG instrumentation plugin.
    ///
    /// Uses rabin2 to scan import and symbol tables for dangerous sinks
    /// (system, popen, execve, nvram_get, sprintf, etc.) from the FAT
    /// taint profile catalog. Resolves PLT stub addresses for dynamically
    /// linked binaries and handles MIPS `imp.` prefixed symbols.
    ///
    /// Sink categories:
    ///   command-exec    — system, popen, execl, execve, lxmldbc_system
    ///   config-read     — nvram_get, nvram_safe_get, nvram_config_get
    ///   config-write    — nvram_set, xmldbc_set, uci_set
    ///   input-source    — getenv, cgibin_get_var, websGetVar
    ///   string-overflow — sprintf, strcpy, strcat
    ///
    /// The output hooks.yaml can be passed to `fat emulate --instrument`.
    ///
    /// Examples:
    ///   fat instrument-hooks --file alphapd
    ///   fat instrument-hooks --file busybox --output hooks.yaml
    ///   fat instrument-hooks --file busybox --categories command-exec --json
    ///   fat taint --file httpd --json > taint.json && fat instrument-hooks --from-taint taint.json --output hooks.yaml
    ///   fat emulate --project ./camera-project --instrument hooks.yaml
    #[command(name = "instrument-hooks")]
    InstrumentHooks {
        /// Path to an ELF binary to analyze (catalog mode).
        /// Mutually exclusive with --from-taint and --from-sinks.
        #[arg(
            long,
            required_unless_present_any = ["from_taint", "from_sinks"],
            conflicts_with_all = ["from_taint", "from_sinks"]
        )]
        file: Option<PathBuf>,
        /// Generate hooks from TaintFinding JSON (output of `fat taint --json`).
        /// Each ChainStep becomes a hook; addresses resolved from location field
        /// or by rabin2 function-name lookup against the finding's binary.
        /// Note: accepts TaintFinding format only, not taint-cross output.
        #[arg(long, conflicts_with_all = ["file", "from_sinks"])]
        from_taint: Option<PathBuf>,
        /// Generate hooks from SinkDiscoveryReport JSON (output of `fat sink-discovery --json`).
        #[arg(long, conflicts_with_all = ["file", "from_taint"])]
        from_sinks: Option<PathBuf>,
        /// Write hooks.yaml to this path instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
        /// Filter by sink categories (catalog mode only; mutually exclusive with --from-taint).
        /// Comma-separated: command-exec,config-read,config-write,input-source,string-overflow
        #[arg(long, conflicts_with_all = ["from_taint", "from_sinks"])]
        categories: Option<String>,
        /// Output as JSON instead of YAML
        #[arg(long)]
        json: bool,
    },
    /// Ingest QEMU TCG hook JSONL traces as runtime capture artifacts.
    ///
    /// Normalizes the JSONL emitted by the FAT hook plugin, preserves degraded
    /// register-capture metadata, and indexes the result on the active runtime
    /// run as a RuntimeCapture artifact.
    ///
    /// Examples:
    ///   fat trace-ingest --project ./camera-project --trace hooks.jsonl
    ///   fat trace-ingest --project ./camera-project --session-id shell --trace hooks.jsonl --json
    #[command(name = "trace-ingest")]
    TraceIngest {
        /// Project directory containing runtime session records
        #[arg(long)]
        project: PathBuf,
        /// JSONL trace emitted by the FAT QEMU TCG hook plugin
        #[arg(long)]
        trace: PathBuf,
        /// Runtime session id or requested session alias. Defaults to latest session.
        #[arg(long = "session-id")]
        session_id: Option<String>,
        /// Output normalized trace report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Evaluate runtime hook traces against taint findings.
    ///
    /// This is the oracle half of probe automation: it consumes existing taint
    /// findings and hook traces, then reports whether the marker propagated
    /// through the static chain. It does not start emulation or inject traffic.
    ///
    /// Examples:
    ///   fat probe evaluate --taint taint.json --trace hooks.jsonl --marker FAT_MARKER
    ///   fat probe evaluate --taint taint.json --trace trace-report.json --json
    Probe {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    /// Trace local import/export and linked-library dependencies across an SDK directory.
    ///
    /// Scans a directory tree for ELF binaries and shared libraries, then
    /// correlates imports, exports, and linked-library names to reconstruct
    /// layered SDK dependency chains such as `P2PTunnel -> RDT -> IOTC`.
    ///
    /// Examples:
    ///   fat sdk-trace --dir ./Lib/Linux/x86
    ///   fat sdk-trace --dir ./Lib/Linux/x86 --json
    #[command(name = "sdk-trace")]
    SdkTrace {
        /// Path to a directory containing ELF binaries or shared libraries
        #[arg(long)]
        dir: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },

    /// Decompile one function mechanically with r2ghidra.
    ///
    /// Examples:
    ///   fat decompile --file iCamera --function 0x440b3c
    ///   fat decompile --file STM32.bin --function 0x080002ac --arch cortex-m --base 0x08000000
    ///   fat decompile --file iCamera --function 0x440b3c --output ./decompiled/ --json
    #[command(name = "decompile")]
    Decompile {
        /// Path to an ELF binary or raw firmware blob
        #[arg(long)]
        file: PathBuf,
        /// Function address in hex (e.g., 0x440b3c)
        #[arg(long)]
        function: String,
        /// Architecture hint for raw blobs. Use `cortex-m` for STM32/NXP/Nordic style ARM microcontroller images.
        #[arg(long)]
        arch: Option<String>,
        /// Base address for raw blobs (for example `0x08000000` for STM32 internal flash).
        #[arg(long)]
        base: Option<String>,
        /// Family hint for raw blobs (for example `STM32H7`).
        #[arg(long)]
        family: Option<String>,
        /// Output directory for the raw C pseudocode
        #[arg(long)]
        output: Option<PathBuf>,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// Number of callee levels to decompile for context (default: 1)
        #[arg(long, default_value_t = 1)]
        context: usize,
    },

    /// Determine whether a binary is likely a thin launcher/bootstrapper.
    ///
    /// Uses binary profile, function complexity, linked libraries, and a small
    /// entrypoint disassembly slice to decide whether the binary mostly hands
    /// off to deeper logic elsewhere.
    ///
    /// Examples:
    ///   fat identify-launcher --file ./rootfs/usr/sbin/service-launcher
    ///   fat identify-launcher --file ./rootfs/usr/sbin/service-launcher --json
    #[command(name = "identify-launcher")]
    IdentifyLauncher {
        /// Path to a binary or shared library
        #[arg(long)]
        file: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },

    /// Trace data flow from attacker-controlled inputs to dangerous sinks.
    ///
    /// Uses angr Reaching Definitions analysis on the binary directly.
    /// For Linux ELFs: traces CGI/HTTP input → system()/popen()/exec().
    /// For bare-metal MCU: traces network/serial input → EEPROM/flash/UART writes.
    /// With --lang shell: parses shell scripts with tree-sitter-bash and traces
    /// $(cat ...) / $1 / read / uci get / nvram_get → eval, sed -i, sh -c.
    ///
    /// Examples:
    ///   fat taint --file quick.cgi
    ///   fat taint --file quick.cgi --severity high
    ///   fat taint --file quick.cgi --summary
    ///   fat taint --file firmware.bin --arch cortex-m --base 0x08000000
    ///   fat taint --file router.cgi --json
    ///   fat taint --file router.cgi --augment hooks.jsonl --marker FAT_MARKER --json
    ///   fat taint --lang shell --file ./init/wifi.sh --summary
    ///   fat taint --lang shell --rootfs ./squashfs-root --json
    Taint {
        /// Path to an ELF binary, raw firmware blob, or (with --lang shell) a script
        #[arg(long)]
        file: Option<PathBuf>,
        /// Analyze a source language instead of a compiled binary. Values: shell
        #[arg(long)]
        lang: Option<String>,
        /// Rootfs directory to sweep for shell scripts (requires --lang shell)
        #[arg(long)]
        rootfs: Option<PathBuf>,
        /// Architecture for raw blobs (auto-detected for ELF).
        /// Values: cortex-m, arm, armhf, mipsel, mips, x86, x86_64
        #[arg(long)]
        arch: Option<String>,
        /// Base address for raw blobs (e.g., 0x08000000 for STM32 flash).
        /// For Cortex-M, the entry point is auto-read from the IVT.
        #[arg(long)]
        base: Option<String>,
        /// Filter findings by minimum severity: critical, high, medium, low, info
        #[arg(long)]
        severity: Option<String>,
        /// Show one-line-per-finding summary instead of full details
        #[arg(long)]
        summary: bool,
        /// Output findings as JSON
        #[arg(long)]
        json: bool,
        /// Include r2ghidra decompiled source context for each finding
        #[arg(long)]
        decompile: bool,
        /// Skip cache and force re-analysis
        #[arg(long)]
        no_cache: bool,
        /// Augment static taint findings with a hook trace JSONL file or trace-ingest JSON report
        #[arg(long)]
        augment: Option<PathBuf>,
        /// Optional marker string expected to propagate through runtime hook string captures
        #[arg(long)]
        marker: Option<String>,
        /// Optional SinkDiscoveryReport JSON file whose candidates can extend sink metadata.
        #[arg(long = "sink-candidates")]
        sink_candidates: Option<PathBuf>,
        /// Path to an external taint source profile, merged on top of the core
        /// models. FAT ships no profiles; without this, analysis uses the core
        /// models alone. With --lang shell this selects a shell overlay file.
        #[arg(long = "source-profile")]
        source_profile: Option<PathBuf>,
    },
    #[command(name = "taint-query")]
    TaintQuery {
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        json: bool,
    },
    /// Detect, classify, and extract crypto artifacts from a firmware binary.
    ///
    /// Scans imports/exports for crypto function patterns, classifies usage
    /// (bounded decryptor, firmware decryptor, signature verifier), detects
    /// weaknesses (custom crypto, ECB mode), and extracts embedded key material.
    ///
    /// Examples:
    ///   fat crypto --file libdecrypter.so
    ///   fat crypto --file libdecrypter.so --json
    Crypto {
        /// Path to a firmware binary (ELF shared object or executable)
        #[arg(long)]
        file: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
        /// Show the full uncapped report instead of the compact panel
        #[arg(long)]
        full: bool,
    },
    /// Extract embedded key material and crypto evidence from a firmware binary.
    ///
    /// Extraction-focused alias for `fat crypto`. Use this when the immediate
    /// question is whether the binary contains embedded keys, certs, or other
    /// crypto material worth pivoting on before trust-path reconstruction.
    /// FAT also detects exact-length ASCII-hex AES key literals such as
    /// 32-character AES-128 constants, decodes them, and marks them validated
    /// when the decoded byte length is a legal AES key size.
    ///
    /// Examples:
    ///   fat crypto-extract --file libdecrypter.so
    ///   fat crypto-extract --file libdecrypter.so --json
    #[command(name = "crypto-extract")]
    CryptoExtract {
        /// Path to a firmware binary (ELF shared object or executable)
        #[arg(long)]
        file: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
        /// Write extracted PEM/raw key artifacts and a manifest to this directory
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Test whether a firmware byte window behaves like a signature for a public key.
    ///
    /// Applies the RSA public operation to the selected signature window, then
    /// checks whether the result fits the RSA-PSS/SHA-256 structure for the
    /// firmware bytes after the configured ranges are zeroed.
    ///
    /// Examples:
    ///   fat signature-fit --firmware fw.bin --key-blob vendor.publickeyblob \
    ///     --signature-offset 0x20 --signature-size 0x100 --signature-byte-order little
    #[command(name = "signature-fit")]
    SignatureFit {
        /// Firmware/package file containing the suspected signature window
        #[arg(long)]
        firmware: PathBuf,
        /// Raw Microsoft PUBLICKEYBLOB file exported by `fat crypto-extract`
        #[arg(long)]
        key_blob: PathBuf,
        /// Start offset of the suspected signature window, decimal or hex
        #[arg(long)]
        signature_offset: String,
        /// Size of the suspected signature window, decimal or hex
        #[arg(long)]
        signature_size: String,
        /// Byte order for interpreting the signature integer: big or little
        #[arg(long, default_value = "big")]
        signature_byte_order: String,
        /// Range to zero before hashing, as offset:length or start..end; repeatable
        #[arg(long)]
        zero_range: Vec<String>,
        /// Directory for verified PSS salt, firmware hash, and manifest artifacts
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },

    /// Trace data flow across multiple binaries connected by shared state (nvram, config files).
    ///
    /// Runs taint analysis on each binary individually, then stitches findings
    /// across binaries by matching shared-state write operations (e.g., nvram_set)
    /// to shared-state read-to-sink chains (e.g., nvram_get -> system).
    ///
    /// Neither binary may be vulnerable alone — the pair creates an attack chain.
    ///
    /// Which function names write shared state and which read it is a claim
    /// about one platform, so FAT ships no such catalog: pass --state-profile
    /// to supply one. Without it, no name is assigned a read/write role and
    /// no cross-binary findings are emitted (an empty array in JSON mode).
    ///
    /// Examples:
    ///   fat taint-cross --file httpd --file apply_daemon
    ///   fat taint-cross --rootfs ./rootfs/
    ///   fat taint-cross --rootfs ./rootfs/ --state-profile ./my-target-state.yaml
    ///   fat taint-cross --file quick.cgi --file authLogin.cgi --json
    ///   fat taint-cross --file httpd --file apply_daemon --as-taint-json > taint.json
    #[command(name = "taint-cross")]
    TaintCross {
        /// Paths to ELF binaries to analyze together
        #[arg(long = "file", num_args = 1..)]
        files: Vec<PathBuf>,
        /// Path to extracted rootfs (scans for all ELF binaries)
        #[arg(long)]
        rootfs: Option<PathBuf>,
        /// Path to a shared-state profile declaring this target's read/write
        /// function families. FAT ships none and never selects one on its own.
        #[arg(long)]
        state_profile: Option<PathBuf>,
        /// Path to binary source/sink models passed to the analysis engine.
        /// Use with --state-profile when the selected families use custom APIs.
        #[arg(long)]
        source_profile: Option<PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Emit stable TaintFinding JSON suitable for instrument-hooks/probe inputs
        #[arg(long)]
        as_taint_json: bool,
    },

    /// Map firmware update, auth, and crypto trust boundaries across a rootfs.
    ///
    /// Walks an extracted firmware rootfs, identifies binaries that handle
    /// firmware updates (signature verification / decryption), authentication,
    /// and crypto operations.  Shows the library dependency chain between them
    /// and corroborates with init-script references.
    ///
    /// Requires rabin2 (radare2) in PATH.
    ///
    /// Examples:
    ///   fat trust-boundary --rootfs ./rootfs
    ///   fat trust-boundary --rootfs ./rootfs --json
    #[command(name = "trust-boundary")]
    TrustBoundary {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Check or query security invariants against a codebase
    #[command(name = "invariant")]
    Invariant {
        #[command(subcommand)]
        command: InvariantCommand,
    },
    Patch {
        #[command(subcommand)]
        command: PatchCommand,
    },
    Chain {
        #[command(subcommand)]
        command: ChainCommand,
    },
    Verify {
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum GraphCommand {
    /// Export an evidence graph for a research profile.
    Export {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Research profile to export. `inventory` emits neutral Directory/File/Symbol
        /// facts and rabin2 import/export edges. `update-authority` adds update-trust
        /// labels, candidates, verdict hints, rollups, and negative evidence.
        #[arg(long)]
        profile: Option<String>,
        /// Output format. Currently `json`.
        #[arg(long, default_value = "json")]
        format: String,
        /// Persist the exported graph to a file instead of printing it to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum LabelCommand {
    /// Scan a rootfs and emit evidence-backed labels.
    Scan {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Research profile to scan. `inventory` emits neutral file and ELF facts.
        /// `update-authority` tags updater candidates, decision-provider candidates,
        /// crypto providers, helper-only files, and supporting trust-boundary components.
        #[arg(long)]
        profile: Option<String>,
        /// Emit format. Currently `json`.
        #[arg(long, default_value = "json")]
        emit: String,
        /// Persist the emitted graph to a file instead of printing it to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum LabelsCommand {
    /// Explain why a firmware path received its evidence-backed labels.
    Explain {
        /// Path to the extracted firmware rootfs directory
        #[arg(long)]
        rootfs: PathBuf,
        /// Research profile that produced the labels to explain. Currently label
        /// explanations are available for `update-authority`.
        #[arg(long)]
        profile: Option<String>,
        /// Firmware path inside the rootfs, such as /sbin/slpupgrade
        #[arg(long)]
        path: String,
        /// Emit the explanation as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum ProbeCommand {
    /// Emit a runner-facing probe plan for Linux, UEFI, MCU, or bare-metal targets.
    Plan {
        /// Target class: linux, uefi, mcu, or bare-metal
        #[arg(long)]
        target_class: String,
        /// Optional target architecture metadata such as arm64, riscv64, x86_64, or mipsel
        #[arg(long)]
        architecture: Option<String>,
        /// Optional firmware image or binary input
        #[arg(long)]
        file: Option<PathBuf>,
        /// Optional TaintFinding JSON input to include in the plan contract
        #[arg(long)]
        taint: Option<PathBuf>,
        /// Optional peripheral-map JSON input for MCU/bare-metal plans
        #[arg(long)]
        peripheral_map: Option<PathBuf>,
        /// Write the JSON plan to a file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inject an HTTP stimulus through an existing debug session, then evaluate the trace.
    Run {
        /// Project directory containing FAT runtime/session metadata
        #[arg(long)]
        project: PathBuf,
        /// Existing emulation/debug session id to attach to
        #[arg(long)]
        session_id: Option<String>,
        /// TaintFinding JSON emitted by `fat taint --json` or `fat taint-cross --as-taint-json`
        #[arg(long)]
        taint: PathBuf,
        /// Hook trace JSONL or trace-ingest JSON report
        #[arg(long)]
        trace: PathBuf,
        /// HTTP injection spec, e.g. `POST /cgi-bin/webproc action=MARKER`
        #[arg(long)]
        inject_http: String,
        /// Optional marker expected to appear in captured hook string arguments
        #[arg(long)]
        marker: Option<String>,
        /// Timeout to wait for trace creation/marker observation
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Optional SQLite query snapshot for runtime evidence graph nodes/edges
        #[arg(long)]
        evidence_snapshot: Option<PathBuf>,
    },
    /// Evaluate marker propagation in an existing hook trace.
    Evaluate {
        /// TaintFinding JSON emitted by `fat taint --json`
        #[arg(long)]
        taint: PathBuf,
        /// Hook trace JSONL or trace-ingest JSON report
        #[arg(long)]
        trace: PathBuf,
        /// Optional marker expected to appear in captured hook string arguments
        #[arg(long)]
        marker: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Optional SQLite query snapshot for runtime evidence graph nodes/edges
        #[arg(long)]
        evidence_snapshot: Option<PathBuf>,
    },
    /// Ingest JSONL emitted by an external UEFI/MCU/bare-metal runner.
    #[command(name = "ingest-runner")]
    IngestRunner {
        /// Runner JSONL trace to normalize as RuntimeCapture evidence
        #[arg(long)]
        trace: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Optional SQLite query snapshot for runner runtime evidence nodes
        #[arg(long)]
        evidence_snapshot: Option<PathBuf>,
    },
    /// Enrich probe plans with vendor SVD/CMSIS register metadata.
    #[command(name = "enrich-svd")]
    EnrichSvd {
        /// SVD/CMSIS XML file
        #[arg(long)]
        svd: PathBuf,
        /// Write the JSON enrichment report to a file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum InvariantCommand {
    /// Query a source tree for invariant violations using the shared query graph.
    Query {
        /// Fixture repo path used in tests or lightweight local analysis.
        #[arg(long)]
        fixture: Option<PathBuf>,
        /// Source repository path to analyze.
        #[arg(long)]
        repo: Option<PathBuf>,
        /// The invariant rule to evaluate.
        #[arg(long)]
        rule: String,
        /// Source analysis mode: triage or deep.
        #[arg(long, default_value = "deep")]
        mode: String,
        /// Optional directory where debug bundle artifacts should be persisted.
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        /// Output JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum PatchCommand {
    Check {
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        find_variants: bool,
        #[arg(long, default_value = "deep")]
        mode: String,
        #[arg(long = "debug-bundle-dir")]
        debug_bundle_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum ChainCommand {
    Query {
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        goal: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum DebugCommand {
    Surfaces {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Shell {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        command: Option<String>,
    },
    Maps {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        target: String,
    },
    Monitor {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        command: Option<String>,
    },
    Gdb {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        command: Option<String>,
    },
    Suggest {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum ObserveCommand {
    Ps {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Services {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Net {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum DiffCommand {
    Role {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare two firmware projects across filesystem, config, and binary layers
    Firmware {
        /// Path to the base (older) project directory
        #[arg(long)]
        base: PathBuf,
        /// Path to the head (newer) project directory
        #[arg(long)]
        head: PathBuf,
        /// Explicit base partition trees (bypasses auto-discovery). Repeat for multiple.
        #[arg(long = "base-tree")]
        base_trees: Vec<PathBuf>,
        /// Explicit head partition trees (bypasses auto-discovery). Repeat for multiple.
        #[arg(long = "head-tree")]
        head_trees: Vec<PathBuf>,
        /// Focus on security-relevant changes only
        #[arg(long, default_value = "false")]
        security: bool,
        /// Specific layer to diff (filesystem, config, binary, all)
        #[arg(long, default_value = "all")]
        layer: String,
        /// Output as JSON
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum BootloaderCommand {
    New {
        project: PathBuf,
        #[arg(long)]
        profile: String,
    },
    ExportEnv {
        project: PathBuf,
    },
    Emulate {
        project: PathBuf,
        #[arg(long)]
        assist: bool,
    },
    Console {
        project: PathBuf,
    },
    /// Stop the running bootloader emulation session for a project.
    Stop {
        /// Project whose session to stop. Omit when using --all.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        project: Option<PathBuf>,
        /// Stop every FAT-managed bootloader session on this host, including
        /// orphans whose project directory is gone.
        #[arg(long)]
        all: bool,
    },
    Status {
        project: PathBuf,
    },
    Inspect {
        project: PathBuf,
    },
    /// Find static kernel handoff candidates in a raw bootloader blob
    Handoff {
        /// Raw bootloader blob to inspect
        #[arg(long)]
        file: PathBuf,
        /// Treat the input as a raw blob instead of an object file
        #[arg(long, default_value = "false")]
        raw: bool,
        /// Raw architecture model; v1 supports mips-pic
        #[arg(long)]
        arch: Option<String>,
        /// Load base for raw address reporting, for example 0x0
        #[arg(long)]
        base: Option<String>,
        /// Boot landmark string to use for candidate discovery. Repeat for multiple.
        #[arg(long = "landmark")]
        landmarks: Vec<String>,
        /// Analyze a specific candidate function address instead of landmark-derived candidates
        #[arg(long)]
        function: Option<String>,
        /// Saved raw r2ghidra C file to scan instead of invoking decompilation
        #[arg(long = "decompile-file")]
        decompile_file: Option<PathBuf>,
        /// Output as JSON
        #[arg(long, default_value = "false")]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum InspectCommand {
    Headers {
        project: Option<PathBuf>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Layout {
        project: Option<PathBuf>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Envelope {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Update {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Detect and characterize bare-metal MCU firmware from IVT analysis
    Mcu {
        /// Path to a raw firmware binary
        #[arg(long)]
        file: PathBuf,
        /// Override the inferred base address (for example 0x08000000)
        #[arg(long)]
        base: Option<String>,
        /// Force a family pack hint (for example STM32H7)
        #[arg(long)]
        family: Option<String>,
        /// Output as JSON instead of structured text
        #[arg(long)]
        json: bool,
    },
    /// Inspect family-backed peripheral and register surfaces for a raw MCU blob
    #[command(name = "peripheral-map")]
    PeripheralMap {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect interrupt-boundary shared-state candidates for a raw MCU blob
    #[command(name = "isr-state")]
    IsrState {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        family: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Rank candidate SVD/CMSIS files by exact MMIO register-address literals in a raw MCU blob
    #[command(name = "svd-rank")]
    SvdRank {
        #[arg(long)]
        file: PathBuf,
        #[arg(long = "svd-corpus")]
        svd_corpus: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_results: usize,
        #[arg(long)]
        json: bool,
    },
}

type DynResult<T> = Result<T, Box<dyn Error>>;

fn require_research_profile(profile: Option<String>) -> DynResult<String> {
    profile.ok_or_else(|| {
        "no research profile selected; pass --profile inventory for neutral firmware inventory or --profile update-authority for update-trust research".into()
    })
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// clap help styling: matches the fat Palette (style.rs) — bold bright-blue
/// section headings, bold cyan literals (flags/subcommands), dimmed
/// placeholders, and clap's default red error styling.
fn clap_help_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Styles};

    Styles::styled()
        .header(AnsiColor::Blue.on_default() | Effects::BOLD)
        .usage(AnsiColor::Blue.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(clap::builder::styling::Style::new().effects(Effects::DIMMED))
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

/// Respect fat's color gating for clap's own help/error rendering so
/// `FAT_COLOR`, `NO_COLOR`, and piped output behave the same for clap as they
/// do for fat's own styled output.
fn clap_help_color_choice() -> clap::ColorChoice {
    use std::env;

    if let Ok(value) = env::var("FAT_COLOR") {
        match value.to_ascii_lowercase().as_str() {
            "always" | "1" | "true" => return clap::ColorChoice::Always,
            "never" | "0" | "false" => return clap::ColorChoice::Never,
            _ => {}
        }
    }
    if env::var_os("NO_COLOR").is_some() {
        return clap::ColorChoice::Never;
    }
    // Otherwise let clap's Auto decide (colors only when stdout is a TTY),
    // matching how fat's own Palette gates styling for piped output.
    clap::ColorChoice::Auto
}

/// Remove color-selection variables from this process's environment so child
/// processes never see a parent-forced color mode. fat renders its own
/// styling; r2/rabin2 emit a spurious "Color mode 3" warning when they
/// inherit `COLORTERM=truecolor` while running colorless with piped output.
fn sanitize_child_color_env() {
    use std::env;

    env::remove_var("COLORTERM");
    env::remove_var("CLICOLOR_FORCE");
}

fn run() -> DynResult<()> {
    // Keep child processes (r2/rabin2, extractors) plain: fat renders its own
    // styling, and a parent-forced color environment makes r2 emit
    // "WARN: Color mode 3 requested but terminal only supports 0" into our
    // output. Must happen before any child process is spawned.
    sanitize_child_color_env();

    let mut command = Cli::command()
        .color(clap_help_color_choice())
        .styles(clap_help_styles());
    helptext::apply(&mut command);
    let args = normalize_bare_path_args(std::env::args_os().collect(), &command);
    let matches = command.get_matches_from(args);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());

    match cli.command {
        Some(Command::Android { subject }) => android_cmd::run(subject),
        Some(Command::New {
            firmware,
            name,
            projects_dir,
        }) => cmd_new(&firmware, name.as_deref(), &projects_dir),
        Some(Command::Identify { path, file, json }) => {
            identify_cmd::run(path.as_deref(), file.as_deref(), json)
        }
        Some(Command::Extract {
            project,
            project_flag,
            force,
            extract_timeout,
            extractor,
            unblob_processes,
            unblob_depth,
            json,
        }) => cmd_extract(
            &resolve_project_arg(project, project_flag)?,
            force,
            resolve_extract_timeout(extract_timeout)?,
            resolve_extractor_selection(extractor.as_deref())?,
            ExternalExtractorOptions {
                processes: unblob_processes,
                max_depth: unblob_depth,
            },
            OutputFormat::from_flag(json),
        ),
        Some(Command::ExtractPayload {
            project,
            file,
            offset,
            format,
        }) => extract_payload_cmd::run(project.as_deref(), file.as_deref(), &offset, &format),
        Some(Command::Carve {
            project,
            file,
            offset,
            size,
            format,
            output,
        }) => carve_cmd::run(
            project.as_deref(),
            file.as_deref(),
            &offset,
            size.as_deref(),
            format.as_deref(),
            output.as_deref(),
        ),
        Some(Command::Analyze {
            project,
            project_flag,
            json,
        }) => cmd_analyze(
            &resolve_project_arg(project, project_flag)?,
            OutputFormat::from_flag(json),
        ),
        Some(Command::EdgeAi { command }) => edge_ai_cmd::run(command),
        Some(Command::Preflight {
            project,
            signals,
            json,
        }) => cmd_preflight(project.as_deref(), signals, OutputFormat::from_flag(json)),
        Some(Command::Info {
            project,
            project_flag,
            json,
        }) => info_cmd::run(&resolve_project_arg(project, project_flag)?, json),
        Some(Command::List { projects_dir, json }) => list_cmd::run_list(&projects_dir, json),
        Some(Command::Delete {
            project,
            projects_dir,
            yes,
        }) => list_cmd::run_delete(&project, &projects_dir, yes),
        Some(Command::RehostingTrace {
            project,
            session_id,
            json,
        }) => rehosting_trace_cmd::run(&project, session_id.as_deref(), json),
        Some(Command::Rehost { command }) => rehost_cmd::run(command),
        Some(Command::Experiment { command }) => experiment_cmd::run(command),
        Some(Command::Kernel { command }) => kernel_cmd::run(command),
        Some(Command::Data { command }) => data_cmd::run(command),
        Some(Command::SinkDiscovery(args)) => sink_discovery_cmd::run(args),
        Some(Command::Doctor { strict, json }) => doctor_cmd::run(strict, json),
        Some(Command::Debug { subject }) => match subject {
            DebugCommand::Surfaces {
                project,
                session_id,
                json,
            } => debug_cmd::run_surfaces(&project, session_id.as_deref(), json),
            DebugCommand::Shell {
                project,
                session_id,
                command,
            } => debug_cmd::run_shell(&project, session_id.as_deref(), command.as_deref()),
            DebugCommand::Maps {
                project,
                session_id,
                target,
            } => debug_cmd::run_maps(&project, session_id.as_deref(), &target),
            DebugCommand::Monitor {
                project,
                session_id,
                command,
            } => debug_cmd::run_monitor(&project, session_id.as_deref(), command.as_deref()),
            DebugCommand::Gdb {
                project,
                session_id,
                target,
                command,
            } => debug_cmd::run_gdb(
                &project,
                session_id.as_deref(),
                target.as_deref(),
                command.as_deref(),
            ),
            DebugCommand::Suggest {
                project,
                session_id,
                json,
            } => debug_cmd::run_suggest(&project, session_id.as_deref(), json),
        },
        Some(Command::Observe { subject }) => match subject {
            ObserveCommand::Ps {
                project,
                session_id,
                json,
            } => observe_cmd::run_ps(&project, session_id.as_deref(), json),
            ObserveCommand::Services {
                project,
                session_id,
                json,
            } => observe_cmd::run_services(&project, session_id.as_deref(), json),
            ObserveCommand::Net {
                project,
                session_id,
                json,
            } => observe_cmd::run_net(&project, session_id.as_deref(), json),
        },
        Some(Command::Benchmark { subject }) => benchmark_cmd::run(subject),
        Some(Command::Discover {
            subject,
            fixture,
            repo,
            family,
            top_k,
            mode,
            debug_bundle_dir,
            json,
        }) => match subject {
            Some(DiscoverCommand::Leads(args)) => discover_cmd::run_leads(
                args.fixture.as_deref(),
                args.repo.as_deref(),
                args.family.as_deref(),
                args.top_k,
                parse_execution_mode(&args.mode)?,
                args.debug_bundle_dir.as_deref(),
                args.json,
            ),
            Some(DiscoverCommand::Preflight(args)) => {
                discover_cmd::run_preflight(&args.manifest, args.json)
            }
            Some(DiscoverCommand::Harvest(args)) => discover_cmd::run_harvest(
                &args.manifest,
                &args.family,
                args.top_k,
                parse_execution_mode(&args.mode)?,
                args.debug_bundle_dir.as_deref(),
                args.json,
            ),
            Some(DiscoverCommand::Run(args)) => discover_cmd::run_execute(
                &args.manifest,
                &args.family,
                args.top_k,
                parse_execution_mode(&args.mode)?,
                args.debug_bundle_dir.as_deref(),
                args.json,
            ),
            Some(DiscoverCommand::Triage(args)) => {
                discover_cmd::run_triage(&args.attempt_record, args.json)
            }
            None => discover_cmd::run_legacy(
                fixture.as_deref(),
                repo.as_deref(),
                family.as_deref(),
                top_k,
                parse_execution_mode(&mode)?,
                debug_bundle_dir.as_deref(),
                json,
            ),
        },
        Some(Command::Hsm { command }) => match command {
            HsmCommand::Registry { json } => hsm_cmd::run_registry(json),
            HsmCommand::Derive {
                leads_file,
                fixture,
                repo,
                manifest,
                family,
                top_k,
                mode,
                debug_bundle_dir,
                out_file,
                lead_id,
                json,
            } => hsm_cmd::run_derive(
                hsm_cmd::LeadSource {
                    leads_file: leads_file.as_deref(),
                    fixture: fixture.as_deref(),
                    repo: repo.as_deref(),
                    manifest: manifest.as_deref(),
                    family: family.as_deref(),
                    top_k,
                    mode: parse_execution_mode(&mode)?,
                    debug_bundle_dir: debug_bundle_dir.as_deref(),
                },
                out_file.as_deref(),
                lead_id.as_deref(),
                json,
            ),
            HsmCommand::Query { command } => match command {
                HsmQueryCommand::EventPath {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    event_id,
                    json,
                } => hsm_cmd::run_query_event_path(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    &event_id,
                    json,
                ),
                HsmQueryCommand::InvalidationPath {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    json,
                } => hsm_cmd::run_query_invalidation_path(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    json,
                ),
                HsmQueryCommand::Coexistence {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    json,
                } => hsm_cmd::run_query_coexistence(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    json,
                ),
                HsmQueryCommand::GhostState {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    json,
                } => hsm_cmd::run_query_ghost_state(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    json,
                ),
                HsmQueryCommand::StateCondition {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    state_id,
                    json,
                } => hsm_cmd::run_query_state_condition(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    &state_id,
                    json,
                ),
                HsmQueryCommand::Counterfactual {
                    machines_file,
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    machine_id,
                    guard_id,
                    json,
                } => hsm_cmd::run_query_counterfactual(
                    machines_file.as_deref(),
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    &machine_id,
                    guard_id.as_deref(),
                    json,
                ),
                HsmQueryCommand::LocalityPolicy {
                    leads_file,
                    fixture,
                    repo,
                    manifest,
                    family,
                    top_k,
                    mode,
                    debug_bundle_dir,
                    lead_id,
                    json,
                } => hsm_cmd::run_query_locality_policy(
                    hsm_cmd::LeadSource {
                        leads_file: leads_file.as_deref(),
                        fixture: fixture.as_deref(),
                        repo: repo.as_deref(),
                        manifest: manifest.as_deref(),
                        family: family.as_deref(),
                        top_k,
                        mode: parse_execution_mode(&mode)?,
                        debug_bundle_dir: debug_bundle_dir.as_deref(),
                    },
                    lead_id.as_deref(),
                    json,
                ),
            },
            HsmCommand::Plan {
                machines_file,
                manifest,
                lead_id,
                machine_id,
                transition_id,
                json,
            } => hsm_cmd::run_plan(
                &machines_file,
                &manifest,
                lead_id.as_deref(),
                machine_id.as_deref(),
                transition_id.as_deref(),
                json,
            ),
        },
        Some(Command::SourceMap {
            rootfs,
            source_profile,
            json,
        }) => source_map_cmd::run(&rootfs, source_profile.as_deref(), json),
        Some(Command::StartupMap {
            rootfs,
            profile,
            name,
            binary,
            api,
            library,
            max,
            json,
            explain,
            emit_actions,
            all_scripts,
            no_r2,
        }) => startup_map_cmd::run(startup_map_cmd::StartupMapRequest {
            rootfs: &rootfs,
            profile: profile.as_deref(),
            name: name.as_deref(),
            binary: binary.as_deref(),
            api: api.as_deref(),
            library: library.as_deref(),
            max,
            json,
            explain,
            emit_actions,
            all_scripts,
            no_r2,
        }),
        Some(Command::Search {
            rootfs,
            include,
            profiles,
            case_insensitive,
            exclude,
            path,
            max,
            all_files,
            min_len,
            context,
            unique,
            no_discover_rootfs,
            show_empty,
            min_strength,
            context_filter,
            verbose,
            summary,
            format,
            color,
            progress,
            json,
        }) => search_cmd::run(search_cmd::SearchRequest {
            rootfs: &rootfs,
            include: include.as_deref(),
            excludes: &exclude,
            profiles: &profiles,
            path: path.as_deref(),
            max,
            all_files,
            min_len,
            case_insensitive,
            context,
            unique,
            discover_rootfs: !no_discover_rootfs,
            show_empty,
            min_strength: &min_strength,
            context_filter: &context_filter,
            verbose,
            summary,
            format: &format,
            color: color.as_deref(),
            progress: &progress,
            json,
        }),
        Some(Command::XrefSearch {
            file,
            vaddr,
            string_pattern,
            raw,
            arch,
            base,
            scan,
            json,
        }) => xref_search_cmd::run(
            &file,
            vaddr.as_deref(),
            string_pattern.as_deref(),
            raw,
            arch.as_deref(),
            base.as_deref(),
            &scan,
            json,
        ),
        Some(Command::HandlerTable {
            file,
            patterns,
            entry_size,
            scan,
            source_map,
            json,
        }) => handler_table_cmd::run(
            &file,
            patterns.as_deref(),
            entry_size,
            &scan,
            source_map.as_deref(),
            json,
        ),
        Some(Command::Emulate {
            project_arg,
            project,
            backend,
            substrate_policy,
            ports,
            session_id,
            status,
            list,
            list_json,
            gc,
            stop,
            instrument,
            pack,
            experimental_rehosting,
            accept_degraded_rehosting,
            kernel_class,
        }) => {
            let (project_arg, list) = resolve_emulate_list_alias(project_arg, list);
            cmd_emulate(
                project.or(project_arg),
                backend,
                substrate_policy,
                session_id,
                ports,
                status,
                list,
                list_json,
                gc,
                stop,
                instrument,
                pack,
                experimental_rehosting,
                accept_degraded_rehosting,
                kernel_class,
            )
        }
        Some(Command::SuperviseManagedVm {
            project,
            session_id,
        }) => emulate_cmd::run_managed_supervisor(project, session_id),
        Some(Command::Diff { subject }) => match subject {
            DiffCommand::Role { left, right, json } => diff_cmd::run_role(&left, &right, json),
            DiffCommand::Firmware {
                base,
                head,
                base_trees,
                head_trees,
                security,
                layer,
                json,
            } => firmware_diff_cmd::run(
                &base,
                &head,
                &base_trees,
                &head_trees,
                security,
                &layer,
                json,
            ),
        },
        Some(Command::Graph { command }) => match command {
            GraphCommand::Export {
                rootfs,
                profile,
                format,
                output,
            } => {
                let profile = require_research_profile(profile)?;
                let format = fat_graph_cmd::parse_graph_output(&format)?;
                fat_graph_cmd::run_graph_export(&rootfs, &profile, format, output.as_deref())
            }
        },
        Some(Command::Label { command }) => match command {
            LabelCommand::Scan {
                rootfs,
                profile,
                emit,
                output,
            } => {
                let profile = require_research_profile(profile)?;
                let emit = fat_graph_cmd::parse_graph_output(&emit)?;
                fat_graph_cmd::run_label_scan(&rootfs, &profile, emit, output.as_deref())
            }
        },
        Some(Command::Labels { command }) => match command {
            LabelsCommand::Explain {
                rootfs,
                profile,
                path,
                json,
            } => {
                let profile = require_research_profile(profile)?;
                fat_graph_cmd::run_labels_explain(&rootfs, &profile, &path, json)
            }
        },
        Some(Command::Ls {
            rootfs,
            profile,
            tags,
            json,
        }) => {
            let profile = require_research_profile(profile)?;
            fat_graph_cmd::run_ls(&rootfs, &profile, tags, json)
        }
        Some(Command::Tree {
            rootfs,
            profile,
            tags,
            summary,
            json,
        }) => {
            let profile = require_research_profile(profile)?;
            fat_graph_cmd::run_tree(&rootfs, &profile, tags, summary, json)
        }
        Some(Command::Bootloader { command }) => match command {
            BootloaderCommand::New { project, profile } => cmd_bootloader_new(&project, &profile),
            BootloaderCommand::ExportEnv { project } => cmd_bootloader_export_env(&project),
            BootloaderCommand::Emulate { project, assist } => {
                cmd_bootloader_emulate(&project, assist)
            }
            BootloaderCommand::Console { project } => cmd_bootloader_console(&project),
            BootloaderCommand::Stop { project, all } => {
                cmd_bootloader_stop(project.as_deref(), all)
            }
            BootloaderCommand::Status { project } => cmd_bootloader_status(&project),
            BootloaderCommand::Inspect { project } => cmd_bootloader_inspect(&project),
            BootloaderCommand::Handoff {
                file,
                raw,
                arch,
                base,
                landmarks,
                function,
                decompile_file,
                json,
            } => bootloader_handoff_cmd::run(
                &file,
                raw,
                arch.as_deref(),
                base.as_deref(),
                &landmarks,
                function.as_deref(),
                decompile_file.as_deref(),
                json,
            ),
        },
        Some(Command::Inspect { subject }) => match subject {
            InspectCommand::Headers {
                project,
                file,
                json,
            } => inspect_cmd::run_headers(project.as_deref(), file.as_deref(), json),
            InspectCommand::Layout {
                project,
                file,
                json,
            } => inspect_cmd::run_layout(project.as_deref(), file.as_deref(), json),
            InspectCommand::Envelope {
                file,
                reference,
                json,
            } => inspect_cmd::run_envelope(&file, reference.as_deref(), json),
            InspectCommand::Update {
                file,
                rootfs,
                reference,
                json,
            } => inspect_cmd::run_update(&file, &rootfs, reference.as_deref(), json),
            InspectCommand::Mcu {
                file,
                base,
                family,
                json,
            } => inspect_cmd::run_mcu(&file, base.as_deref(), family.as_deref(), json),
            InspectCommand::PeripheralMap {
                file,
                base,
                family,
                json,
            } => inspect_cmd::run_peripheral_map(&file, base.as_deref(), family.as_deref(), json),
            InspectCommand::IsrState {
                file,
                base,
                family,
                json,
            } => inspect_cmd::run_isr_state(&file, base.as_deref(), family.as_deref(), json),
            InspectCommand::SvdRank {
                file,
                svd_corpus,
                max_results,
                json,
            } => inspect_cmd::run_svd_rank(&file, &svd_corpus, max_results, json),
        },
        Some(Command::InspectHandoff { file, json }) => inspect_handoff_cmd::run(&file, json),
        Some(Command::BundleReality { file, json }) => bundle_reality_cmd::run(&file, json),
        Some(Command::RuntimePlane { file, json }) => runtime_plane_cmd::run(&file, json),
        Some(Command::Crypto { file, json, full }) => crypto_cmd::run(&file, json, None, full),
        Some(Command::CryptoExtract {
            file,
            json,
            output_dir,
        }) => crypto_cmd::run(&file, json, output_dir.as_deref(), false),
        Some(Command::SignatureFit {
            firmware,
            key_blob,
            signature_offset,
            signature_size,
            signature_byte_order,
            zero_range,
            output_dir,
            json,
        }) => signature_fit_cmd::run(
            &firmware,
            &key_blob,
            &signature_offset,
            &signature_size,
            &signature_byte_order,
            &zero_range,
            output_dir.as_deref(),
            json,
        ),
        Some(Command::R2Triage {
            file,
            arch,
            base,
            family,
            json,
            full,
        }) => r2_triage_cmd::run(
            &file,
            arch.as_deref(),
            base.as_deref(),
            family.as_deref(),
            json,
            full,
        ),
        Some(Command::InstrumentHooks {
            file,
            from_taint,
            from_sinks,
            output,
            categories,
            json,
        }) => {
            if let Some(taint_path) = from_taint {
                instrument_hooks_cmd::run_from_taint(&taint_path, output.as_deref(), json)
            } else if let Some(sinks_path) = from_sinks {
                instrument_hooks_cmd::run_from_sinks(&sinks_path, output.as_deref(), json)
            } else {
                let Some(file) = file.as_ref() else {
                    return Err(
                        "instrument-hooks requires --file, --from-taint, or --from-sinks"
                            .to_string()
                            .into(),
                    );
                };
                instrument_hooks_cmd::run(file, output.as_deref(), json, categories.as_deref())
            }
        }
        Some(Command::TraceIngest {
            project,
            trace,
            session_id,
            json,
        }) => trace_ingest_cmd::run(&project, &trace, session_id.as_deref(), json),
        Some(Command::Probe { command }) => match command {
            ProbeCommand::Plan {
                target_class,
                architecture,
                file,
                taint,
                peripheral_map,
                output,
                json,
            } => probe_cmd::run_plan(
                &target_class,
                architecture.as_deref(),
                file.as_deref(),
                taint.as_deref(),
                peripheral_map.as_deref(),
                output.as_deref(),
                json,
            ),
            ProbeCommand::Run {
                project,
                session_id,
                taint,
                trace,
                inject_http,
                marker,
                timeout_seconds,
                json,
                evidence_snapshot,
            } => probe_cmd::run_probe(
                &project,
                session_id.as_deref(),
                &taint,
                &trace,
                &inject_http,
                marker.as_deref(),
                timeout_seconds,
                json,
                evidence_snapshot.as_deref(),
            ),
            ProbeCommand::Evaluate {
                taint,
                trace,
                marker,
                json,
                evidence_snapshot,
            } => probe_cmd::run_evaluate(
                &taint,
                &trace,
                marker.as_deref(),
                json,
                evidence_snapshot.as_deref(),
            ),
            ProbeCommand::IngestRunner {
                trace,
                json,
                evidence_snapshot,
            } => probe_cmd::run_ingest_runner(&trace, json, evidence_snapshot.as_deref()),
            ProbeCommand::EnrichSvd { svd, output, json } => {
                probe_cmd::run_enrich_svd(&svd, output.as_deref(), json)
            }
        },
        Some(Command::Decompile {
            file,
            function,
            arch,
            base,
            family,
            output,
            json,
            context,
        }) => decompile_cmd::run(
            &file,
            &function,
            arch.as_deref(),
            base.as_deref(),
            family.as_deref(),
            output.as_deref(),
            json,
            context,
        ),
        Some(Command::SdkTrace { dir, json }) => sdk_trace_cmd::run(&dir, json),
        Some(Command::IdentifyLauncher { file, json }) => identify_launcher_cmd::run(&file, json),
        Some(Command::TrustMap { rootfs, json }) => {
            trust_boundary_cmd::run(&rootfs, json, trust_boundary_cmd::RenderMode::TrustMap)
        }
        Some(Command::DetectEncryption { file, json }) => {
            inspect_cmd::run_envelope(&file, None, json)
        }
        Some(Command::Compare {
            encrypted,
            reference,
            json,
        }) => inspect_cmd::run_envelope(&encrypted, Some(&reference), json),
        Some(Command::CryptoCensus {
            rootfs,
            only,
            group_by,
            json,
        }) => crypto_census_cmd::run(&rootfs, only.as_deref(), &group_by, json),
        Some(Command::Taint {
            file,
            lang,
            rootfs,
            arch,
            base,
            severity,
            summary,
            json,
            decompile,
            no_cache,
            augment,
            marker,
            sink_candidates,
            source_profile,
        }) => taint_cmd::run(
            file.as_deref(),
            lang.as_deref(),
            rootfs.as_deref(),
            arch.as_deref(),
            base.as_deref(),
            severity.as_deref(),
            summary,
            json,
            decompile,
            no_cache,
            augment.as_deref(),
            marker.as_deref(),
            sink_candidates.as_deref(),
            source_profile.as_deref(),
        ),
        Some(Command::TaintQuery {
            fixture,
            file,
            from,
            to,
            json,
        }) => taint_query_cmd::run(fixture.as_deref(), file.as_deref(), &from, &to, json),
        Some(Command::TaintCross {
            files,
            rootfs,
            state_profile,
            source_profile,
            json,
            as_taint_json,
        }) => taint_cross_cmd::run(
            &files,
            rootfs.as_deref(),
            state_profile.as_deref(),
            source_profile.as_deref(),
            json,
            as_taint_json,
        ),
        Some(Command::TrustBoundary { rootfs, json }) => {
            trust_boundary_cmd::run(&rootfs, json, trust_boundary_cmd::RenderMode::TrustBoundary)
        }
        Some(Command::Invariant { command }) => match command {
            InvariantCommand::Query {
                fixture,
                repo,
                rule,
                mode,
                debug_bundle_dir,
                json,
            } => invariant_query_cmd::run(
                fixture.as_deref(),
                repo.as_deref(),
                &rule,
                parse_execution_mode(&mode)?,
                debug_bundle_dir.as_deref(),
                json,
            ),
        },
        Some(Command::Patch { command }) => match command {
            PatchCommand::Check {
                fixture,
                repo,
                find_variants,
                mode,
                debug_bundle_dir,
                json,
            } => patch_check_cmd::run(
                fixture.as_deref(),
                repo.as_deref(),
                find_variants,
                parse_execution_mode(&mode)?,
                debug_bundle_dir.as_deref(),
                json,
            ),
        },
        Some(Command::Chain { command }) => match command {
            ChainCommand::Query {
                fixture,
                goal,
                json,
            } => chain_query_cmd::run(fixture.as_deref(), &goal, json),
        },
        Some(Command::Verify { fixture, json }) => verify_cmd::run(fixture.as_deref(), json),
        None => Ok(()),
    }
}

fn normalize_bare_path_args(mut args: Vec<OsString>, command: &clap::Command) -> Vec<OsString> {
    normalize_bare_path_args_with_exists(&mut args, command, |path| path.exists());
    args
}

fn normalize_bare_path_args_with_exists<F>(
    args: &mut Vec<OsString>,
    command: &clap::Command,
    exists: F,
) where
    F: Fn(&PathBuf) -> bool,
{
    let Some(first_arg) = args.get(1).cloned() else {
        return;
    };

    let is_flag = {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;

            first_arg.as_os_str().as_bytes().starts_with(b"-")
        }
        #[cfg(not(unix))]
        {
            first_arg
                .to_str()
                .is_some_and(|first_arg_str| first_arg_str.starts_with('-'))
        }
    };
    if is_flag {
        return;
    }

    if let Some(first_arg_str) = first_arg.to_str() {
        if command.find_subcommand(first_arg_str).is_some() {
            return;
        }
    }

    let path = PathBuf::from(first_arg.as_os_str());
    if exists(&path) {
        args.insert(1, OsString::from("identify"));
    }
}

fn cmd_new(firmware: &Path, name: Option<&str>, projects_dir: &Path) -> DynResult<()> {
    let (project, project_dir, copied_firmware) = create_project(firmware, name, projects_dir)?;

    println!("project: {}", project.name);
    println!("dir: {}", project_dir.display());
    println!("firmware: {}", copied_firmware.display());

    Ok(())
}

fn create_project(
    firmware: &Path,
    name: Option<&str>,
    projects_dir: &Path,
) -> DynResult<(Project, PathBuf, PathBuf)> {
    if !firmware.is_file() {
        return Err(format!(
            "firmware path does not exist or is not a file: {}",
            firmware.display()
        )
        .into());
    }

    let project_name = name
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| slugify_name(firmware));
    let project_dir = projects_dir.join(&project_name);
    let input_dir = project_dir.join("input");
    let analysis_dir = project_dir.join("analysis");
    let work_dir = project_dir.join("work");

    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&analysis_dir)?;
    fs::create_dir_all(&work_dir)?;

    let firmware_name = firmware
        .file_name()
        .ok_or_else(|| format!("firmware path has no file name: {}", firmware.display()))?
        .to_string_lossy()
        .into_owned();
    let copied_firmware = input_dir.join(&firmware_name);
    fs::copy(firmware, &copied_firmware)?;

    let mut project = Project::new(project_name.clone(), firmware_name);
    project.fingerprint = Some(compute_fingerprint(&copied_firmware)?);

    let db = ProjectDb::open(&project_dir)?;
    db.save(&project)?;
    let store = RuntimeStore::open(&project_dir)?;
    ensure_target_record(&store, &project)?;

    Ok((project, project_dir, copied_firmware))
}

fn parse_execution_mode(value: &str) -> DynResult<fat_query::adapters::traits::ExecutionMode> {
    match value {
        "triage" => Ok(fat_query::adapters::traits::ExecutionMode::Triage),
        "deep" => Ok(fat_query::adapters::traits::ExecutionMode::Deep),
        other => Err(format!("unsupported mode: {other}").into()),
    }
}

fn sync_extracted_rootfs_view(project_dir: &Path, rootfs_path: Option<&Path>) -> DynResult<()> {
    let extracted_path = project_dir.join("extracted");
    remove_existing_path_if_present(&extracted_path)?;

    let Some(rootfs_path) = rootfs_path else {
        return Ok(());
    };
    create_directory_link(rootfs_path, &extracted_path)
}

fn remove_existing_path_if_present(path: &Path) -> DynResult<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_directory_link(source: &Path, destination: &Path) -> DynResult<()> {
    std::os::unix::fs::symlink(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn create_directory_link(source: &Path, destination: &Path) -> DynResult<()> {
    std::os::windows::fs::symlink_dir(source, destination)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_directory_link(source: &Path, destination: &Path) -> DynResult<()> {
    let _ = source;
    let _ = destination;
    Err("directory symlinks are unsupported on this platform".into())
}

fn cmd_extract(
    project_dir: &Path,
    force: bool,
    extract_timeout: Option<Duration>,
    extractor_selection: ExtractorSelection,
    extractor_options: ExternalExtractorOptions,
    format: OutputFormat,
) -> DynResult<()> {
    let palette = crate::style::Palette::stdout();
    // The panel look is the TTY treatment; piped and --json runs keep the
    // historical plain text byte-for-byte.
    let panel_mode = format.is_text() && palette.enabled();
    // Header facts (project/dir/firmware) are collected while the run sets
    // itself up so the panel can carry them once at the end instead of
    // echoing them mid-stream.
    let mut setup_rows: Vec<(String, String)> = Vec::new();
    let mut refresh_note: Option<String> = None;
    let mut note = |key: &str, value: &str| {
        if panel_mode {
            setup_rows.push((key.to_string(), value.to_string()));
        } else {
            format.note(format!("{key}: {value}"));
        }
    };
    let project_dir = if project_dir.is_file() {
        let default_project_dir = Path::new(DEFAULT_PROJECTS_DIR).join(slugify_name(project_dir));
        if default_project_dir.join(".fat.db").is_file() {
            note(
                "project",
                default_project_dir
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("firmware"),
            );
            note("dir", &default_project_dir.display().to_string());
            note("project_status", "existing project reused");
            fs::canonicalize(default_project_dir)?
        } else {
            let (project, created_project_dir, copied_firmware) =
                create_project(project_dir, None, Path::new(DEFAULT_PROJECTS_DIR))?;
            note("project", &project.name);
            note("dir", &created_project_dir.display().to_string());
            note("firmware", &copied_firmware.display().to_string());
            fs::canonicalize(created_project_dir)?
        }
    } else {
        normalize_project_dir(project_dir)?
    };
    let db = ProjectDb::open(&project_dir)?;
    let mut project = load_project(&db, &project_dir)?;
    let extraction_root = project_dir.join("work").join("extractions");
    let manifest_path = extraction_manifest_path(&project_dir);
    let firmware_path = project_firmware_path(&project_dir, &project);
    let mut container_probe = None;
    let mut refresh_stale_empty_container = false;

    if manifest_path.is_file() && !force {
        let manifest = match load_manifest(&project_dir) {
            Ok(manifest) => manifest,
            Err(error) => return fail_extract_with_error(&db, &mut project, error),
        };
        let manifest_tree_valid = extraction_manifest_is_reusable(&manifest, &extraction_root);
        if project.status != ProjectStatus::Extracted || !manifest_tree_valid {
            let probe_spinner = if panel_mode {
                crate::style::PipelineProgress::start(format!("probing image · {}", project.name))
            } else {
                crate::style::PipelineProgress::none()
            };
            container_probe = match known_container::probe_known_container_file(&firmware_path) {
                Ok(probe) => Some(probe),
                Err(error) => return fail_extract_with_error(&db, &mut project, error),
            };
            drop(probe_spinner);
            refresh_stale_empty_container = true;
            // The project line belongs to the final summary alone, so a refresh
            // run reports the status once instead of duplicating the header.
            let status_message = if let (0, Some(container)) = (
                manifest.file_count,
                container_probe.as_ref().and_then(|probe| probe.container),
            ) {
                format!(
                    "stale empty {} extraction detected; refreshing",
                    container.short_name()
                )
            } else {
                "stale or incomplete extraction detected; refreshing".to_string()
            };
            if panel_mode {
                refresh_note = Some(status_message);
            } else {
                format.note(format!("status: {status_message}"));
            }
        } else {
            if format.is_json() {
                return print_json(&extract_json(
                    &project,
                    "already-extracted",
                    &manifest,
                    &project_dir,
                    &extraction_root,
                    Some(&manifest_path),
                ));
            }
            if panel_mode {
                let lines = extract_panel_lines(
                    &palette,
                    &manifest,
                    &project_dir,
                    &extraction_root,
                    Some(&manifest_path),
                    None,
                    &[],
                    Some("already extracted"),
                    None,
                    &[],
                    Some("use --force to re-run extraction and overwrite existing artifacts"),
                );
                println!(
                    "{}",
                    palette.panel(&format!("fat extract · {}", project.name), &lines)
                );
                println!("{}", palette.next_hint("fat analyze <project>"));
                return Ok(());
            }
            println!("project: {}", project.name);
            println!("status: already extracted");
            if let Some(container) =
                known_container::detect_cached_container(&project_dir, &extraction_root)
            {
                let decryption_log = container.decryption_log(&project_dir);
                println!("container: {}", container.display_name());
                println!("decryption: already completed (cached)");
                println!("decryption_log: {}", decryption_log.display());
            }
            println!("manifest: {}", manifest_path.display());
            println!("extractions: {}", extraction_root.display());
            print_engine_provenance(&manifest);
            print_extraction_artifacts(&manifest, &project_dir);
            println!("use --force to re-run extraction and overwrite existing artifacts");
            return Ok(());
        }
    }

    let fresh_probe_spinner = if panel_mode && container_probe.is_none() {
        Some(crate::style::PipelineProgress::start(format!(
            "probing image · {}",
            project.name
        )))
    } else {
        None
    };
    let container_probe = match container_probe {
        Some(probe) => probe,
        None => match known_container::probe_known_container_file(&firmware_path) {
            Ok(probe) => probe,
            Err(error) => return fail_extract_with_error(&db, &mut project, error),
        },
    };
    drop(fresh_probe_spinner);
    let known_container = container_probe.container;
    let image_entropy = container_probe.envelope.entropy;
    if force || refresh_stale_empty_container {
        let cleanup = (|| -> DynResult<()> {
            remove_existing_path_if_present(&extraction_root)?;
            remove_existing_path_if_present(&project_dir.join("extracted"))?;
            remove_existing_path_if_present(&manifest_path)?;
            Ok(())
        })();
        if let Err(error) = cleanup {
            return fail_extract_with_error(&db, &mut project, error);
        }
    }

    project.status = ProjectStatus::Extracting;
    db.save(&project)?;

    // Declared outside the closure so the summary panel can read the engine
    // durations after extraction completes.
    let mut engine_outcomes: Vec<ExtractionOutcome> = Vec::new();
    let extraction_result = (|| -> DynResult<ExtractionManifest> {
        // Which engine produced the result — and why the others did not run — is
        // the first diagnostic question when a rootfs looks wrong, so record the
        // decisions as they are made instead of leaving them in work/*.log.
        let mut engine_reports: Vec<EngineReport> = Vec::new();
        let mut progress = ExtractionProgress::new(format, panel_mode, &project.name);

        // Actionable container handlers run before native and generic extraction.
        let extracted_container = if let Some(container) = known_container {
            known_container::extract_container(
                container,
                &firmware_path,
                &extraction_root,
                &project_dir,
                &|line: String| progress.note(&line),
            )?;

            engine_reports.push(
                EngineReport::new(container_engine_id(container), EngineStatus::Succeeded)
                    .with_detail(format!("unpacked {}", container.display_name())),
            );
            true
        } else {
            false
        };
        if extracted_container {
            // Every engine the container handler preempted still gets a report.
            for extractor in extractor_registry().iter() {
                engine_reports.push(
                    EngineReport::new(extractor.id(), EngineStatus::Skipped)
                        .with_detail("container handler already unpacked the image"),
                );
            }
        } else {
            let registry = tuned_extractor_registry(extractor_options);
            let context = StrategyContext {
                firmware: firmware_path.clone(),
                extraction_root: extraction_root.clone(),
                log_root: project_dir.join("work"),
                timeout: extract_timeout,
            };
            let outcomes = run_extraction_strategy(
                &registry,
                &extractor_selection,
                &context,
                &mut |extractor, elapsed| progress.tick(extractor, elapsed),
            );
            engine_outcomes = outcomes.clone();
            progress.finish_with("extraction complete");
            if !panel_mode {
                print_engine_durations(&outcomes, format);
            }

            // A tool that was attempted and never succeeded is the actionable
            // failure: without one, nothing downstream has anything to read.
            let attempted_tools: Vec<&ExtractionOutcome> = outcomes
                .iter()
                .filter(|outcome| outcome.requires_external_tool && outcome.status.attempted())
                .collect();
            let tool_succeeded = attempted_tools
                .iter()
                .any(|outcome| outcome.status.succeeded());
            let timed_out: Vec<&str> = outcomes
                .iter()
                .filter(|outcome| outcome.status == ExtractStatus::TimedOut)
                .map(|outcome| outcome.extractor.as_str())
                .collect();

            engine_reports.extend(outcomes.iter().map(engine_report_for));

            if !attempted_tools.is_empty() && !tool_succeeded {
                let native_dir = extraction_root.join("native");
                if file_count(&native_dir) == 0 {
                    remove_existing_path_if_present(&extraction_root)?;
                }
                project.status = ProjectStatus::Error;
                db.save(&project)?;
                let timeout_note = if timed_out.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} hit the extraction timeout (raise it with --extract-timeout <secs>)",
                        timed_out.join(" and ")
                    )
                };
                return Err(format!(
                "firmware extraction failed: neither binwalk nor unblob completed successfully{timeout_note}; inspect {} and {}, install the missing tools, run `fat doctor`, then retry `fat extract --force {}`",
                project_dir.join("work/binwalk.log").display(),
                project_dir.join("work/unblob.log").display(),
                project_dir.display(),
            )
            .into());
            }
        }
        let recover_spinner = if panel_mode {
            crate::style::PipelineProgress::start("recovering rootfs")
        } else {
            crate::style::PipelineProgress::none()
        };
        let mut manifest = recover_rootfs_if_needed(
            build_extraction_manifest(&extraction_root)?,
            &extraction_root,
            &firmware_path,
            &project_dir.join("work").join("rootfs-fallback.log"),
        )?;
        drop(recover_spinner);
        manifest.engine = attribute_engine(&manifest, &extraction_root, &engine_reports);
        if let Some(engine) = manifest.engine.clone() {
            // Reproducing a run should not depend on the version installed
            // today, so pin what actually produced this tree.
            // Probe inside the project's own work directory: a `--version` run
            // that misbehaves must not scatter files across the directory the
            // user invoked fat from.
            manifest.engine_version = engine_version(&engine, &project_dir.join("work"));
            manifest.engine_args = engine_outcomes
                .iter()
                .find(|outcome| outcome.extractor == engine)
                .map(|outcome| outcome.args.clone())
                .unwrap_or_default();
        }
        manifest.engine_reports = engine_reports;
        if manifest.file_count == 0 {
            let mut message =
                "firmware extraction produced no recoverable files; refusing an empty success state"
                    .to_string();
            if container_probe.envelope.is_encrypted_like() {
                message.push_str(&format!(
                    "; envelope classification: {}; ecb_assessment: {}",
                    container_probe.envelope.classification,
                    container_probe.envelope.ecb_assessment
                ));
                if let Some(header_len) = container_probe.envelope.likely_plaintext_header_len {
                    message.push_str(&format!("; likely_plaintext_header_len: 0x{header_len:X}"));
                }
            }
            return Err(message.into());
        }
        sync_extracted_rootfs_view(&project_dir, manifest.rootfs_path.as_deref())?;
        fs::write(
            extraction_manifest_path(&project_dir),
            serde_json::to_vec_pretty(&manifest)?,
        )?;

        let store = RuntimeStore::open(&project_dir)?;
        let target = ensure_target_record(&store, &project)?;
        record_target_artifact(
            &store,
            &project,
            ArtifactKind::Extraction,
            "extraction-manifest",
            &extraction_manifest_path(&project_dir),
            "fat extract manifest",
            "application/json",
            "extract target evidence",
        )?;
        fat_plugin_host::dispatch_target_analysis(
            &project_dir,
            &target.target_id,
            fat_plugin_api::AnalysisTrigger::ExtractionCompleted,
            None,
        )?;

        Ok(manifest)
    })();

    let manifest = match extraction_result {
        Ok(manifest) => manifest,
        Err(error) => {
            let mut cleanup_errors = Vec::new();
            let extracted_view = project_dir.join("extracted");
            let preserve_native_evidence = file_count(&extraction_root.join("native")) > 0;
            for path in [&extraction_root, &extracted_view, &manifest_path] {
                if path == &extraction_root && preserve_native_evidence {
                    continue;
                }
                if let Err(cleanup_error) = remove_existing_path_if_present(path) {
                    cleanup_errors.push(format!("{}: {cleanup_error}", path.display()));
                }
            }
            project.status = ProjectStatus::Error;
            if let Err(save_error) = db.save(&project) {
                return Err(format!(
                    "{error}; additionally failed to persist the Error state: {save_error}"
                )
                .into());
            }
            if cleanup_errors.is_empty() {
                return Err(error);
            }
            return Err(format!(
                "{error}; additionally failed to clean stale extraction state: {}",
                cleanup_errors.join("; ")
            )
            .into());
        }
    };

    project.status = ProjectStatus::Extracted;
    db.save(&project)?;

    if format.is_json() {
        return print_json(&extract_json(
            &project,
            "extracted",
            &manifest,
            &project_dir,
            &extraction_root,
            Some(&manifest_path),
        ));
    }

    if panel_mode {
        let engine_durations: Vec<(String, Duration)> = engine_outcomes
            .iter()
            .filter(|outcome| outcome.duration >= HEARTBEAT_TTY_INTERVAL)
            .map(|outcome| (outcome.extractor.clone(), outcome.duration))
            .collect();
        let image = fs::metadata(&firmware_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        let lines = extract_panel_lines(
            &palette,
            &manifest,
            &project_dir,
            &extraction_root,
            Some(&manifest_path),
            Some((project.firmware_name.clone(), image, Some(image_entropy))),
            &setup_rows,
            None,
            refresh_note.as_deref(),
            &engine_durations,
            None,
        );
        println!(
            "{}",
            palette.panel(&format!("fat extract · {}", project.name), &lines)
        );
        println!("{}", palette.next_hint("fat analyze <project>"));
        return Ok(());
    }

    println!("project: {}", project.name);
    println!("extractions: {}", extraction_root.display());
    print_engine_provenance(&manifest);
    print_extraction_artifacts(&manifest, &project_dir);

    Ok(())
}

/// The machine-readable form of an extraction result. Field names mirror the
/// manifest so the two can be read together.
fn extract_json(
    project: &Project,
    status: &str,
    manifest: &ExtractionManifest,
    project_dir: &Path,
    extraction_root: &Path,
    manifest_path: Option<&Path>,
) -> serde_json::Value {
    let rootfs = manifest.rootfs_path.as_deref().map(|rootfs| {
        serde_json::json!({
            "path": rootfs.display().to_string(),
            "relative_path": display_relative(rootfs, project_dir),
            "size_bytes": tree_size_bytes(rootfs),
            "filesystem": rootfs_filesystem_kind(rootfs),
            "top_level": top_level_entries(rootfs),
        })
    });
    let kernel_paths: Vec<serde_json::Value> = manifest
        .kernel_paths
        .iter()
        .map(|kernel| {
            serde_json::json!({
                "path": kernel.display().to_string(),
                "relative_path": display_relative(kernel, project_dir),
                "size_bytes": fs::metadata(kernel).map(|meta| meta.len()).ok(),
            })
        })
        .collect();
    let engines: Vec<serde_json::Value> = manifest
        .engine_reports
        .iter()
        .map(|report| {
            serde_json::json!({
                "engine": report.engine,
                "status": report.status.label(),
                "detail": report.detail,
            })
        })
        .collect();

    json_envelope(
        "fat.extract.v1",
        serde_json::json!({
            "project": project.name,
            "status": status,
            "project_dir": project_dir.display().to_string(),
            "extractions": extraction_root.display().to_string(),
            "manifest": manifest_path.map(|path| path.display().to_string()),
            "engine": manifest.engine,
            "engine_version": manifest.engine_version,
            "engine_args": manifest.engine_args,
            "engines": engines,
            "rootfs": rootfs,
            "kernel_paths": kernel_paths,
            "file_count": manifest.file_count,
        }),
    )
}

/// The extraction chain, in priority order: FAT's own region carving first,
/// then the external tools.
fn extractor_registry() -> ExtractorRegistry {
    tuned_extractor_registry(ExternalExtractorOptions::default())
}

fn tuned_extractor_registry(options: ExternalExtractorOptions) -> ExtractorRegistry {
    let mut registry = ExtractorRegistry::new();
    registry.register(NativeExtractor);
    registry.register(ExternalExtractor::binwalk().with_options(options));
    registry.register(ExternalExtractor::unblob().with_options(options));
    registry
}

/// Ask an engine what it is, so the manifest can pin the version that produced
/// the tree. A failed probe records nothing rather than guessing.
fn engine_version(engine: &str, working_dir: &Path) -> Option<String> {
    let program = find_program_on_path(engine)?;
    doctor_cmd::program_version_in(&program, Some(working_dir)).ok()
}

fn find_program_on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// FAT's built-in region carving, exposed through the same trait as the
/// external tools so the strategy treats them uniformly.
struct NativeExtractor;

impl Extractor for NativeExtractor {
    fn id(&self) -> &str {
        "native"
    }

    fn available(&self) -> bool {
        true
    }

    fn requires_external_tool(&self) -> bool {
        false
    }

    fn log_path(&self, log_root: &Path) -> PathBuf {
        log_root.join("native-extract.log")
    }

    /// Carved boot evidence is worth keeping but is not a rootfs, so it must
    /// not stop binwalk and unblob from trying.
    fn sufficiency(&self) -> Sufficiency {
        Sufficiency::RootfsOnly
    }

    fn precedence_reason(&self, _evidence: &CarvedEvidence) -> Option<String> {
        Some("native extraction recovered a rootfs".to_string())
    }

    fn extract(
        &self,
        request: &ExtractionRequest,
        _on_tick: &mut dyn FnMut(Duration),
    ) -> ExtractionOutcome {
        let started = Instant::now();
        let outcome = try_extract_native_regions(
            &request.firmware,
            request
                .work_dir
                .parent()
                .unwrap_or(&request.work_dir)
                .to_path_buf()
                .as_path(),
            &request.log_path,
        );
        let duration = started.elapsed();

        match outcome {
            Ok(NativeExtractionOutcome::RootfsRecovered) => {
                ExtractionOutcome::new(self.id(), ExtractStatus::Succeeded)
                    .with_detail("recovered a rootfs")
                    .with_evidence(CarvedEvidence::survey(&request.work_dir))
                    .with_duration(duration)
            }
            Ok(NativeExtractionOutcome::EvidenceOnly) => {
                ExtractionOutcome::new(self.id(), ExtractStatus::Succeeded)
                    .with_detail("carved boot evidence without a rootfs")
                    .with_evidence(CarvedEvidence::survey(&request.work_dir))
                    .with_duration(duration)
            }
            Ok(NativeExtractionOutcome::NoSupportedRegion) => {
                ExtractionOutcome::new(self.id(), ExtractStatus::Skipped)
                    .with_detail("no supported regions in the image")
                    .with_duration(duration)
            }
            Err(err) => ExtractionOutcome::new(self.id(), ExtractStatus::Failed)
                .with_detail(err.to_string())
                .with_duration(duration),
        }
    }
}

/// Default deadline for a single extractor invocation. Generous, because a
/// legitimate `binwalk -e` over a large image can run for many minutes; the
/// point is to bound the documented hangs both tools exhibit on the malformed
/// images this toolkit targets, not to cut real work short.
const DEFAULT_EXTRACT_TIMEOUT_SECS: u64 = 1800;
const EXTRACT_TIMEOUT_ENV: &str = "FAT_EXTRACT_TIMEOUT";

/// Resolve the extractor deadline: explicit flag, then `FAT_EXTRACT_TIMEOUT`,
/// then the default. `0` disables the deadline entirely.
fn resolve_extract_timeout(flag: Option<u64>) -> DynResult<Option<Duration>> {
    let seconds = match flag {
        Some(seconds) => seconds,
        None => match std::env::var(EXTRACT_TIMEOUT_ENV) {
            Ok(raw) => raw.trim().parse::<u64>().map_err(|_| {
                format!("{EXTRACT_TIMEOUT_ENV} must be a whole number of seconds, got {raw:?}")
            })?,
            Err(_) => DEFAULT_EXTRACT_TIMEOUT_SECS,
        },
    };
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

/// Resolve `--extractor` against the registered extraction chain.
fn resolve_extractor_selection(flag: Option<&str>) -> DynResult<ExtractorSelection> {
    match flag {
        None => Ok(ExtractorSelection::Auto),
        Some(value) => {
            ExtractorSelection::parse(value, &extractor_registry().ids()).map_err(Into::into)
        }
    }
}

const HEARTBEAT_TTY_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_PLAIN_INTERVAL: Duration = Duration::from_secs(30);

/// A first report is due once the interval has passed, and each later one an
/// interval after the last, so a quick run stays silent and a long one reports
/// at a steady cadence.
fn heartbeat_is_due(elapsed: Duration, last_report: Option<Duration>, interval: Duration) -> bool {
    match last_report {
        Some(last) => elapsed >= last + interval,
        None => elapsed >= interval,
    }
}

/// Elapsed-time reporting for a running extractor, so a multi-minute `binwalk
/// -e` does not look like a hang. A TTY run animates a stderr spinner; anything
/// else (CI, batch pipelines) gets a sparse line so logs stay readable.
struct ExtractionProgress {
    spinner: crate::style::PipelineProgress,
    format: OutputFormat,
    active: Option<(String, Duration)>,
    reported_any: bool,
}

impl ExtractionProgress {
    /// `interactive` drives the spinner; stdout belongs to the JSON payload
    /// when one is being emitted, so JSON runs never spin.
    fn new(format: OutputFormat, panel_mode: bool, project_name: &str) -> Self {
        Self {
            spinner: if panel_mode {
                crate::style::PipelineProgress::start(format!("extracting · {project_name}"))
            } else {
                crate::style::PipelineProgress::none()
            },
            format,
            active: None,
            reported_any: false,
        }
    }
}

impl ExtractionProgress {
    fn interval(&self) -> Duration {
        if self.spinner.pb().is_some() {
            HEARTBEAT_TTY_INTERVAL
        } else {
            HEARTBEAT_PLAIN_INTERVAL
        }
    }

    fn tick(&mut self, extractor: &str, elapsed: Duration) {
        let last = match &self.active {
            Some((id, last)) if id == extractor => Some(*last),
            _ => None,
        };
        if !heartbeat_is_due(elapsed, last, self.interval()) {
            return;
        }
        self.active = Some((extractor.to_string(), elapsed));
        self.reported_any = true;

        if self.spinner.pb().is_some() {
            self.spinner
                .set_message(format!("{extractor} · {}s", elapsed.as_secs()));
        } else {
            self.format
                .note(format!("{extractor}: running ({}s)", elapsed.as_secs()));
        }
    }

    /// A mid-stream progress line that is not tied to the engine cadence: on a
    /// TTY it rides the spinner, anywhere else it is a note like before.
    fn note(&self, line: &str) {
        if self.spinner.pb().is_some() {
            self.spinner.set_message(line.to_string());
        } else {
            self.format.note(line);
        }
    }

    /// Close the progress display with a final status line.
    fn finish_with(&mut self, status: &str) {
        self.spinner.finish_with(status.to_string());
    }
}

/// Report how long anything slow enough to notice actually took.
fn print_engine_durations(outcomes: &[ExtractionOutcome], format: OutputFormat) {
    for outcome in outcomes {
        if outcome.duration < HEARTBEAT_TTY_INTERVAL {
            continue;
        }
        let label = match outcome.status {
            ExtractStatus::Succeeded => "completed",
            ExtractStatus::Failed => "failed",
            ExtractStatus::TimedOut => "timed out",
            ExtractStatus::Skipped => continue,
        };
        format.note(format!(
            "{}: {label} after {:.1}s",
            outcome.extractor,
            outcome.duration.as_secs_f64()
        ));
    }
}

fn engine_report_for(outcome: &ExtractionOutcome) -> EngineReport {
    let log_hint = format!("work/{}.log", outcome.extractor);
    match outcome.status {
        ExtractStatus::Succeeded => {
            let report = EngineReport::new(&outcome.extractor, EngineStatus::Succeeded);
            match &outcome.detail {
                Some(detail) => report.with_detail(detail),
                None => report,
            }
        }
        ExtractStatus::Skipped => {
            let report = EngineReport::new(&outcome.extractor, EngineStatus::Skipped);
            match &outcome.detail {
                Some(detail) => report.with_detail(detail),
                None => report,
            }
        }
        ExtractStatus::TimedOut => EngineReport::new(&outcome.extractor, EngineStatus::Failed)
            .with_detail(format!("timed out; see {log_hint}")),
        ExtractStatus::Failed => EngineReport::new(&outcome.extractor, EngineStatus::Failed)
            .with_detail(match &outcome.detail {
                Some(detail) => format!("{detail}; see {log_hint}"),
                None => format!("see {log_hint}"),
            }),
    }
}

/// How a command reports its result. JSON output is a single object on stdout
/// with nothing else mixed in, so a pipeline can parse it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    fn from_flag(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Text
        }
    }

    fn is_json(self) -> bool {
        self == Self::Json
    }

    fn is_text(self) -> bool {
        self == Self::Text
    }

    /// Human progress belongs on stderr whenever stdout is carrying JSON.
    fn note(self, line: impl std::fmt::Display) {
        if self.is_json() {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

/// The schema tag every JSON payload carries, so a consumer can detect a change.
fn json_envelope(schema: &str, body: serde_json::Value) -> serde_json::Value {
    let mut envelope = serde_json::json!({ "schema": schema });
    if let (Some(envelope_map), serde_json::Value::Object(body)) = (envelope.as_object_mut(), body)
    {
        envelope_map.extend(body);
    }
    envelope
}

fn print_json(value: &serde_json::Value) -> DynResult<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Longest list a summary prints before collapsing the tail into a count.
const SUMMARY_LIST_CAP: usize = 10;

/// Report the recovered artifacts with enough substance to judge them — what the
/// rootfs is and how large, where each kernel landed, and what the tree looks
/// like at its top level — instead of bare counts that need a follow-up `ls`.
fn print_extraction_artifacts(manifest: &ExtractionManifest, project_dir: &Path) {
    match manifest.rootfs_path.as_deref() {
        Some(rootfs) => println!("rootfs: {}", describe_tree(rootfs, project_dir)),
        None => println!("rootfs: not found"),
    }

    println!("kernel_paths: {}", manifest.kernel_paths.len());
    for line in capped_list(
        manifest
            .kernel_paths
            .iter()
            .map(|kernel| describe_file(kernel, project_dir)),
    ) {
        println!("  {line}");
    }

    println!("files: {}", manifest.file_count);

    if let Some(rootfs) = manifest.rootfs_path.as_deref() {
        let entries = top_level_entries(rootfs);
        if !entries.is_empty() {
            println!("top-level: {}", entries.join(" "));
        }
    }
}

/// Panel-mode summary of an extraction: the image, what every engine did, and
/// the recovered artifacts. Mirrors the plain-mode facts 1:1 — only the layout
/// and the glyphs differ.
#[allow(clippy::too_many_arguments)]
fn extract_panel_lines(
    palette: &crate::style::Palette,
    manifest: &ExtractionManifest,
    project_dir: &Path,
    extraction_root: &Path,
    manifest_path: Option<&Path>,
    image: Option<(String, u64, Option<f64>)>,
    header_rows: &[(String, String)],
    status_row: Option<&str>,
    refresh_note: Option<&str>,
    engine_durations: &[(String, Duration)],
    force_note: Option<&str>,
) -> Vec<String> {
    let duration_note = |engine: &str| -> String {
        engine_durations
            .iter()
            .find(|(id, _)| id == engine)
            .map(|(_, duration)| format!("({:.1}s)", duration.as_secs_f64()))
            .unwrap_or_default()
    };

    let mut lines: Vec<String> = Vec::new();
    if let Some((name, size, entropy)) = image {
        let mut image_line = format!(
            "{} {} · {}",
            palette.dot_ok(),
            palette.good(name),
            format_size(size)
        );
        if let Some(entropy) = entropy {
            image_line.push_str(&format!(" · entropy {entropy:.2}/8.0"));
        }
        lines.push(image_line);
    }
    for (key, value) in header_rows {
        lines.push(palette.kv(key, value));
    }
    if let Some(status) = status_row {
        lines.push(format!("{} {}", palette.dot_ok(), palette.good(status)));
    }
    if let Some(note) = refresh_note {
        lines.push(format!("{} {}", palette.dot_warn(), palette.muted(note)));
    }

    if !manifest.engine_reports.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Engines"));
        for report in &manifest.engine_reports {
            let mut detail_parts: Vec<String> = Vec::new();
            if let Some(detail) = &report.detail {
                detail_parts.push(detail.clone());
            }
            let duration = duration_note(&report.engine);
            if !duration.is_empty() {
                detail_parts.push(duration);
            }
            let detail = if detail_parts.is_empty() {
                String::new()
            } else {
                format!(
                    "  {}",
                    palette.muted(format!("— {}", detail_parts.join(", ")))
                )
            };
            match report.status {
                EngineStatus::Succeeded => lines.push(format!(
                    "{} {}{}",
                    palette.dot_ok(),
                    palette.good(&report.engine),
                    detail
                )),
                EngineStatus::Skipped => lines.push(format!(
                    "{} {}{}",
                    palette.dot_muted(),
                    palette.muted(&report.engine),
                    detail
                )),
                EngineStatus::Failed => lines.push(format!(
                    "{} {}{}",
                    palette.dot_bad(),
                    palette.bad(&report.engine),
                    detail
                )),
            }
        }
        lines.push(String::new());
    }

    match manifest.rootfs_path.as_deref() {
        Some(rootfs) => lines.push(format!(
            "{} rootfs: {}",
            palette.dot_ok(),
            describe_tree(rootfs, project_dir)
        )),
        None => lines.push(format!("{} rootfs: not found", palette.dot_bad())),
    }
    lines.push(palette.kv("files", manifest.file_count.to_string()));
    if !manifest.kernel_paths.is_empty() {
        lines.push(palette.kv("kernels", manifest.kernel_paths.len().to_string()));
        for kernel in capped_list(
            manifest
                .kernel_paths
                .iter()
                .map(|kernel| describe_file(kernel, project_dir)),
        ) {
            lines.push(format!("  {} {}", palette.muted("-"), kernel));
        }
    }
    if let Some(rootfs) = manifest.rootfs_path.as_deref() {
        let entries = top_level_entries(rootfs);
        if !entries.is_empty() {
            lines.push(palette.kv("top-level", entries.join(" ")));
        }
    }
    lines.push(palette.kv("extractions", extraction_root.display().to_string()));
    if let Some(manifest_path) = manifest_path {
        lines.push(palette.kv("manifest", manifest_path.display().to_string()));
    }
    if let Some(note) = force_note {
        lines.push(palette.muted(note));
    }
    lines
}

/// `- entry` lines, with everything past the cap collapsed into a count so a
/// 400-binary rootfs does not bury the rest of the summary.
fn capped_list<I>(entries: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let entries: Vec<String> = entries.into_iter().collect();
    let shown = entries.len().min(SUMMARY_LIST_CAP);
    let mut lines: Vec<String> = entries[..shown]
        .iter()
        .map(|entry| format!("- {entry}"))
        .collect();
    if entries.len() > shown {
        lines.push(format!("... and {} more", entries.len() - shown));
    }
    lines
}

fn describe_tree(path: &Path, project_dir: &Path) -> String {
    let size = format_size(tree_size_bytes(path));
    match rootfs_filesystem_kind(path) {
        Some(kind) => format!("{} ({size}, {kind})", display_relative(path, project_dir)),
        None => format!("{} ({size})", display_relative(path, project_dir)),
    }
}

fn describe_file(path: &Path, project_dir: &Path) -> String {
    match fs::metadata(path).map(|metadata| metadata.len()) {
        Ok(size) => format!(
            "{} ({})",
            display_relative(path, project_dir),
            format_size(size)
        ),
        Err(_) => display_relative(path, project_dir),
    }
}

fn describe_binary(binary: &BinaryRecord, project_dir: &Path) -> String {
    let path = Path::new(&binary.rel_path);
    let architecture = architecture_label(binary.architecture);
    match fs::metadata(path).map(|metadata| metadata.len()) {
        Ok(size) => format!(
            "{} ({architecture}, {})",
            display_relative(path, project_dir),
            format_size(size)
        ),
        Err(_) => format!("{} ({architecture})", display_relative(path, project_dir)),
    }
}

/// Paths inside the project print relative to it; anything else prints in full.
fn display_relative(path: &Path, project_dir: &Path) -> String {
    path.strip_prefix(project_dir)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Stable, skimmable sizes. Binary units, conventional labels.
pub(crate) fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    match bytes {
        bytes if bytes >= GB => format!("{:.1} GB", bytes as f64 / GB as f64),
        bytes if bytes >= MB => format!("{:.1} MB", bytes as f64 / MB as f64),
        bytes if bytes >= KB => format!("{:.1} KB", bytes as f64 / KB as f64),
        bytes => format!("{bytes} B"),
    }
}

fn tree_size_bytes(root: &Path) -> u64 {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .sum()
}

/// Name the filesystem only when the extractor's own directory naming says what
/// it was. Nothing here inspects content, so an unnamed tree reports no kind
/// rather than a guess.
fn rootfs_filesystem_kind(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    [
        ("squashfs", "squashfs"),
        ("cramfs", "cramfs"),
        ("jffs2", "jffs2"),
        ("ubifs", "ubifs"),
        ("yaffs", "yaffs"),
        ("debugfs-root", "ext"),
    ]
    .into_iter()
    .find_map(|(marker, kind)| name.contains(marker).then_some(kind))
}

fn top_level_entries(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let total = names.len();
    if total > SUMMARY_LIST_CAP {
        names.truncate(SUMMARY_LIST_CAP);
        names.push(format!("(+{} more)", total - SUMMARY_LIST_CAP));
    }
    names
}

fn architecture_label(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::Armel => "armel",
        Architecture::Arm => "arm",
        Architecture::Arm64 => "arm64",
        Architecture::Mips => "mips",
        Architecture::Mipsel => "mipsel",
        Architecture::Riscv64 => "riscv64",
        Architecture::X86 => "x86",
        Architecture::X86_64 => "x86_64",
        Architecture::Unknown => "unknown",
    }
}

/// Report which engine produced the manifest and what every other engine did.
/// Manifests written before provenance was recorded simply print nothing.
fn print_engine_provenance(manifest: &ExtractionManifest) {
    if let Some(engine) = &manifest.engine {
        println!("engine: {engine}");
    }
    if manifest.engine_reports.is_empty() {
        return;
    }
    println!("engines:");
    for report in &manifest.engine_reports {
        println!("  - {}", report.summary_line());
    }
}

fn container_engine_id(container: known_container::KnownContainer) -> String {
    format!("container:{}", container.short_name().to_ascii_lowercase())
}

/// Attribute the manifest to the engine whose output tree it was built from.
/// The recovered evidence decides: a rootfs (or, failing that, a carved kernel)
/// lives under exactly one engine's directory. Only when there is no such
/// evidence does this fall back to whichever engine reported success.
fn attribute_engine(
    manifest: &ExtractionManifest,
    extraction_root: &Path,
    reports: &[EngineReport],
) -> Option<String> {
    let evidence = manifest
        .rootfs_path
        .as_deref()
        .or_else(|| manifest.kernel_paths.first().map(PathBuf::as_path));
    evidence
        .and_then(|path| engine_for_extraction_path(extraction_root, path, reports))
        .or_else(|| {
            reports
                .iter()
                .find(|report| report.status == EngineStatus::Succeeded)
                .map(|report| report.engine.clone())
        })
}

fn engine_for_extraction_path(
    extraction_root: &Path,
    path: &Path,
    reports: &[EngineReport],
) -> Option<String> {
    let subtree = path
        .strip_prefix(extraction_root)
        .ok()?
        .components()
        .next()?
        .as_os_str()
        .to_str()?;
    match subtree {
        "native" | "binwalk" | "unblob" => Some(subtree.to_string()),
        // Recovered by FAT's own fallback from an image no engine could unpack.
        "debugfs-root" => Some("debugfs-fallback".to_string()),
        // Container handlers own their own subtree names.
        _ => reports
            .iter()
            .map(|report| report.engine.clone())
            .find(|engine| engine.starts_with("container:")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeExtractionOutcome {
    RootfsRecovered,
    EvidenceOnly,
    NoSupportedRegion,
}

fn try_extract_native_regions(
    firmware_path: &Path,
    extraction_root: &Path,
    log_path: &Path,
) -> DynResult<NativeExtractionOutcome> {
    let bytes = fs::read(firmware_path)?;
    let scan = scan_firmware_formats(&bytes);
    let native_root = extraction_root.join("native");
    let mut log = String::new();
    let mut recovered_rootfs = false;
    let mut recovered_evidence = false;

    for (index, header) in scan
        .filesystem_headers
        .iter()
        .filter(|header| header.format == "cramfs")
        .enumerate()
    {
        let Some(image_size) = header.image_size else {
            continue;
        };
        let Some(start) = usize::try_from(header.offset).ok() else {
            log.push_str("skipped CramFS region whose offset does not fit this platform\n");
            continue;
        };
        let Some(end_u64) = header.offset.checked_add(image_size) else {
            log.push_str("skipped CramFS region whose span overflows\n");
            continue;
        };
        let Some(end) = usize::try_from(end_u64).ok() else {
            log.push_str("skipped CramFS region whose end does not fit this platform\n");
            continue;
        };
        let Some(image) = bytes.get(start..end) else {
            log.push_str("skipped CramFS region whose declared span exceeds the firmware\n");
            continue;
        };
        let directory_name = if index == 0 {
            "cramfs-root".to_string()
        } else {
            format!("cramfs-root-{}", index + 1)
        };
        let destination = native_root.join(directory_name);
        match extract_cramfs(
            image,
            &destination,
            CramfsLimits {
                max_inodes: 262_144,
                max_depth: 128,
                max_file_size: 16 * 1024 * 1024,
                max_total_output: 512 * 1024 * 1024,
            },
        ) {
            Ok(result) => {
                recovered_rootfs = true;
                recovered_evidence = true;
                writeln!(
                    log,
                    "extracted CramFS @ 0x{:08X} to {} ({} files, {} directories, {} symlinks, {} special entries skipped)",
                    header.offset,
                    result.root.display(),
                    result.files,
                    result.directories,
                    result.symlinks,
                    result.skipped_special,
                )?;
            }
            Err(error) => {
                writeln!(
                    log,
                    "native CramFS extraction failed @ 0x{:08X}: {error}",
                    header.offset
                )?;
            }
        }
    }

    for (index, member) in scan
        .compression_members
        .iter()
        .filter(|member| member.format == "gzip")
        .filter(|member| {
            !scan.filesystem_headers.iter().any(|header| {
                header.image_size.is_some_and(|size| {
                    member.offset > header.offset
                        && member.offset < header.offset.saturating_add(size)
                })
            })
        })
        .enumerate()
    {
        let Some(compressed_size) = member.compressed_size else {
            continue;
        };
        let Some(start) = usize::try_from(member.offset).ok() else {
            log.push_str("skipped gzip member whose offset does not fit this platform\n");
            continue;
        };
        let Some(end_u64) = member.offset.checked_add(compressed_size) else {
            log.push_str("skipped gzip member whose span overflows\n");
            continue;
        };
        let Some(end) = usize::try_from(end_u64).ok() else {
            log.push_str("skipped gzip member whose end does not fit this platform\n");
            continue;
        };
        let Some(member_bytes) = bytes.get(start..end) else {
            log.push_str("skipped gzip member whose span exceeds the firmware\n");
            continue;
        };
        let directory_name = if index == 0 {
            "kernel".to_string()
        } else {
            format!("kernel-{}", index + 1)
        };
        let destination = native_root.join(directory_name);
        match extract_gzip_member(
            member_bytes,
            &destination,
            GzipExtractionOptions {
                original_name: member.original_name.clone(),
                max_output: 128 * 1024 * 1024,
            },
        ) {
            Ok(result) => {
                recovered_evidence = true;
                writeln!(
                    log,
                    "extracted gzip @ 0x{:08X} to {} ({} bytes)",
                    member.offset,
                    result.decompressed_path.display(),
                    result.decompressed_size
                )?;
            }
            Err(error) => {
                writeln!(
                    log,
                    "native gzip extraction failed @ 0x{:08X}: {error}",
                    member.offset
                )?;
            }
        }
    }

    if !recovered_evidence {
        remove_existing_path_if_present(&native_root)?;
        log.push_str("no supported native region was materialized\n");
    }
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(log_path, log)?;

    Ok(if recovered_rootfs {
        NativeExtractionOutcome::RootfsRecovered
    } else if recovered_evidence {
        NativeExtractionOutcome::EvidenceOnly
    } else {
        NativeExtractionOutcome::NoSupportedRegion
    })
}

fn fail_extract_with_error<T>(
    db: &ProjectDb,
    project: &mut Project,
    error: Box<dyn Error>,
) -> DynResult<T> {
    project.status = ProjectStatus::Error;
    if let Err(save_error) = db.save(project) {
        return Err(format!(
            "{error}; additionally failed to persist the Error state: {save_error}"
        )
        .into());
    }
    Err(error)
}

fn cmd_analyze(project_dir: &Path, format: OutputFormat) -> DynResult<()> {
    let palette = crate::style::Palette::stdout();
    let panel_mode = format.is_text() && palette.enabled();
    let project_dir = normalize_project_dir(project_dir)?;
    let db = ProjectDb::open(&project_dir)?;
    let mut project = load_project(&db, &project_dir)?;
    let spinner = if panel_mode {
        crate::style::PipelineProgress::start(format!("analyzing · {}", project.name))
    } else {
        crate::style::PipelineProgress::none()
    };
    project.status = ProjectStatus::Analyzing;
    db.save(&project)?;

    let manifest = load_manifest(&project_dir)?;
    let extraction_root = project_dir.join("work").join("extractions");
    let firmware_path = project_firmware_path(&project_dir, &project);

    spinner.set_message("collecting bootloader evidence");
    let bootloader_text = collect_bootloader_text(&project_dir, &manifest, &firmware_path);
    let bootloader_snapshot = merge_bootloader_snapshots(
        analyze_bootloader_text(&bootloader_text),
        analyze_bootloader_firmware(&firmware_path)?,
    );
    spinner.set_message("deriving signals");
    let derived_signals = derive_signals(&manifest, &firmware_path, &bootloader_snapshot)?;
    // signals.txt stays a bare signal list: it is what preflight, family
    // classification and backend ranking read. Provenance rides along in the
    // summary instead of changing that contract.
    let signals: Vec<String> = derived_signals
        .iter()
        .map(|signal| signal.signal.clone())
        .collect();
    spinner.set_message("discovering binaries");
    let binaries = discover_binaries(&extraction_root, detect_architecture(&signals));
    let snapshot = AnalysisSnapshot {
        binaries,
        findings: Vec::new(),
    };

    fs::create_dir_all(project_dir.join("analysis"))?;
    fs::write(project_signals_path(&project_dir), signals.join("\n"))?;
    fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&bootloader_snapshot)?,
    )?;
    fs::write(
        project_dir.join("analysis").join("image-headers.json"),
        serde_json::to_vec_pretty(&bootloader_snapshot.image_headers)?,
    )?;
    // One rendering feeds both stdout and summary.txt, so the persisted record
    // cannot drift from what the run reported.
    let mut summary_lines = vec![
        format!("project: {}", project.name),
        format!(
            "signals: {}",
            derived_signals
                .iter()
                .map(DerivedSignal::rendered)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("binaries: {}", snapshot.binaries.len()),
    ];
    summary_lines.extend(
        capped_list(
            snapshot
                .binaries
                .iter()
                .map(|binary| describe_binary(binary, &project_dir)),
        )
        .into_iter()
        .map(|line| format!("  {line}")),
    );

    // Findings are only known once the analyzer engine has run below, and the
    // summary is registered as a target artifact before dispatch, so the file is
    // written twice: an interim record without a findings count, then the final
    // record carrying the real count.
    let summary_path = project_dir.join("analysis").join("summary.txt");
    fs::write(&summary_path, render_summary(&summary_lines))?;

    let store = RuntimeStore::open(&project_dir)?;
    let target = ensure_target_record(&store, &project)?;
    record_target_artifact(
        &store,
        &project,
        ArtifactKind::Analysis,
        "signals",
        &project_signals_path(&project_dir),
        "fat analyze signals",
        "text/plain",
        "analysis signals for target",
    )?;
    record_target_artifact(
        &store,
        &project,
        ArtifactKind::Analysis,
        "summary",
        &project_dir.join("analysis").join("summary.txt"),
        "fat analyze summary",
        "text/plain",
        "analysis summary for target",
    )?;
    record_target_artifact(
        &store,
        &project,
        ArtifactKind::DiagnosticSupport,
        "bootloader",
        &project_dir.join("analysis").join("bootloader.json"),
        "fat analyze bootloader",
        "application/json",
        "diagnostic support for target",
    )?;
    record_target_artifact(
        &store,
        &project,
        ArtifactKind::DiagnosticSupport,
        "image-headers",
        &project_dir.join("analysis").join("image-headers.json"),
        "fat analyze image headers",
        "application/json",
        "structured image header evidence for target",
    )?;
    spinner.set_message("dispatching analyzer plugins");
    let analysis = fat_plugin_host::dispatch_target_analysis(
        &project_dir,
        &target.target_id,
        fat_plugin_api::AnalysisTrigger::AnalysisRequested,
        Some(snapshot.clone()),
    )?;
    let findings_count = analysis.findings.len();
    summary_lines.push(format!("findings: {findings_count}"));

    let summary = render_summary(&summary_lines);
    fs::write(&summary_path, &summary)?;
    spinner.finish_with("analysis complete");

    project.status = ProjectStatus::Analyzed;
    db.save(&project)?;

    if format.is_json() {
        return print_json(&analyze_json(
            &project,
            &project_dir,
            &derived_signals,
            &snapshot,
            findings_count,
        ));
    }

    if panel_mode {
        let lines = analyze_panel_lines(
            &palette,
            &derived_signals,
            &snapshot,
            &analysis,
            &project_dir,
        );
        println!(
            "{}",
            palette.panel(&format!("fat analyze · {}", project.name), &lines)
        );
        println!("{}", palette.next_hint("fat preflight <project>"));
        return Ok(());
    }

    print!("{summary}");

    Ok(())
}

fn analyze_json(
    project: &Project,
    project_dir: &Path,
    signals: &[DerivedSignal],
    snapshot: &AnalysisSnapshot,
    findings: usize,
) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = signals
        .iter()
        .map(|signal| {
            serde_json::json!({
                "signal": signal.signal,
                "provenance": signal.provenance.label(),
            })
        })
        .collect();
    let binaries: Vec<serde_json::Value> = snapshot
        .binaries
        .iter()
        .map(|binary| {
            let path = Path::new(&binary.rel_path);
            serde_json::json!({
                "name": binary.name,
                "path": binary.rel_path,
                "relative_path": display_relative(path, project_dir),
                "architecture": architecture_label(binary.architecture),
                "size_bytes": fs::metadata(path).map(|meta| meta.len()).ok(),
            })
        })
        .collect();

    json_envelope(
        "fat.analyze.v1",
        serde_json::json!({
            "project": project.name,
            "project_dir": project_dir.display().to_string(),
            "signals": signals,
            "binaries": binaries,
            "findings": findings,
        }),
    )
}

/// Panel-mode summary of an analysis run. Same facts as the plain summary —
/// signals with provenance, binaries with arch/size, findings with severity —
/// only the layout and glyphs differ.
fn analyze_panel_lines(
    palette: &crate::style::Palette,
    derived_signals: &[DerivedSignal],
    snapshot: &AnalysisSnapshot,
    analysis: &fat_plugin_api::AnalysisResult,
    project_dir: &Path,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push(palette.heading("Signals"));
    for signal in derived_signals {
        lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            signal.signal,
            palette.muted(format!("({})", signal.provenance.label()))
        ));
    }

    lines.push(String::new());
    lines.push(palette.heading("Binaries"));
    if snapshot.binaries.is_empty() {
        lines.push(format!("{} {}", palette.dot_muted(), palette.muted("none")));
    } else {
        for line in capped_list(
            snapshot
                .binaries
                .iter()
                .map(|binary| describe_binary(binary, project_dir)),
        ) {
            lines.push(format!(
                "{} {}",
                palette.dot_ok(),
                line.trim_start_matches("- ")
            ));
        }
    }

    lines.push(String::new());
    if analysis.findings.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_ok(),
            palette.muted("findings: 0")
        ));
    } else {
        lines.push(format!(
            "{} {}",
            palette.dot_warn(),
            palette.kv("findings", analysis.findings.len().to_string())
        ));
        for finding in analysis.findings.iter().take(SUMMARY_LIST_CAP) {
            lines.push(format!(
                "{} {} {}  {}",
                palette.dot_warn(),
                palette.severity_tag(&finding.severity),
                finding.title,
                palette.muted(&finding.id)
            ));
        }
    }
    lines
}

fn render_summary(lines: &[String]) -> String {
    let mut summary = lines.join("\n");
    summary.push('\n');
    summary
}

fn ensure_target_record(store: &RuntimeStore, project: &Project) -> DynResult<TargetRecord> {
    let target_id = derive_target_id(&project.name, &project.firmware_name);
    let now = current_timestamp_string();
    let target = match store.read_target(&target_id) {
        Ok(existing) => existing.touch(now),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            TargetRecord::new(project.name.clone(), target_id, project.name.clone(), now)
        }
        Err(err) => return Err(err.into()),
    };
    store.write_target(&target)?;
    Ok(target)
}

fn record_target_artifact(
    store: &RuntimeStore,
    project: &Project,
    kind: ArtifactKind,
    subkind: &str,
    path: &Path,
    producer_id: &str,
    content_type: &str,
    provenance: &str,
) -> DynResult<TargetArtifactRecord> {
    let metadata = fs::metadata(path)?;
    let target_id = derive_target_id(&project.name, &project.firmware_name);
    let artifact = TargetArtifactRecord::new(
        project.name.clone(),
        target_id,
        kind,
        subkind.to_string(),
        "fat",
        producer_id.to_string(),
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        content_type.to_string(),
        metadata.len(),
        None,
        provenance.to_string(),
        ArtifactRetentionPolicy::Project,
    )
    .with_phase(subkind.to_string())
    .with_tool_version(env!("CARGO_PKG_VERSION"));

    store.write_target_artifact(&artifact)?;
    store.append_target_artifact_index(&artifact)?;
    Ok(artifact)
}

fn current_timestamp_string() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis();
    format!("unix-ms:{millis}")
}

fn cmd_preflight(
    project: Option<&Path>,
    signals: Vec<String>,
    format: OutputFormat,
) -> DynResult<()> {
    let palette = crate::style::Palette::stdout();
    let panel_mode = format.is_text() && palette.enabled();
    let mut effective_signals = Vec::new();
    let has_project = project.is_some();
    let mut project_mode_summary = None;

    if let Some(project_dir) = project {
        effective_signals.extend(load_project_signals(project_dir)?);
        project_mode_summary = Some(render_project_boot_mode_summary(project_dir)?);
    }
    effective_signals.extend(signals);

    if !has_project && effective_signals.is_empty() {
        return Err("preflight requires either a project path or at least one --signal".into());
    }

    let report = PreflightReport::from_signals(effective_signals.clone());
    if format.is_json() {
        return print_json(&preflight_json(&report, &effective_signals));
    }
    if panel_mode {
        println!(
            "{}",
            palette.panel(
                "fat preflight",
                &preflight_panel_lines(&palette, &report, project_mode_summary.as_deref()),
            )
        );
        println!(
            "{}",
            preflight_next_hint(&palette, &report, project.is_some())
        );
        return Ok(());
    }
    if let Some(summary) = project_mode_summary {
        print!("{}", colorize_preflight_project_summary(&summary, &palette));
    }
    print!("{}", render_preflight_report(&report, &palette));
    Ok(())
}

fn preflight_json(report: &PreflightReport, signals: &[String]) -> serde_json::Value {
    let backends: Vec<serde_json::Value> = report
        .backends
        .iter()
        .map(|backend| {
            serde_json::json!({
                "backend_id": backend.backend_id,
                "display_name": backend.display_name,
                "score": backend.score,
                "reason": backend.reason,
                "available": backend.is_available,
                "availability_detail": backend.availability_detail,
            })
        })
        .collect();

    json_envelope(
        "fat.preflight.v1",
        serde_json::json!({
            "signals": signals,
            "family": {
                "family_id": report.primary_family.family_id,
                "confidence": report.primary_family.confidence,
            },
            "backends": backends,
        }),
    )
}

/// `fat emulate list` is accepted as an alias for `fat emulate --list`.
///
/// The positional slot is a project path, so a literal `list` that is not an
/// existing directory is read as the subcommand-style form; a real directory
/// named `list` still wins and is treated as the project.
fn resolve_emulate_list_alias(project_arg: Option<PathBuf>, list: bool) -> (Option<PathBuf>, bool) {
    match project_arg {
        Some(path) if path.as_os_str() == "list" && !path.is_dir() => (None, true),
        other => (other, list),
    }
}

fn cmd_emulate(
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
    emulate_cmd::run(
        project,
        backend,
        substrate_policy,
        session_id,
        ports,
        status,
        list,
        list_json,
        gc,
        stop,
        instrument,
        pack,
        experimental_rehosting,
        accept_degraded_rehosting,
        kernel_class,
    )
}

fn cmd_bootloader_inspect(project_dir: &Path) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let snapshot = load_bootloader_snapshot(&project_dir)?;
    let discovery = discover_boot_artifacts(&project_dir)?;
    print!("{}", render_bootloader_snapshot(&snapshot, &discovery));
    Ok(())
}

fn cmd_bootloader_new(project_dir: &Path, profile: &str) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let workspace = materialize_workspace(&project_dir, profile)?;

    println!("project: {}", project_dir.display());
    println!("bootloader: {}", workspace.bootloader_dir.display());
    println!("env: {}", workspace.env_path.display());
    println!("manifest: {}", workspace.manifest_path.display());

    Ok(())
}

fn cmd_bootloader_export_env(project_dir: &Path) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let env_path = project_dir.join("bootloader").join("env.txt");
    let env_text = fs::read_to_string(&env_path)?;
    print!("{env_text}");
    Ok(())
}

fn cmd_bootloader_emulate(project_dir: &Path, assist: bool) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    if assist {
        let result = assist_boot(&project_dir)?;
        println!("project: {}", project_dir.display());
        println!("assist log: {}", result.command_log);
        println!("commands sent: {}", result.commands_sent.len());
        println!("execution stage: {}", result.execution.stage);
        println!("execution result: {}", result.execution.result);
        return Ok(());
    }

    let launch = launch_in_tmux(&project_dir)?;

    println!("project: {}", project_dir.display());
    println!(
        "launch: {}",
        project_dir.join("bootloader/qemu/launch.json").display()
    );
    println!("serial: {}", launch.serial_log);
    println!("qemu: {}", launch.qemu_binary);
    println!("machine: {}", launch.machine);
    println!("u-boot: {}", launch.u_boot_asset_reference);
    println!("console: {}", launch.console);
    println!("tmux: {}", launch.tmux_session);
    println!("attach: {}", launch.attach_command);

    if let Some(reason) = &launch.reason {
        return Err(format!("bootloader launch is not runnable yet: {reason}").into());
    }

    Ok(())
}

fn cmd_bootloader_console(project_dir: &Path) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let launch = prepare_launch(&project_dir)?;

    println!("project: {}", project_dir.display());
    println!(
        "launch: {}",
        project_dir.join("bootloader/qemu/launch.json").display()
    );
    println!("serial: {}", launch.serial_log);
    println!("console: {}", launch.console);
    println!("qemu: {}", launch.qemu_binary);
    println!("tmux: {}", launch.tmux_session);
    println!("attach: {}", launch.attach_command);

    if let Some(reason) = &launch.reason {
        return Err(format!("no live console session is running yet: {reason}").into());
    }

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        let tmux =
            find_tmux_binary().ok_or_else(|| "tmux is unavailable on this host".to_string())?;
        let status = ProcessCommand::new(tmux)
            .args(["attach-session", "-t", &launch.tmux_session])
            .status()?;
        if !status.success() {
            return Err(format!("failed to attach to tmux session {}", launch.tmux_session).into());
        }
    }

    Ok(())
}

fn cmd_bootloader_stop(project_dir: Option<&Path>, all: bool) -> DynResult<()> {
    if all {
        return cmd_bootloader_stop_all();
    }

    // Clap enforces that one of the two is present.
    let project_dir = project_dir.ok_or("pass a project directory or --all")?;
    let project_dir = normalize_project_dir(project_dir)?;
    let outcome = stop_tmux_session(&project_dir)?;

    println!("project: {}", project_dir.display());
    println!("tmux session: {}", outcome.tmux_session);
    println!("stopped: {}", outcome.stopped);
    if let Some(reason) = outcome.reason {
        println!("reason: {reason}");
    }

    Ok(())
}

/// Sweep every FAT-managed bootloader session on the host. Unlike the
/// per-project form this needs no project directory, which is what makes it
/// able to reap orphans whose project has been deleted.
fn cmd_bootloader_stop_all() -> DynResult<()> {
    let stopped = stop_all_tmux_sessions()?;

    println!("stopped: {}", stopped.len());
    for session in &stopped {
        println!("  {session}");
    }
    if stopped.is_empty() {
        println!("reason: no FAT-managed bootloader sessions were running");
    }

    Ok(())
}

fn cmd_bootloader_status(project_dir: &Path) -> DynResult<()> {
    let project_dir = normalize_project_dir(project_dir)?;
    let launch = prepare_launch(&project_dir)?;
    let execution_path = project_dir
        .join("bootloader")
        .join("qemu")
        .join("execution-result.json");
    let execution = if execution_path.is_file() {
        let bytes = fs::read(&execution_path)?;
        Some(serde_json::from_slice::<fat_bootloader::BootExecutionResult>(&bytes)?)
    } else {
        None
    };

    println!("project: {}", project_dir.display());
    println!("launchable: {}", launch.launchable);
    println!("launched: {}", launch.launched);
    println!("tmux session: {}", launch.tmux_session);
    println!("attach: {}", launch.attach_command);
    println!("console: {}", launch.console);
    println!(
        "launch: {}",
        project_dir.join("bootloader/qemu/launch.json").display()
    );
    if let Some(reason) = launch.reason {
        println!("reason: {reason}");
    }
    if let Some(execution) = execution {
        println!("last execution: {} ({})", execution.stage, execution.result);
    } else {
        println!("last execution: none");
    }
    Ok(())
}

/// Resolve a project argument that can be supplied either positionally or via
/// `--project` (non-breaking alias). Errors clearly when neither is given.
pub(crate) fn resolve_project_arg(
    positional: Option<PathBuf>,
    flag: Option<PathBuf>,
) -> DynResult<PathBuf> {
    positional
        .or(flag)
        .ok_or_else(|| "a project directory is required (positionally or via --project)".into())
}

fn normalize_project_dir(project_dir: &Path) -> DynResult<PathBuf> {
    if project_dir.is_dir() {
        Ok(fs::canonicalize(project_dir)?)
    } else {
        Err(format!("project path does not exist: {}", project_dir.display()).into())
    }
}

fn find_tmux_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            let candidate = entry.join("tmux");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let fallback = PathBuf::from("/opt/homebrew/bin/tmux");
    fallback.is_file().then_some(fallback)
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn compute_fingerprint(path: &Path) -> DynResult<FirmwareFingerprint> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let sha256 = format!("{:x}", hasher.finalize());
    let size_bytes = fs::metadata(path)?.len();
    Ok(FirmwareFingerprint::new(sha256, size_bytes))
}

fn slugify_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("firmware");
    let mut slug = String::new();

    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }

    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "firmware".to_string()
    } else {
        slug.to_string()
    }
}

fn project_firmware_path(project_dir: &Path, project: &Project) -> PathBuf {
    project_dir.join("input").join(&project.firmware_name)
}

fn extraction_manifest_path(project_dir: &Path) -> PathBuf {
    project_dir.join("work").join("extraction-manifest.json")
}

fn project_signals_path(project_dir: &Path) -> PathBuf {
    project_dir.join("analysis").join("signals.txt")
}

fn load_manifest(project_dir: &Path) -> DynResult<ExtractionManifest> {
    let bytes = fs::read(extraction_manifest_path(project_dir))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_bootloader_snapshot(project_dir: &Path) -> DynResult<BootloaderSnapshot> {
    let bytes = fs::read(project_dir.join("analysis").join("bootloader.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn load_project_signals(project_dir: &Path) -> DynResult<Vec<String>> {
    let content = fs::read_to_string(project_signals_path(project_dir))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn build_extraction_manifest(extraction_root: &Path) -> DynResult<ExtractionManifest> {
    Ok(ExtractionManifest {
        rootfs_path: find_rootfs(extraction_root),
        file_count: file_count(extraction_root),
        kernel_paths: kernel_candidates(extraction_root),
        filesystem_trees: filesystem_tree_records(extraction_root),
        // Engine provenance is owned by the caller that ran the engines.
        ..ExtractionManifest::default()
    })
}

fn filesystem_tree_records(
    extraction_root: &Path,
) -> Vec<fat_extract::manifest::ExtractedFilesystemTree> {
    find_all_trees(extraction_root)
        .into_iter()
        .map(
            |(role, path)| fat_extract::manifest::ExtractedFilesystemTree {
                tree_kind: role.clone(),
                role,
                path,
            },
        )
        .collect()
}

fn recover_rootfs_if_needed(
    mut manifest: ExtractionManifest,
    extraction_root: &Path,
    firmware_path: &Path,
    log_path: &Path,
) -> DynResult<ExtractionManifest> {
    let mut log = String::new();

    if manifest.rootfs_path.is_none() {
        for image in squashfs_candidates(extraction_root) {
            if let Some(rootfs_path) = extract_rootfs_fallback(&image, &mut log)? {
                manifest.rootfs_path = Some(rootfs_path);
                manifest.file_count = file_count(extraction_root);
                break;
            }
        }

        if manifest.rootfs_path.is_none() {
            if let Some(rootfs_path) =
                extract_ext_rootfs_fallback(firmware_path, extraction_root, &mut log)?
            {
                manifest.rootfs_path = Some(rootfs_path);
                manifest.file_count = file_count(extraction_root);
            }
        }
    } else {
        log.push_str("rootfs already discovered during primary extraction\n");
    }

    manifest.filesystem_trees = filesystem_tree_records(extraction_root);

    fs::write(log_path, log)?;
    Ok(manifest)
}

fn kernel_candidates(root: &Path) -> Vec<PathBuf> {
    let mut kernels = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if name.ends_with(".gz") {
            continue;
        }

        if matches!(
            name.as_str(),
            "decompressed.bin"
                | "lzma.uncompressed"
                | "kernel.bin"
                | "vmlinux"
                | "vmlinuz"
                | "zimage"
        ) || name.contains("kernel")
            || name.starts_with("vmlinux.")
        {
            kernels.push(path.to_path_buf());
        }
    }

    kernels.sort();
    kernels.dedup();
    kernels
}

fn extract_rootfs_fallback(image: &Path, log: &mut String) -> DynResult<Option<PathBuf>> {
    let parent = image
        .parent()
        .ok_or_else(|| format!("candidate image has no parent: {}", image.display()))?;
    let destination = parent.join("squashfs-root");

    for extractor in ["sasquatch", "unsquashfs"] {
        if destination.exists() {
            let _ = fs::remove_dir_all(&destination);
        }

        match ProcessCommand::new(extractor)
            .arg("-d")
            .arg(&destination)
            .arg(image)
            .output()
        {
            Ok(output) => {
                let _ = writeln!(
                    log,
                    "$ {extractor} -d {} {}",
                    destination.display(),
                    image.display()
                );
                let _ = writeln!(log, "exit={}", output.status.code().unwrap_or(-1));
                log.push_str(&String::from_utf8_lossy(&output.stdout));
                log.push_str(&String::from_utf8_lossy(&output.stderr));

                if destination_contains_files(&destination) {
                    return Ok(Some(destination));
                }
            }
            Err(err) => {
                let _ = writeln!(
                    log,
                    "$ {extractor} -d {} {}",
                    destination.display(),
                    image.display()
                );
                let _ = writeln!(log, "spawn-error={err}");
            }
        }
    }

    Ok(None)
}

fn extract_ext_rootfs_fallback(
    image: &Path,
    extraction_root: &Path,
    log: &mut String,
) -> DynResult<Option<PathBuf>> {
    if !is_ext_filesystem_image(image) {
        return Ok(None);
    }

    let Some(debugfs) = find_debugfs_binary() else {
        writeln!(
            log,
            "ext filesystem detected, but debugfs was not found on PATH or in Homebrew e2fsprogs"
        )?;
        return Ok(None);
    };

    let destination = extraction_root.join("debugfs-root");
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;

    let command = "rdump / debugfs-root";
    let output = ProcessCommand::new(&debugfs)
        .arg("-R")
        .arg(command)
        .arg(image)
        .current_dir(extraction_root)
        .output();

    match output {
        Ok(output) => {
            writeln!(
                log,
                "$ {} -R {} {}",
                debugfs.display(),
                command,
                image.display()
            )?;
            writeln!(log, "exit={}", output.status.code().unwrap_or(-1))?;
            log.push_str(&String::from_utf8_lossy(&output.stdout));
            log.push_str(&String::from_utf8_lossy(&output.stderr));

            if destination_contains_files(&destination) {
                return Ok(Some(destination));
            }
        }
        Err(err) => {
            writeln!(
                log,
                "$ {} -R {} {}",
                debugfs.display(),
                command,
                image.display()
            )?;
            writeln!(log, "spawn-error={err}")?;
        }
    }

    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    Ok(None)
}

fn is_ext_filesystem_image(path: &Path) -> bool {
    const EXT_MAGIC_OFFSET: usize = 1024 + 56;
    const EXT_MAGIC: [u8; 2] = 0xef53u16.to_le_bytes();

    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut prefix = vec![0u8; EXT_MAGIC_OFFSET + EXT_MAGIC.len()];
    file.read_exact(&mut prefix).is_ok()
        && prefix[EXT_MAGIC_OFFSET..EXT_MAGIC_OFFSET + EXT_MAGIC.len()] == EXT_MAGIC
}

fn find_debugfs_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            let candidate = entry.join("debugfs");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    [
        "/opt/homebrew/opt/e2fsprogs/sbin/debugfs",
        "/usr/local/opt/e2fsprogs/sbin/debugfs",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|candidate| candidate.is_file())
}

fn extraction_manifest_is_reusable(manifest: &ExtractionManifest, extraction_root: &Path) -> bool {
    if manifest.file_count == 0 || file_count(extraction_root) < manifest.file_count {
        return false;
    }
    let Ok(canonical_root) = extraction_root.canonicalize() else {
        return false;
    };
    manifest
        .rootfs_path
        .as_deref()
        .is_none_or(|path| canonical_descendant(path, &canonical_root, true))
        && manifest
            .kernel_paths
            .iter()
            .all(|path| canonical_descendant(path, &canonical_root, false))
}

fn canonical_descendant(path: &Path, canonical_root: &Path, require_directory: bool) -> bool {
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    canonical.starts_with(canonical_root)
        && if require_directory {
            canonical.is_dir()
        } else {
            canonical.is_file()
        }
}

fn destination_contains_files(path: &Path) -> bool {
    path.exists()
        && WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .any(|entry| entry.file_type().is_file())
}

/// Where a signal came from. Recorded so a reader can tell a measured fact from
/// a guess: a header FAT parsed itself outranks a name in the extracted tree,
/// which outranks a string that merely appeared somewhere in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SignalProvenance {
    /// A header FAT parsed, or a tool description of a real binary.
    Measured,
    /// A name in the recovered extraction tree.
    TreeName,
    /// A string somewhere in the firmware or kernel image — the weakest source.
    StringsFallback,
}

impl SignalProvenance {
    fn label(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::TreeName => "tree-name",
            Self::StringsFallback => "strings-fallback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DerivedSignal {
    signal: String,
    provenance: SignalProvenance,
}

impl DerivedSignal {
    fn new(signal: impl Into<String>, provenance: SignalProvenance) -> Self {
        Self {
            signal: signal.into(),
            provenance,
        }
    }

    fn rendered(&self) -> String {
        format!("{} ({})", self.signal, self.provenance.label())
    }
}

/// Derive analysis signals from what extraction actually recovered.
///
/// Signals are read from the extraction tree and parsed headers rather than
/// from extractor logs. Log scraping made the result depend on which engine
/// happened to run — binwalk's log embeds scan signatures, unblob's does not,
/// and a skipped engine's log holds only a skip reason — so the same firmware
/// classified differently depending on which tools were installed. `strings`
/// survives only as a last-resort layer, and says so in its provenance.
fn derive_signals(
    manifest: &ExtractionManifest,
    firmware_path: &Path,
    bootloader_snapshot: &BootloaderSnapshot,
) -> DynResult<Vec<DerivedSignal>> {
    let mut signals: Vec<DerivedSignal> = Vec::new();

    if let Some((signal, provenance)) =
        infer_architecture_signal(manifest, bootloader_snapshot, firmware_path)
    {
        signals.push(DerivedSignal::new(signal, provenance));
    }

    if let Some((signal, provenance)) = infer_filesystem_signal(manifest, bootloader_snapshot) {
        signals.push(DerivedSignal::new(signal, provenance));
    }

    match manifest.rootfs_path.as_deref() {
        Some(rootfs_path) => {
            for (needle, signal) in [("busybox", "init:busybox"), ("nvram", "nvram:present")] {
                if tree_contains_name(rootfs_path, needle) {
                    signals.push(DerivedSignal::new(signal, SignalProvenance::TreeName));
                }
            }
            if ["boa", "goahead", "cgi-bin", "cgi"]
                .iter()
                .any(|needle| tree_contains_name(rootfs_path, needle))
            {
                signals.push(DerivedSignal::new("web:cgi", SignalProvenance::TreeName));
            }
            for signal in infer_service_signals_from_rootfs(rootfs_path) {
                signals.push(DerivedSignal::new(signal, SignalProvenance::TreeName));
            }
        }
        None => {
            // Nothing was recovered to inspect, so fall back to the image
            // itself and mark the result for what it is.
            let strings = strings_output(firmware_path);
            for (needles, signal) in [
                (&["busybox"][..], "init:busybox"),
                (&["boa", "goahead", "cgi"][..], "web:cgi"),
                (&["nvram"][..], "nvram:present"),
            ] {
                if contains_text(&strings, needles) {
                    signals.push(DerivedSignal::new(
                        signal,
                        SignalProvenance::StringsFallback,
                    ));
                }
            }
        }
    }

    let mut bootloader_signals = Vec::new();
    extend_signals_from_bootloader_snapshot(&mut bootloader_signals, bootloader_snapshot);
    signals.extend(
        bootloader_signals
            .into_iter()
            .map(|signal| DerivedSignal::new(signal, SignalProvenance::Measured)),
    );

    signals.sort();
    // Keep the best-evidenced provenance when the same signal has several.
    signals.dedup_by(|left, right| left.signal == right.signal);
    Ok(signals)
}

/// Architecture, best evidence first: a real binary the host's `file` can
/// describe, then a parsed image header, then kernel strings, and only then a
/// scan of the raw image.
fn infer_architecture_signal(
    manifest: &ExtractionManifest,
    bootloader_snapshot: &BootloaderSnapshot,
    firmware_path: &Path,
) -> Option<(String, SignalProvenance)> {
    let rootfs_signal = manifest
        .rootfs_path
        .as_ref()
        .and_then(|rootfs_path| architecture_signal_from_rootfs_binaries(rootfs_path));
    let bootloader_signal = architecture_signal_from_bootloader(bootloader_snapshot);
    if rootfs_signal.is_none() && bootloader_signal.is_none() {
        // Reading the kernel and then the whole image is the expensive path;
        // only take it when nothing measured is available.
        let kernel_signal = architecture_signal_from_kernel_paths(&manifest.kernel_paths);
        let image_strings = if kernel_signal.is_none() {
            strings_output(firmware_path)
        } else {
            String::new()
        };
        return select_architecture_signal(None, None, kernel_signal, &image_strings);
    }
    select_architecture_signal(rootfs_signal, bootloader_signal, None, "")
}

/// Pick the architecture signal from the available sources, best evidence
/// first, and report how well evidenced the winner is.
fn select_architecture_signal(
    rootfs_signal: Option<String>,
    bootloader_signal: Option<String>,
    kernel_signal: Option<String>,
    image_strings: &str,
) -> Option<(String, SignalProvenance)> {
    if let Some(signal) = rootfs_signal.or(bootloader_signal) {
        return Some((signal, SignalProvenance::Measured));
    }
    kernel_signal
        .or_else(|| architecture_signal_from_text(image_strings))
        .map(|signal| (signal, SignalProvenance::StringsFallback))
}

fn architecture_signal_from_text(text: &str) -> Option<String> {
    if contains_text(text, &["riscv64", "risc-v", "riscv", "arch/riscv/"]) {
        Some("arch:riscv64".to_string())
    } else if contains_text(text, &["arm64", "aarch64", "arch/arm64/"]) {
        Some("arch:arm64".to_string())
    } else if contains_text(
        text,
        &[
            "arch/arm/",
            "arm926",
            "arm1176",
            "cortex-a",
            "cortex-r",
            "armv7",
            "armv6",
        ],
    ) {
        Some("arch:armel".to_string())
    } else if contains_text(text, &["mips32", "arch/mips/"]) {
        Some("arch:mips".to_string())
    } else {
        None
    }
}

fn architecture_signal_from_bootloader(snapshot: &BootloaderSnapshot) -> Option<String> {
    for header in &snapshot.image_headers {
        let arch = header.architecture.as_deref()?.to_ascii_lowercase();
        if arch.contains("riscv64") || arch.contains("risc-v") || arch.contains("riscv") {
            return Some("arch:riscv64".to_string());
        }
        if arch.contains("aarch64") || arch.contains("arm64") {
            return Some("arch:arm64".to_string());
        }
        if arch.contains("arm") {
            return Some("arch:armel".to_string());
        }
        if arch.contains("mips") {
            return Some("arch:mips".to_string());
        }
    }

    None
}

fn architecture_signal_from_kernel_paths(kernel_paths: &[PathBuf]) -> Option<String> {
    for kernel_path in kernel_paths {
        let text = strings_output(kernel_path);
        if contains_text(&text, &["riscv64", "risc-v", "riscv", "arch/riscv/"]) {
            return Some("arch:riscv64".to_string());
        }
        if contains_text(&text, &["arm64", "aarch64", "arch/arm64/"]) {
            return Some("arch:arm64".to_string());
        }
        if contains_text(
            &text,
            &[
                "arch/arm/",
                "arm926",
                "arm1176",
                "cortex-a",
                "cortex-r",
                "armv7",
                "armv6",
            ],
        ) {
            return Some("arch:armel".to_string());
        }
        if contains_text(&text, &["mips32", "arch/mips/"]) {
            return Some("arch:mips".to_string());
        }
    }

    None
}

fn architecture_signal_from_rootfs_binaries(rootfs_path: &Path) -> Option<String> {
    for candidate in interesting_binary_paths(rootfs_path) {
        let description = file_output(&candidate);
        if let Some(signal) = architecture_signal_from_file_description(&description) {
            return Some(signal);
        }
    }

    None
}

fn architecture_signal_from_file_description(description: &str) -> Option<String> {
    if contains_text(description, &["riscv64", "risc-v", "riscv"]) {
        return Some("arch:riscv64".to_string());
    }
    if contains_text(description, &["aarch64", "arm64"]) {
        return Some("arch:arm64".to_string());
    }
    if contains_text(description, &[" arm,", " arm "]) {
        return Some("arch:armel".to_string());
    }
    if contains_text(description, &["mips"]) {
        let lowered = description.to_ascii_lowercase();
        if lowered.contains("lsb") || lowered.contains("little-endian") {
            return Some("arch:mipsel".to_string());
        }
        return Some("arch:mips".to_string());
    }

    None
}

fn infer_service_signals_from_rootfs(rootfs_path: &Path) -> Vec<String> {
    const WEB_SERVICE_CANDIDATES: &[(&str, &str)] = &[
        ("/bin/alphapd", "web:alphapd"),
        ("/usr/sbin/alphapd", "web:alphapd"),
        ("/usr/sbin/uhttpd", "web:uhttpd"),
        ("/usr/sbin/httpd", "web:httpd"),
        ("/bin/httpd", "web:httpd"),
        ("/usr/sbin/boa", "web:httpd"),
        ("/bin/boa", "web:httpd"),
        ("/usr/sbin/goahead", "web:httpd"),
        ("/bin/goahead", "web:httpd"),
    ];

    let mut signals = Vec::new();
    for (service_path, web_signal) in WEB_SERVICE_CANDIDATES {
        if rootfs_path
            .join(service_path.trim_start_matches('/'))
            .is_file()
        {
            signals.push(format!("service:{service_path}"));
            signals.push((*web_signal).to_string());
            break;
        }
    }
    signals
}

/// The filesystem, read from the tree that was actually recovered, falling back
/// to a header FAT parsed from the raw image. The two sources are reported
/// differently: a directory name is what the extractor called it, a header is
/// something FAT measured.
fn infer_filesystem_signal(
    manifest: &ExtractionManifest,
    bootloader_snapshot: &BootloaderSnapshot,
) -> Option<(String, SignalProvenance)> {
    if let Some(name) = manifest
        .rootfs_path
        .as_ref()
        .and_then(|rootfs_path| rootfs_path.file_name())
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase())
    {
        if name.contains("jffs2") {
            return Some(("fs:jffs2".to_string(), SignalProvenance::TreeName));
        }
        if name.contains("squashfs") {
            return Some(("fs:squashfs".to_string(), SignalProvenance::TreeName));
        }
        if name.contains("cramfs") {
            return Some(("fs:cramfs".to_string(), SignalProvenance::TreeName));
        }
    }

    for header in &bootloader_snapshot.filesystem_headers {
        let format = header.format.to_ascii_lowercase();
        if format.contains("jffs2") {
            return Some(("fs:jffs2".to_string(), SignalProvenance::Measured));
        }
        if format.contains("squashfs") {
            return Some(("fs:squashfs".to_string(), SignalProvenance::Measured));
        }
        if format.contains("cramfs") {
            return Some(("fs:cramfs".to_string(), SignalProvenance::Measured));
        }
    }

    None
}

fn extend_signals_from_bootloader_snapshot(
    signals: &mut Vec<String>,
    bootloader_snapshot: &BootloaderSnapshot,
) {
    if let Some(family) = &bootloader_snapshot.family {
        signals.push(format!("bootloader:{family}"));
    }

    for header in &bootloader_snapshot.image_headers {
        signals.push(format!("container:{}", header.format));
        if let Some(architecture) = &header.architecture {
            signals.push(format!("uimage:arch:{architecture}"));
        }
        if let Some(operating_system) = &header.operating_system {
            signals.push(format!("uimage:os:{operating_system}"));
        }
        if let Some(image_type) = &header.image_type {
            signals.push(format!("uimage:type:{image_type}"));
        }
        if let Some(name) = &header.name {
            signals.push(format!("uimage:name:{name}"));
        }
    }

    if bootloader_snapshot
        .findings
        .iter()
        .any(|finding| finding == "BOOT-UIMAGE-CRC32-ONLY")
    {
        signals.push("auth:crc32-only".to_string());
    }
}

fn collect_bootloader_text(
    _project_dir: &Path,
    manifest: &ExtractionManifest,
    firmware_path: &Path,
) -> String {
    let mut combined = String::new();
    combined.push_str(&strings_output(firmware_path));

    for kernel_path in &manifest.kernel_paths {
        combined.push_str(&strings_output(kernel_path));
    }

    if let Some(rootfs_path) = &manifest.rootfs_path {
        for candidate in bootloader_candidate_files(rootfs_path) {
            combined.push_str(&strings_output(&candidate));
        }
    }

    combined
}

fn strings_output(path: &Path) -> String {
    match ProcessCommand::new("strings").arg("-a").arg(path).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

fn file_output(path: &Path) -> String {
    match ProcessCommand::new("file").arg(path).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

fn contains_text(haystack: &str, needles: &[&str]) -> bool {
    let haystack = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
}

fn bootloader_candidate_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "uenv.txt"
                | "u-boot.env"
                | "uboot.env"
                | "env.txt"
                | "default.txt"
                | "boot.cmd"
                | "boot.scr"
                | "cmdline"
                | "fw_env.config"
        ) || name.contains("boot")
            || name.contains("env")
        {
            files.push(entry.path().to_path_buf());
        }
    }

    files.sort();
    files.dedup();
    files
}

fn interesting_binary_paths(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "alphapd" | "busybox" | "boa" | "goahead" | "httpd" | "lighttpd"
        ) {
            files.push(entry.path().to_path_buf());
        }
    }

    files.sort();
    files.dedup();
    files
}

fn tree_contains_name(root: &Path, needle: &str) -> bool {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains(needle)
        })
}

fn detect_architecture(signals: &[String]) -> Architecture {
    if signals.iter().any(|signal| signal == "arch:mipsel") {
        Architecture::Mipsel
    } else if signals.iter().any(|signal| signal == "arch:mips") {
        Architecture::Mips
    } else if signals.iter().any(|signal| signal == "arch:riscv64") {
        Architecture::Riscv64
    } else if signals.iter().any(|signal| signal == "arch:arm64") {
        Architecture::Arm64
    } else if signals.iter().any(|signal| signal == "arch:armel") {
        Architecture::Armel
    } else {
        Architecture::Unknown
    }
}

fn discover_binaries(root: &Path, architecture: Architecture) -> Vec<BinaryRecord> {
    let mut binaries = Vec::new();
    let interesting = ["alphapd", "busybox", "httpd", "boa", "goahead"];

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if !interesting.iter().any(|candidate| candidate == &name) {
            continue;
        }

        binaries.push(BinaryRecord {
            id: format!("bin-{}", binaries.len() + 1),
            name: name.clone(),
            rel_path: entry.path().display().to_string(),
            architecture,
            nx: None,
            pie: None,
            canary: None,
        });
    }

    binaries
}

fn render_bootloader_snapshot(
    snapshot: &BootloaderSnapshot,
    discovery: &BootArtifactDiscovery,
) -> String {
    let mut output = String::new();
    let compatibility = discovery
        .bootloader_images
        .first()
        .map(|image| evaluate_true_boot_chain(image, discovery.primary.as_ref(), None));
    let mode = compatibility
        .as_ref()
        .map(|result| {
            if result.compatible {
                result.mode.as_str()
            } else {
                "hybrid-boot-chain"
            }
        })
        .unwrap_or("hybrid-boot-chain");

    let _ = writeln!(&mut output, "mode: {mode}");
    let _ = writeln!(
        &mut output,
        "family: {}",
        snapshot.family.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(
        &mut output,
        "version hint: {}",
        snapshot.version_hint.as_deref().unwrap_or("unknown")
    );

    let _ = writeln!(&mut output, "env variables:");
    if snapshot.env_variables.is_empty() {
        let _ = writeln!(&mut output, "  none");
    } else {
        for variable in &snapshot.env_variables {
            let _ = writeln!(
                &mut output,
                "  {}={} ({:?})",
                variable.key, variable.value, variable.source
            );
        }
    }

    let risky_values = risky_env_variables(snapshot);
    let _ = writeln!(&mut output, "risky values:");
    if risky_values.is_empty() {
        let _ = writeln!(&mut output, "  none");
    } else {
        for variable in risky_values {
            let _ = writeln!(&mut output, "  {}={}", variable.key, variable.value);
        }
    }

    let _ = writeln!(&mut output, "findings:");
    if snapshot.findings.is_empty() {
        let _ = writeln!(&mut output, "  none");
    } else {
        for finding in &snapshot.findings {
            let _ = writeln!(&mut output, "  {finding}");
        }
    }

    let _ = writeln!(
        &mut output,
        "boot method: {}",
        inspect_boot_method(discovery)
    );
    let _ = writeln!(&mut output, "primary boot set:");
    if let Some(primary) = &discovery.primary {
        render_boot_artifact_set(&mut output, primary);
    } else {
        let _ = writeln!(&mut output, "  none");
    }

    let _ = writeln!(&mut output, "alternate boot sets:");
    if discovery.alternates.is_empty() {
        let _ = writeln!(&mut output, "  none");
    } else {
        for alternate in &discovery.alternates {
            render_boot_artifact_set(&mut output, alternate);
        }
    }

    if !discovery.rejection_reasons.is_empty() {
        let _ = writeln!(&mut output, "rejection reasons:");
        for reason in &discovery.rejection_reasons {
            let _ = writeln!(&mut output, "  {reason}");
        }
    }

    if let Some(compatibility) = compatibility {
        if !compatibility.compatible {
            let _ = writeln!(&mut output, "why not true-boot-chain:");
            for reason in &compatibility.reasons {
                let _ = writeln!(&mut output, "  {reason}");
            }
        }
    } else {
        let _ = writeln!(&mut output, "why not true-boot-chain:");
        let _ = writeln!(
            &mut output,
            "  no extracted bootloader image candidate was discovered"
        );
    }

    output
}

fn render_project_boot_mode_summary(project_dir: &Path) -> DynResult<String> {
    let mut output = String::new();
    let bootloader_json = project_dir.join("analysis").join("bootloader.json");

    if !bootloader_json.is_file() {
        let _ = writeln!(&mut output, "boot mode support: inspect-only");
        let _ = writeln!(
            &mut output,
            "boot mode detail: no bootloader analysis artifact is present for this project"
        );
        return Ok(output);
    }

    let discovery = discover_boot_artifacts(project_dir)?;
    if let Some(image) = discovery.bootloader_images.first() {
        let compatibility = evaluate_true_boot_chain(image, discovery.primary.as_ref(), None);
        if compatibility.compatible {
            let _ = writeln!(&mut output, "boot mode support: {}", compatibility.mode);
            let _ = writeln!(
                &mut output,
                "boot mode detail: {}",
                compatibility
                    .reasons
                    .first()
                    .map(String::as_str)
                    .unwrap_or("compatible extracted bootloader and boot artifacts were found")
            );
            return Ok(output);
        }

        let _ = writeln!(&mut output, "boot mode support: hybrid-boot-chain");
        let _ = writeln!(
            &mut output,
            "boot mode detail: {}",
            compatibility
                .reasons
                .first()
                .map(String::as_str)
                .unwrap_or("true boot-chain compatibility could not be proven")
        );
        return Ok(output);
    }

    if discovery.primary.is_some() {
        let _ = writeln!(&mut output, "boot mode support: hybrid-boot-chain");
        let _ = writeln!(
            &mut output,
            "boot mode detail: {}",
            discovery
                .rejection_reasons
                .first()
                .map(String::as_str)
                .unwrap_or(
                "boot artifacts were found, but no compatible extracted bootloader was discovered"
            )
        );
        return Ok(output);
    }

    let _ = writeln!(&mut output, "boot mode support: inspect-only");
    let _ = writeln!(
        &mut output,
        "boot mode detail: {}",
        discovery
            .rejection_reasons
            .first()
            .map(String::as_str)
            .unwrap_or("no viable boot artifact set was recovered from the project")
    );
    Ok(output)
}

fn colorize_preflight_project_summary(summary: &str, palette: &crate::style::Palette) -> String {
    let mut out = String::new();
    for line in summary.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            let styled_value = if key == "boot mode support" {
                match value {
                    "true-boot-chain" => palette.good(value),
                    "hybrid-boot-chain" => palette.warn(value),
                    _ => palette.muted(value),
                }
            } else {
                value.to_string()
            };
            let _ = writeln!(&mut out, "{}: {}", palette.key(key), styled_value);
        } else {
            let _ = writeln!(&mut out, "{line}");
        }
    }
    out
}

fn render_preflight_report(report: &PreflightReport, palette: &crate::style::Palette) -> String {
    fn availability_detail(detail: &str) -> &str {
        detail
            .strip_prefix("unavailable (")
            .and_then(|trimmed| trimmed.strip_suffix(')'))
            .unwrap_or(detail)
    }

    let mut output = String::new();
    let _ = writeln!(&mut output, "{}", palette.heading("Preflight"));
    let _ = writeln!(
        &mut output,
        "{}",
        palette.kv(
            "primary family",
            format!(
                "{} ({:.0}% confidence)",
                report.primary_family.family_id,
                report.primary_family.confidence * 100.0
            )
        )
    );

    if let Some(preferred) = report.backends.first() {
        let availability = if preferred.is_available {
            palette.good("available")
        } else {
            palette.warn("unavailable")
        };
        let _ = writeln!(
            &mut output,
            "{}",
            palette.kv(
                "preferred backend",
                format!(
                    "{} [{}] ({:.2}) - {} ({})",
                    preferred.display_name,
                    preferred.backend_id,
                    preferred.score,
                    availability,
                    availability_detail(&preferred.availability_detail)
                )
            )
        );
    } else {
        let _ = writeln!(
            &mut output,
            "{}",
            palette.kv(
                "preferred backend",
                palette.muted("none (no ranked backends for detected family)")
            )
        );
    }

    let available: Vec<_> = report
        .backends
        .iter()
        .filter(|backend| backend.is_available)
        .collect();
    if !available.is_empty() {
        let _ = writeln!(&mut output);
        let _ = writeln!(&mut output, "{}", palette.heading("available backends:"));
        for backend in available {
            let _ = writeln!(
                &mut output,
                "{} {} [{}]: {:.2} - {}; {}",
                palette.bullet("-"),
                palette.good(&backend.display_name),
                backend.backend_id,
                backend.score,
                backend.reason,
                availability_detail(&backend.availability_detail)
            );
        }
    }

    let unavailable: Vec<_> = report
        .backends
        .iter()
        .filter(|backend| !backend.is_available)
        .collect();
    if !unavailable.is_empty() {
        let _ = writeln!(&mut output);
        let _ = writeln!(&mut output, "{}", palette.heading("unavailable backends:"));
        for backend in unavailable {
            let _ = writeln!(
                &mut output,
                "{} {} [{}]: {:.2} - {}; {}",
                palette.bullet("-"),
                palette.warn(&backend.display_name),
                backend.backend_id,
                backend.score,
                backend.reason,
                availability_detail(&backend.availability_detail)
            );
        }
    }

    if !report.host_capabilities.diagnostics.is_empty() {
        let _ = writeln!(&mut output);
        let _ = writeln!(&mut output, "{}", palette.heading("host diagnostics:"));
        for diagnostic in &report.host_capabilities.diagnostics {
            let _ = writeln!(
                &mut output,
                "{} {} {}",
                palette.bullet("-"),
                palette.warn(&diagnostic.summary),
                palette.muted(format!("[{}]", diagnostic.diagnostic_id))
            );
        }
    }

    output
}

/// Panel-mode preflight: the detected device family with a confidence bar,
/// boot-mode evidence, and the ranked backends with score bars.
fn preflight_panel_lines(
    palette: &crate::style::Palette,
    report: &PreflightReport,
    project_mode_summary: Option<&str>,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} Device family: {}  {}",
        palette.dot_ok(),
        palette.good(&report.primary_family.family_id),
        palette.bar(report.primary_family.confidence, 10),
    ));

    if let Some(summary) = project_mode_summary {
        let mut support = None;
        let mut detail = None;
        for line in summary.lines() {
            if let Some((key, value)) = line.split_once(": ") {
                if key == "boot mode support" {
                    support = Some(value.to_string());
                } else if key == "boot mode detail" {
                    detail = Some(value.to_string());
                }
            }
        }
        let dot = match support.as_deref() {
            Some("true-boot-chain") => palette.dot_ok(),
            Some("hybrid-boot-chain") => palette.dot_warn(),
            _ => palette.dot_muted(),
        };
        let mut boot_line = format!(
            "{dot} boot mode: {}",
            support
                .as_deref()
                .map(|mode| match mode {
                    "true-boot-chain" => palette.good(mode),
                    "hybrid-boot-chain" => palette.warn(mode),
                    _ => palette.muted(mode),
                })
                .unwrap_or_else(|| palette.muted("unknown"))
        );
        if let Some(detail) = detail {
            boot_line.push_str(&format!("  {}", palette.muted(format!("— {detail}"))));
        }
        lines.push(boot_line);
    }

    if !report.backends.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Backends"));
        for backend in &report.backends {
            let (dot, name) = if backend.is_available {
                (palette.dot_ok(), palette.good(&backend.display_name))
            } else {
                (palette.dot_bad(), palette.bad(&backend.display_name))
            };
            let mut detail_parts = vec![backend.reason.clone()];
            let availability = if backend.is_available {
                String::new()
            } else {
                format!(
                    " · {}",
                    backend
                        .availability_detail
                        .strip_prefix("unavailable (")
                        .and_then(|trimmed| trimmed.strip_suffix(')'))
                        .unwrap_or(&backend.availability_detail)
                )
            };
            detail_parts.push(format!("[{}{availability}]", backend.backend_id));
            lines.push(format!(
                "{dot} {name}  {}  {}",
                palette.bar(backend.score, 10),
                palette.muted(detail_parts.join(" — ")),
                name = name,
            ));
        }
    }

    if !report.host_capabilities.diagnostics.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Host diagnostics"));
        for diagnostic in &report.host_capabilities.diagnostics {
            lines.push(format!(
                "{} {}  {}",
                palette.dot_warn(),
                palette.warn(&diagnostic.summary),
                palette.muted(format!("[{}]", diagnostic.diagnostic_id))
            ));
        }
    }
    lines
}

/// The hand-off line after a preflight: name the best available backend when
/// one exists, so the next command is copy-pasteable.
fn preflight_next_hint(
    palette: &crate::style::Palette,
    report: &PreflightReport,
    has_project: bool,
) -> String {
    if !has_project {
        return palette.next_hint("fat preflight <project>");
    }
    if let Some(backend) = report.backends.iter().find(|backend| backend.is_available) {
        palette.next_hint(&format!(
            "fat emulate <project> --backend {}",
            backend.backend_id
        ))
    } else {
        palette.next_hint("install or repair a backend (see fat doctor)")
    }
}

fn render_boot_artifact_set(output: &mut String, set: &fat_bootloader::BootArtifactSet) {
    if let Some(primary) = &set.primary {
        let _ = writeln!(
            output,
            "  primary: {} [{}] {}",
            primary.kind, primary.format, primary.path
        );
    } else {
        let _ = writeln!(output, "  primary: none");
    }

    if set.alternates.is_empty() {
        let _ = writeln!(output, "  alternates: none");
    } else {
        for artifact in &set.alternates {
            let _ = writeln!(
                output,
                "  alternate: {} [{}] {}",
                artifact.kind, artifact.format, artifact.path
            );
        }
    }

    if set.missing_requirements.is_empty() {
        let _ = writeln!(output, "  missing: none");
    } else {
        for requirement in &set.missing_requirements {
            let _ = writeln!(output, "  missing: {requirement}");
        }
    }
}

fn inspect_boot_method(discovery: &BootArtifactDiscovery) -> &'static str {
    match discovery
        .primary
        .as_ref()
        .and_then(|set| set.primary.as_ref())
        .map(|artifact| (artifact.kind.as_str(), artifact.format.as_str()))
    {
        Some(("fit", _)) | Some(("kernel", "uImage")) => "bootm",
        Some(("kernel", "zImage")) => "bootz",
        Some(("kernel", "Image")) => "booti",
        Some(_) => "unsupported",
        None => "unknown",
    }
}

fn risky_env_variables(snapshot: &BootloaderSnapshot) -> Vec<&BootEnvVariable> {
    snapshot
        .env_variables
        .iter()
        .filter(|variable| is_risky_bootloader_variable(variable))
        .collect()
}

fn is_risky_bootloader_variable(variable: &BootEnvVariable) -> bool {
    let key = variable.key.to_ascii_lowercase();
    let value = variable.value.trim().to_ascii_lowercase();

    matches!(
        key.as_str(),
        "sig_check" | "verify" | "bootdelay" | "recovery_mode"
    ) || matches!(value.as_str(), "0" | "no" | "false" | "off" | "disabled")
}

#[cfg(test)]
mod tests {
    use super::{
        architecture_signal_from_file_description, detect_architecture, format_size,
        heartbeat_is_due, normalize_bare_path_args_with_exists, resolve_extract_timeout,
        rootfs_filesystem_kind, select_architecture_signal, SignalProvenance,
    };
    use fat_core::inventory::Architecture;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn heartbeat_stays_quiet_until_the_first_interval_passes() {
        let interval = Duration::from_secs(30);
        assert!(!heartbeat_is_due(Duration::from_secs(29), None, interval));
        assert!(heartbeat_is_due(Duration::from_secs(30), None, interval));
    }

    #[test]
    fn heartbeat_reports_at_a_steady_cadence() {
        let interval = Duration::from_secs(30);
        let last = Some(Duration::from_secs(30));
        assert!(!heartbeat_is_due(Duration::from_secs(59), last, interval));
        assert!(heartbeat_is_due(Duration::from_secs(60), last, interval));
    }

    #[test]
    fn sizes_render_in_stable_human_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(50_540_871), "48.2 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn rootfs_kind_comes_from_extractor_naming_and_is_omitted_otherwise() {
        assert_eq!(
            rootfs_filesystem_kind(Path::new("/work/binwalk/squashfs-root")),
            Some("squashfs")
        );
        assert_eq!(
            rootfs_filesystem_kind(Path::new("/work/native/cramfs-root")),
            Some("cramfs")
        );
        assert_eq!(
            rootfs_filesystem_kind(Path::new("/work/extractions/debugfs-root")),
            Some("ext")
        );
        assert_eq!(
            rootfs_filesystem_kind(Path::new("/work/unblob/0-4096.squashfs_v4_le_extract")),
            Some("squashfs")
        );
        // Nothing in the name says what it is, so nothing is claimed.
        assert_eq!(
            rootfs_filesystem_kind(Path::new("/work/unblob/rootfs")),
            None
        );
    }

    #[test]
    fn extract_timeout_flag_wins_and_zero_disables() {
        assert_eq!(
            resolve_extract_timeout(Some(120)).expect("flag parses"),
            Some(Duration::from_secs(120))
        );
        assert_eq!(resolve_extract_timeout(Some(0)).expect("zero parses"), None);
    }

    #[test]
    fn architecture_signal_from_file_description_prefers_mipsel_for_lsb_binaries() {
        let description = "ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), stripped";
        assert_eq!(
            architecture_signal_from_file_description(description),
            Some("arch:mipsel".to_string())
        );
    }

    #[test]
    fn architecture_signal_from_file_description_keeps_big_endian_mips_generic() {
        let description = "ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), stripped";
        assert_eq!(
            architecture_signal_from_file_description(description),
            Some("arch:mips".to_string())
        );
    }

    #[test]
    fn select_architecture_signal_prefers_rootfs_endianness_over_generic_bootloader() {
        assert_eq!(
            select_architecture_signal(
                Some("arch:mipsel".to_string()),
                Some("arch:mips".to_string()),
                Some("arch:mips".to_string()),
                ""
            ),
            Some(("arch:mipsel".to_string(), SignalProvenance::Measured))
        );
    }

    #[test]
    fn detect_architecture_preserves_mipsel_signal() {
        assert_eq!(
            detect_architecture(&["arch:mipsel".to_string()]),
            Architecture::Mipsel
        );
    }

    #[test]
    fn detect_architecture_preserves_arm64_signal() {
        assert_eq!(
            detect_architecture(&["arch:arm64".to_string()]),
            Architecture::Arm64
        );
    }

    #[test]
    fn select_architecture_signal_detects_riscv64() {
        assert_eq!(
            select_architecture_signal(None, None, None, "SiFive riscv64 arch/riscv/"),
            Some((
                "arch:riscv64".to_string(),
                SignalProvenance::StringsFallback
            ))
        );
        assert_eq!(
            detect_architecture(&["arch:riscv64".to_string()]),
            Architecture::Riscv64
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalize_bare_path_args_keeps_dash_leading_non_utf8_paths_unmodified() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut args = vec![
            OsString::from("fat"),
            OsString::from_vec(vec![b'-', b'f', b'w', 0xFF, b'.', b'b', b'i', b'n']),
        ];
        let command = clap::Command::new("fat");

        normalize_bare_path_args_with_exists(&mut args, &command, |_| true);

        assert_eq!(
            args[1],
            OsString::from_vec(vec![b'-', b'f', b'w', 0xFF, b'.', b'b', b'i', b'n'])
        );
        assert_eq!(args.len(), 2);
    }
}
