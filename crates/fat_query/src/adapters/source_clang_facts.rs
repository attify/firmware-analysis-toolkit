use crate::adapters::source::scan_source_facts;
use crate::adapters::traits::ExecutionMode;
use crate::planner::ResourceBudgets;
use crate::result::{
    AdapterDiagnostics, AdequacyForQuery, AdequacyIntent, AdequacyTier, ConfidenceSource,
    EvidenceBasis, LocalityStatus, ParseStatus, ScoreTrace, SourceAnalysisSummary,
    SourceBackendKind, SourceCallFact, SourceEvidenceReport, SourceFactCacheStatus,
    SourceFactCacheTelemetry, SourceMethodFact, VisibilityStatus,
};
use crate::store::{
    load_source_fact_records_for_cache_key, write_source_fact_records, SourceFactRecord,
    SOURCE_FACT_CACHE_SCHEMA_VERSION,
};
use crate::toolchain_profile::{load_toolchain_profile, ToolchainProfile};
use crate::tu_spec::{resolve_tu_spec, resolve_tu_spec_for_codeql_database, TUSpec};
use clang::{Clang, Index};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const FACT_SCHEMA_VERSION: &str = "source-facts-v1";

#[derive(Debug, Clone)]
pub struct SourceAnalysisOptions {
    pub mode: ExecutionMode,
    pub debug_bundle_dir: Option<PathBuf>,
    pub budgets: Option<ResourceBudgets>,
}

impl Default for SourceAnalysisOptions {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: None,
            budgets: None,
        }
    }
}

pub fn maybe_analyze_source_tree(root: &Path) -> Result<Option<SourceAnalysisSummary>, String> {
    maybe_analyze_source_tree_with_options(root, &SourceAnalysisOptions::default())
}

pub fn maybe_analyze_source_tree_with_options(
    root: &Path,
    options: &SourceAnalysisOptions,
) -> Result<Option<SourceAnalysisSummary>, String> {
    let tu_spec = resolve_tu_spec(root, None).ok();
    if let Some(tu_spec) = tu_spec {
        let toolchain_profile = ToolchainProfile::from_arguments(&tu_spec.arguments)
            .merge(load_toolchain_profile(root)?);
        return analyze_with_prepared_tu(root, &tu_spec, &toolchain_profile, options).map(Some);
    }
    if contains_python_sources(root) {
        return Ok(Some(build_scan_only_summary(root, options)?));
    }
    Ok(None)
}

pub fn maybe_analyze_codeql_database_with_options(
    source_root: &Path,
    db_root: &Path,
    options: &SourceAnalysisOptions,
) -> Result<Option<SourceAnalysisSummary>, String> {
    let tu_spec = resolve_tu_spec_for_codeql_database(source_root, db_root, None).ok();
    if let Some(tu_spec) = tu_spec {
        let toolchain_profile = ToolchainProfile::from_arguments(&tu_spec.arguments)
            .merge(load_toolchain_profile(source_root)?);
        return analyze_with_prepared_tu(source_root, &tu_spec, &toolchain_profile, options)
            .map(Some);
    }
    if contains_python_sources(source_root) {
        return Ok(Some(build_scan_only_summary(source_root, options)?));
    }
    Ok(None)
}

fn analyze_with_prepared_tu(
    _root: &Path,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
    options: &SourceAnalysisOptions,
) -> Result<SourceAnalysisSummary, String> {
    let cache_key = compute_source_fact_cache_key(tu_spec, toolchain_profile);
    let cache_path = options
        .debug_bundle_dir
        .as_ref()
        .map(|bundle_dir| bundle_dir.join("source-facts.sqlite"));

    let expected_backends = expected_backends_for_mode(options.mode);
    let mut cache_status = SourceFactCacheStatus::Unavailable;
    let mut cache_observed = Vec::new();
    let mut cache_inferred = Vec::new();
    let reports = if let Some(bundle_dir) = &options.debug_bundle_dir {
        let store_path = bundle_dir.join("source-facts.sqlite");
        match load_cached_reports(&store_path, &cache_key, &expected_backends) {
            Ok(Some(cached_reports)) => {
                cache_status = SourceFactCacheStatus::ReusedCachedReports;
                cache_observed.push(format!(
                    "reused {} cached source reports from {}",
                    cached_reports.len(),
                    store_path.display()
                ));
                materialize_debug_bundle(
                    bundle_dir,
                    tu_spec,
                    toolchain_profile,
                    &cached_reports,
                    false,
                )?;
                cached_reports
            }
            Ok(None) => {
                let fresh_reports = run_source_backends(options.mode, tu_spec, toolchain_profile);
                cache_status = SourceFactCacheStatus::FreshWrite;
                cache_observed.push(format!(
                    "wrote {} fresh source reports to {}",
                    fresh_reports.len(),
                    store_path.display()
                ));
                materialize_debug_bundle(
                    bundle_dir,
                    tu_spec,
                    toolchain_profile,
                    &fresh_reports,
                    true,
                )?;
                fresh_reports
            }
            Err(error) => {
                cache_status = SourceFactCacheStatus::FreshWrite;
                cache_inferred.push(format!("cache read failed, ran fresh analysis: {error}"));
                let fresh_reports = run_source_backends(options.mode, tu_spec, toolchain_profile);
                cache_observed.push(format!(
                    "wrote {} fresh source reports to {}",
                    fresh_reports.len(),
                    store_path.display()
                ));
                materialize_debug_bundle(
                    bundle_dir,
                    tu_spec,
                    toolchain_profile,
                    &fresh_reports,
                    true,
                )?;
                fresh_reports
            }
        }
    } else {
        let fresh_reports = run_source_backends(options.mode, tu_spec, toolchain_profile);
        cache_inferred.push("debug bundle disabled, source fact cache unavailable".into());
        fresh_reports
    };

    let mut merged_observed = BTreeSet::new();
    let mut merged_inferred = BTreeSet::new();
    for report in &reports {
        for observed in &report.diagnostics.observed {
            merged_observed.insert(observed.clone());
        }
        for inferred in &report.diagnostics.inferred {
            merged_inferred.insert(inferred.clone());
        }
    }
    let report_count = reports.len();

    let mut metadata = BTreeMap::new();
    metadata.insert("fact_schema_version".into(), FACT_SCHEMA_VERSION.into());
    metadata.insert("tu_spec_hash".into(), tu_spec.hash.clone());
    metadata.insert("toolchain_profile_hash".into(), toolchain_profile.hash());
    metadata.insert("tu_file".into(), tu_spec.file.display().to_string());
    metadata.insert("mode".into(), options.mode.as_str().into());
    metadata.insert("source_fact_cache_key".into(), cache_key.clone());
    metadata.insert(
        "source_fact_cache_status".into(),
        format!("{cache_status:?}"),
    );
    if let Some(budgets) = &options.budgets {
        metadata.insert(
            "per_tu_timeout_ms".into(),
            budgets.per_tu_timeout_ms.to_string(),
        );
        metadata.insert(
            "max_neighborhood_breadth".into(),
            budgets.max_neighborhood_breadth.to_string(),
        );
    }
    if let Some(bundle_dir) = &options.debug_bundle_dir {
        metadata.insert("debug_bundle_dir".into(), bundle_dir.display().to_string());
        metadata.insert(
            "source_fact_cache_path".into(),
            bundle_dir.join("source-facts.sqlite").display().to_string(),
        );
    }

    Ok(SourceAnalysisSummary {
        reports,
        merged_observed: merged_observed.into_iter().collect(),
        merged_inferred: merged_inferred.into_iter().collect(),
        cache: Some(SourceFactCacheTelemetry {
            cache_key,
            status: cache_status,
            cache_path,
            report_count,
            backend_kinds: expected_backends
                .iter()
                .map(|backend| backend.as_str().to_string())
                .collect(),
            observed: cache_observed,
            inferred: cache_inferred,
        }),
        metadata,
    })
}

fn build_scan_only_summary(
    root: &Path,
    options: &SourceAnalysisOptions,
) -> Result<SourceAnalysisSummary, String> {
    let scanned = scan_source_facts(root)?;
    let observed = vec![
        "text scanner recovered source facts without TU-backed parsing".into(),
        format!("recovered {} methods", scanned.methods.len()),
        format!("recovered {} callsites", scanned.calls.len()),
    ];
    let report = SourceEvidenceReport {
        adapter_id: "source-text-scan".into(),
        backend: SourceBackendKind::TextScan,
        backend_version: "text-scan-v1".into(),
        tu_file: root.to_path_buf(),
        tu_spec_hash: format!("scan-only:{}", root.display()),
        toolchain_profile_hash: "scan-only".into(),
        diagnostics: AdapterDiagnostics {
            visibility: VisibilityStatus::Present,
            parse: ParseStatus::Degraded,
            locality: LocalityStatus::RepoLocal,
            confidence_source: ConfidenceSource::Heuristic,
            observed,
            inferred: vec![format!(
                "mode={} used scan-only source evidence",
                options.mode.as_str()
            )],
            adequacy: vec![AdequacyForQuery {
                family: "source-visibility".into(),
                intent: AdequacyIntent::ReplaySiting,
                tier: AdequacyTier::ReplaySitingAdequate,
                required_facts_satisfied: vec!["method_identity".into(), "callsites".into()],
            }],
        },
        methods: scanned.methods,
        calls: scanned.calls,
        score_trace: ScoreTrace {
            adapters: vec!["source-text-scan".into()],
            family_pack_hits: vec!["source-visibility".into()],
            penalties: vec!["no-tu-context".into()],
            locality_notes: vec!["repo-local source".into()],
        },
    };
    Ok(SourceAnalysisSummary {
        reports: vec![report],
        merged_observed: vec!["text scanner source analysis completed".into()],
        merged_inferred: vec!["scan-only source analysis summary".into()],
        cache: None,
        metadata: BTreeMap::from([
            ("analysis_mode".into(), options.mode.as_str().into()),
            ("analysis_root".into(), root.display().to_string()),
            ("source_analysis_backend".into(), "text-scan".into()),
        ]),
    })
}

fn contains_python_sources(root: &Path) -> bool {
    walkdir::WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
        })
}

fn materialize_debug_bundle(
    bundle_dir: &Path,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
    reports: &[SourceEvidenceReport],
    write_raw_ast: bool,
) -> Result<String, String> {
    std::fs::create_dir_all(bundle_dir).map_err(|e| {
        format!(
            "failed to create debug bundle dir {}: {}",
            bundle_dir.display(),
            e
        )
    })?;
    let cache_key = compute_source_fact_cache_key(tu_spec, toolchain_profile);

    let summary_path = bundle_dir.join("summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "tu_file": tu_spec.file,
            "tu_spec_hash": tu_spec.hash,
            "toolchain_profile_hash": toolchain_profile.hash(),
            "reports": reports,
        }))
        .map_err(|e| format!("failed to serialize source debug bundle: {e}"))?,
    )
    .map_err(|e| format!("failed to write {}: {}", summary_path.display(), e))?;

    for report in reports {
        let report_path = bundle_dir.join(format!("{}-report.json", report.backend.as_str()));
        std::fs::write(
            &report_path,
            serde_json::to_vec_pretty(report).map_err(|e| {
                format!(
                    "failed to serialize {} report: {}",
                    report.backend.as_str(),
                    e
                )
            })?,
        )
        .map_err(|e| format!("failed to write {}: {}", report_path.display(), e))?;
    }

    if write_raw_ast
        && reports
            .iter()
            .any(|report| report.backend == SourceBackendKind::AstDumpJson)
    {
        let raw_ast = run_ast_dump_json(tu_spec)?;
        let ast_path = bundle_dir.join("AstDumpJson.ast.json");
        std::fs::write(&ast_path, raw_ast)
            .map_err(|e| format!("failed to write {}: {}", ast_path.display(), e))?;
    }

    let store_path = bundle_dir.join("source-facts.sqlite");
    let records = reports
        .iter()
        .map(|report| SourceFactRecord {
            cache_key: cache_key.clone(),
            backend_kind: report.backend.as_str().into(),
            backend_version: report.backend_version.clone(),
            fact_schema_version: SOURCE_FACT_CACHE_SCHEMA_VERSION.into(),
            tu_spec_hash: report.tu_spec_hash.clone(),
            toolchain_profile_hash: report.toolchain_profile_hash.clone(),
            query_family_version: Some("source-visibility-v1".into()),
            report: report.clone(),
        })
        .collect::<Vec<_>>();
    write_source_fact_records(&store_path, &records)?;

    Ok(cache_key)
}

fn load_cached_reports(
    store_path: &Path,
    cache_key: &str,
    expected_backends: &[SourceBackendKind],
) -> Result<Option<Vec<SourceEvidenceReport>>, String> {
    if !store_path.is_file() {
        return Ok(None);
    }
    let records = load_source_fact_records_for_cache_key(store_path, cache_key)?;
    if records.is_empty() {
        return Ok(None);
    }
    let mut cached_backends = records
        .iter()
        .map(|record| record.backend_kind.clone())
        .collect::<Vec<_>>();
    cached_backends.sort();
    let mut expected = expected_backends
        .iter()
        .map(|backend| backend.as_str().to_string())
        .collect::<Vec<_>>();
    expected.sort();
    if cached_backends != expected {
        return Ok(None);
    }
    Ok(Some(
        records.into_iter().map(|record| record.report).collect(),
    ))
}

fn run_source_backends(
    mode: ExecutionMode,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
) -> Vec<SourceEvidenceReport> {
    match mode {
        ExecutionMode::Triage => vec![run_backend(
            SourceBackendKind::LibclangBackend,
            tu_spec,
            toolchain_profile,
        )],
        ExecutionMode::Deep => vec![
            run_backend(SourceBackendKind::AstDumpJson, tu_spec, toolchain_profile),
            run_backend(
                SourceBackendKind::LibclangBackend,
                tu_spec,
                toolchain_profile,
            ),
        ],
    }
}

fn expected_backends_for_mode(mode: ExecutionMode) -> Vec<SourceBackendKind> {
    match mode {
        ExecutionMode::Triage => vec![SourceBackendKind::LibclangBackend],
        ExecutionMode::Deep => vec![
            SourceBackendKind::AstDumpJson,
            SourceBackendKind::LibclangBackend,
        ],
    }
}

fn compute_source_fact_cache_key(tu_spec: &TUSpec, toolchain_profile: &ToolchainProfile) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FACT_SCHEMA_VERSION.as_bytes());
    hasher.update(tu_spec.hash.as_bytes());
    hasher.update(toolchain_profile.hash().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn run_backend(
    backend: SourceBackendKind,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
) -> SourceEvidenceReport {
    match backend {
        SourceBackendKind::AstDumpJson => {
            match analyze_with_ast_dump_json(tu_spec, toolchain_profile) {
                Ok(report) => report,
                Err(error) => failed_report(
                    SourceBackendKind::AstDumpJson,
                    tu_spec,
                    toolchain_profile,
                    error,
                ),
            }
        }
        SourceBackendKind::LibclangBackend => {
            match analyze_with_libclang(tu_spec, toolchain_profile) {
                Ok(report) => report,
                Err(error) => failed_report(
                    SourceBackendKind::LibclangBackend,
                    tu_spec,
                    toolchain_profile,
                    error,
                ),
            }
        }
        SourceBackendKind::TextScan => failed_report(
            SourceBackendKind::TextScan,
            tu_spec,
            toolchain_profile,
            "text scan is produced by scan-only source analysis, not direct backend execution"
                .into(),
        ),
        SourceBackendKind::SyntheticSliceRepair => failed_report(
            SourceBackendKind::SyntheticSliceRepair,
            tu_spec,
            toolchain_profile,
            "synthetic slice repair is produced by slice expansion, not direct backend execution"
                .into(),
        ),
    }
}

fn failed_report(
    backend: SourceBackendKind,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
    error: String,
) -> SourceEvidenceReport {
    SourceEvidenceReport {
        adapter_id: "source-clang-facts".into(),
        backend: backend.clone(),
        backend_version: clang_version_string(),
        tu_file: tu_spec.file.clone(),
        tu_spec_hash: tu_spec.hash.clone(),
        toolchain_profile_hash: toolchain_profile.hash(),
        diagnostics: AdapterDiagnostics {
            visibility: VisibilityStatus::Present,
            parse: ParseStatus::Failed,
            locality: LocalityStatus::RepoLocal,
            confidence_source: ConfidenceSource::Direct,
            observed: vec![format!("backend {} failed to parse TU", backend.as_str())],
            inferred: vec![error],
            adequacy: vec![AdequacyForQuery {
                family: "source-visibility".into(),
                intent: AdequacyIntent::Proof,
                tier: AdequacyTier::ProofInadequate,
                required_facts_satisfied: vec![],
            }],
        },
        methods: vec![],
        calls: vec![],
        score_trace: ScoreTrace {
            adapters: vec!["source-clang-facts".into()],
            family_pack_hits: vec![],
            penalties: vec!["parse_failed".into()],
            locality_notes: vec![],
        },
    }
}

fn analyze_with_ast_dump_json(
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
) -> Result<SourceEvidenceReport, String> {
    let output = run_ast_dump_json(tu_spec)?;
    let ast: Value = serde_json::from_str(&output)
        .map_err(|e| format!("failed to parse clang AST JSON: {e}"))?;
    let extraction = extract_from_ast_json(&ast, &tu_spec.file);
    let method_count = extraction.methods.len();
    let call_count = extraction.calls.len();
    Ok(build_report(
        SourceBackendKind::AstDumpJson,
        tu_spec,
        toolchain_profile,
        extraction.methods,
        extraction.calls,
        vec![
            "clang ast-dump=json succeeded".into(),
            format!("recovered {} methods", method_count),
            format!("recovered {} callsites", call_count),
        ],
        vec![],
        vec![],
    ))
}

fn analyze_with_libclang(
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
) -> Result<SourceEvidenceReport, String> {
    // clang-sys honors LIBCLANG_PATH and discovers platform toolchain directories.
    let clang = Clang::new().map_err(|e| format!("failed to initialize libclang: {e:?}"))?;
    let index = Index::new(&clang, false, false);
    let normalized_args = normalized_clang_arguments(tu_spec);
    let arg_refs = normalized_args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    index
        .parser(&tu_spec.file)
        .arguments(&arg_refs)
        .parse()
        .map_err(|e| format!("libclang parse failed: {e:?}"))?;

    let output = run_ast_dump_json(tu_spec)?;
    let ast: Value = serde_json::from_str(&output)
        .map_err(|e| format!("failed to parse clang AST JSON after libclang validation: {e}"))?;
    let extraction = extract_from_ast_json(&ast, &tu_spec.file);
    let method_count = extraction.methods.len();
    let call_count = extraction.calls.len();
    Ok(build_report(
        SourceBackendKind::LibclangBackend,
        tu_spec,
        toolchain_profile,
        extraction.methods,
        extraction.calls,
        vec![
            "libclang parse succeeded".into(),
            "shared AST normalizer recovered source facts".into(),
            format!("recovered {} methods", method_count),
            format!("recovered {} callsites", call_count),
        ],
        vec!["libclang validation succeeded before normalization".into()],
        vec![],
    ))
}

fn build_report(
    backend: SourceBackendKind,
    tu_spec: &TUSpec,
    toolchain_profile: &ToolchainProfile,
    methods: Vec<SourceMethodFact>,
    calls: Vec<SourceCallFact>,
    mut observed: Vec<String>,
    inferred: Vec<String>,
    penalties: Vec<String>,
) -> SourceEvidenceReport {
    if !toolchain_profile.is_complete() {
        observed.push("toolchain profile is incomplete".into());
    }
    let adequacy = vec![
        AdequacyForQuery {
            family: "source-visibility".into(),
            intent: AdequacyIntent::ReplaySiting,
            tier: AdequacyTier::ReplaySitingAdequate,
            required_facts_satisfied: vec!["method_identity".into(), "callsites".into()],
        },
        AdequacyForQuery {
            family: "source-visibility".into(),
            intent: AdequacyIntent::VariantHunting,
            tier: if methods.is_empty() || calls.is_empty() {
                AdequacyTier::ProofInadequate
            } else {
                AdequacyTier::VariantHuntingAdequate
            },
            required_facts_satisfied: vec![
                "file_line_provenance".into(),
                "enclosing_symbol".into(),
            ],
        },
        AdequacyForQuery {
            family: "source-visibility".into(),
            intent: AdequacyIntent::Proof,
            tier: AdequacyTier::ProofInadequate,
            required_facts_satisfied: vec![],
        },
    ];
    SourceEvidenceReport {
        adapter_id: "source-clang-facts".into(),
        backend: backend.clone(),
        backend_version: clang_version_string(),
        tu_file: tu_spec.file.clone(),
        tu_spec_hash: tu_spec.hash.clone(),
        toolchain_profile_hash: toolchain_profile.hash(),
        diagnostics: AdapterDiagnostics {
            visibility: VisibilityStatus::Present,
            parse: if toolchain_profile.is_complete() {
                ParseStatus::Parsed
            } else {
                ParseStatus::Degraded
            },
            locality: LocalityStatus::RepoLocal,
            confidence_source: ConfidenceSource::Direct,
            observed,
            inferred,
            adequacy,
        },
        methods,
        calls,
        score_trace: ScoreTrace {
            adapters: vec![format!("source-clang-facts/{}", backend.as_str())],
            family_pack_hits: vec!["source-visibility".into()],
            penalties,
            locality_notes: vec!["repo-local source".into()],
        },
    }
}

fn normalized_clang_arguments(tu_spec: &TUSpec) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut iter = tu_spec.arguments.iter().peekable();
    if iter
        .peek()
        .is_some_and(|arg| arg.contains("clang") || arg.ends_with("cc") || arg.ends_with("c++"))
    {
        iter.next();
    }
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" => continue,
            "-o" => {
                iter.next();
                continue;
            }
            _ => {}
        }
        let path = PathBuf::from(arg);
        if path == tu_spec.file {
            continue;
        }
        normalized.push(arg.clone());
    }
    normalized
}

fn run_ast_dump_json(tu_spec: &TUSpec) -> Result<String, String> {
    // This runs the clang *driver*, not libclang. A host can have libclang
    // installed and still fail here, so the error has to name the binary.
    let driver = tu_spec
        .arguments
        .first()
        .cloned()
        .unwrap_or_else(|| "clang++".into());
    let mut command = Command::new(&driver);
    let normalized = normalized_clang_arguments(tu_spec);
    command.args(&normalized);
    command.arg("-fsyntax-only");
    command.arg("-Xclang");
    command.arg("-ast-dump=json");
    command.arg(&tu_spec.file);
    command.current_dir(&tu_spec.directory);
    let output = command.output().map_err(|e| {
        format!("failed to run `{driver}` for the clang AST dump: {e}. The clang driver has to be on PATH; libclang alone is not enough.")
    })?;
    if !output.status.success() {
        return Err(format!(
            "clang AST dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("invalid utf8 in clang AST dump: {e}"))
}

fn extract_from_ast_json(ast: &Value, source_file: &Path) -> Extraction {
    let mut extraction = Extraction::default();
    walk_ast(ast, source_file, None, None, &mut extraction);
    dedup_extraction(&mut extraction);
    extraction
}

#[derive(Default)]
struct Extraction {
    methods: Vec<SourceMethodFact>,
    calls: Vec<SourceCallFact>,
}

fn walk_ast(
    node: &Value,
    source_file: &Path,
    current_method: Option<&SourceMethodFact>,
    inherited_line: Option<u32>,
    extraction: &mut Extraction,
) {
    let kind = node.get("kind").and_then(Value::as_str).unwrap_or_default();
    let line = node
        .get("loc")
        .and_then(|loc| loc.get("line"))
        .and_then(Value::as_u64)
        .map(|line| line as u32)
        .or_else(|| {
            node.get("range")
                .and_then(|range| range.get("begin"))
                .and_then(|begin| begin.get("line"))
                .and_then(Value::as_u64)
                .map(|line| line as u32)
        })
        .or(inherited_line);

    let mut next_method = current_method.cloned();
    if matches!(kind, "FunctionDecl" | "CXXMethodDecl" | "ObjCMethodDecl") {
        if let Some(method) = build_method_fact(node, source_file, line.unwrap_or_default()) {
            extraction.methods.push(method.clone());
            next_method = Some(method);
        }
    }
    if kind == "CallExpr" {
        if let Some(call) = build_call_fact(
            node,
            source_file,
            next_method.as_ref(),
            line.unwrap_or_default(),
        ) {
            extraction.calls.push(call);
        }
    }

    for child in node
        .get("inner")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk_ast(child, source_file, next_method.as_ref(), line, extraction);
    }
}

fn build_method_fact(node: &Value, source_file: &Path, line: u32) -> Option<SourceMethodFact> {
    if line == 0 {
        return None;
    }
    let name = node.get("name").and_then(Value::as_str)?;
    let begin_line = node
        .get("range")
        .and_then(|range| range.get("begin"))
        .and_then(|begin| begin.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(line as u64) as u32;
    let end_line = node
        .get("range")
        .and_then(|range| range.get("end"))
        .and_then(|end| end.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(begin_line as u64) as u32;
    let signature_hash = hash_signature(name, begin_line, end_line);
    Some(SourceMethodFact {
        qualified_name: name.to_string(),
        signature_hash,
        file: source_file.to_path_buf(),
        line,
        begin_line,
        end_line,
    })
}

fn build_call_fact(
    node: &Value,
    source_file: &Path,
    current_method: Option<&SourceMethodFact>,
    line: u32,
) -> Option<SourceCallFact> {
    if line == 0 {
        return None;
    }
    let callee = find_callee_name(node)?;
    let enclosing_symbol = current_method
        .map(|method| method.qualified_name.clone())
        .unwrap_or_else(|| "<global>".into());
    Some(SourceCallFact {
        callee_name: callee,
        enclosing_symbol,
        file: source_file.to_path_buf(),
        line,
        basis: EvidenceBasis::ObservedFromAstFacts,
    })
}

fn find_callee_name(node: &Value) -> Option<String> {
    for child in node
        .get("inner")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = find_callee_name_in_child(child) {
            return Some(name);
        }
    }
    None
}

fn find_callee_name_in_child(node: &Value) -> Option<String> {
    if node.get("kind").and_then(Value::as_str) == Some("DeclRefExpr") {
        return node
            .get("referencedDecl")
            .and_then(|decl| decl.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
    }
    for child in node
        .get("inner")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = find_callee_name_in_child(child) {
            return Some(name);
        }
    }
    None
}

fn dedup_extraction(extraction: &mut Extraction) {
    let mut seen_methods = BTreeSet::new();
    extraction.methods.retain(|method| {
        seen_methods.insert((
            method.qualified_name.clone(),
            method.begin_line,
            method.end_line,
        ))
    });
    let mut seen_calls = BTreeSet::new();
    extraction.calls.retain(|call| {
        seen_calls.insert((
            call.callee_name.clone(),
            call.enclosing_symbol.clone(),
            call.line,
        ))
    });
}

fn hash_signature(name: &str, begin_line: u32, end_line: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{name}:{begin_line}:{end_line}").as_bytes());
    format!("{:x}", hasher.finalize())
}

fn clang_version_string() -> String {
    Command::new("clang++")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|text| text.lines().next().map(str::to_string))
        })
        .unwrap_or_else(|| "unknown clang".into())
}
