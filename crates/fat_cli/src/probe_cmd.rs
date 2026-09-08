use crate::debug_cmd;
use crate::runtime_augment::{self, RuntimeAugmentationReport, RuntimeDecision};
use crate::trace_ingest_cmd;
use fat_query::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord, Provenance};
use fat_query::store::{init_snapshot, GraphWriter, SnapshotMeta};
use fat_taint::TaintFinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub(crate) fn evaluate_probe(
    taint_path: &Path,
    trace_path: &Path,
    marker: Option<&str>,
) -> DynResult<RuntimeAugmentationReport> {
    let taint_json = fs::read_to_string(taint_path)?;
    let findings: Vec<TaintFinding> = serde_json::from_str(&taint_json)?;
    let trace = trace_ingest_cmd::load_trace_report(trace_path)?;
    Ok(runtime_augment::augment_findings(&findings, &trace, marker))
}

pub(crate) fn run_evaluate(
    taint_path: &Path,
    trace_path: &Path,
    marker: Option<&str>,
    json: bool,
    evidence_snapshot: Option<&Path>,
) -> DynResult<()> {
    let report = evaluate_probe(taint_path, trace_path, marker)?;
    if let Some(snapshot_path) = evidence_snapshot {
        write_runtime_evidence_snapshot(snapshot_path, &report, trace_path, marker)?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!(
            "{}",
            runtime_augment::render_runtime_augmentation_summary(&report)
        );
    }
    Ok(())
}

pub(crate) fn run_plan(
    target_class: &str,
    architecture: Option<&str>,
    file: Option<&Path>,
    taint: Option<&Path>,
    peripheral_map: Option<&Path>,
    output: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let plan = build_probe_plan(ProbePlanRequest {
        target_class: ProbeTargetClass::parse(target_class)?,
        architecture,
        file,
        taint,
        peripheral_map,
    })?;
    let contents = serde_json::to_string_pretty(&plan)?;
    if let Some(output_path) = output {
        fs::write(output_path, &contents)?;
    }
    if json {
        println!("{contents}");
    } else {
        print!("{}", render_probe_plan(&plan));
    }
    Ok(())
}

pub(crate) fn run_ingest_runner(
    trace_path: &Path,
    json: bool,
    evidence_snapshot: Option<&Path>,
) -> DynResult<()> {
    let contents = fs::read_to_string(trace_path)?;
    let mut report = ingest_runner_jsonl(&contents);
    report.source_path = Some(trace_path.display().to_string());
    if let Some(snapshot_path) = evidence_snapshot {
        write_runner_evidence_snapshot(snapshot_path, &report, trace_path)?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_runner_ingest_report(&report));
    }
    Ok(())
}

pub(crate) fn run_enrich_svd(svd_path: &Path, output: Option<&Path>, json: bool) -> DynResult<()> {
    let contents = fs::read_to_string(svd_path)?;
    let enrichment = parse_svd_enrichment(&contents, svd_path)?;
    let rendered_json = serde_json::to_string_pretty(&enrichment)?;
    if let Some(output_path) = output {
        fs::write(output_path, &rendered_json)?;
    }
    if json {
        println!("{rendered_json}");
    } else {
        print!("{}", render_svd_enrichment(&enrichment));
    }
    Ok(())
}

pub(crate) fn run_probe(
    project_dir: &Path,
    session_id: Option<&str>,
    taint_path: &Path,
    trace_path: &Path,
    inject_http: &str,
    marker: Option<&str>,
    timeout_seconds: u64,
    json: bool,
    evidence_snapshot: Option<&Path>,
) -> DynResult<()> {
    let marker = marker
        .map(str::to_string)
        .unwrap_or_else(generate_probe_marker);
    let request = ProbeRunRequest {
        project_dir,
        session_id,
        taint_path,
        trace_path,
        inject_http,
        marker: &marker,
        timeout: Duration::from_secs(timeout_seconds),
    };
    validate_probe_run_request(&request)?;
    let http_spec = parse_http_probe_spec(request.inject_http)?;
    let injection_command = build_http_probe_command(&http_spec, request.marker)?;

    debug_cmd::run_shell(
        request.project_dir,
        request.session_id,
        Some(&injection_command),
    )?;
    let trace_wait = wait_for_trace_marker(request.trace_path, request.marker, request.timeout)?;
    let evaluation = evaluate_probe(request.taint_path, request.trace_path, Some(request.marker))?;
    if let Some(snapshot_path) = evidence_snapshot {
        write_runtime_evidence_snapshot(
            snapshot_path,
            &evaluation,
            request.trace_path,
            Some(request.marker),
        )?;
    }
    let report = ProbeRunReport {
        marker,
        injection_command,
        trace_wait: trace_wait.as_str().to_string(),
        evaluation,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("marker: {}", report.marker);
        println!("injection: {}", report.injection_command);
        println!("trace wait: {}", report.trace_wait);
        print!(
            "{}",
            runtime_augment::render_runtime_augmentation_summary(&report.evaluation)
        );
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpProbeSpec {
    method: String,
    path: String,
    body: Option<String>,
}

struct ProbeRunRequest<'a> {
    project_dir: &'a Path,
    session_id: Option<&'a str>,
    taint_path: &'a Path,
    trace_path: &'a Path,
    inject_http: &'a str,
    marker: &'a str,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeTargetClass {
    Linux,
    Uefi,
    Mcu,
    BareMetal,
}

impl ProbeTargetClass {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux" => Ok(Self::Linux),
            "uefi" => Ok(Self::Uefi),
            "mcu" => Ok(Self::Mcu),
            "bare-metal" | "baremetal" => Ok(Self::BareMetal),
            other => Err(format!(
                "unsupported probe target class {other}; expected linux, uefi, mcu, or bare-metal"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Uefi => "uefi",
            Self::Mcu => "mcu",
            Self::BareMetal => "bare-metal",
        }
    }
}

struct ProbePlanRequest<'a> {
    target_class: ProbeTargetClass,
    architecture: Option<&'a str>,
    file: Option<&'a Path>,
    taint: Option<&'a Path>,
    peripheral_map: Option<&'a Path>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProbePlan {
    schema_version: u32,
    target_class: String,
    architecture: Option<String>,
    inputs: Vec<ProbePlanInput>,
    probes: Vec<ProbePlanStep>,
    runner_requirements: Vec<String>,
    evidence_expectations: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProbePlanInput {
    kind: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProbePlanStep {
    intent: String,
    target: String,
    oracle: String,
    evidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RunnerIngestReport {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_path: Option<String>,
    event_count: usize,
    parse_error_count: usize,
    events: Vec<RunnerEvent>,
    errors: Vec<RunnerParseError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RunnerEvent {
    line: usize,
    payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunnerParseError {
    line: usize,
    error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SvdEnrichment {
    schema_version: u32,
    source_kind: String,
    source_path: String,
    device: String,
    peripherals: Vec<SvdPeripheral>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SvdPeripheral {
    name: String,
    base_address: String,
    registers: Vec<SvdRegister>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SvdRegister {
    name: String,
    address_offset: String,
    fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceWaitOutcome {
    MarkerObserved,
    MarkerNotObserved,
}

impl TraceWaitOutcome {
    fn as_str(self) -> &'static str {
        match self {
            TraceWaitOutcome::MarkerObserved => "marker-observed",
            TraceWaitOutcome::MarkerNotObserved => "marker-not-observed",
        }
    }
}

#[derive(Debug, Serialize)]
struct ProbeRunReport {
    marker: String,
    injection_command: String,
    trace_wait: String,
    evaluation: RuntimeAugmentationReport,
}

fn validate_probe_run_request(request: &ProbeRunRequest<'_>) -> Result<(), String> {
    if request.session_id.is_none() {
        return Err(
            "fat probe run is a session-attached MVP and requires --session-id; use fat probe evaluate --taint <taint.json> --trace <trace.jsonl> after capturing a trace without a live session"
                .to_string(),
        );
    }
    if request.inject_http.trim().is_empty() {
        return Err("--inject-http must not be empty".to_string());
    }
    if request.marker.trim().is_empty() {
        return Err("--marker must not be empty".to_string());
    }

    Ok(())
}

fn wait_for_trace_marker(
    trace_path: &Path,
    marker: &str,
    timeout: Duration,
) -> Result<TraceWaitOutcome, String> {
    let started = Instant::now();
    loop {
        if trace_path.exists() {
            let trace = fs::read_to_string(trace_path)
                .map_err(|err| format!("failed to read trace {}: {err}", trace_path.display()))?;
            if trace.contains(marker) {
                return Ok(TraceWaitOutcome::MarkerObserved);
            }
            if started.elapsed() >= timeout {
                return Ok(TraceWaitOutcome::MarkerNotObserved);
            }
        } else if started.elapsed() >= timeout {
            return Err(format!(
                "trace file was not created before timeout: {}. Capture a trace and run fat probe evaluate --taint <taint.json> --trace <trace.jsonl>",
                trace_path.display()
            ));
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parse_http_probe_spec(input: &str) -> Result<HttpProbeSpec, String> {
    let mut parts = input.splitn(3, char::is_whitespace);
    let method = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HTTP probe spec requires a method".to_string())?
        .to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST") {
        return Err(format!(
            "unsupported HTTP probe method {method}; expected GET or POST"
        ));
    }

    let path = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HTTP probe spec requires a path".to_string())?
        .to_string();
    if !path.starts_with('/') {
        return Err(format!("HTTP probe path must start with '/': {path}"));
    }

    let body = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if method == "GET" && body.is_some() {
        return Err("GET HTTP probe spec must not include a body".to_string());
    }

    Ok(HttpProbeSpec { method, path, body })
}

fn build_http_probe_command(spec: &HttpProbeSpec, marker: &str) -> Result<String, String> {
    if spec.path.contains('\'') {
        return Err("HTTP probe path must not contain a single quote".to_string());
    }
    let path = spec.path.replace("MARKER", marker);
    let mut command = format!("curl -sS -X {} http://127.0.0.1{}", spec.method, path);

    if let Some(body) = &spec.body {
        if body.contains('\'') {
            return Err("HTTP probe body must not contain a single quote".to_string());
        }
        command.push_str(" --data '");
        command.push_str(&body.replace("MARKER", marker));
        command.push('\'');
    }

    Ok(command)
}

fn build_probe_plan(request: ProbePlanRequest<'_>) -> Result<ProbePlan, String> {
    let mut inputs = Vec::new();
    if let Some(path) = request.file {
        inputs.push(ProbePlanInput {
            kind: "firmware-image".to_string(),
            path: path.display().to_string(),
        });
    }
    if let Some(path) = request.taint {
        inputs.push(ProbePlanInput {
            kind: "taint-findings".to_string(),
            path: path.display().to_string(),
        });
    }
    if let Some(path) = request.peripheral_map {
        inputs.push(ProbePlanInput {
            kind: "peripheral-map".to_string(),
            path: path.display().to_string(),
        });
    }

    let (probes, runner_requirements, evidence_expectations, notes) = match request.target_class {
        ProbeTargetClass::Linux => (
            vec![ProbePlanStep {
                intent: "linux-http-marker-injection".to_string(),
                target: "http-service-via-existing-debug-session".to_string(),
                oracle: "marker-observed-in-tcg-hook-trace".to_string(),
                evidence: "trace-ingest-json-or-jsonl".to_string(),
            }],
            vec![
                "fat-debug-session".to_string(),
                "tcg-hook-plugin-or-trace-report".to_string(),
            ],
            vec!["runtime-capture:instrument-trace-summary".to_string()],
            vec!["Use fat probe run/evaluate for the closed Linux appliance loop.".to_string()],
        ),
        ProbeTargetClass::Uefi => (
            vec![
                ProbePlanStep {
                    intent: "uefi-variable-enumeration".to_string(),
                    target: "uefi-variable-store".to_string(),
                    oracle: "runner-reports-variable-name-and-access-path".to_string(),
                    evidence: "runner-jsonl-event".to_string(),
                },
                ProbePlanStep {
                    intent: "uefi-service-table-check".to_string(),
                    target: "efi-system-table-and-boot-services".to_string(),
                    oracle: "runner-reports-service-table-observation".to_string(),
                    evidence: "runner-jsonl-event".to_string(),
                },
            ],
            vec![
                "external-runner-required".to_string(),
                "uefi-aware-runner".to_string(),
            ],
            vec!["runtime-capture:external-runner-jsonl".to_string()],
            vec![
                "FAT emits the plan and ingests evidence; a UEFI runner executes the probes."
                    .to_string(),
            ],
        ),
        ProbeTargetClass::Mcu | ProbeTargetClass::BareMetal => (
            vec![
                ProbePlanStep {
                    intent: "mcu-peripheral-register-read".to_string(),
                    target: "peripheral-map-register-surface".to_string(),
                    oracle: "runner-reports-register-read-or-fault".to_string(),
                    evidence: "runner-jsonl-event".to_string(),
                },
                ProbePlanStep {
                    intent: "mcu-vector-table-context".to_string(),
                    target: "interrupt-vector-table".to_string(),
                    oracle: "runner-reports-vector-or-exception-context".to_string(),
                    evidence: "runner-jsonl-event".to_string(),
                },
            ],
            vec![
                "external-runner-required".to_string(),
                "bare-metal-or-mcu-runner".to_string(),
            ],
            vec!["runtime-capture:external-runner-jsonl".to_string()],
            vec![
                "SVD/CMSIS/vendor packs may enrich register names; FAT does not execute MMIO directly."
                    .to_string(),
            ],
        ),
    };

    Ok(ProbePlan {
        schema_version: 1,
        target_class: request.target_class.as_str().to_string(),
        architecture: request.architecture.map(str::to_string),
        inputs,
        probes,
        runner_requirements,
        evidence_expectations,
        notes,
    })
}

fn render_probe_plan(plan: &ProbePlan) -> String {
    let mut output = String::new();
    output.push_str(&format!("probe plan: {}\n", plan.target_class));
    if let Some(architecture) = &plan.architecture {
        output.push_str(&format!("architecture: {architecture}\n"));
    }
    if !plan.runner_requirements.is_empty() {
        output.push_str("runner requirements:\n");
        for requirement in &plan.runner_requirements {
            output.push_str(&format!("  - {requirement}\n"));
        }
    }
    if !plan.probes.is_empty() {
        output.push_str("probes:\n");
        for probe in &plan.probes {
            output.push_str(&format!(
                "  - {} -> {} ({})\n",
                probe.intent, probe.target, probe.oracle
            ));
        }
    }
    output
}

fn ingest_runner_jsonl(content: &str) -> RunnerIngestReport {
    let mut events = Vec::new();
    let mut errors = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(payload @ Value::Object(_)) => events.push(RunnerEvent {
                line: line_number,
                payload,
            }),
            Ok(_) => errors.push(RunnerParseError {
                line: line_number,
                error: "runner event must be a JSON object".to_string(),
            }),
            Err(error) => errors.push(RunnerParseError {
                line: line_number,
                error: error.to_string(),
            }),
        }
    }

    RunnerIngestReport {
        schema_version: 1,
        source_path: None,
        event_count: events.len(),
        parse_error_count: errors.len(),
        events,
        errors,
    }
}

fn render_runner_ingest_report(report: &RunnerIngestReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("runner events: {}\n", report.event_count));
    output.push_str(&format!("parse errors: {}\n", report.parse_error_count));
    if let Some(path) = &report.source_path {
        output.push_str(&format!("source: {path}\n"));
    }
    output
}

fn write_runner_evidence_snapshot(
    snapshot_path: &Path,
    report: &RunnerIngestReport,
    trace_path: &Path,
) -> Result<(), String> {
    init_snapshot(
        snapshot_path,
        &SnapshotMeta::new("fat-probe", "runner-evidence"),
    )?;
    let mut writer = GraphWriter::open(snapshot_path)?;
    let mut source_attrs = BTreeMap::new();
    source_attrs.insert("artifact_kind".to_string(), "runtime-capture".to_string());
    source_attrs.insert("trace".to_string(), trace_path.display().to_string());
    source_attrs.insert("event_count".to_string(), report.event_count.to_string());
    source_attrs.insert(
        "parse_error_count".to_string(),
        report.parse_error_count.to_string(),
    );
    let source_node = NodeRecord {
        id: 0,
        kind: NodeKind::Source,
        label: format!("runner-trace:{}", trace_path.display()),
        attrs: source_attrs,
        provenance: runner_provenance(),
    };
    let source_id = writer.insert_node(&source_node)?;

    for event in &report.events {
        let mut attrs = BTreeMap::new();
        attrs.insert("artifact_kind".to_string(), "runtime-capture".to_string());
        attrs.insert("line".to_string(), event.line.to_string());
        attrs.insert("payload_json".to_string(), event.payload.to_string());
        if let Some(runner) = event.payload.get("runner").and_then(Value::as_str) {
            attrs.insert("runner".to_string(), runner.to_string());
        }
        if let Some(event_name) = event.payload.get("event").and_then(Value::as_str) {
            attrs.insert("runner_event".to_string(), event_name.to_string());
        }
        let label = event
            .payload
            .get("event")
            .and_then(Value::as_str)
            .map(|event_name| format!("runner-event:{event_name}"))
            .unwrap_or_else(|| format!("runner-event:line-{}", event.line));
        let event_node = NodeRecord {
            id: 0,
            kind: NodeKind::RuntimeEvent,
            label,
            attrs,
            provenance: runner_provenance(),
        };
        let event_id = writer.insert_node(&event_node)?;
        let mut edge = EdgeRecord::new(EdgeKind::DefUse, source_id, event_id);
        edge.attrs.insert(
            "relationship".to_string(),
            "contains-runner-event".to_string(),
        );
        edge.provenance = runner_provenance();
        writer.insert_edge(&edge)?;
    }

    Ok(())
}

fn runner_provenance() -> Provenance {
    Provenance {
        source: "fat probe runner ingest".to_string(),
        confidence_millis: 850,
    }
}

fn parse_svd_enrichment(content: &str, source_path: &Path) -> Result<SvdEnrichment, String> {
    let device =
        extract_tag(content, "name").ok_or_else(|| "SVD device is missing <name>".to_string())?;
    let mut peripherals = Vec::new();
    for peripheral_block in extract_blocks(content, "peripheral") {
        let name = extract_tag(&peripheral_block, "name")
            .ok_or_else(|| "SVD peripheral is missing <name>".to_string())?;
        let base_address = extract_tag(&peripheral_block, "baseAddress").unwrap_or_default();
        let mut registers = Vec::new();
        for register_block in extract_blocks(&peripheral_block, "register") {
            let register_name = extract_tag(&register_block, "name")
                .ok_or_else(|| format!("SVD register in {name} is missing <name>"))?;
            let address_offset = extract_tag(&register_block, "addressOffset").unwrap_or_default();
            let fields = extract_blocks(&register_block, "field")
                .into_iter()
                .filter_map(|field_block| extract_tag(&field_block, "name"))
                .collect();
            registers.push(SvdRegister {
                name: register_name,
                address_offset,
                fields,
            });
        }
        peripherals.push(SvdPeripheral {
            name,
            base_address,
            registers,
        });
    }

    Ok(SvdEnrichment {
        schema_version: 1,
        source_kind: "vendor-svd".to_string(),
        source_path: source_path.display().to_string(),
        device,
        peripherals,
        notes: vec![
            "Vendor SVD/CMSIS metadata is enrichment input, not FAT's canonical register database."
                .to_string(),
        ],
    })
}

fn render_svd_enrichment(enrichment: &SvdEnrichment) -> String {
    let register_count: usize = enrichment
        .peripherals
        .iter()
        .map(|peripheral| peripheral.registers.len())
        .sum();
    format!(
        "svd enrichment: {}\nperipherals: {}\nregisters: {}\nsource: {}\n",
        enrichment.device,
        enrichment.peripherals.len(),
        register_count,
        enrichment.source_path
    )
}

fn extract_tag(content: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = content.find(&open)? + open.len();
    let end = content[start..].find(&close)? + start;
    Some(content[start..end].trim().to_string())
}

fn extract_blocks(content: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut remaining = content;
    while let Some(start_index) = remaining.find(&open) {
        let after_open = start_index + open.len();
        let Some(end_relative) = remaining[after_open..].find(&close) else {
            break;
        };
        let end_index = after_open + end_relative;
        blocks.push(remaining[after_open..end_index].to_string());
        let after_close = end_index + close.len();
        remaining = &remaining[after_close..];
    }
    blocks
}

fn write_runtime_evidence_snapshot(
    snapshot_path: &Path,
    report: &RuntimeAugmentationReport,
    trace_path: &Path,
    marker: Option<&str>,
) -> Result<(), String> {
    init_snapshot(
        snapshot_path,
        &SnapshotMeta::new("fat-probe", "runtime-evidence"),
    )?;
    let mut writer = GraphWriter::open(snapshot_path)?;

    for finding in &report.findings {
        let mut finding_attrs = BTreeMap::new();
        finding_attrs.insert("finding_id".to_string(), finding.id.clone());
        finding_attrs.insert("title".to_string(), finding.title.clone());
        finding_attrs.insert("decision".to_string(), format!("{:?}", finding.decision));
        finding_attrs.insert(
            "runtime_status".to_string(),
            format!("{:?}", finding.runtime_status),
        );
        finding_attrs.insert(
            "runtime_severity".to_string(),
            format!("{:?}", finding.runtime_severity),
        );
        finding_attrs.insert("trace".to_string(), trace_path.display().to_string());
        if let Some(marker) = marker {
            finding_attrs.insert("marker".to_string(), marker.to_string());
        }
        let finding_node = NodeRecord {
            id: 0,
            kind: NodeKind::Observation,
            label: format!("taint-finding:{}", finding.id),
            attrs: finding_attrs,
            provenance: runtime_provenance(),
        };
        let finding_id = writer.insert_node(&finding_node)?;

        let mut observed_any_step = false;
        for observation in finding
            .observations
            .iter()
            .filter(|observation| observation.observed)
        {
            observed_any_step = true;
            let mut event_attrs = BTreeMap::new();
            event_attrs.insert("finding_id".to_string(), finding.id.clone());
            event_attrs.insert("function".to_string(), observation.function.clone());
            event_attrs.insert(
                "chain_index".to_string(),
                observation.chain_index.to_string(),
            );
            event_attrs.insert(
                "marker_observed".to_string(),
                observation.marker_observed.to_string(),
            );
            event_attrs.insert("trace".to_string(), trace_path.display().to_string());
            if let Some(line) = observation.event_line {
                event_attrs.insert("event_line".to_string(), line.to_string());
            }
            if let Some(address) = &observation.event_address {
                event_attrs.insert("event_address".to_string(), address.clone());
            }
            if !observation.observed_strings.is_empty() {
                event_attrs.insert(
                    "observed_strings".to_string(),
                    observation.observed_strings.join("; "),
                );
            }

            let event_node = NodeRecord {
                id: 0,
                kind: NodeKind::RuntimeEvent,
                label: format!("runtime:{}:{}", finding.id, observation.function),
                attrs: event_attrs,
                provenance: runtime_provenance(),
            };
            let event_id = writer.insert_node(&event_node)?;
            if let Some(edge_kind) = runtime_edge_kind(&finding.decision) {
                let mut edge = EdgeRecord::new(edge_kind, event_id, finding_id);
                edge.attrs
                    .insert("finding_id".to_string(), finding.id.clone());
                edge.attrs
                    .insert("reason".to_string(), finding.decision_reason.clone());
                edge.provenance = runtime_provenance();
                writer.insert_edge(&edge)?;
            }
        }

        if !observed_any_step {
            let mut event_attrs = BTreeMap::new();
            event_attrs.insert("finding_id".to_string(), finding.id.clone());
            event_attrs.insert("decision".to_string(), format!("{:?}", finding.decision));
            event_attrs.insert("trace".to_string(), trace_path.display().to_string());
            if let Some(marker) = marker {
                event_attrs.insert("marker".to_string(), marker.to_string());
            }
            let event_node = NodeRecord {
                id: 0,
                kind: NodeKind::RuntimeEvent,
                label: format!("runtime:{}:no-observation", finding.id),
                attrs: event_attrs,
                provenance: runtime_provenance(),
            };
            let event_id = writer.insert_node(&event_node)?;
            if let Some(edge_kind) = runtime_edge_kind(&finding.decision) {
                let mut edge = EdgeRecord::new(edge_kind, event_id, finding_id);
                edge.attrs
                    .insert("finding_id".to_string(), finding.id.clone());
                edge.attrs
                    .insert("reason".to_string(), finding.decision_reason.clone());
                edge.provenance = runtime_provenance();
                writer.insert_edge(&edge)?;
            }
        }
    }

    Ok(())
}

fn runtime_edge_kind(decision: &RuntimeDecision) -> Option<EdgeKind> {
    match decision {
        RuntimeDecision::RuntimeConfirmed => Some(EdgeKind::ConfirmedByRuntime),
        RuntimeDecision::RuntimeContradicted | RuntimeDecision::RuntimeUnobserved => {
            Some(EdgeKind::ContradictedByRuntime)
        }
        RuntimeDecision::RuntimeObserved | RuntimeDecision::PartiallyObserved => None,
    }
}

fn runtime_provenance() -> Provenance {
    Provenance {
        source: "fat probe runtime evidence".to_string(),
        confidence_millis: 900,
    }
}

fn generate_probe_marker() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("FATPROBE_{:x}_{:x}", millis, std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_augment::{AugmentedTaintFinding, RuntimeDecision, RuntimeStepObservation};
    use fat_core::finding::FindingSeverity;
    use fat_query::ir::{EdgeKind, NodeKind};
    use fat_query::store::GraphReader;
    use fat_taint::{ChainStep, EdgeType, FindingStatus, SourceClass, TaintFinding};

    fn fixture_findings() -> Vec<TaintFinding> {
        vec![TaintFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: "TAINT-001".to_string(),
            title: "command injection".to_string(),
            severity: FindingSeverity::High,
            chain: vec![
                ChainStep {
                    binary: "httpd".to_string(),
                    function: "cgibin_get_var".to_string(),
                    location: "0x00412000".to_string(),
                    action: "source".to_string(),
                    edge_type: EdgeType::DirectFlow,
                },
                ChainStep {
                    binary: "httpd".to_string(),
                    function: "system".to_string(),
                    location: "0x00413f10".to_string(),
                    action: "sink".to_string(),
                    edge_type: EdgeType::DirectFlow,
                },
            ],
            status: FindingStatus::Proven,
            status_reason: "static flow".to_string(),
            confidence: 0.95,
            source_class: SourceClass::Primary,
        }]
    }

    #[test]
    fn evaluate_probe_accepts_taint_and_trace_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let taint = dir.path().join("taint.json");
        let trace = dir.path().join("hooks.jsonl");
        std::fs::write(
            &taint,
            serde_json::to_string(&fixture_findings()).expect("taint json"),
        )
        .expect("write taint");
        std::fs::write(
            &trace,
            r#"{"hook":"cgibin_get_var","addr":"0x00412000","a0_str":"MARKER"}
{"hook":"system","addr":"0x00413f10","a0_str":"MARKER"}
"#,
        )
        .expect("write trace");

        let report = evaluate_probe(&taint, &trace, Some("MARKER")).expect("evaluate probe");

        assert_eq!(report.finding_count, 1);
        assert_eq!(
            report.findings[0].decision,
            RuntimeDecision::RuntimeConfirmed
        );
    }

    #[test]
    fn builds_http_probe_command_from_marker_template() {
        let request = parse_http_probe_spec("POST /cgi-bin/webproc action=MARKER").expect("parse");
        let command = build_http_probe_command(&request, "FATPROBE_123").expect("command");

        assert_eq!(
            command,
            "curl -sS -X POST http://127.0.0.1/cgi-bin/webproc --data 'action=FATPROBE_123'"
        );
    }

    #[test]
    fn rejects_http_probe_body_with_single_quote() {
        let request =
            parse_http_probe_spec("POST /cgi-bin/webproc action='MARKER'").expect("parse");
        let error = build_http_probe_command(&request, "FATPROBE_123").expect_err("quote rejected");

        assert!(error.contains("single quote"));
    }

    #[test]
    fn probe_run_requires_session_for_mvp() {
        let request = ProbeRunRequest {
            project_dir: Path::new("."),
            session_id: None,
            taint_path: Path::new("taint.json"),
            trace_path: Path::new("trace.jsonl"),
            inject_http: "POST /cgi-bin/webproc action=MARKER",
            marker: "FATPROBE_123",
            timeout: std::time::Duration::from_millis(1),
        };

        let error = validate_probe_run_request(&request).expect_err("session required");

        assert!(error.contains("session-attached MVP"));
        assert!(error.contains("fat probe evaluate"));
    }

    #[test]
    fn trace_wait_timeout_is_not_probe_crash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("trace.jsonl");
        std::fs::write(&trace, r#"{"hook":"system","a0_str":"different"}"#).expect("write trace");

        let outcome = wait_for_trace_marker(&trace, "FATPROBE_123", std::time::Duration::ZERO)
            .expect("existing trace should not be a hard failure");

        assert_eq!(outcome, TraceWaitOutcome::MarkerNotObserved);
    }

    #[test]
    fn writes_runtime_evidence_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snapshot = dir.path().join("runtime-evidence.sqlite");
        let trace = dir.path().join("trace.jsonl");
        std::fs::write(&trace, "{}\n").expect("write trace");
        let report = RuntimeAugmentationReport {
            finding_count: 1,
            trace_event_count: 2,
            parse_error_count: 0,
            marker: Some("FATPROBE_123".into()),
            runtime_confirmed_count: 1,
            partially_observed_count: 0,
            runtime_unobserved_count: 0,
            runtime_observed_count: 0,
            findings: vec![AugmentedTaintFinding {
                id: "TAINT-001".into(),
                title: "command injection".into(),
                original_status: FindingStatus::Proven,
                runtime_status: FindingStatus::DynamicallyConfirmed,
                original_severity: FindingSeverity::High,
                runtime_severity: FindingSeverity::Critical,
                decision: RuntimeDecision::RuntimeConfirmed,
                decision_reason: "marker propagated".into(),
                runtime_confirmation_edges: vec!["ConfirmedByRuntime".into()],
                observations: vec![RuntimeStepObservation {
                    chain_index: 1,
                    function: "system".into(),
                    expected_address: Some("0x413f10".into()),
                    observed: true,
                    event_line: Some(2),
                    event_address: Some("0x413f10".into()),
                    marker_observed: true,
                    observed_strings: vec!["a0=FATPROBE_123".into()],
                }],
            }],
        };

        write_runtime_evidence_snapshot(&snapshot, &report, &trace, report.marker.as_deref())
            .expect("write snapshot");

        let reader = GraphReader::open(&snapshot).expect("open snapshot");
        let nodes = reader.nodes().expect("read nodes");
        let edges = reader.edges().expect("read edges");

        assert!(nodes.iter().any(|node| node.kind == NodeKind::RuntimeEvent));
        assert!(edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::ConfirmedByRuntime));
    }

    #[test]
    fn build_probe_plan_for_uefi_marks_external_runner_contract() {
        let plan = build_probe_plan(ProbePlanRequest {
            target_class: ProbeTargetClass::Uefi,
            architecture: Some("x86_64"),
            file: Some(Path::new("firmware.fd")),
            taint: None,
            peripheral_map: None,
        })
        .expect("probe plan");

        assert_eq!(plan.target_class, "uefi");
        assert!(plan
            .runner_requirements
            .contains(&"external-runner-required".to_string()));
        assert!(plan
            .probes
            .iter()
            .any(|probe| probe.intent == "uefi-variable-enumeration"));
        assert!(plan
            .probes
            .iter()
            .any(|probe| probe.intent == "uefi-service-table-check"));
    }

    #[test]
    fn build_probe_plan_for_mcu_references_peripheral_map_and_vector_context() {
        let plan = build_probe_plan(ProbePlanRequest {
            target_class: ProbeTargetClass::Mcu,
            architecture: Some("arm64"),
            file: Some(Path::new("device.bin")),
            taint: None,
            peripheral_map: Some(Path::new("peripherals.json")),
        })
        .expect("probe plan");

        assert_eq!(plan.target_class, "mcu");
        assert!(plan
            .inputs
            .iter()
            .any(|input| input.kind == "peripheral-map" && input.path == "peripherals.json"));
        assert!(plan
            .probes
            .iter()
            .any(|probe| probe.intent == "mcu-peripheral-register-read"));
        assert!(plan
            .probes
            .iter()
            .any(|probe| probe.intent == "mcu-vector-table-context"));
    }

    #[test]
    fn runner_ingest_preserves_valid_events_and_counts_parse_errors() {
        let report = ingest_runner_jsonl(
            r#"{"runner":"kanzashi","event":"mmio-read","addr":"0x40000000"}
not json
{"runner":"kanzashi","event":"uefi-variable","name":"BootOrder"}
"#,
        );

        assert_eq!(report.event_count, 2);
        assert_eq!(report.parse_error_count, 1);
        assert_eq!(report.events[0].payload["event"], "mmio-read");
        assert_eq!(report.errors[0].line, 2);
    }

    #[test]
    fn writes_runner_evidence_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snapshot = dir.path().join("runner-evidence.sqlite");
        let trace = dir.path().join("runner.jsonl");
        std::fs::write(&trace, r#"{"runner":"kanzashi","event":"mmio-read"}"#)
            .expect("write runner trace");
        let report = ingest_runner_jsonl(&std::fs::read_to_string(&trace).expect("read trace"));

        write_runner_evidence_snapshot(&snapshot, &report, &trace).expect("write snapshot");

        let reader = GraphReader::open(&snapshot).expect("open snapshot");
        let nodes = reader.nodes().expect("read nodes");
        assert!(nodes.iter().any(|node| {
            node.kind == NodeKind::RuntimeEvent
                && node.attr("artifact_kind") == Some("runtime-capture")
                && node.attr("runner_event") == Some("mmio-read")
        }));
    }

    #[test]
    fn parses_svd_enrichment_subset() {
        let enrichment = parse_svd_enrichment(
            r#"<device>
  <name>DemoDevice</name>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40020000</baseAddress>
      <registers>
        <register>
          <name>MODER</name>
          <addressOffset>0x00</addressOffset>
          <fields><field><name>MODE0</name></field></fields>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>"#,
            Path::new("demo.svd"),
        )
        .expect("parse svd");

        assert_eq!(enrichment.device, "DemoDevice");
        assert_eq!(enrichment.source_kind, "vendor-svd");
        assert_eq!(enrichment.peripherals[0].name, "GPIOA");
        assert_eq!(enrichment.peripherals[0].registers[0].fields[0], "MODE0");
    }
}
