use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::Path;

use fat_core::artifacts::ArtifactKind;

use crate::debug_cmd::{load_context, write_runtime_json_artifact};

type DynResult<T> = Result<T, Box<dyn Error>>;

const TRACE_ARTIFACT_SUBKIND: &str = "instrument-trace-summary";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HookTraceReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_path: Option<String>,
    pub event_count: usize,
    pub parse_error_count: usize,
    pub plugin_mode: Option<String>,
    pub resolved_regs: Option<u32>,
    pub total_regs: Option<u32>,
    pub hooks: Vec<HookTraceSummary>,
    pub events: Vec<HookTraceEvent>,
    pub errors: Vec<TraceParseError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HookTraceSummary {
    pub name: String,
    pub address: String,
    pub hit_count: u64,
    pub vcpus: Vec<u32>,
    pub string_observations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HookTraceEvent {
    pub line: usize,
    pub hook: String,
    pub address: String,
    pub hit: Option<u64>,
    pub vcpu: Option<u32>,
    pub mode: Option<String>,
    pub registers: BTreeMap<String, Option<String>>,
    pub strings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TraceParseError {
    pub line: usize,
    pub error: String,
}

#[derive(Default)]
struct HookSummaryBuilder {
    name: String,
    address: String,
    event_hits: u64,
    summary_hits: Option<u64>,
    vcpus: BTreeSet<u32>,
    string_observations: BTreeSet<String>,
}

fn hook_key(name: &str, address: &str) -> String {
    format!("{name}@{address}")
}

pub fn run(
    project_dir: &Path,
    trace_path: &Path,
    session_id: Option<&str>,
    json: bool,
) -> DynResult<()> {
    let context = load_context(project_dir, session_id)?;
    let trace = fs::read_to_string(trace_path)?;
    let mut report = parse_trace_jsonl(&trace)?;
    report.session_id = Some(context.view.session.session_id.clone());
    report.run_id = Some(context.view.run.run_id.clone());
    report.backend_id = Some(context.view.run.backend_driver.clone());
    report.trace_path = Some(trace_path.to_string_lossy().into_owned());

    let contents = serde_json::to_string_pretty(&report)?;
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &context.view.session.session_id,
        &context.view.run.run_id,
        ArtifactKind::RuntimeCapture,
        TRACE_ARTIFACT_SUBKIND,
        "fat trace-ingest",
        &format!(
            "normalized QEMU TCG hook trace from {}",
            trace_path.display()
        ),
        "trace-ingest",
        &context.view.run.backend_driver,
        context.view.run.substrate_kind,
        &contents,
    )?;

    if json {
        println!("{contents}");
    } else {
        print!("{}", render_trace_report(&report));
    }

    Ok(())
}

pub(crate) fn load_trace_report(path: &Path) -> DynResult<HookTraceReport> {
    let contents = fs::read_to_string(path)?;
    match serde_json::from_str::<HookTraceReport>(&contents) {
        Ok(report) => Ok(report),
        Err(_) => parse_trace_jsonl(&contents),
    }
}

fn parse_trace_jsonl(content: &str) -> DynResult<HookTraceReport> {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut hooks: BTreeMap<String, HookSummaryBuilder> = BTreeMap::new();
    let mut plugin_mode = None;
    let mut resolved_regs = None;
    let mut total_regs = None;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(err) => {
                errors.push(TraceParseError {
                    line: line_number,
                    error: err.to_string(),
                });
                continue;
            }
        };

        if value.get("event").and_then(|value| value.as_str()) == Some("summary") {
            plugin_mode = value
                .get("mode")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            resolved_regs = value
                .get("resolved_regs")
                .and_then(|value| value.as_u64())
                .map(|value| value as u32);
            total_regs = value
                .get("total_regs")
                .and_then(|value| value.as_u64())
                .map(|value| value as u32);

            if let Some(summary_hooks) = value.get("hooks").and_then(|value| value.as_array()) {
                for hook in summary_hooks {
                    let Some(name) = hook.get("name").and_then(|value| value.as_str()) else {
                        continue;
                    };
                    let address = hook
                        .get("addr")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let hits = hook.get("hits").and_then(|value| value.as_u64());
                    let entry = hooks.entry(hook_key(name, &address)).or_default();
                    if entry.name.is_empty() {
                        entry.name = name.to_string();
                    }
                    if entry.address.is_empty() {
                        entry.address = address;
                    }
                    entry.summary_hits = hits;
                }
            }
            continue;
        }

        let Some(hook_name) = value.get("hook").and_then(|value| value.as_str()) else {
            continue;
        };
        let address = value
            .get("addr")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        let hit = value.get("hit").and_then(|value| value.as_u64());
        let vcpu = value
            .get("vcpu")
            .and_then(|value| value.as_u64())
            .map(|value| value as u32);
        let mode = value
            .get("mode")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        let mut registers = BTreeMap::new();
        let mut strings = BTreeMap::new();

        for register in ["a0", "a1", "a2", "a3", "v0", "ra", "sp"] {
            if let Some(register_value) = value.get(register) {
                registers.insert(
                    register.to_string(),
                    register_value.as_str().map(str::to_string),
                );
            }
        }
        for register in ["a0", "a1", "a2", "a3"] {
            let key = format!("{register}_str");
            if let Some(string_value) = value.get(&key).and_then(|value| value.as_str()) {
                strings.insert(register.to_string(), string_value.to_string());
            }
        }

        let entry = hooks.entry(hook_key(hook_name, &address)).or_default();
        if entry.name.is_empty() {
            entry.name = hook_name.to_string();
        }
        if entry.address.is_empty() {
            entry.address = address.clone();
        }
        entry.event_hits += 1;
        if let Some(vcpu) = vcpu {
            entry.vcpus.insert(vcpu);
        }
        for (register, value) in &strings {
            entry
                .string_observations
                .insert(format!("{register}={value}"));
        }

        events.push(HookTraceEvent {
            line: line_number,
            hook: hook_name.to_string(),
            address,
            hit,
            vcpu,
            mode,
            registers,
            strings,
        });
    }

    let hooks = hooks
        .into_values()
        .map(|builder| HookTraceSummary {
            name: builder.name,
            address: builder.address,
            hit_count: builder.summary_hits.unwrap_or(builder.event_hits),
            vcpus: builder.vcpus.into_iter().collect(),
            string_observations: builder.string_observations.into_iter().collect(),
        })
        .collect();

    Ok(HookTraceReport {
        session_id: None,
        run_id: None,
        backend_id: None,
        trace_path: None,
        event_count: events.len(),
        parse_error_count: errors.len(),
        plugin_mode,
        resolved_regs,
        total_regs,
        hooks,
        events,
        errors,
    })
}

fn render_trace_report(report: &HookTraceReport) -> String {
    let mut output = String::new();
    if let Some(session_id) = &report.session_id {
        output.push_str(&format!("session: {session_id}\n"));
    }
    if let Some(run_id) = &report.run_id {
        output.push_str(&format!("run: {run_id}\n"));
    }
    if let Some(backend_id) = &report.backend_id {
        output.push_str(&format!("backend: {backend_id}\n"));
    }
    if let Some(trace_path) = &report.trace_path {
        output.push_str(&format!("trace: {trace_path}\n"));
    }
    output.push_str(&format!("events: {}\n", report.event_count));
    output.push_str(&format!("parse errors: {}\n", report.parse_error_count));
    output.push_str(&format!(
        "plugin mode: {}\n",
        report.plugin_mode.as_deref().unwrap_or("unknown")
    ));
    if let (Some(resolved), Some(total)) = (report.resolved_regs, report.total_regs) {
        output.push_str(&format!("register coverage: {resolved}/{total}\n"));
    }
    output.push_str(&format!("hooks: {}\n", report.hooks.len()));
    for hook in &report.hooks {
        let vcpus = if hook.vcpus.is_empty() {
            "none".to_string()
        } else {
            hook.vcpus
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        output.push_str(&format!(
            "hook {} {} hits={} vcpus={} strings={}\n",
            hook.name,
            hook.address,
            hook.hit_count,
            vcpus,
            hook.string_observations.len()
        ));
    }
    output.push_str(&format!(
        "wrote runtime capture: {TRACE_ARTIFACT_SUBKIND}\n"
    ));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use fat_core::database::ProjectDb;
    use fat_core::project::Project;
    use fat_core::runs::{RunOrigin, RunRecord, RunStatus, SubstrateKind};
    use fat_core::runtime_store::RuntimeStore;
    use fat_core::sessions::{SessionOrigin, SessionRecord, SessionStatus};
    use fat_core::targets::derive_target_id;
    use std::fs;

    #[test]
    fn parse_trace_jsonl_normalizes_hits_and_summary() {
        let trace = r#"{"hook":"system","addr":"0x00413f10","hit":1,"vcpu":0,"a0":"0x7fff0000","a1":null,"a2":"0x00000000","a3":"0x00000000","v0":"0x00000000","ra":"0x00401000","sp":"0x7ffefff0","a0_str":"reboot"}
{"hook":"nvram_get","addr":"0x00412000","hit":1,"vcpu":1,"mode":"degraded"}
{"event":"summary","mode":"partial","resolved_regs":4,"total_regs":7,"hooks":[{"name":"system","addr":"0x00413f10","hits":1},{"name":"nvram_get","addr":"0x00412000","hits":1}]}
"#;

        let report = parse_trace_jsonl(trace).expect("trace should parse");

        assert_eq!(report.event_count, 2);
        assert_eq!(report.parse_error_count, 0);
        assert_eq!(report.plugin_mode.as_deref(), Some("partial"));
        assert_eq!(report.hooks.len(), 2);

        let system = report
            .hooks
            .iter()
            .find(|hook| hook.name == "system")
            .expect("system summary");
        assert_eq!(system.address, "0x00413f10");
        assert_eq!(system.hit_count, 1);
        assert_eq!(system.vcpus, vec![0]);
        assert_eq!(system.string_observations, vec!["a0=reboot".to_string()]);

        let degraded = report
            .events
            .iter()
            .find(|event| event.hook == "nvram_get")
            .expect("degraded event");
        assert_eq!(degraded.mode.as_deref(), Some("degraded"));
    }

    #[test]
    fn parse_trace_jsonl_keeps_bad_lines_as_errors() {
        let trace = r#"{"hook":"system","addr":"0x00413f10","hit":1,"vcpu":0}
not json
{"event":"summary","mode":"full","resolved_regs":7,"total_regs":7,"hooks":[]}
"#;

        let report = parse_trace_jsonl(trace).expect("trace should parse with errors");

        assert_eq!(report.event_count, 1);
        assert_eq!(report.parse_error_count, 1);
        assert_eq!(report.errors[0].line, 2);
    }

    #[test]
    fn parse_trace_jsonl_keeps_same_name_different_addresses_separate() {
        let trace = r#"{"hook":"system","addr":"0x00413f10","hit":1,"vcpu":0}
{"hook":"system","addr":"0x00415000","hit":1,"vcpu":1}
{"event":"summary","mode":"full","resolved_regs":7,"total_regs":7,"hooks":[{"name":"system","addr":"0x00413f10","hits":1},{"name":"system","addr":"0x00415000","hits":1}]}
"#;

        let report = parse_trace_jsonl(trace).expect("trace should parse");

        assert_eq!(report.hooks.len(), 2);
        assert!(report.hooks.iter().any(|hook| hook.address == "0x00413f10"));
        assert!(report.hooks.iter().any(|hook| hook.address == "0x00415000"));
    }

    #[test]
    fn load_trace_report_accepts_raw_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("hooks.jsonl");
        fs::write(
            &trace,
            r#"{"hook":"system","addr":"0x00413f10","a0_str":"MARKER"}"#,
        )
        .expect("write trace");

        let report = load_trace_report(&trace).expect("load trace report");

        assert_eq!(report.event_count, 1);
        assert_eq!(report.events[0].hook, "system");
    }

    #[test]
    fn load_trace_report_accepts_pretty_report_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("report.json");
        let report =
            parse_trace_jsonl(r#"{"hook":"system","addr":"0x00413f10","a0_str":"MARKER"}"#)
                .expect("parse report");
        fs::write(&trace, serde_json::to_string_pretty(&report).expect("json"))
            .expect("write report");

        let loaded = load_trace_report(&trace).expect("load trace report");

        assert_eq!(loaded.event_count, 1);
        assert_eq!(loaded.events[0].hook, "system");
    }

    #[test]
    fn run_writes_runtime_capture_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let project_dir = dir.path().join("project");
        let db = ProjectDb::open(&project_dir).expect("project db");
        let project = Project::new("project".to_string(), "firmware.bin".to_string());
        db.save(&project).expect("save project");

        let store = RuntimeStore::open(&project_dir).expect("runtime store");
        let target_id = derive_target_id(&project.name, &project.firmware_name);
        let mut session = SessionRecord::new(
            project.name.clone(),
            target_id,
            "trace hooks",
            "qemu-direct",
            SessionOrigin::Manual,
            "2026-04-11T00:00:00Z",
        )
        .with_requested_session_id("trace-session")
        .with_status(SessionStatus::Active);
        let run = RunRecord::new(
            session.session_id.clone(),
            "recipe-1",
            "qemu-direct",
            SubstrateKind::NativeHost,
            1,
            RunOrigin::Manual,
        )
        .with_status(RunStatus::Running);
        session = session.with_run_ids(vec![run.run_id.clone()]);
        store.write_session(&session).expect("write session");
        store.write_run(&run).expect("write run");

        let trace_path = dir.path().join("hooks.jsonl");
        fs::write(
            &trace_path,
            r#"{"hook":"system","addr":"0x00413f10","hit":1,"vcpu":0,"a0":"0x7fff0000","a0_str":"reboot"}"#,
        )
        .expect("write trace");

        super::run(&project_dir, &trace_path, Some("trace-session"), false).expect("trace ingest");

        let artifacts = store
            .read_run_artifacts(&session.session_id, &run.run_id)
            .expect("run artifacts");
        let artifact = artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == ArtifactKind::RuntimeCapture
                    && artifact.subkind == "instrument-trace-summary"
            })
            .expect("runtime capture artifact");
        let contents = fs::read_to_string(&artifact.path).expect("artifact contents");
        let report: HookTraceReport = serde_json::from_str(&contents).expect("report json");

        assert_eq!(report.event_count, 1);
        assert_eq!(report.hooks[0].name, "system");
    }
}
