use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::diagnostics::DiagnosticRecord;
use crate::finding::Finding;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDiff {
    pub base_run_id: String,
    pub head_run_id: String,
    pub added_services: Vec<String>,
    pub removed_services: Vec<String>,
    pub added_runtime_states: Vec<String>,
    pub removed_runtime_states: Vec<String>,
    pub added_diagnostics: Vec<String>,
    pub removed_diagnostics: Vec<String>,
    pub added_findings: Vec<String>,
    pub removed_findings: Vec<String>,
}

impl RunDiff {
    pub fn is_empty(&self) -> bool {
        self.added_services.is_empty()
            && self.removed_services.is_empty()
            && self.added_runtime_states.is_empty()
            && self.removed_runtime_states.is_empty()
            && self.added_diagnostics.is_empty()
            && self.removed_diagnostics.is_empty()
            && self.added_findings.is_empty()
            && self.removed_findings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub run_count: usize,
    pub total_findings: usize,
    pub total_diagnostics: usize,
    pub service_names: Vec<String>,
    pub runtime_states: Vec<String>,
    pub finding_titles: Vec<String>,
    pub diagnostic_signatures: Vec<String>,
}

pub fn diff_runs(
    base_run_id: impl Into<String>,
    head_run_id: impl Into<String>,
    base_findings: &[Finding],
    head_findings: &[Finding],
    base_diagnostics: &[DiagnosticRecord],
    head_diagnostics: &[DiagnosticRecord],
    base_services: &[String],
    head_services: &[String],
    base_runtime_states: &[String],
    head_runtime_states: &[String],
) -> RunDiff {
    RunDiff {
        base_run_id: base_run_id.into(),
        head_run_id: head_run_id.into(),
        added_services: set_diff(
            normalize_services(head_services),
            normalize_services(base_services),
        ),
        removed_services: set_diff(
            normalize_services(base_services),
            normalize_services(head_services),
        ),
        added_runtime_states: set_diff(
            normalize_runtime_states(head_runtime_states),
            normalize_runtime_states(base_runtime_states),
        ),
        removed_runtime_states: set_diff(
            normalize_runtime_states(base_runtime_states),
            normalize_runtime_states(head_runtime_states),
        ),
        added_diagnostics: set_diff(
            normalize_diagnostics(head_diagnostics),
            normalize_diagnostics(base_diagnostics),
        ),
        removed_diagnostics: set_diff(
            normalize_diagnostics(base_diagnostics),
            normalize_diagnostics(head_diagnostics),
        ),
        added_findings: set_diff(
            normalize_findings(head_findings),
            normalize_findings(base_findings),
        ),
        removed_findings: set_diff(
            normalize_findings(base_findings),
            normalize_findings(head_findings),
        ),
    }
}

pub fn summarize_session(
    session_id: impl Into<String>,
    run_count: usize,
    findings: &[Finding],
    diagnostics: &[DiagnosticRecord],
    services: &[String],
    runtime_states: &[String],
) -> SessionSummary {
    SessionSummary {
        session_id: session_id.into(),
        run_count,
        total_findings: findings.len(),
        total_diagnostics: diagnostics.len(),
        service_names: normalize_services(services),
        runtime_states: normalize_runtime_states(runtime_states),
        finding_titles: normalize_findings(findings),
        diagnostic_signatures: normalize_diagnostics(diagnostics),
    }
}

fn normalize_services(services: &[String]) -> Vec<String> {
    services
        .iter()
        .map(|service| service.trim().to_ascii_lowercase())
        .filter(|service| !service.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_runtime_states(runtime_states: &[String]) -> Vec<String> {
    runtime_states
        .iter()
        .map(|state| state.trim().to_ascii_lowercase())
        .filter(|state| !state.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_findings(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            let plugin_id = finding.plugin_id.as_deref().unwrap_or("unknown");
            format!("{plugin_id}:{}", finding.title)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_diagnostics(diagnostics: &[DiagnosticRecord]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| format!("{}:{}", diagnostic.class.as_str(), diagnostic.summary))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn set_diff(left: Vec<String>, right: Vec<String>) -> Vec<String> {
    let right = right.into_iter().collect::<BTreeSet<_>>();
    left.into_iter()
        .filter(|value| !right.contains(value))
        .collect()
}
