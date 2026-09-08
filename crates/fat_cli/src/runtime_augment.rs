use crate::trace_ingest_cmd::{HookTraceEvent, HookTraceReport};
use fat_core::finding::FindingSeverity;
use fat_taint::{ChainStep, FindingStatus, TaintFinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RuntimeDecision {
    RuntimeConfirmed,
    RuntimeObserved,
    PartiallyObserved,
    RuntimeUnobserved,
    RuntimeContradicted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RuntimeAugmentationReport {
    pub finding_count: usize,
    pub trace_event_count: usize,
    pub parse_error_count: usize,
    pub marker: Option<String>,
    pub runtime_confirmed_count: usize,
    pub partially_observed_count: usize,
    pub runtime_unobserved_count: usize,
    pub runtime_observed_count: usize,
    pub findings: Vec<AugmentedTaintFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AugmentedTaintFinding {
    pub id: String,
    pub title: String,
    pub original_status: FindingStatus,
    pub runtime_status: FindingStatus,
    pub original_severity: FindingSeverity,
    pub runtime_severity: FindingSeverity,
    pub decision: RuntimeDecision,
    pub decision_reason: String,
    pub runtime_confirmation_edges: Vec<String>,
    pub observations: Vec<RuntimeStepObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RuntimeStepObservation {
    pub chain_index: usize,
    pub function: String,
    pub expected_address: Option<String>,
    pub observed: bool,
    pub event_line: Option<usize>,
    pub event_address: Option<String>,
    pub marker_observed: bool,
    pub observed_strings: Vec<String>,
}

pub(crate) fn augment_findings(
    findings: &[TaintFinding],
    report: &HookTraceReport,
    marker: Option<&str>,
) -> RuntimeAugmentationReport {
    let findings_out = findings
        .iter()
        .map(|finding| augment_finding(finding, report, marker))
        .collect::<Vec<_>>();

    RuntimeAugmentationReport {
        finding_count: findings.len(),
        trace_event_count: report.event_count,
        parse_error_count: report.parse_error_count,
        marker: marker.map(str::to_string),
        runtime_confirmed_count: findings_out
            .iter()
            .filter(|finding| finding.decision == RuntimeDecision::RuntimeConfirmed)
            .count(),
        runtime_observed_count: findings_out
            .iter()
            .filter(|finding| finding.decision == RuntimeDecision::RuntimeObserved)
            .count(),
        partially_observed_count: findings_out
            .iter()
            .filter(|finding| finding.decision == RuntimeDecision::PartiallyObserved)
            .count(),
        runtime_unobserved_count: findings_out
            .iter()
            .filter(|finding| finding.decision == RuntimeDecision::RuntimeUnobserved)
            .count(),
        findings: findings_out,
    }
}

pub(crate) fn render_runtime_augmentation_summary(report: &RuntimeAugmentationReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("findings: {}\n", report.finding_count));
    output.push_str(&format!("trace events: {}\n", report.trace_event_count));
    output.push_str(&format!("parse errors: {}\n", report.parse_error_count));
    if let Some(marker) = &report.marker {
        output.push_str(&format!("marker: {marker}\n"));
    }
    output.push_str(&format!(
        "runtime-confirmed: {}\n",
        report.runtime_confirmed_count
    ));
    output.push_str(&format!(
        "runtime-observed: {}\n",
        report.runtime_observed_count
    ));
    output.push_str(&format!(
        "partially-observed: {}\n",
        report.partially_observed_count
    ));
    output.push_str(&format!(
        "runtime-unobserved: {}\n",
        report.runtime_unobserved_count
    ));

    for finding in &report.findings {
        output.push_str(&format!(
            "finding {} {:?} {:?}->{:?} {:?}->{:?}\n",
            finding.id,
            finding.decision,
            finding.original_status,
            finding.runtime_status,
            finding.original_severity,
            finding.runtime_severity
        ));
        for edge in &finding.runtime_confirmation_edges {
            output.push_str(&format!("  evidence: {edge}\n"));
        }
    }

    output
}

fn augment_finding(
    finding: &TaintFinding,
    report: &HookTraceReport,
    marker: Option<&str>,
) -> AugmentedTaintFinding {
    let observations = finding
        .chain
        .iter()
        .enumerate()
        .map(|(index, step)| observe_step(index, step, report, marker))
        .collect::<Vec<_>>();
    let first_observed = observations
        .iter()
        .position(|observation| observation.observed);
    let last_observed = observations
        .iter()
        .rposition(|observation| observation.observed);
    let sink_marker_observed = observations
        .last()
        .map(|observation| observation.marker_observed)
        .unwrap_or(false);
    let any_observed = observations.iter().any(|observation| observation.observed);

    let (decision, decision_reason) = match (first_observed, last_observed, marker) {
        (Some(first), Some(last), Some(_)) if first < last && sink_marker_observed => (
            RuntimeDecision::RuntimeConfirmed,
            "marker propagated from an earlier chain step to the sink".to_string(),
        ),
        (Some(first), Some(last), None) if first < last => (
            RuntimeDecision::RuntimeObserved,
            "source and sink functions were observed in order; no marker was supplied".to_string(),
        ),
        _ if any_observed => (
            RuntimeDecision::PartiallyObserved,
            "some chain steps were observed, but runtime confirmation was incomplete".to_string(),
        ),
        _ => (
            RuntimeDecision::RuntimeUnobserved,
            "no chain steps were observed in the runtime trace".to_string(),
        ),
    };

    let runtime_status = if decision == RuntimeDecision::RuntimeConfirmed {
        FindingStatus::DynamicallyConfirmed
    } else {
        finding.status
    };
    let runtime_severity = if decision == RuntimeDecision::RuntimeConfirmed {
        upgrade_severity(finding.severity)
    } else {
        finding.severity
    };
    let runtime_confirmation_edges = if decision == RuntimeDecision::RuntimeConfirmed {
        vec!["ConfirmedByRuntime".to_string()]
    } else if decision == RuntimeDecision::RuntimeUnobserved && report.event_count > 0 {
        vec!["ContradictedByRuntime".to_string()]
    } else {
        Vec::new()
    };

    AugmentedTaintFinding {
        id: finding.id.clone(),
        title: finding.title.clone(),
        original_status: finding.status,
        runtime_status,
        original_severity: finding.severity,
        runtime_severity,
        decision,
        decision_reason,
        runtime_confirmation_edges,
        observations,
    }
}

fn observe_step(
    chain_index: usize,
    step: &ChainStep,
    report: &HookTraceReport,
    marker: Option<&str>,
) -> RuntimeStepObservation {
    let expected_address = normalize_hex_address(&step.location);
    let event = report
        .events
        .iter()
        .find(|event| event_matches_step(event, step, expected_address.as_deref()));
    let observed_strings = event
        .map(|event| {
            event
                .strings
                .iter()
                .map(|(register, value)| format!("{register}={value}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let marker_observed = marker
        .map(|marker| observed_strings.iter().any(|value| value.contains(marker)))
        .unwrap_or(false);

    RuntimeStepObservation {
        chain_index,
        function: step.function.clone(),
        expected_address,
        observed: event.is_some(),
        event_line: event.map(|event| event.line),
        event_address: event.map(|event| normalize_address_string(&event.address)),
        marker_observed,
        observed_strings,
    }
}

fn event_matches_step(
    event: &HookTraceEvent,
    step: &ChainStep,
    expected_address: Option<&str>,
) -> bool {
    if event.hook != step.function {
        return false;
    }
    if let Some(expected_address) = expected_address {
        normalize_address_string(&event.address) == expected_address
    } else {
        true
    }
}

fn normalize_hex_address(value: &str) -> Option<String> {
    let start = value.find("0x").or_else(|| value.find("0X"))?;
    let hex = value[start + 2..]
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if hex.is_empty() {
        None
    } else {
        let normalized = hex.trim_start_matches('0');
        let normalized = if normalized.is_empty() {
            "0"
        } else {
            normalized
        };
        Some(format!("0x{}", normalized.to_ascii_lowercase()))
    }
}

fn normalize_address_string(value: &str) -> String {
    normalize_hex_address(value).unwrap_or_else(|| value.to_ascii_lowercase())
}

fn upgrade_severity(severity: FindingSeverity) -> FindingSeverity {
    match severity {
        FindingSeverity::Info
        | FindingSeverity::Low
        | FindingSeverity::Medium
        | FindingSeverity::High => FindingSeverity::Critical,
        FindingSeverity::Critical => FindingSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_ingest_cmd::{HookTraceEvent, HookTraceReport};
    use fat_core::finding::FindingSeverity;
    use fat_taint::{ChainStep, EdgeType, FindingStatus, SourceClass, TaintFinding};
    use std::collections::BTreeMap;

    fn step(function: &str, location: &str, action: &str) -> ChainStep {
        ChainStep {
            binary: "httpd".to_string(),
            function: function.to_string(),
            location: location.to_string(),
            action: action.to_string(),
            edge_type: EdgeType::DirectFlow,
        }
    }

    fn fixture_finding(chain: Vec<ChainStep>) -> TaintFinding {
        TaintFinding {
            model_provenance: None,
            state_model_provenance: None,
            id: "taint-1".to_string(),
            title: "source reaches sink".to_string(),
            severity: FindingSeverity::High,
            chain,
            status: FindingStatus::Proven,
            status_reason: "static flow".to_string(),
            confidence: 0.95,
            source_class: SourceClass::Primary,
        }
    }

    fn event(hook: &str, address: &str, value: &str) -> HookTraceEvent {
        let mut strings = BTreeMap::new();
        strings.insert("a0".to_string(), value.to_string());
        HookTraceEvent {
            line: 1,
            hook: hook.to_string(),
            address: address.to_string(),
            hit: Some(1),
            vcpu: Some(0),
            mode: None,
            registers: BTreeMap::new(),
            strings,
        }
    }

    fn fixture_report(events: Vec<HookTraceEvent>) -> HookTraceReport {
        HookTraceReport {
            session_id: None,
            run_id: None,
            backend_id: None,
            trace_path: None,
            event_count: events.len(),
            parse_error_count: 0,
            plugin_mode: None,
            resolved_regs: None,
            total_regs: None,
            hooks: Vec::new(),
            events,
            errors: Vec::new(),
        }
    }

    #[test]
    fn confirms_ordered_source_to_sink_when_marker_reaches_sink() {
        let findings = vec![fixture_finding(vec![
            step("cgibin_get_var", "0x00412000", "source"),
            step("system", "0x00413f10", "sink"),
        ])];
        let report = fixture_report(vec![
            event("cgibin_get_var", "0x00412000", "MARKER"),
            event("system", "0x00413f10", "MARKER"),
        ]);

        let out = augment_findings(&findings, &report, Some("MARKER"));

        assert_eq!(out.findings[0].decision, RuntimeDecision::RuntimeConfirmed);
        assert_eq!(
            out.findings[0].runtime_status,
            FindingStatus::DynamicallyConfirmed
        );
        assert_eq!(out.findings[0].runtime_severity, FindingSeverity::Critical);
    }

    #[test]
    fn marks_partial_when_only_source_is_observed() {
        let findings = vec![fixture_finding(vec![
            step("cgibin_get_var", "0x00412000", "source"),
            step("system", "0x00413f10", "sink"),
        ])];
        let report = fixture_report(vec![event("cgibin_get_var", "0x00412000", "MARKER")]);

        let out = augment_findings(&findings, &report, Some("MARKER"));

        assert_eq!(out.findings[0].decision, RuntimeDecision::PartiallyObserved);
    }

    #[test]
    fn normalizes_zero_address_without_dropping_the_digit() {
        assert_eq!(normalize_hex_address("0x00000000").as_deref(), Some("0x0"));
    }
}
