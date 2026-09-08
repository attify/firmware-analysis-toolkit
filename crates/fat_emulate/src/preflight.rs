use fat_backend::model::{
    BackendAvailabilitySummary, BackendCheckRecord, BackendHealthSummary, BackendRegistry,
    BackendScore, CommandProbe, PathCommandProbe,
};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticSeverity,
};
use fat_family::{classifier, FamilyGuess};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub struct PreflightBackend {
    pub backend_id: String,
    pub display_name: String,
    pub score: f32,
    pub reason: String,
    pub is_available: bool,
    pub availability_detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostCapabilities {
    pub report_id: String,
    pub primary_family: FamilyGuess,
    pub backend_summaries: Vec<BackendAvailabilitySummary>,
    pub diagnostics: Vec<ReportDiagnosticRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorReport {
    pub report_id: String,
    pub host_os: String,
    pub host_arch: String,
    pub backend_summaries: Vec<BackendHealthSummary>,
    pub diagnostics: Vec<ReportDiagnosticRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportDiagnosticRecord {
    pub diagnostic_id: String,
    pub report_id: String,
    pub phase: DiagnosticPhase,
    pub owner: DiagnosticOwner,
    pub class: DiagnosticClass,
    pub subclass: Option<String>,
    pub severity: DiagnosticSeverity,
    pub confidence: DiagnosticConfidence,
    pub actionability: DiagnosticActionability,
    pub summary: String,
    pub suggested_next_actions: Vec<String>,
}

impl ReportDiagnosticRecord {
    #[allow(clippy::too_many_arguments)]
    fn new(
        report_id: impl Into<String>,
        phase: DiagnosticPhase,
        owner: DiagnosticOwner,
        class: DiagnosticClass,
        subclass: Option<String>,
        severity: DiagnosticSeverity,
        confidence: DiagnosticConfidence,
        actionability: DiagnosticActionability,
        summary: impl Into<String>,
        suggested_next_actions: Vec<String>,
    ) -> Self {
        let report_id = report_id.into();
        let summary = summary.into();
        let diagnostic_id = fat_core::ids::stable_prefixed_id(
            "rdiag",
            [
                report_id.as_str(),
                phase.as_str(),
                owner.as_str(),
                class.as_str(),
                subclass.as_deref().unwrap_or(""),
            ],
        );

        Self {
            diagnostic_id,
            report_id,
            phase,
            owner,
            class,
            subclass,
            severity,
            confidence,
            actionability,
            summary,
            suggested_next_actions,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreflightReport {
    pub primary_family: FamilyGuess,
    pub backends: Vec<PreflightBackend>,
    pub host_capabilities: HostCapabilities,
}

impl PreflightReport {
    pub fn for_test() -> Self {
        let probe = PathCommandProbe;
        Self::from_signals_with_probe(
            [
                "arch:armel",
                "fs:squashfs",
                "init:busybox",
                "web:cgi",
                "nvram:present",
            ],
            &probe,
        )
    }

    pub fn from_signals<I, S>(signals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let probe = PathCommandProbe;
        Self::from_signals_with_probe(signals, &probe)
    }

    pub fn from_signals_with_probe<I, S, P>(signals: I, probe: &P) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        P: CommandProbe + ?Sized,
    {
        let normalized_signals: Vec<String> = signals
            .into_iter()
            .map(|signal| signal.as_ref().trim().to_ascii_lowercase())
            .collect();

        let primary_family =
            classifier::classify(normalized_signals.iter().map(|signal| signal.as_str()));
        let registry = BackendRegistry::with_test_backends();
        let scores = registry.rank_family_with_probe(&primary_family.family_id, probe);
        let backend_summaries = scores
            .iter()
            .map(BackendScore::availability_summary)
            .collect::<Vec<_>>();
        let report_id = format!("preflight:{}", primary_family.family_id);
        let diagnostics =
            HostCapabilities::diagnostics_from_backend_summaries(&report_id, &backend_summaries);
        let host_capabilities = HostCapabilities {
            report_id,
            primary_family: primary_family.clone(),
            backend_summaries,
            diagnostics,
        };
        let backends = scores
            .into_iter()
            .map(|score| {
                let score_value = score.score;
                let backend_id = score.backend_id;
                let display_name = score.display_name;
                let rationale = score.rationale;

                PreflightBackend {
                    backend_id,
                    display_name: display_name.clone(),
                    score: score_value,
                    reason: format!(
                        "family {} matched backend {}: {}",
                        primary_family.family_id, display_name, rationale
                    ),
                    is_available: score.availability.is_available,
                    availability_detail: score.availability.detail,
                }
            })
            .collect();

        Self {
            primary_family,
            backends,
            host_capabilities,
        }
    }
}

pub fn doctor_report() -> DoctorReport {
    let probe = PathCommandProbe;
    doctor_report_with_probe(&probe)
}

pub fn doctor_report_with_probe<P>(probe: &P) -> DoctorReport
where
    P: CommandProbe + ?Sized,
{
    let registry = BackendRegistry::with_test_backends();
    let backend_summaries = registry.health_with_probe(probe);
    let report_id = format!("doctor:{}:{}", std::env::consts::OS, std::env::consts::ARCH);
    let diagnostics = doctor_diagnostics_from_backend_summaries(&report_id, &backend_summaries);

    DoctorReport {
        report_id,
        host_os: std::env::consts::OS.to_string(),
        host_arch: std::env::consts::ARCH.to_string(),
        backend_summaries,
        diagnostics,
    }
}

pub fn render_doctor(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str("host health:\n");
    output.push_str(&format!("host os: {}\n", report.host_os));
    output.push_str(&format!("host arch: {}\n", report.host_arch));

    let available: Vec<&BackendHealthSummary> = report
        .backend_summaries
        .iter()
        .filter(|summary| summary.is_available)
        .collect();
    if !available.is_empty() {
        output.push_str("available backends:\n");
        for summary in available {
            output.push_str(&format!("- {}\n", summary.stable_summary));
        }
    } else {
        output.push_str("available backends: none\n");
    }

    let unavailable: Vec<&BackendHealthSummary> = report
        .backend_summaries
        .iter()
        .filter(|summary| !summary.is_available)
        .collect();
    if !unavailable.is_empty() {
        output.push_str("unavailable backends:\n");
        for summary in unavailable {
            output.push_str(&format!("- {}\n", summary.stable_summary));
        }
    }

    let checks = report
        .backend_summaries
        .iter()
        .flat_map(|summary| {
            summary.checks.iter().map(move |check| {
                format!(
                    "{} {} {}: {} ({})",
                    summary.backend_id,
                    check.check_type,
                    check.subject,
                    if check.passed { "pass" } else { "fail" },
                    check.detail
                )
            })
        })
        .collect::<Vec<_>>();
    if !checks.is_empty() {
        output.push_str("backend checks:\n");
        for check in checks {
            output.push_str(&format!("- {check}\n"));
        }
    }

    if !report.diagnostics.is_empty() {
        output.push_str("diagnostics:\n");
        for diagnostic in &report.diagnostics {
            output.push_str(&format!(
                "- {} [{}]\n",
                diagnostic.summary, diagnostic.diagnostic_id
            ));
        }
    }

    output
}

impl HostCapabilities {
    fn diagnostics_from_backend_summaries(
        report_id: &str,
        backend_summaries: &[BackendAvailabilitySummary],
    ) -> Vec<ReportDiagnosticRecord> {
        let mut diagnostics: Vec<ReportDiagnosticRecord> = backend_summaries
            .iter()
            .filter(|summary| !summary.is_available)
            .map(|summary| {
                ReportDiagnosticRecord::new(
                    report_id.to_string(),
                    DiagnosticPhase::BackendProvisioning,
                    DiagnosticOwner::BackendTool,
                    DiagnosticClass::BackendUnavailable,
                    Some(summary.backend_id.clone()),
                    DiagnosticSeverity::Medium,
                    DiagnosticConfidence::High,
                    DiagnosticActionability::FallbackRecommended,
                    summary.stable_summary.clone(),
                    vec![format!(
                        "make {} available or choose a fallback backend",
                        summary.backend_id
                    )],
                )
            })
            .collect();

        diagnostics.extend(backend_summaries.iter().filter_map(|summary| {
            native_recipe_diagnostic(
                report_id,
                summary.backend_id.as_str(),
                summary.display_name.as_str(),
                summary.is_available,
                &summary.checks,
                DiagnosticPhase::BackendProvisioning,
                DiagnosticOwner::BackendTool,
                DiagnosticClass::BackendUnavailable,
            )
        }));

        diagnostics
    }
}

fn doctor_diagnostics_from_backend_summaries(
    report_id: &str,
    backend_summaries: &[BackendHealthSummary],
) -> Vec<ReportDiagnosticRecord> {
    let mut diagnostics: Vec<ReportDiagnosticRecord> = backend_summaries
        .iter()
        .filter(|summary| !summary.is_available)
        .map(|summary| {
            ReportDiagnosticRecord::new(
                report_id.to_string(),
                DiagnosticPhase::SubstrateProvisioning,
                DiagnosticOwner::Substrate,
                DiagnosticClass::SubstrateUnavailable,
                Some(summary.backend_id.clone()),
                DiagnosticSeverity::Medium,
                DiagnosticConfidence::High,
                DiagnosticActionability::FallbackRecommended,
                summary.stable_summary.clone(),
                vec![format!(
                    "make {} available or choose a fallback backend",
                    summary.backend_id
                )],
            )
        })
        .collect();

    diagnostics.extend(backend_summaries.iter().filter_map(|summary| {
        native_recipe_diagnostic(
            report_id,
            summary.backend_id.as_str(),
            summary.display_name.as_str(),
            summary.is_available,
            &summary.checks,
            DiagnosticPhase::SubstrateProvisioning,
            DiagnosticOwner::Substrate,
            DiagnosticClass::SubstrateUnavailable,
        )
    }));

    diagnostics
}

pub fn render(report: &PreflightReport) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "primary family: {} ({:.0}% confidence)\n",
        report.primary_family.family_id,
        report.primary_family.confidence * 100.0
    ));

    if let Some(preferred) = report.backends.first() {
        output.push_str(&format!(
            "preferred backend: {} [{}] ({:.2}) - {} ({})\n",
            preferred.display_name,
            preferred.backend_id,
            preferred.score,
            availability_label(preferred.is_available),
            preferred.availability_detail
        ));
    } else {
        output.push_str("preferred backend: none (no ranked backends for detected family)\n");
    }

    let available: Vec<&PreflightBackend> = report
        .backends
        .iter()
        .filter(|backend| backend.is_available)
        .collect();
    if !available.is_empty() {
        output.push_str("available backends:\n");
        for backend in available {
            output.push_str(&format!(
                "- {} [{}]: {:.2} - {}; {}\n",
                backend.display_name,
                backend.backend_id,
                backend.score,
                backend.reason,
                backend.availability_detail
            ));
        }
    }

    let unavailable: Vec<&PreflightBackend> = report
        .backends
        .iter()
        .filter(|backend| !backend.is_available)
        .collect();
    if !unavailable.is_empty() {
        output.push_str("unavailable backends:\n");
    }

    for backend in unavailable {
        output.push_str(&format!(
            "- {} [{}]: {:.2} - {}; {}\n",
            backend.display_name,
            backend.backend_id,
            backend.score,
            backend.reason,
            backend.availability_detail
        ));
    }

    if !report.host_capabilities.diagnostics.is_empty() {
        output.push_str("host diagnostics:\n");
        for diagnostic in &report.host_capabilities.diagnostics {
            output.push_str(&format!(
                "- {} [{}]\n",
                diagnostic.summary, diagnostic.diagnostic_id
            ));
        }
    }

    output
}

fn native_recipe_diagnostic(
    report_id: &str,
    backend_id: &str,
    display_name: &str,
    is_available: bool,
    checks: &[BackendCheckRecord],
    phase: DiagnosticPhase,
    owner: DiagnosticOwner,
    class: DiagnosticClass,
) -> Option<ReportDiagnosticRecord> {
    if backend_id != "firmae" || !is_available {
        return None;
    }

    let failed_recipe_checks: Vec<&BackendCheckRecord> = checks
        .iter()
        .filter(|check| check.check_type == "recipe" && !check.passed)
        .collect();
    if failed_recipe_checks.is_empty() {
        return None;
    }

    let detail = failed_recipe_checks
        .iter()
        .map(|check| check.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let actions = failed_recipe_checks
        .iter()
        .map(|check| format!("repair the FirmAE recipe check {}", check.subject))
        .collect();

    Some(ReportDiagnosticRecord::new(
        report_id.to_string(),
        phase,
        owner,
        class,
        Some("firmae-native-recipe".to_string()),
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("{display_name} [{backend_id}] native FirmAE recipe incomplete: {detail}"),
        actions,
    ))
}

fn availability_label(is_available: bool) -> &'static str {
    if is_available {
        "available"
    } else {
        "unavailable"
    }
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    #[test]
    fn doctor_report_serializes_to_json() {
        let probe = PathCommandProbe;
        let report = doctor_report_with_probe(&probe);
        let value = serde_json::to_value(&report).expect("doctor report serializes");
        assert_eq!(value["host_os"], std::env::consts::OS);
        assert_eq!(value["host_arch"], std::env::consts::ARCH);
        assert!(value["backend_summaries"].is_array());
        assert!(value["diagnostics"].is_array());
    }
}
