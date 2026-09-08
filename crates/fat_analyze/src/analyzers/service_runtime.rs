use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_core::services::{
    managed_stop_summary_from_runtime_state_json, services_from_runtime_state_json,
    services_from_runtime_summary_json, ObservedService, ServiceSummaryArtifact,
};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, ArtifactScope,
    PluginDescriptor, PluginTrustTier, ProducedArtifact,
};

#[derive(Debug, Default)]
pub struct ServiceRuntimeAnalyzer;

impl Analyzer for ServiceRuntimeAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "service-runtime",
            "Service Runtime",
            AnalyzerClass::Runtime,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![
            AnalysisTrigger::RunCompleted,
            AnalysisTrigger::RunDegradedCompleted,
            AnalysisTrigger::RunFailed,
        ])
        .with_supported_artifacts(vec![
            ArtifactInputRef::required(ArtifactKind::RuntimeLog),
            ArtifactInputRef::optional(ArtifactKind::RuntimeState),
        ])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let mut findings = Vec::new();
        let mut observed_services = Vec::new();
        let mut evidence_artifact_ids = Vec::new();
        let mut produced_stop_summary: Option<String> = None;
        let has_managed_runtime_summary = request.artifact_documents.iter().any(|document| {
            document.scope == fat_plugin_api::ArtifactScope::Run
                && document.kind == ArtifactKind::RuntimeState
                && document.subkind == "managed-runtime-summary"
        });

        for document in &request.artifact_documents {
            if document.scope != fat_plugin_api::ArtifactScope::Run {
                continue;
            }
            let Some(text) = &document.text_content else {
                continue;
            };
            if document.kind == ArtifactKind::RuntimeState {
                if has_managed_runtime_summary
                    && matches!(
                        document.subkind.as_str(),
                        "managed-linux-vm-stop-state" | "managed-runtime-status"
                    )
                {
                    continue;
                }
                if matches!(
                    document.subkind.as_str(),
                    "managed-linux-vm-stop-state"
                        | "managed-runtime-status"
                        | "managed-runtime-summary"
                        | "firmae-upstream-observation"
                ) {
                    if let Some((stop_summary, maybe_finding)) =
                        extract_stop_summary_from_runtime_state(
                            &document.subkind,
                            text,
                            &document.artifact_id,
                            &document.rel_path,
                        )
                    {
                        if produced_stop_summary.is_none() {
                            produced_stop_summary = Some(stop_summary);
                        }
                        if let Some(finding) = maybe_finding {
                            findings.push(finding);
                        }
                        evidence_artifact_ids.push(document.artifact_id.clone());
                    }
                }
                if document.subkind == "managed-linux-vm-stop-state" {
                    continue;
                }
            }

            if has_managed_runtime_summary && document.kind == ArtifactKind::RuntimeLog {
                continue;
            }

            let document_services = match document.kind {
                ArtifactKind::RuntimeLog => extract_services_from_log(text),
                ArtifactKind::RuntimeState => {
                    extract_services_from_runtime_state(&document.subkind, text)
                }
                _ => Vec::new(),
            };
            if document_services.is_empty() {
                continue;
            }
            evidence_artifact_ids.push(document.artifact_id.clone());
            observed_services.extend(document_services);

            findings.push(
                Finding::new(
                    format!("service-runtime-{}", document.artifact_id),
                    format!(
                        "management service observed in runtime artifact {}",
                        document.rel_path.as_deref().unwrap_or("artifact")
                    ),
                    FindingSeverity::Medium,
                    FindingSubject::File {
                        rel_path: document
                            .rel_path
                            .clone()
                            .unwrap_or_else(|| document.artifact_id.clone()),
                    },
                )
                .with_plugin_id("service-runtime")
                .with_evidence_artifact_ids(vec![document.artifact_id.clone()]),
            );
        }

        if observed_services.is_empty() && produced_stop_summary.is_none() {
            return AnalysisResult::default();
        }

        let mut produced_artifacts = Vec::new();
        if !observed_services.is_empty() {
            let summary = ServiceSummaryArtifact::new("service-runtime", observed_services);
            let summary_json = summary.to_json_string();
            produced_artifacts.push(
                ProducedArtifact::text(
                    ArtifactScope::Run,
                    ArtifactKind::RuntimeState,
                    "service-summary",
                    "application/json",
                    summary_json,
                    "normalized service observations emitted by runtime analyzer",
                )
                .with_labels(vec!["service-summary".to_string()])
                .with_related_artifact_ids(evidence_artifact_ids.clone()),
            );
        }

        if let Some(stop_summary_json) = produced_stop_summary {
            produced_artifacts.push(
                ProducedArtifact::text(
                    ArtifactScope::Run,
                    ArtifactKind::RuntimeState,
                    "managed-stop-summary",
                    "application/json",
                    stop_summary_json,
                    "normalized managed stop observations emitted by runtime analyzer",
                )
                .with_labels(vec!["stop-summary".to_string()])
                .with_related_artifact_ids(evidence_artifact_ids.clone()),
            );
        }

        AnalysisResult {
            findings,
            diagnostics: Vec::new(),
            produced_artifacts,
            produced_artifact_ids: Vec::new(),
        }
    }
}

fn extract_services_from_log(text: &str) -> Vec<ObservedService> {
    text.lines().filter_map(parse_service_line).collect()
}

fn extract_services_from_runtime_state(subkind: &str, text: &str) -> Vec<ObservedService> {
    if subkind == "managed-runtime-summary" {
        return services_from_runtime_summary_json(text);
    }

    if !matches!(
        subkind,
        "managed-linux-vm-launch-state" | "managed-runtime-status" | "firmae-upstream-observation"
    ) {
        return Vec::new();
    }

    services_from_runtime_state_json(text)
}

fn extract_stop_summary_from_runtime_state(
    subkind: &str,
    text: &str,
    artifact_id: &str,
    rel_path: &Option<String>,
) -> Option<(String, Option<Finding>)> {
    let summary = managed_stop_summary_from_runtime_state_json(subkind, text)?;
    let summary_json = summary.to_json_string();

    let finding = if summary.is_fully_verified() {
        None
    } else {
        Some(
            Finding::new(
                format!("managed-stop-{artifact_id}"),
                "Managed stop contract was not fully verified".to_string(),
                FindingSeverity::Medium,
                FindingSubject::File {
                    rel_path: rel_path.clone().unwrap_or_else(|| artifact_id.to_string()),
                },
            )
            .with_plugin_id("service-runtime")
            .with_evidence_artifact_ids(vec![artifact_id.to_string()]),
        )
    };

    Some((summary_json, finding))
}

fn parse_service_line(line: &str) -> Option<ObservedService> {
    let lowered = line.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return None;
    }

    for service_name in ["uhttpd", "httpd", "dropbear", "sshd"] {
        if !lowered.contains(service_name) {
            continue;
        }

        let endpoint = lowered
            .split_whitespace()
            .find(|token| token.contains(':') && token.chars().any(|ch| ch.is_ascii_digit()))
            .map(str::to_string);
        let service = match endpoint {
            Some(endpoint) => ObservedService::new(service_name).with_endpoint(endpoint),
            None => ObservedService::new(service_name),
        };
        return Some(service);
    }

    None
}
