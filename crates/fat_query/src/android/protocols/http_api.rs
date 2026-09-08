use crate::android::protocols::{ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidSemanticBundle, AndroidSemanticFact, AndroidSupportLevel,
};
use std::collections::BTreeSet;

pub(crate) fn derive_http_api_semantics(
    index: &ProtocolIndex,
    _mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut emitted_controls = BTreeSet::new();
    let mut emitted_facts = BTreeSet::new();

    for file in &index.files {
        for signal in &file.signals {
            match signal.kind {
                ProtocolSignalKind::HttpApiEndpoint => {
                    let Some(detail) = signal.detail.as_deref() else {
                        continue;
                    };
                    let endpoint = decode_http_endpoint(detail);
                    if endpoint.path.is_empty() {
                        continue;
                    }
                    let kind = if is_signaling_endpoint(&endpoint.path) {
                        "signaling-endpoint"
                    } else {
                        "http-api-endpoint"
                    };
                    let surface_id = format!(
                        "control-http-endpoint-{}",
                        sanitize_subject(&format!("{}-{}", endpoint.method, endpoint.path))
                    );
                    if emitted_controls.insert(surface_id.clone()) {
                        let mut notes = vec![format!("method={}", endpoint.method)];
                        if endpoint.dynamic {
                            notes.push("dynamic-path".into());
                        }
                        bundle.control_surfaces.push(AndroidControlSurface {
                            surface_id,
                            kind: kind.into(),
                            entry_symbol: None,
                            exported_component: None,
                            trigger: Some(endpoint.path.clone()),
                            notes,
                        });
                    }
                }
                ProtocolSignalKind::HttpAuthHeader => {
                    let Some(subject) = signal.detail.as_deref() else {
                        continue;
                    };
                    let fact_id = format!("fact-http-auth-header-{}", sanitize_subject(subject));
                    if emitted_facts.insert(fact_id.clone()) {
                        bundle.facts.push(AndroidSemanticFact {
                            fact_id,
                            kind: "http.auth-header".into(),
                            subject: subject.into(),
                            support_level: AndroidSupportLevel::Observed,
                            provenance: vec![file.provenance.clone()],
                            attributes: std::collections::BTreeMap::new(),
                        });
                    }
                }
                ProtocolSignalKind::HttpDynamicPath => {
                    let Some(subject) = signal.detail.as_deref() else {
                        continue;
                    };
                    let fact_id = format!("fact-http-dynamic-path-{}", sanitize_subject(subject));
                    if emitted_facts.insert(fact_id.clone()) {
                        bundle.facts.push(AndroidSemanticFact {
                            fact_id,
                            kind: "http.dynamic-path".into(),
                            subject: subject.into(),
                            support_level: AndroidSupportLevel::Observed,
                            provenance: vec![file.provenance.clone()],
                            attributes: std::collections::BTreeMap::new(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    bundle
}

#[derive(Debug, Default)]
struct HttpEndpointDetail {
    method: String,
    path: String,
    dynamic: bool,
}

fn decode_http_endpoint(detail: &str) -> HttpEndpointDetail {
    let mut endpoint = HttpEndpointDetail::default();
    for part in detail.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "method" => endpoint.method = value.to_string(),
            "path" => endpoint.path = value.to_string(),
            "dynamic" => endpoint.dynamic = value == "true",
            _ => {}
        }
    }
    endpoint
}

fn is_signaling_endpoint(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("webrtc")
        || lower.contains("signal")
        || lower.contains("turn")
        || lower.contains("con_check")
        || lower.contains("con_ing")
}

fn sanitize_subject(subject: &str) -> String {
    subject
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn empty_bundle() -> AndroidSemanticBundle {
    crate::android::semantic::AndroidSemanticBundle {
        bundle_version: String::new(),
        target: crate::android::semantic::AndroidSemanticTarget {
            application_id: None,
            package_name: String::new(),
            version_code: None,
            version_name: None,
            split_names: Vec::new(),
        },
        extractor: crate::android::semantic::AndroidExtractorMetadata {
            extractor_id: String::new(),
            extractor_version: String::new(),
            input_kind: String::new(),
            generated_at_utc: None,
            degraded: false,
            notes: Vec::new(),
        },
        facts: Vec::new(),
        symbol_identities: Vec::new(),
        control_surfaces: Vec::new(),
        transport_surfaces: Vec::new(),
        trust_boundaries: Vec::new(),
        resources: Vec::new(),
        native_semantics: Vec::new(),
        subsystems: Vec::new(),
        revelations: Vec::new(),
        correlations: Vec::new(),
        warnings: Vec::new(),
    }
}
