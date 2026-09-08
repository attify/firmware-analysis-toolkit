use crate::android::protocols::{ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{AndroidSemanticBundle, AndroidSemanticFact, AndroidSupportLevel};
use std::collections::BTreeSet;

pub(crate) fn derive_security_constant_semantics(
    index: &ProtocolIndex,
    _mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut emitted = BTreeSet::new();

    for file in &index.files {
        for signal in &file.signals {
            let Some(kind) = signal_fact_kind(signal.kind) else {
                continue;
            };
            let Some(subject) = signal.detail.as_deref() else {
                continue;
            };
            if !emitted.insert((kind, subject.to_string())) {
                continue;
            }

            bundle.facts.push(AndroidSemanticFact {
                fact_id: format!(
                    "fact-{}-{}",
                    kind.replace('.', "-"),
                    sanitize_subject(subject)
                ),
                kind: kind.into(),
                subject: subject.into(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![file.provenance.clone()],
                attributes: std::collections::BTreeMap::new(),
            });
        }
    }

    bundle
}

fn signal_fact_kind(kind: ProtocolSignalKind) -> Option<&'static str> {
    match kind {
        ProtocolSignalKind::StaticSecret => Some("security.static-secret"),
        ProtocolSignalKind::PublicKey => Some("security.public-key"),
        ProtocolSignalKind::SymmetricKeyMaterial => Some("security.symmetric-key-material"),
        ProtocolSignalKind::DefaultCredential => Some("security.default-credential"),
        ProtocolSignalKind::NetworkStaticEndpoint => Some("network.static-endpoint"),
        _ => None,
    }
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
