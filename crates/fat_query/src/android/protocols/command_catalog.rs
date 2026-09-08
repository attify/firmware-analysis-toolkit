use crate::android::protocols::{ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{AndroidSemanticBundle, AndroidSemanticFact, AndroidSupportLevel};
use std::collections::BTreeSet;

pub(crate) fn derive_command_catalog_semantics(
    index: &ProtocolIndex,
    _mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut emitted = BTreeSet::new();

    for file in &index.files {
        for signal in &file.signals {
            let Some((kind, subject)) = signal_to_fact(signal.kind, signal.detail.as_deref())
            else {
                continue;
            };
            let fact_id = format!(
                "fact-{}-{}",
                kind.replace('.', "-"),
                sanitize_subject(subject)
            );
            if !emitted.insert(fact_id.clone()) {
                continue;
            }
            bundle.facts.push(AndroidSemanticFact {
                fact_id,
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

fn signal_to_fact(kind: ProtocolSignalKind, subject: Option<&str>) -> Option<(&'static str, &str)> {
    let subject = subject?;
    match kind {
        ProtocolSignalKind::CommandCatalogEntry => Some(("role.command-catalog-entry", subject)),
        ProtocolSignalKind::CommandEnvelopeField => Some(("role.command-envelope-field", subject)),
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
