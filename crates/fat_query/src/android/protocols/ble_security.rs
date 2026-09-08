use crate::android::protocols::{ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSupportLevel,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn derive_ble_security_semantics(
    index: &ProtocolIndex,
    mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut emitted = BTreeSet::new();
    let mut has_local_device_control = false;
    let mut bootstrap_members = Vec::new();

    for file in &index.files {
        for signal in &file.signals {
            let Some(kind) = signal_to_fact_kind(signal.kind) else {
                continue;
            };
            let Some(subject) = signal.detail.as_deref() else {
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
                fact_id: fact_id.clone(),
                kind: kind.into(),
                subject: subject.into(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![file.provenance.clone()],
                attributes: BTreeMap::from([(
                    "mode".into(),
                    if mode == crate::android::extractor::AndroidSemanticMode::Dense {
                        "dense"
                    } else {
                        "default"
                    }
                    .into(),
                )]),
            });
            bootstrap_members.push(fact_id);
        }

        if file
            .signals
            .iter()
            .any(|signal| signal.kind == ProtocolSignalKind::LocalDeviceControl)
        {
            has_local_device_control = true;
        }
    }

    if has_local_device_control && !bootstrap_members.is_empty() {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-local-device-bootstrap".into(),
            kind: "role.local-device-bootstrap".into(),
            subject: "local-device-bootstrap".into(),
            support_level: AndroidSupportLevel::Inferred,
            provenance: Vec::new(),
            attributes: BTreeMap::from([(
                "mode".into(),
                if mode == crate::android::extractor::AndroidSemanticMode::Dense {
                    "dense"
                } else {
                    "default"
                }
                .into(),
            )]),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-local-device-bootstrap".into(),
            kind: "local-device-bootstrap".into(),
            entry_symbol: None,
            exported_component: None,
            trigger: Some("ble bootstrap".into()),
            notes: vec![
                "BLE UUID, crypto, and session-key hints align with local device bootstrap".into(),
            ],
        });
        let mut members = vec!["fact-local-device-bootstrap".into()];
        members.extend(bootstrap_members);
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-local-device-bootstrap".into(),
            kind: "local-device-bootstrap".into(),
            members,
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some(
                "BLE UUID, crypto mode, and session-key hints align with a local bootstrap path"
                    .into(),
            ),
        });
    }

    bundle
}

fn signal_to_fact_kind(kind: ProtocolSignalKind) -> Option<&'static str> {
    match kind {
        ProtocolSignalKind::BleCharacteristicUuid => Some("ble.characteristic-uuid"),
        ProtocolSignalKind::BleCryptoMode => Some("ble.crypto-mode"),
        ProtocolSignalKind::BleSessionKeyDerivation => Some("ble.session-key-derivation"),
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
