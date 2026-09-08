use crate::android::protocols::{ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSupportLevel,
};
use std::collections::BTreeMap;

pub(crate) fn derive_matter_semantics(
    index: &ProtocolIndex,
    mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut commissioning_provenance = Vec::new();
    let mut commissioning_field_provenance = Vec::new();

    for file in &index.files {
        let commissioning = file
            .signals
            .iter()
            .any(|signal| signal.kind == ProtocolSignalKind::MatterCommissioning);
        if !commissioning {
            continue;
        }

        push_unique_provenance(&mut commissioning_provenance, &file.provenance);

        if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            let mut details = Vec::new();
            for signal in &file.signals {
                if signal.kind == ProtocolSignalKind::MatterCommissioningField {
                    if let Some(detail) = &signal.detail {
                        details.push(detail.clone());
                    }
                }
            }
            if !details.is_empty() {
                push_unique_provenance(&mut commissioning_field_provenance, &file.provenance);
            }
        }
    }

    if commissioning_provenance.is_empty() {
        return bundle;
    }

    bundle.facts.push(AndroidSemanticFact {
        fact_id: "fact-matter-commissioning".into(),
        kind: "protocol.matter-commissioning".into(),
        subject: "commissioning".into(),
        support_level: AndroidSupportLevel::Observed,
        provenance: commissioning_provenance.clone(),
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
        surface_id: "control-matter-commissioning-session".into(),
        kind: "matter-commissioning-session".into(),
        entry_symbol: None,
        exported_component: None,
        trigger: Some("manualPairingCode".into()),
        notes: if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            vec![format!("files={}", commissioning_provenance.len())]
        } else {
            vec!["source-derived Matter commissioning session".into()]
        },
    });
    bundle.correlations.push(AndroidCorrelation {
        correlation_id: "corr-matter-commissioning".into(),
        kind: "matter-commissioning-session".into(),
        members: vec![
            "fact-matter-commissioning".into(),
            "control-matter-commissioning-session".into(),
        ],
        support_level: AndroidSupportLevel::Inferred,
        rationale: Some("Matter commissioning data and session surface co-occur".into()),
    });

    if mode == crate::android::extractor::AndroidSemanticMode::Dense
        && !commissioning_field_provenance.is_empty()
    {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-matter-commissioning-fields".into(),
            kind: "protocol.matter-commissioning-fields".into(),
            subject: "commissioning-fields".into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: commissioning_field_provenance,
            attributes: BTreeMap::from([("symbol_count".into(), "1".into())]),
        });
    }

    bundle
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

fn push_unique_provenance(
    slot: &mut Vec<crate::android::semantic::AndroidProvenance>,
    provenance: &crate::android::semantic::AndroidProvenance,
) {
    if !slot.iter().any(|existing| existing == provenance) {
        slot.push(provenance.clone());
    }
}
