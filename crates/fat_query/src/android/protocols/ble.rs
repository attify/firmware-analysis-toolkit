use crate::android::protocols::{ProtocolFileView, ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSupportLevel,
};
use std::collections::BTreeMap;

pub(crate) fn derive_ble_semantics(
    index: &ProtocolIndex,
    mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut best_file: Option<&ProtocolFileView> = None;
    let mut best_score = 0;

    for file in &index.files {
        let mut score = 0;
        if file
            .signals
            .iter()
            .any(|signal| signal.kind == ProtocolSignalKind::BleImport)
        {
            score += 1;
        }
        if file
            .signals
            .iter()
            .any(|signal| signal.kind == ProtocolSignalKind::BleSymbol)
        {
            score += 2;
        }

        if score > best_score {
            best_score = score;
            best_file = Some(file);
        }
    }

    let Some(file) = best_file else {
        return bundle;
    };

    bundle.facts.push(AndroidSemanticFact {
        fact_id: "fact-ble-family".into(),
        kind: "source.protocol-family".into(),
        subject: "ble".into(),
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
    bundle.control_surfaces.push(AndroidControlSurface {
        surface_id: "control-ble-adapter-surface".into(),
        kind: "ble-adapter-surface".into(),
        entry_symbol: None,
        exported_component: None,
        trigger: Some("android.bluetooth.BluetoothAdapter".into()),
        notes: if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            vec![format!("source={}", file.path.display())]
        } else {
            vec!["source-derived BLE adapter surface".into()]
        },
    });
    bundle.correlations.push(AndroidCorrelation {
        correlation_id: "corr-ble-import-symbol".into(),
        kind: "ble-import-symbol".into(),
        members: vec![
            "fact-ble-family".into(),
            "control-ble-adapter-surface".into(),
        ],
        support_level: AndroidSupportLevel::Inferred,
        rationale: Some("android.bluetooth imports or BLE symbols co-occur".into()),
    });

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
