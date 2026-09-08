use crate::android::protocols::{ProtocolFileView, ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidNativeSemantic, AndroidProvenance,
    AndroidSemanticBundle, AndroidSemanticFact, AndroidSupportLevel,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn derive_weave_semantics(
    index: &ProtocolIndex,
    mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut signals = BTreeSet::new();
    let mut auth_provenance = Vec::new();
    let mut fabric_provenance = Vec::new();
    let mut key_export_provenance = Vec::new();
    let mut native_provenance = Vec::new();

    for file in &index.files {
        if has_signal(file, ProtocolSignalKind::WeaveAuth) {
            push_unique_provenance(&mut auth_provenance, &file.provenance);
            signals.insert("auth");
        }
        if has_signal(file, ProtocolSignalKind::WeaveFabric) {
            push_unique_provenance(&mut fabric_provenance, &file.provenance);
            signals.insert("fabric");
        }
        if has_signal(file, ProtocolSignalKind::WeaveKeyExport) {
            push_unique_provenance(&mut key_export_provenance, &file.provenance);
            signals.insert("key-export");
        }
        if has_signal(file, ProtocolSignalKind::WeaveNativeKeyExport) {
            push_unique_provenance(&mut native_provenance, &file.provenance);
            signals.insert("native");
        }
    }

    if signals.is_empty() {
        return bundle;
    }

    if !auth_provenance.is_empty() {
        emit_weave_fact(
            &mut bundle,
            "fact-weave-auth",
            "protocol.weave-auth",
            "authorization",
            &auth_provenance,
            mode,
        );
    }
    if !fabric_provenance.is_empty() {
        emit_weave_fact(
            &mut bundle,
            "fact-weave-fabric",
            "protocol.weave-fabric",
            "fabric-membership",
            &fabric_provenance,
            mode,
        );
    }
    if !key_export_provenance.is_empty() {
        emit_weave_fact(
            &mut bundle,
            "fact-weave-key-export",
            "protocol.weave-key-export",
            "key-export",
            &key_export_provenance,
            mode,
        );
    }

    bundle.control_surfaces.push(AndroidControlSurface {
        surface_id: "control-weave-security-plane".into(),
        kind: "weave-security-plane".into(),
        entry_symbol: None,
        exported_component: None,
        trigger: Some("beginRendezvousDeviceAccessToken".into()),
        notes: if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            vec![format!(
                "signals={}",
                signals.into_iter().collect::<Vec<_>>().join(",")
            )]
        } else {
            vec!["source-derived Weave security plane".into()]
        },
    });

    if !native_provenance.is_empty() {
        emit_weave_native_semantics(&mut bundle, &native_provenance, mode);
    }

    let mut correlation_members = Vec::new();
    if !auth_provenance.is_empty() {
        correlation_members.push("fact-weave-auth".into());
    }
    if !fabric_provenance.is_empty() {
        correlation_members.push("fact-weave-fabric".into());
    }
    if !key_export_provenance.is_empty() {
        correlation_members.push("fact-weave-key-export".into());
    }
    if !correlation_members.is_empty() {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-weave-auth-fabric-key-export".into(),
            kind: "weave-auth-fabric-key-export".into(),
            members: correlation_members,
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("Weave auth, fabric, and key-export signals co-occur".into()),
        });
    }

    bundle
}

fn emit_weave_fact(
    bundle: &mut AndroidSemanticBundle,
    fact_id: &str,
    kind: &str,
    subject: &str,
    provenance: &[AndroidProvenance],
    mode: crate::android::extractor::AndroidSemanticMode,
) {
    bundle.facts.push(AndroidSemanticFact {
        fact_id: fact_id.into(),
        kind: kind.into(),
        subject: subject.into(),
        support_level: AndroidSupportLevel::Observed,
        provenance: provenance.to_vec(),
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
}

fn emit_weave_native_semantics(
    bundle: &mut AndroidSemanticBundle,
    provenance: &[AndroidProvenance],
    mode: crate::android::extractor::AndroidSemanticMode,
) {
    bundle.native_semantics.push(AndroidNativeSemantic {
        native_id: "native-weave-key-export".into(),
        kind: "weave-key-export-native".into(),
        library_name: Some("WeaveSecuritySupport".into()),
        symbol_name: "generateKeyExportRequest".into(),
        linked_symbol_id: None,
        synthetic: false,
        notes: if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            vec!["Weave native bridge supporting key export and certificate translation".into()]
        } else {
            vec!["Weave native bridge".into()]
        },
    });
    if mode == crate::android::extractor::AndroidSemanticMode::Dense {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-weave-native-key-export".into(),
            kind: "protocol.weave-native-key-export".into(),
            subject: "WeaveSecuritySupport".into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: provenance.to_vec(),
            attributes: BTreeMap::new(),
        });
    }
}

fn has_signal(file: &ProtocolFileView, kind: ProtocolSignalKind) -> bool {
    file.signals.iter().any(|signal| signal.kind == kind)
}

fn push_unique_provenance(slot: &mut Vec<AndroidProvenance>, provenance: &AndroidProvenance) {
    if !slot.iter().any(|existing| existing == provenance) {
        slot.push(provenance.clone());
    }
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
