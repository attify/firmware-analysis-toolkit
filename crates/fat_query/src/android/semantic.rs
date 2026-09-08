use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticBundle {
    pub bundle_version: String,
    pub target: AndroidSemanticTarget,
    pub extractor: AndroidExtractorMetadata,
    #[serde(default)]
    pub facts: Vec<AndroidSemanticFact>,
    #[serde(default)]
    pub symbol_identities: Vec<AndroidSymbolIdentity>,
    #[serde(default)]
    pub control_surfaces: Vec<AndroidControlSurface>,
    #[serde(default)]
    pub transport_surfaces: Vec<AndroidTransportSurface>,
    #[serde(default)]
    pub trust_boundaries: Vec<AndroidTrustBoundary>,
    #[serde(default)]
    pub resources: Vec<AndroidResourceSemantic>,
    #[serde(default)]
    pub native_semantics: Vec<AndroidNativeSemantic>,
    #[serde(default)]
    pub subsystems: Vec<AndroidSubsystem>,
    #[serde(default)]
    pub revelations: Vec<AndroidRevelation>,
    #[serde(default)]
    pub correlations: Vec<AndroidCorrelation>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    pub package_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_name: Option<String>,
    #[serde(default)]
    pub split_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidExtractorMetadata {
    pub extractor_id: String,
    pub extractor_version: String,
    pub input_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at_utc: Option<String>,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidSupportLevel {
    Observed,
    Inferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidProvenance {
    pub origin: String,
    pub artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticFact {
    pub fact_id: String,
    pub kind: String,
    pub subject: String,
    pub support_level: AndroidSupportLevel,
    #[serde(default)]
    pub provenance: Vec<AndroidProvenance>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSymbolIdentity {
    pub symbol_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub kind: String,
    pub qualified_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
    #[serde(default)]
    pub synthetic: bool,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidControlSurface {
    pub surface_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidTransportSurface {
    pub surface_id: String,
    pub kind: String,
    pub source: String,
    pub sink: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidTrustBoundary {
    pub boundary_id: String,
    pub kind: String,
    pub from_zone: String,
    pub to_zone: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidResourceSemantic {
    pub resource_id: String,
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub qualifiers: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidNativeSemantic {
    pub native_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_name: Option<String>,
    pub symbol_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_symbol_id: Option<String>,
    #[serde(default)]
    pub synthetic: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSubsystem {
    pub subsystem_id: String,
    pub kind: String,
    pub support_level: AndroidSupportLevel,
    #[serde(default)]
    pub package_prefixes: Vec<String>,
    #[serde(default)]
    pub symbol_ids: Vec<String>,
    #[serde(default)]
    pub control_surface_ids: Vec<String>,
    #[serde(default)]
    pub transport_surface_ids: Vec<String>,
    #[serde(default)]
    pub trust_boundary_ids: Vec<String>,
    #[serde(default)]
    pub native_ids: Vec<String>,
    #[serde(default)]
    pub fact_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidRevelation {
    pub revelation_id: String,
    pub kind: String,
    pub support_level: AndroidSupportLevel,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub subsystem_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidCorrelation {
    pub correlation_id: String,
    pub kind: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub support_level: AndroidSupportLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticRevelation {
    pub name: String,
    pub support_level: AndroidSupportLevel,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_bundle_round_trips_observed_and_inferred_facts() {
        let bundle = AndroidSemanticBundle {
            bundle_version: "android-semantic/v1alpha1".into(),
            target: AndroidSemanticTarget {
                application_id: Some("com.example.app".into()),
                package_name: "com.example.app".into(),
                version_code: Some("42".into()),
                version_name: Some("1.0".into()),
                split_names: vec!["base".into(), "feature.camera".into()],
            },
            extractor: AndroidExtractorMetadata {
                extractor_id: "jadx-recon".into(),
                extractor_version: "0.1.0".into(),
                input_kind: "jadx-tree".into(),
                generated_at_utc: Some("2026-04-06T12:00:00Z".into()),
                degraded: false,
                notes: vec!["semantic extraction complete".into()],
            },
            facts: vec![
                AndroidSemanticFact {
                    fact_id: "fact-observed-1".into(),
                    kind: "control-surface.router-dispatch".into(),
                    subject: "Lcom/example/Router;->dispatch(Ljava/lang/String;)V".into(),
                    support_level: AndroidSupportLevel::Observed,
                    provenance: vec![AndroidProvenance {
                        origin: "jadx".into(),
                        artifact: "sources/com/example/Router.java".into(),
                        location: Some("dispatch:41".into()),
                        detail: Some("switch over route token".into()),
                    }],
                    attributes: std::collections::BTreeMap::from([(
                        "route_source".into(),
                        "intent-extra".into(),
                    )]),
                },
                AndroidSemanticFact {
                    fact_id: "fact-inferred-1".into(),
                    kind: "trust-boundary.deep-link-to-router".into(),
                    subject: "route://deeplink".into(),
                    support_level: AndroidSupportLevel::Inferred,
                    provenance: vec![AndroidProvenance {
                        origin: "correlator".into(),
                        artifact: "deeplink-routing".into(),
                        location: None,
                        detail: Some("manifest filter aligns with router sink".into()),
                    }],
                    attributes: std::collections::BTreeMap::new(),
                },
            ],
            symbol_identities: vec![AndroidSymbolIdentity {
                symbol_id: "sym-router-dispatch".into(),
                language: Some("java".into()),
                kind: "method".into(),
                qualified_name: "com.example.Router.dispatch".into(),
                descriptor: Some("(Ljava/lang/String;)V".into()),
                synthetic: false,
                aliases: vec!["Lcom/example/Router;->dispatch(Ljava/lang/String;)V".into()],
            }],
            control_surfaces: vec![AndroidControlSurface {
                surface_id: "control-router-dispatch".into(),
                kind: "router-dispatch".into(),
                entry_symbol: Some("sym-router-dispatch".into()),
                exported_component: Some("com.example.DeepLinkActivity".into()),
                trigger: Some("android.intent.action.VIEW".into()),
                notes: vec!["dispatches untrusted route material".into()],
            }],
            transport_surfaces: vec![AndroidTransportSurface {
                surface_id: "transport-deeplink-intent".into(),
                kind: "intent-parse".into(),
                source: "external-deeplink".into(),
                sink: "control-router-dispatch".into(),
                carrier: Some("android.net.Uri".into()),
                notes: vec!["URI path becomes route token".into()],
            }],
            trust_boundaries: vec![AndroidTrustBoundary {
                boundary_id: "boundary-deeplink-router".into(),
                kind: "deep-link-to-internal-router".into(),
                from_zone: "external-caller".into(),
                to_zone: "app-router".into(),
                guard: Some("route allowlist".into()),
                notes: vec!["allowlist not confirmed at extraction time".into()],
            }],
            resources: vec![AndroidResourceSemantic {
                resource_id: "resource-network-config".into(),
                kind: "xml-network-security-config".into(),
                path: "res/xml/network_security_config.xml".into(),
                qualifiers: vec![],
                notes: vec!["debug-overrides absent".into()],
            }],
            native_semantics: vec![AndroidNativeSemantic {
                native_id: "native-jni-dispatch".into(),
                kind: "jni-registration".into(),
                library_name: Some("librouter.so".into()),
                symbol_name: "Java_com_example_Router_nativeDispatch".into(),
                linked_symbol_id: Some("sym-router-dispatch".into()),
                synthetic: false,
                notes: vec!["Java entrypoint crosses into native parser".into()],
            }],
            subsystems: vec![AndroidSubsystem {
                subsystem_id: "subsystem-router".into(),
                kind: "router".into(),
                support_level: AndroidSupportLevel::Observed,
                package_prefixes: vec!["com.example".into()],
                symbol_ids: vec!["sym-router-dispatch".into()],
                control_surface_ids: vec!["control-router-dispatch".into()],
                transport_surface_ids: vec!["transport-deeplink-intent".into()],
                trust_boundary_ids: vec!["boundary-deeplink-router".into()],
                native_ids: vec!["native-jni-dispatch".into()],
                fact_ids: vec!["fact-observed-1".into()],
                rationale: Some("router symbols and deeplink handling cluster together".into()),
                notes: vec!["synthetic subsystem fixture".into()],
            }],
            revelations: vec![AndroidRevelation {
                revelation_id: "rev-router-native".into(),
                kind: "router-native-crossing".into(),
                support_level: AndroidSupportLevel::Observed,
                members: vec!["sym-router-dispatch".into(), "native-jni-dispatch".into()],
                subsystem_ids: vec!["subsystem-router".into()],
                rationale: Some("JNI name and descriptor match".into()),
            }],
            correlations: vec![AndroidCorrelation {
                correlation_id: "corr-router-native".into(),
                kind: "symbol-to-native".into(),
                members: vec!["sym-router-dispatch".into(), "native-jni-dispatch".into()],
                support_level: AndroidSupportLevel::Observed,
                rationale: Some("JNI name and descriptor match".into()),
            }],
            warnings: vec!["no kotlin metadata available".into()],
        };

        let encoded = serde_json::to_string_pretty(&bundle).expect("serialize semantic bundle");
        let decoded: AndroidSemanticBundle =
            serde_json::from_str(&encoded).expect("deserialize semantic bundle");

        assert_eq!(decoded.target.package_name, "com.example.app");
        assert_eq!(decoded.facts.len(), 2);
        assert_eq!(
            decoded.facts[0].support_level,
            AndroidSupportLevel::Observed
        );
        assert_eq!(
            decoded.facts[1].support_level,
            AndroidSupportLevel::Inferred
        );
        assert_eq!(
            decoded.control_surfaces[0].entry_symbol.as_deref(),
            Some("sym-router-dispatch")
        );
        assert_eq!(decoded.subsystems.len(), 1);
        assert_eq!(decoded.subsystems[0].subsystem_id, "subsystem-router");
        assert_eq!(decoded.subsystems[0].kind, "router");
        assert_eq!(decoded.revelations.len(), 1);
        assert_eq!(decoded.revelations[0].revelation_id, "rev-router-native");
        assert_eq!(decoded.revelations[0].kind, "router-native-crossing");
        assert_eq!(
            decoded.revelations[0].support_level,
            AndroidSupportLevel::Observed
        );
        assert_eq!(
            decoded.revelations[0].members,
            vec![
                "sym-router-dispatch".to_string(),
                "native-jni-dispatch".to_string()
            ]
        );
        assert_eq!(
            decoded.revelations[0].subsystem_ids,
            vec!["subsystem-router".to_string()]
        );
        assert_eq!(
            decoded.revelations[0].rationale.as_deref(),
            Some("JNI name and descriptor match")
        );
    }
}
