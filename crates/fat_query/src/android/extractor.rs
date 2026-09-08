use crate::android::discovery::{AndroidComponentKind, AndroidManifestFact};
use crate::android::protocols::{
    derive_protocol_semantics, ProtocolFileView, ProtocolIndex, ProtocolSignal, ProtocolSignalKind,
};
use crate::android::revelations::derive_revelations;
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidExtractorMetadata, AndroidNativeSemantic,
    AndroidProvenance, AndroidResourceSemantic, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSemanticTarget, AndroidSupportLevel, AndroidSymbolIdentity, AndroidTransportSurface,
    AndroidTrustBoundary,
};
use crate::android::subsystems::derive_subsystems;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidSemanticMode {
    Default,
    Dense,
}

impl AndroidSemanticMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Dense => "dense",
        }
    }
}

impl FromStr for AndroidSemanticMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "dense" => Ok(Self::Dense),
            other => Err(format!("unsupported android semantic mode: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidProgressPhase {
    InventoryApks,
    RunJadx,
    IndexJadxSources,
    DeriveSemanticFacts,
    BuildSubsystems,
    DeriveRevelations,
    RankDiscoveryLeads,
}

impl AndroidProgressPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::InventoryApks => "Inventory APKs",
            Self::RunJadx => "Run JADX",
            Self::IndexJadxSources => "Index JADX sources",
            Self::DeriveSemanticFacts => "Derive semantic facts",
            Self::BuildSubsystems => "Build subsystems",
            Self::DeriveRevelations => "Derive revelations",
            Self::RankDiscoveryLeads => "Rank discovery leads",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AndroidProgressSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystems: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revelations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub trait AndroidProgressSink {
    fn phase_started(&mut self, _phase: AndroidProgressPhase, _snapshot: &AndroidProgressSnapshot) {
    }
    fn phase_progress(
        &mut self,
        _phase: AndroidProgressPhase,
        _snapshot: &AndroidProgressSnapshot,
    ) {
    }
    fn phase_completed(
        &mut self,
        _phase: AndroidProgressPhase,
        _snapshot: &AndroidProgressSnapshot,
    ) {
    }
}

pub struct NullAndroidProgressSink;

impl AndroidProgressSink for NullAndroidProgressSink {}

#[derive(Debug)]
struct SourceFile {
    path: PathBuf,
    text: String,
    lower_text: String,
    package_name: Option<String>,
    package_family: Option<String>,
    imports: Vec<String>,
    import_families: Vec<String>,
    protocol_families: Vec<String>,
    security_families: Vec<String>,
    class_names: Vec<String>,
    interesting_method_names: Vec<String>,
    has_high_signal_method: bool,
    loaded_libraries: Vec<String>,
}

#[derive(Debug)]
struct AndroidSemanticIndex {
    files: Vec<SourceFile>,
    package_family_summaries: Vec<FamilySummary>,
    import_family_summaries: Vec<FamilySummary>,
    native_bridge_summaries: Vec<NativeBridgeSummary>,
    resource_summaries: Vec<ResourceSummary>,
    protocol_security_markers: Vec<ProtocolSecurityMarker>,
}

#[derive(Debug, Clone)]
struct FamilySummary {
    family: String,
    sample_subject: String,
    provenance: AndroidProvenance,
    is_semantically_relevant: bool,
}

#[derive(Debug)]
struct NativeBridgeSummary {
    path: PathBuf,
    loaded_libraries: Vec<String>,
    is_semantically_relevant: bool,
}

#[derive(Debug)]
struct ResourceSummary {
    path: PathBuf,
    kind: String,
}

#[derive(Debug)]
struct ProtocolSecurityMarker {
    path: PathBuf,
    sample_subject: String,
    protocol_families: Vec<String>,
    security_families: Vec<String>,
    is_semantically_relevant: bool,
}

#[derive(Debug, Default)]
struct FamilyObservation {
    sample_subject: String,
    provenance: Vec<AndroidProvenance>,
    occurrences: usize,
}

#[derive(Debug, Clone)]
struct JavascriptInterfaceMethod {
    name: String,
    parameter_types: Vec<String>,
    sink_notes: Vec<String>,
}

pub fn derive_semantic_bundle_from_jadx_root(
    jadx_root: &Path,
    manifest: Option<&AndroidManifestFact>,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> Result<AndroidSemanticBundle, String> {
    let mut sink = NullAndroidProgressSink;
    derive_semantic_bundle_from_jadx_root_with_progress(
        jadx_root,
        manifest,
        package_name,
        mode,
        &mut sink,
    )
}

pub fn derive_semantic_bundle_from_jadx_root_with_progress(
    jadx_root: &Path,
    manifest: Option<&AndroidManifestFact>,
    package_name: &str,
    mode: AndroidSemanticMode,
    sink: &mut dyn AndroidProgressSink,
) -> Result<AndroidSemanticBundle, String> {
    sink.phase_started(
        AndroidProgressPhase::IndexJadxSources,
        &AndroidProgressSnapshot::default(),
    );
    let index = collect_semantic_index(jadx_root, sink)?;
    sink.phase_completed(
        AndroidProgressPhase::IndexJadxSources,
        &AndroidProgressSnapshot {
            completed: Some(index.files.len()),
            total: Some(index.files.len()),
            message: Some(format!("indexed {} files", index.files.len())),
            ..AndroidProgressSnapshot::default()
        },
    );
    sink.phase_started(
        AndroidProgressPhase::DeriveSemanticFacts,
        &AndroidProgressSnapshot::default(),
    );
    let target_identity = derive_target_identity_from_jadx_root(jadx_root);
    let mut bundle = AndroidSemanticBundle {
        bundle_version: "android-semantic/v1alpha1".into(),
        target: AndroidSemanticTarget {
            application_id: Some(package_name.into()),
            package_name: package_name.into(),
            version_code: target_identity.version_code,
            version_name: target_identity.version_name,
            split_names: target_identity.split_names,
        },
        extractor: AndroidExtractorMetadata {
            extractor_id: "fat-android-heuristic-jadx".into(),
            extractor_version: env!("CARGO_PKG_VERSION").into(),
            input_kind: "jadx-tree".into(),
            generated_at_utc: None,
            degraded: false,
            notes: vec![
                "heuristic semantic bundle synthesized from JADX output".into(),
                format!("semantic-mode={}", mode.as_str()),
                "tier0-manifest + tier1-resource + tier2-framework-api + tier3-pattern matching"
                    .into(),
            ],
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
    };

    if let Ok(marker_text) = fs::read_to_string(jadx_root.join(".fat-jadx-nonzero")) {
        bundle.extractor.degraded = true;
        bundle.extractor.notes.push(marker_text.trim().to_string());
    }

    if let Some(manifest) = manifest {
        merge_semantics(
            &mut bundle,
            derive_manifest_semantics(manifest, package_name),
        );
    }
    merge_semantics(&mut bundle, derive_source_identity_semantics(&index, mode));
    let protocol_index = collect_protocol_index(&index, package_name, mode);
    merge_semantics(
        &mut bundle,
        derive_protocol_semantics(&protocol_index, mode),
    );
    merge_semantics(
        &mut bundle,
        derive_framework_api_semantics(&index, package_name, mode),
    );
    let router = derive_router_semantics(&index, package_name, mode);
    merge_semantics(&mut bundle, router);
    let webview = derive_webview_semantics(&index, package_name, mode);
    merge_semantics(&mut bundle, webview);
    let capability = derive_capability_chain_semantics(&index, package_name, mode);
    merge_semantics(&mut bundle, capability);
    let binder = derive_binder_native_semantics(&index, package_name, mode);
    merge_semantics(&mut bundle, binder);

    if bundle
        .native_semantics
        .iter()
        .any(|native| native.kind == "java-load-library")
        && bundle
            .control_surfaces
            .iter()
            .any(|surface| surface.kind == "device-management-callback")
    {
        let load_library_fact_id = bundle
            .facts
            .iter()
            .find(|fact| fact.kind == "source.load-library")
            .map(|fact| fact.fact_id.clone())
            .unwrap_or_else(|| "fact-load-library-bridge".into());
        let native_id = bundle
            .native_semantics
            .iter()
            .find(|native| native.kind == "java-load-library")
            .map(|native| native.native_id.clone())
            .unwrap_or_else(|| "native-load-library-bridge".into());
        let callback_surface_id = bundle
            .control_surfaces
            .iter()
            .find(|surface| surface.kind == "device-management-callback")
            .map(|surface| surface.surface_id.clone())
            .unwrap_or_else(|| "control-callback-bridge".into());
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-java-native-bridge".into(),
            kind: "java-native-bridge".into(),
            members: vec![load_library_fact_id, native_id, callback_surface_id],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("Java loadLibrary and device-management callback co-occur".into()),
        });
    }

    if bundle.control_surfaces.is_empty() {
        bundle
            .warnings
            .push("heuristic JADX extraction found no Android control surfaces".into());
    }

    sink.phase_completed(
        AndroidProgressPhase::DeriveSemanticFacts,
        &AndroidProgressSnapshot {
            facts: Some(bundle.facts.len()),
            symbols: Some(bundle.symbol_identities.len()),
            controls: Some(bundle.control_surfaces.len()),
            ..AndroidProgressSnapshot::default()
        },
    );

    dedupe_bundle(&mut bundle);
    sink.phase_started(
        AndroidProgressPhase::BuildSubsystems,
        &AndroidProgressSnapshot::default(),
    );
    bundle.subsystems = derive_subsystems(&bundle);
    dedupe_bundle(&mut bundle);
    sink.phase_completed(
        AndroidProgressPhase::BuildSubsystems,
        &AndroidProgressSnapshot {
            subsystems: Some(bundle.subsystems.len()),
            ..AndroidProgressSnapshot::default()
        },
    );
    sink.phase_started(
        AndroidProgressPhase::DeriveRevelations,
        &AndroidProgressSnapshot::default(),
    );
    let revelations = derive_revelations(&bundle);
    merge_semantics(&mut bundle, revelations);
    dedupe_bundle(&mut bundle);
    let revelation_names = bundle
        .revelations
        .iter()
        .take(3)
        .map(|revelation| revelation.kind.clone())
        .collect::<Vec<_>>()
        .join(", ");
    sink.phase_completed(
        AndroidProgressPhase::DeriveRevelations,
        &AndroidProgressSnapshot {
            revelations: Some(bundle.revelations.len()),
            message: (!revelation_names.is_empty()).then_some(revelation_names),
            ..AndroidProgressSnapshot::default()
        },
    );
    Ok(bundle)
}

fn derive_source_identity_semantics(
    index: &AndroidSemanticIndex,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut observed_protocols = BTreeSet::new();
    let mut observed_grpc = false;
    let mut callback_surface_emitted = false;
    let mut commissioning_surface_emitted = false;
    let mut package_families = std::collections::BTreeMap::<String, FamilyObservation>::new();
    let mut import_families = std::collections::BTreeMap::<String, FamilyObservation>::new();
    let mut security_families = std::collections::BTreeMap::<String, FamilyObservation>::new();
    let mut bridge_evidence =
        std::collections::BTreeMap::<PathBuf, (Vec<String>, Vec<String>)>::new();

    for summary in &index.package_family_summaries {
        if !summary.is_semantically_relevant {
            continue;
        }
        record_family_observation(
            &mut package_families,
            &summary.family,
            &summary.sample_subject,
            summary.provenance.clone(),
        );
        if mode == AndroidSemanticMode::Dense {
            bundle.facts.push(AndroidSemanticFact {
                fact_id: format!("fact-package-{}", sanitize_id(&summary.sample_subject)),
                kind: "source.package".into(),
                subject: summary.sample_subject.clone(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![summary.provenance.clone()],
                attributes: std::collections::BTreeMap::new(),
            });
        }
    }

    for summary in &index.import_family_summaries {
        if !summary.is_semantically_relevant {
            continue;
        }
        record_family_observation(
            &mut import_families,
            &summary.family,
            &summary.sample_subject,
            summary.provenance.clone(),
        );
    }

    for summary in &index.native_bridge_summaries {
        if !summary.is_semantically_relevant {
            continue;
        }
        let provenance = provenance_from_path(&summary.path);
        for library_name in &summary.loaded_libraries {
            let fact_id = format!("fact-load-library-{}", sanitize_id(library_name));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: fact_id.clone(),
                kind: "source.load-library".into(),
                subject: library_name.clone(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance.clone()],
                attributes: std::collections::BTreeMap::new(),
            });
            bundle.native_semantics.push(AndroidNativeSemantic {
                native_id: format!("native-load-library-{}", sanitize_id(library_name)),
                kind: "java-load-library".into(),
                library_name: Some(library_name.clone()),
                symbol_name: "System.loadLibrary".into(),
                linked_symbol_id: None,
                synthetic: false,
                notes: vec!["source-derived Java native bridge".into()],
            });
            let entry = bridge_evidence.entry(summary.path.clone()).or_default();
            entry.0.push(fact_id);
            entry
                .1
                .push(format!("native-load-library-{}", sanitize_id(library_name)));
        }
    }

    for marker in &index.protocol_security_markers {
        if !marker.is_semantically_relevant {
            continue;
        }
        let provenance = provenance_from_path(&marker.path);
        for protocol in &marker.protocol_families {
            if !observed_protocols.insert(protocol.clone()) {
                continue;
            }
            bundle.facts.push(AndroidSemanticFact {
                fact_id: format!("fact-protocol-{}", sanitize_id(protocol)),
                kind: "source.protocol-family".into(),
                subject: protocol.clone(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance.clone()],
                attributes: std::collections::BTreeMap::new(),
            });
            if protocol == "grpc" && !observed_grpc {
                bundle.transport_surfaces.push(AndroidTransportSurface {
                    surface_id: "transport-rpc-grpc".into(),
                    kind: "rpc-grpc".into(),
                    source: "app-source".into(),
                    sink: "grpc-service".into(),
                    carrier: Some("io.grpc".into()),
                    notes: vec!["source-derived gRPC protocol family".into()],
                });
                observed_grpc = true;
            }
        }
        for security_family in &marker.security_families {
            record_family_observation(
                &mut security_families,
                security_family,
                &marker.sample_subject,
                provenance.clone(),
            );
        }
    }

    for file in &index.files {
        if !is_semantically_relevant_file(file) {
            continue;
        }

        if mode == AndroidSemanticMode::Dense {
            let provenance = provenance_from_file(file);
            for import in file
                .imports
                .iter()
                .filter(|import| is_relevant_import(import))
            {
                bundle.facts.push(AndroidSemanticFact {
                    fact_id: format!("fact-import-{}", sanitize_id(import)),
                    kind: "source.import".into(),
                    subject: import.clone(),
                    support_level: AndroidSupportLevel::Observed,
                    provenance: vec![provenance.clone()],
                    attributes: std::collections::BTreeMap::new(),
                });
            }
        }

        for class_name in select_class_symbols(file, mode) {
            let Some(package_name) = file.package_name.as_ref() else {
                continue;
            };
            bundle.symbol_identities.push(AndroidSymbolIdentity {
                symbol_id: format!(
                    "sym-class-{}",
                    sanitize_id(&format!("{package_name}.{class_name}"))
                ),
                language: Some("java".into()),
                kind: "class".into(),
                qualified_name: format!("{package_name}.{class_name}"),
                descriptor: None,
                synthetic: false,
                aliases: Vec::new(),
            });
        }

        for method_name in select_method_symbols(file, mode) {
            let Some(package_name) = file.package_name.as_ref() else {
                continue;
            };
            let class_name = file
                .class_names
                .first()
                .cloned()
                .unwrap_or_else(|| "Unknown".into());
            let qualified_name = format!("{package_name}.{class_name}.{method_name}");
            let symbol_id = format!("sym-method-{}", sanitize_id(&qualified_name));
            bundle.symbol_identities.push(AndroidSymbolIdentity {
                symbol_id: symbol_id.clone(),
                language: Some("java".into()),
                kind: "method".into(),
                qualified_name,
                descriptor: None,
                synthetic: false,
                aliases: Vec::new(),
            });

            if !callback_surface_emitted
                && (method_name.starts_with("onDevice")
                    || method_name.starts_with("onNotify")
                    || method_name.starts_with("onIdentify"))
            {
                bundle.control_surfaces.push(AndroidControlSurface {
                    surface_id: format!("control-callback-{}", sanitize_id(&method_name)),
                    kind: "device-management-callback".into(),
                    entry_symbol: Some(symbol_id),
                    exported_component: None,
                    trigger: Some(method_name.clone()),
                    notes: vec!["source-derived device-management callback".into()],
                });
                let entry = bridge_evidence.entry(file.path.clone()).or_default();
                entry
                    .1
                    .push(format!("control-callback-{}", sanitize_id(&method_name)));
                callback_surface_emitted = true;
            }
        }

        if !commissioning_surface_emitted
            && file.security_families.iter().any(|family| {
                matches!(
                    family.as_str(),
                    "commissioning"
                        | "pairing-code"
                        | "fabric-membership"
                        | "access-token"
                        | "device-descriptor"
                )
            })
            && (file.lower_text.contains("beginrendezvous")
                || file.lower_text.contains("beginidentifydevice")
                || file.lower_text.contains("commissiondevice("))
        {
            bundle.control_surfaces.push(AndroidControlSurface {
                surface_id: "control-device-commissioning".into(),
                kind: "device-commissioning-flow".into(),
                entry_symbol: None,
                exported_component: None,
                trigger: file.package_name.clone(),
                notes: vec![
                    "source-derived commissioning and rendezvous flow".into(),
                    format!("families={}", file.security_families.join(",")),
                ],
            });
            commissioning_surface_emitted = true;
        }
    }

    for (path, (load_library_fact_ids, callback_surface_ids)) in bridge_evidence {
        if load_library_fact_ids.is_empty() || callback_surface_ids.is_empty() {
            continue;
        }
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: format!(
                "corr-java-native-bridge-{}",
                sanitize_id(&path.display().to_string())
            ),
            kind: "java-native-bridge".into(),
            members: load_library_fact_ids
                .into_iter()
                .chain(callback_surface_ids)
                .collect(),
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some(
                "loadLibrary usage and callback surface co-occur in the same source file".into(),
            ),
        });
    }

    emit_family_facts(
        &mut bundle,
        "source.package-family",
        "package-family",
        package_families,
    );
    emit_family_facts(
        &mut bundle,
        "source.import-family",
        "import-family",
        import_families,
    );
    emit_family_facts(
        &mut bundle,
        "source.security-family",
        "security-family",
        security_families,
    );

    if observed_protocols.contains("weave") && observed_protocols.contains("grpc") {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-weave-grpc-stack".into(),
            kind: "device-stack-protocol-composition".into(),
            members: vec!["weave".into(), "grpc".into()],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some(
                "source imports indicate both local device management and RPC transport families"
                    .into(),
            ),
        });
    }

    bundle
}

fn derive_manifest_semantics(
    manifest: &AndroidManifestFact,
    package_name: &str,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let provenance = AndroidProvenance {
        origin: "android-manifest".into(),
        artifact: "AndroidManifest.xml".into(),
        location: None,
        detail: Some("manifest surface extraction".into()),
    };

    for component in &manifest.components {
        if component.exported == Some(true) {
            let trigger = component
                .intent_filters
                .first()
                .and_then(|filter| filter.actions.first())
                .cloned()
                .or_else(|| component.authorities.clone());
            bundle.control_surfaces.push(AndroidControlSurface {
                surface_id: format!("manifest-component-{}", sanitize_id(&component.name)),
                kind: "manifest-exported-component".into(),
                entry_symbol: None,
                exported_component: Some(component.name.clone()),
                trigger,
                notes: vec!["exported AndroidManifest component".into()],
            });
            bundle.facts.push(AndroidSemanticFact {
                fact_id: format!("manifest-exported-{}", sanitize_id(&component.name)),
                kind: "manifest.exported-component".into(),
                subject: component.name.clone(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance.clone()],
                attributes: std::collections::BTreeMap::from([(
                    "component_kind".into(),
                    component_kind_label(&component.kind).into(),
                )]),
            });
        }

        for (index, filter) in component.intent_filters.iter().enumerate() {
            let transport_id = format!(
                "manifest-intent-filter-{}-{}",
                sanitize_id(&component.name),
                index
            );
            bundle.transport_surfaces.push(AndroidTransportSurface {
                surface_id: transport_id.clone(),
                kind: "manifest-intent-filter".into(),
                source: "external-intent".into(),
                sink: format!("manifest-component-{}", sanitize_id(&component.name)),
                carrier: filter.data_schemes.first().cloned(),
                notes: filter.actions.clone(),
            });
            let boundary_kind = match component.kind {
                AndroidComponentKind::Activity => "deep-link-to-internal-router",
                AndroidComponentKind::Service => "service-entry-boundary",
                AndroidComponentKind::Receiver => "broadcast-entry-boundary",
                AndroidComponentKind::Provider => "content-provider-boundary",
            };
            bundle.trust_boundaries.push(AndroidTrustBoundary {
                boundary_id: format!("manifest-boundary-{}", sanitize_id(&transport_id)),
                kind: boundary_kind.into(),
                from_zone: "external-caller".into(),
                to_zone: component.name.clone(),
                guard: component.permission.clone(),
                notes: vec!["manifest-declared exported surface".into()],
            });
        }

        if matches!(component.kind, AndroidComponentKind::Provider) {
            let provider_id = format!("manifest-provider-{}", sanitize_id(&component.name));
            bundle.transport_surfaces.push(AndroidTransportSurface {
                surface_id: provider_id.clone(),
                kind: "provider-uri-access".into(),
                source: "external-caller".into(),
                sink: component.name.clone(),
                carrier: component.authorities.clone(),
                notes: vec!["manifest-declared content provider".into()],
            });
            bundle.trust_boundaries.push(AndroidTrustBoundary {
                boundary_id: format!("boundary-{provider_id}"),
                kind: "content-provider-boundary".into(),
                from_zone: "external-caller".into(),
                to_zone: "app-provider".into(),
                guard: component.permission.clone(),
                notes: vec!["content provider access boundary".into()],
            });
            if let Some(authorities) = &component.authorities {
                bundle.facts.push(AndroidSemanticFact {
                    fact_id: format!("provider-authority-{}", sanitize_id(authorities)),
                    kind: "manifest.provider-authority".into(),
                    subject: authorities.clone(),
                    support_level: AndroidSupportLevel::Observed,
                    provenance: vec![provenance.clone()],
                    attributes: std::collections::BTreeMap::from([(
                        "package_name".into(),
                        package_name.into(),
                    )]),
                });
            }
        }
    }

    for permission in &manifest.requested_permissions {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("manifest-permission-{}", sanitize_id(permission)),
            kind: "manifest.requested-permission".into(),
            subject: permission.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: std::collections::BTreeMap::from([(
                "package_name".into(),
                package_name.into(),
            )]),
        });
    }

    for (flag, enabled) in [
        ("debuggable", manifest.debuggable),
        ("uses-cleartext-traffic", manifest.uses_cleartext_traffic),
    ] {
        if let Some(enabled) = enabled {
            bundle.facts.push(AndroidSemanticFact {
                fact_id: format!("manifest-app-flag-{}", sanitize_id(flag)),
                kind: "manifest.app-flag".into(),
                subject: flag.into(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance.clone()],
                attributes: std::collections::BTreeMap::from([(
                    "enabled".into(),
                    enabled.to_string(),
                )]),
            });
        }
    }

    bundle
}

fn derive_framework_api_semantics(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let candidate_files = index
        .files
        .iter()
        .filter(|file| should_consider_default_heuristic_file(file, package_name, mode))
        .collect::<Vec<_>>();

    let api_patterns = [
        ("android-api.start-activity", "startactivity("),
        ("android-api.bind-service", "bindservice("),
        ("android-api.start-service", "startservice("),
        (
            "android-api.content-resolver-query",
            "contentresolver.query(",
        ),
        (
            "android-api.content-resolver-insert",
            "contentresolver.insert(",
        ),
        (
            "android-api.content-resolver-update",
            "contentresolver.update(",
        ),
        ("android-api.register-receiver", "registerreceiver("),
        ("android-api.webview-load-url", "loadurl("),
        ("android-api.webview-load-data", "loaddata("),
        (
            "android-api.pending-intent-get-activity",
            "pendingintent.getactivity(",
        ),
        (
            "android-api.pending-intent-get-service",
            "pendingintent.getservice(",
        ),
        (
            "android-api.pending-intent-get-broadcast",
            "pendingintent.getbroadcast(",
        ),
        ("android-api.runtime-exec", "runtime.getruntime().exec("),
        ("android-api.process-builder", "processbuilder"),
    ];
    for (kind, pattern) in api_patterns {
        if let Some(file) = candidate_files
            .iter()
            .find(|file| file.lower_text.contains(pattern))
        {
            bundle.facts.push(AndroidSemanticFact {
                fact_id: sanitize_id(kind),
                kind: kind.into(),
                subject: package_name.into(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance_from_file(file)],
                attributes: std::collections::BTreeMap::new(),
            });
        }
    }

    if let Some(file) = candidate_files.iter().find(|file| {
        file.lower_text.contains("pendingintent.flag_mutable")
            || file.lower_text.contains("flag_mutable")
    }) {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "api-pending-intent-mutable".into(),
            kind: "pending-intent.mutability".into(),
            subject: "mutable".into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance_from_file(file)],
            attributes: std::collections::BTreeMap::new(),
        });
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "api-mutable-pending-intent".into(),
            kind: "mutable-pending-intent".into(),
            source: "external-caller".into(),
            sink: "delegated-component".into(),
            carrier: Some("PendingIntent".into()),
            notes: vec!["framework API mutability marker".into()],
        });
    }

    if candidate_files
        .iter()
        .any(|file| file.lower_text.contains("content://"))
    {
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "api-provider-uri".into(),
            kind: "provider-uri-access".into(),
            source: "external-caller".into(),
            sink: "content-provider".into(),
            carrier: Some("content-uri".into()),
            notes: vec!["content resolver usage".into()],
        });
    }

    for resource in &index.resource_summaries {
        let resource_id = match resource.kind.as_str() {
            "xml-network-security-config" => "resource-network-security-config",
            "xml-file-provider-paths" => "resource-file-paths",
            _ => "resource-unknown",
        };
        bundle.resources.push(AndroidResourceSemantic {
            resource_id: resource_id.into(),
            kind: resource.kind.clone(),
            path: resource.path.display().to_string(),
            qualifiers: Vec::new(),
            notes: vec!["resource-tier extraction".into()],
        });
    }

    bundle
}

fn collect_semantic_index(
    root: &Path,
    sink: &mut dyn AndroidProgressSink,
) -> Result<AndroidSemanticIndex, String> {
    let files = collect_source_files(root, sink)?;
    let mut package_family_summaries = Vec::new();
    let mut import_family_summaries = Vec::new();
    let mut native_bridge_summaries = Vec::new();
    let mut resource_summaries = Vec::new();
    let mut protocol_security_markers = Vec::new();

    for file in &files {
        let is_semantically_relevant = is_semantically_relevant_file(file);
        if let (Some(package_name), Some(package_family)) =
            (file.package_name.clone(), file.package_family.clone())
        {
            package_family_summaries.push(FamilySummary {
                family: package_family,
                sample_subject: package_name,
                provenance: provenance_from_file(file),
                is_semantically_relevant,
            });
        }

        for import_family in &file.import_families {
            if let Some(sample_subject) = file
                .imports
                .iter()
                .find(|import| classify_import_family(import) == Some(import_family.as_str()))
            {
                import_family_summaries.push(FamilySummary {
                    family: import_family.clone(),
                    sample_subject: sample_subject.clone(),
                    provenance: provenance_from_file(file),
                    is_semantically_relevant,
                });
            }
        }

        if !file.loaded_libraries.is_empty() {
            native_bridge_summaries.push(NativeBridgeSummary {
                path: file.path.clone(),
                loaded_libraries: file.loaded_libraries.clone(),
                is_semantically_relevant,
            });
        }

        let path = file.path.to_string_lossy().to_string();
        if path.ends_with("network_security_config.xml") {
            resource_summaries.push(ResourceSummary {
                path: file.path.clone(),
                kind: "xml-network-security-config".into(),
            });
        } else if path.ends_with("file_paths.xml") {
            resource_summaries.push(ResourceSummary {
                path: file.path.clone(),
                kind: "xml-file-provider-paths".into(),
            });
        }

        protocol_security_markers.push(ProtocolSecurityMarker {
            path: file.path.clone(),
            sample_subject: file
                .package_name
                .clone()
                .unwrap_or_else(|| file.path.display().to_string()),
            protocol_families: file.protocol_families.clone(),
            security_families: file.security_families.clone(),
            is_semantically_relevant,
        });
    }

    Ok(AndroidSemanticIndex {
        files,
        package_family_summaries,
        import_family_summaries,
        native_bridge_summaries,
        resource_summaries,
        protocol_security_markers,
    })
}

fn collect_protocol_index(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> ProtocolIndex {
    let mut files = Vec::new();

    for file in &index.files {
        if !should_consider_default_heuristic_file(file, package_name, mode) {
            continue;
        }
        let mut signals = Vec::new();
        let provenance = provenance_from_file(file);
        let lower = file.lower_text.as_str();
        let package_lower = file
            .package_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let has_weave_context = file
            .protocol_families
            .iter()
            .any(|family| family == "weave");

        if has_weave_context
            && (lower.contains("authorization")
                || lower.contains("bearer ")
                || lower.contains("oauth"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::WeaveAuth,
                detail: Some("authorization/bearer/oauth marker".into()),
            });
        }
        if has_weave_context
            && (file
                .security_families
                .iter()
                .any(|family| family == "fabric-membership")
                || lower.contains("fabric")
                || lower.contains("targetfabricid")
                || lower.contains("createfabric")
                || lower.contains("joinexistingfabric")
                || lower.contains("leavefabric"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::WeaveFabric,
                detail: Some("fabric-membership marker".into()),
            });
        }
        if (has_weave_context
            && (file
                .security_families
                .iter()
                .any(|family| family == "key-export")
                || lower.contains("keyexport")
                || lower.contains("groupkey")
                || lower.contains("rootkey")))
            || lower.contains("generatekeyexportrequest")
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::WeaveKeyExport,
                detail: Some("key-export marker".into()),
            });
        }
        if lower.contains("generatekeyexportrequest")
            || lower.contains("weavecertificatetox509")
            || lower.contains("x509certificatetoweave")
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::WeaveNativeKeyExport,
                detail: Some("native certificate/key-export bridge".into()),
            });
        }

        if package_lower.contains("matter")
            && (lower.contains("commission")
                || lower.contains("rendezvous")
                || lower.contains("onboardingpayload")
                || lower.contains("shareddevicedata"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::MatterCommissioning,
                detail: Some("commissioning marker".into()),
            });
        }
        if lower.contains("shareddevicedata")
            || lower.contains("manualpairingcode")
            || lower.contains("commissioningwindowexpirationmillis")
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::MatterCommissioningField,
                detail: Some("commissioning field marker".into()),
            });
        }

        if file
            .imports
            .iter()
            .any(|import| import.to_ascii_lowercase().starts_with("android.bluetooth"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleImport,
                detail: file
                    .imports
                    .iter()
                    .find(|import| import.to_ascii_lowercase().starts_with("android.bluetooth"))
                    .cloned(),
            });
        }

        let ble_symbol_hit = file
            .class_names
            .iter()
            .chain(file.interesting_method_names.iter())
            .find(|name| {
                let lower = name.to_ascii_lowercase();
                lower.contains("bluetooth") || lower.contains("ble")
            })
            .cloned();
        if let Some(hit) = ble_symbol_hit {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleSymbol,
                detail: Some(hit),
            });
        }

        let javascript_interface_methods = extract_javascript_interface_methods(&file.text);
        if !javascript_interface_methods.is_empty()
            && (package_lower.contains("web")
                || package_lower.contains("webrtc")
                || lower.contains("webrtc")
                || file
                    .interesting_method_names
                    .iter()
                    .any(|name| name.to_ascii_lowercase().starts_with("web")))
        {
            for method in javascript_interface_methods {
                signals.push(ProtocolSignal {
                    kind: ProtocolSignalKind::WebBridgeEntry,
                    detail: Some(encode_javascript_interface_method(&method)),
                });
            }
        } else if lower.contains("@javascriptinterface") {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::WebBridgeEntry,
                detail: file
                    .interesting_method_names
                    .iter()
                    .find(|name| name.to_ascii_lowercase().starts_with("web"))
                    .cloned(),
            });
        }

        if let Some(topic) = first_regex_capture(command_topic_regex(), &file.text) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::CommandEnvelope,
                detail: Some(topic),
            });
        } else if lower.contains("sendgo2req") && lower.contains("api_id") {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::CommandEnvelope,
                detail: Some("command-envelope".into()),
            });
        }
        if mode == AndroidSemanticMode::Dense
            || file
                .package_name
                .as_deref()
                .is_some_and(|package| is_app_owned_package(package, package_name))
        {
            signals.extend(extract_command_catalog_signals(file));
        }

        if lower.contains("token")
            && (package_lower.contains("webrtc")
                || lower.contains("sdp")
                || lower.contains("dogofferbean"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::SessionOffer,
                detail: first_regex_capture(string_literal_regex("session-token"), &file.text)
                    .or_else(|| Some("token".into())),
            });
        }

        if package_lower.contains("lib_ble")
            || lower.contains("connectbluetooth")
            || lower.contains("uuid_server")
            || lower.contains("uuid_noti")
            || lower.contains("aesutil.instance.decrypt")
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::LocalDeviceControl,
                detail: if lower.contains("uuid_server") {
                    Some("UUID_SERVER".into())
                } else {
                    Some("local-device-control".into())
                },
            });
        }
        signals.extend(extract_ble_security_signals(file));

        if lower.contains("oauth/token") {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::AccountAuth,
                detail: Some("oauth/token".into()),
            });
        }

        if lower.contains("oauth/bind")
            || lower.contains("device_address")
            || (lower.contains("accesstoken") && lower.contains("refreshtoken"))
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::AccountDeviceBinding,
                detail: if lower.contains("oauth/bind") {
                    Some("oauth/bind".into())
                } else {
                    Some("account-device-binding".into())
                },
            });
        }

        if mode == AndroidSemanticMode::Dense
            || file
                .package_name
                .as_deref()
                .is_some_and(|package| is_app_owned_package(package, package_name))
            || lower.contains("@post(")
            || lower.contains("@get(")
            || lower.contains(".addheader(")
            || lower.contains(".header(")
        {
            signals.extend(extract_http_api_signals(file));
        }

        if mode == AndroidSemanticMode::Dense
            || file
                .package_name
                .as_deref()
                .is_some_and(|package| is_app_owned_package(package, package_name))
        {
            signals.extend(extract_security_constant_signals(file));
            signals.extend(extract_security_posture_signals(file));
            signals.extend(extract_security_posture_signals(file));
        }

        if !signals.is_empty() {
            files.push(ProtocolFileView {
                path: file.path.clone(),
                provenance,
                signals,
            });
        }
    }

    ProtocolIndex { files }
}

fn derive_router_semantics(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut has_deeplink = false;
    let mut has_router_dispatch = false;
    let mut has_backend = false;
    let mut has_auth = false;
    let mut has_mqtt = false;
    let mut dispatch_symbol = "com.example.Router.dispatch".to_string();
    let mut dispatch_resolved = false;
    let mut caller_guards = BTreeSet::new();
    let mut router_provenance = None;
    let mut endpoint_templates = Vec::new();
    let endpoint_re = endpoint_regex();

    for file in index.files.iter().filter(|file| {
        should_consider_default_heuristic_file(file, package_name, mode)
            && (mode == AndroidSemanticMode::Dense
                || file
                    .package_name
                    .as_deref()
                    .is_some_and(|package| is_app_owned_package(package, package_name))
                || file.package_family.as_deref() == Some("router"))
    }) {
        let has_deeplink_signal = file.lower_text.contains("intent.action.view")
            || file.lower_text.contains("getdata(")
            || file.lower_text.contains("getdatastring(")
            || file.lower_text.contains("android.intent.action.view");
        if has_deeplink_signal {
            has_deeplink = true;
        }
        let has_router_signal =
            file.lower_text.contains("dispatch(") || file.lower_text.contains("router");
        if has_deeplink_signal || has_router_signal {
            caller_guards.extend(detect_caller_validation_guards(&file.lower_text));
        }
        if has_router_signal {
            has_router_dispatch = true;
            if let Some(symbol) = guess_method_symbol(&file.text, "dispatch") {
                router_provenance = Some(provenance_from_file(file));
                dispatch_symbol = symbol;
                dispatch_resolved = true;
            } else if let Some(class_name) = guess_class_name(&file.text) {
                router_provenance = Some(provenance_from_file(file));
                dispatch_symbol = format!("{class_name}.dispatch");
                dispatch_resolved = true;
            }
        }
        for capture in endpoint_re.captures_iter(&file.text) {
            if let Some(value) = capture.get(1) {
                endpoint_templates.push(value.as_str().to_string());
            }
        }
        if file.lower_text.contains("authorization")
            || file.lower_text.contains("x-device-token")
            || file.lower_text.contains("bearer ")
        {
            has_auth = true;
        }
        let import_text = file.imports.join("\n").to_ascii_lowercase();
        let package_text = file
            .package_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if has_positive_mqtt_signal(&file.lower_text, &import_text, &package_text) {
            has_mqtt = true;
        }
        if file.lower_text.contains("http://")
            || file.lower_text.contains("https://")
            || !endpoint_templates.is_empty()
        {
            has_backend = true;
        }
    }

    if has_deeplink && has_router_dispatch {
        // If no real dispatch symbol was resolved from the decompiled code, the
        // trigger keywords matched Kotlin/AndroidX stdlib, not app logic — don't
        // emit a lead built on the fabricated `com.example.*` fallback.
        let synthetic_symbol = !dispatch_resolved;
        if mode == AndroidSemanticMode::Default && synthetic_symbol {
            return bundle;
        }
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-router-dispatch".into(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: dispatch_symbol.clone(),
            descriptor: None,
            synthetic: synthetic_symbol,
            aliases: Vec::new(),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-router-dispatch".into(),
            kind: "router-dispatch".into(),
            entry_symbol: Some("sym-router-dispatch".into()),
            exported_component: Some("DeepLinkActivity".into()),
            trigger: Some("android.intent.action.VIEW".into()),
            notes: vec!["heuristic JADX detection".into()],
        });
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-deeplink-intent".into(),
            kind: "intent-parse".into(),
            source: "external-deeplink".into(),
            sink: "control-router-dispatch".into(),
            carrier: Some("android.net.Uri".into()),
            notes: vec!["derived from getData/getDataString usage".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-deeplink-router".into(),
            kind: "deep-link-to-internal-router".into(),
            from_zone: "external-caller".into(),
            to_zone: "app-router".into(),
            guard: (!caller_guards.is_empty())
                .then(|| caller_guards.iter().cloned().collect::<Vec<_>>().join(", ")),
            notes: if caller_guards.is_empty() {
                vec![
                    "heuristic JADX detection".into(),
                    "no caller validation detected".into(),
                ]
            } else {
                vec!["heuristic JADX detection".into()]
            },
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-router-dispatch".into(),
            kind: "control-surface.router-dispatch".into(),
            subject: dispatch_symbol,
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![router_provenance
                .clone()
                .unwrap_or_else(|| provenance_from_files(&index.files))],
            attributes: std::collections::BTreeMap::from([(
                "route_source".into(),
                "intent-extra".into(),
            )]),
        });
    }

    let ranked_endpoints = rank_endpoint_templates(endpoint_templates, mode);
    for (template, score) in ranked_endpoints {
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: format!("endpoint-{}", sanitize_id(&template)),
            kind: "endpoint-template".into(),
            entry_symbol: None,
            exported_component: None,
            trigger: Some(template.clone()),
            notes: vec![
                "heuristic endpoint template".into(),
                format!("score={score}"),
            ],
        });
    }
    if has_backend {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-backend-url".into(),
            kind: "environment.backend-url".into(),
            subject: package_name.into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance_from_files(&index.files)],
            attributes: std::collections::BTreeMap::new(),
        });
    }
    if has_auth {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-auth-header".into(),
            kind: "identity.auth-header".into(),
            subject: package_name.into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance_from_files(&index.files)],
            attributes: std::collections::BTreeMap::new(),
        });
    }
    if has_mqtt {
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-mqtt".into(),
            kind: "mqtt-marker".into(),
            source: "authenticated-api".into(),
            sink: "device-transport".into(),
            carrier: None,
            notes: vec!["heuristic MQTT marker".into()],
        });
    }
    if has_auth && has_backend {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-auth-api".into(),
            kind: "auth-to-api".into(),
            members: vec!["fact-auth-header".into(), "fact-backend-url".into()],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("auth marker and backend marker co-occur".into()),
        });
    }
    if has_mqtt && has_backend {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-api-mqtt".into(),
            kind: "api-to-mqtt".into(),
            members: vec!["fact-backend-url".into(), "transport-mqtt".into()],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("backend endpoints and MQTT marker co-occur".into()),
        });
    }
    bundle
}

fn derive_webview_semantics(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut has_webview = false;
    let mut has_load_url = false;
    let mut has_bridge = false;
    let mut has_strong_validation = false;
    let mut symbol = "com.example.WebEntry.loadUrl".to_string();
    let mut symbol_resolved = false;
    let mut webview_provenance = None;
    for file in index
        .files
        .iter()
        .filter(|file| should_consider_default_heuristic_file(file, package_name, mode))
    {
        if file.lower_text.contains("webview") {
            has_webview = true;
        }
        if file.lower_text.contains("loadurl(") {
            has_load_url = true;
            webview_provenance = Some(provenance_from_file(file));
            if let Some(sym) = guess_method_symbol(&file.text, "loadUrl") {
                symbol = sym;
                symbol_resolved = true;
            }
        }
        if file.lower_text.contains("addjavascriptinterface") {
            has_bridge = true;
        }
        if file.lower_text.contains("shouldoverrideurlloading")
            && (file.lower_text.contains("allowlist")
                || file.lower_text.contains("startswith(")
                || file.lower_text.contains("endswith("))
        {
            has_strong_validation = true;
        }
    }
    if has_webview && has_load_url && has_bridge {
        // Only emit when a real loadUrl symbol was resolved; otherwise the
        // webview/bridge keywords matched stdlib code, not app logic.
        let synthetic_symbol = !symbol_resolved;
        if mode == AndroidSemanticMode::Default && synthetic_symbol {
            return bundle;
        }
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-webview-load".into(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: symbol,
            descriptor: None,
            synthetic: synthetic_symbol,
            aliases: Vec::new(),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-webview-load".into(),
            kind: "webview-load-url".into(),
            entry_symbol: Some("sym-webview-load".into()),
            exported_component: None,
            trigger: Some("https://attacker.example/bridge.html".into()),
            notes: vec!["heuristic WebView loadUrl detection".into()],
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-javascript-bridge".into(),
            kind: "javascript-bridge-method".into(),
            entry_symbol: None,
            exported_component: None,
            trigger: None,
            notes: vec!["heuristic addJavascriptInterface detection".into()],
        });
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-webview-uri".into(),
            kind: "webview-uri-load".into(),
            source: "remote-web-content".into(),
            sink: "control-webview-load".into(),
            carrier: Some("android.net.Uri".into()),
            notes: vec!["heuristic WebView URI load".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-webview-bridge".into(),
            kind: "webview-to-bridge".into(),
            from_zone: "remote-web-content".into(),
            to_zone: "javascript-bridge".into(),
            guard: None,
            notes: vec!["heuristic WebView/JS bridge boundary".into()],
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-webview-validation".into(),
            kind: "webview.uri-validation".into(),
            subject: "control-webview-load".into(),
            support_level: if has_strong_validation {
                AndroidSupportLevel::Observed
            } else {
                AndroidSupportLevel::Inferred
            },
            provenance: vec![webview_provenance
                .clone()
                .unwrap_or_else(|| provenance_from_files(&index.files))],
            attributes: std::collections::BTreeMap::from([(
                "strength".into(),
                if has_strong_validation {
                    "strong"
                } else {
                    "weak"
                }
                .into(),
            )]),
        });
    }
    bundle
}

fn derive_capability_chain_semantics(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut has_pending_intent = false;
    let mut mutable = false;
    let mut nested_dispatch = false;
    let mut symbol = "com.example.NotificationHandler.dispatch".to_string();
    let mut capability_provenance = None;

    for file in index
        .files
        .iter()
        .filter(|file| should_consider_default_heuristic_file(file, package_name, mode))
    {
        if file.lower_text.contains("pendingintent") {
            has_pending_intent = true;
            capability_provenance = Some(provenance_from_file(file));
        }
        if file.lower_text.contains("flag_mutable") || file.lower_text.contains("mutable") {
            mutable = true;
            capability_provenance = Some(provenance_from_file(file));
        }
        if file.lower_text.contains("startactivity(")
            || file.lower_text.contains("send(")
            || file.lower_text.contains("intent(")
        {
            nested_dispatch = true;
            capability_provenance = Some(provenance_from_file(file));
            if let Some(sym) = guess_method_symbol(&file.text, "dispatch") {
                symbol = sym;
            }
        }
    }

    if has_pending_intent && nested_dispatch {
        let synthetic_symbol = is_placeholder_symbol(&symbol);
        if mode == AndroidSemanticMode::Default && synthetic_symbol {
            return bundle;
        }
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-capability-dispatch".into(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: symbol,
            descriptor: None,
            synthetic: synthetic_symbol,
            aliases: Vec::new(),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-nested-intent".into(),
            kind: "nested-intent-dispatch".into(),
            entry_symbol: Some("sym-capability-dispatch".into()),
            exported_component: None,
            trigger: Some("notification-action".into()),
            notes: vec!["heuristic nested intent dispatch".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-delegated-identity".into(),
            kind: "delegated-identity-boundary".into(),
            from_zone: "external-caller".into(),
            to_zone: "delegated-component".into(),
            guard: None,
            notes: vec!["heuristic PendingIntent boundary".into()],
        });
        if mutable {
            bundle.facts.push(AndroidSemanticFact {
                fact_id: "fact-pendingintent-mutable".into(),
                kind: "pending-intent.mutability".into(),
                subject: "mutable".into(),
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![capability_provenance
                    .clone()
                    .unwrap_or_else(|| provenance_from_files(&index.files))],
                attributes: std::collections::BTreeMap::new(),
            });
        }
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-delegated-path".into(),
            kind: "delegated-path-composition".into(),
            members: vec![
                "control-nested-intent".into(),
                "boundary-delegated-identity".into(),
            ],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("nested intent crosses delegated boundary".into()),
        });
    }
    bundle
}

fn derive_binder_native_semantics(
    index: &AndroidSemanticIndex,
    package_name: &str,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let mut has_binder = false;
    let mut has_native = false;
    let mut size_sensitive = false;
    let mut has_explicit_binder_method = false;
    let mut symbol = "com.example.NativeBridge.parseBlob".to_string();
    let mut caller_guards = None;
    let mut binder_provenance = None;

    for file in index
        .files
        .iter()
        .filter(|file| should_consider_default_heuristic_file(file, package_name, mode))
    {
        if file.lower_text.contains("ontransact(")
            || (file.lower_text.contains("binder") && file.lower_text.contains("parcel"))
        {
            has_binder = true;
            binder_provenance = Some(provenance_from_file(file));
            caller_guards.get_or_insert_with(|| detect_caller_validation_guards(&file.lower_text));
            if let Some(sym) = guess_method_symbol(&file.text, "onTransact") {
                has_explicit_binder_method = true;
                symbol = sym;
            }
        }
        if file.lower_text.contains("system.loadlibrary")
            || file.lower_text.contains(" native ")
            || file.lower_text.contains("jni")
        {
            has_native = true;
        }
        if file.lower_text.contains("memcpy")
            || file.lower_text.contains("copy")
            || file.lower_text.contains("length")
            || file.lower_text.contains("size")
            || file.lower_text.contains("bytebuffer")
        {
            size_sensitive = true;
        }
    }

    if has_binder && has_native && size_sensitive {
        let caller_guards = caller_guards.unwrap_or_default();
        let synthetic_symbol = is_placeholder_symbol(&symbol);
        if mode == AndroidSemanticMode::Default && synthetic_symbol && !has_explicit_binder_method {
            return bundle;
        }
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-binder-native".into(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: symbol.clone(),
            descriptor: None,
            synthetic: synthetic_symbol,
            aliases: Vec::new(),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-binder-method".into(),
            kind: "binder-method".into(),
            entry_symbol: Some("sym-binder-native".into()),
            exported_component: None,
            trigger: Some("TRANSACTION_parseBlob".into()),
            notes: vec!["heuristic binder method".into()],
        });
        bundle.native_semantics.push(AndroidNativeSemantic {
            native_id: "native-size-sensitive".into(),
            kind: "jni-registration".into(),
            library_name: Some("libnative.so".into()),
            symbol_name: jni_symbol_name_for_method(&symbol)
                .unwrap_or_else(|| "Java_com_example_NativeBridge_parseBlob".into()),
            linked_symbol_id: Some("sym-binder-native".into()),
            synthetic: synthetic_symbol,
            notes: vec!["heuristic native boundary".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-binder-native".into(),
            kind: "binder-to-native".into(),
            from_zone: "binder-caller".into(),
            to_zone: "native-parser".into(),
            guard: (!caller_guards.is_empty())
                .then(|| caller_guards.iter().cloned().collect::<Vec<_>>().join(", ")),
            notes: if caller_guards.is_empty() {
                vec![
                    "heuristic binder/native bridge".into(),
                    "no caller validation detected".into(),
                ]
            } else {
                vec!["heuristic binder/native bridge".into()]
            },
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-native-size-sensitive".into(),
            kind: "native.size-sensitive".into(),
            subject: symbol,
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![binder_provenance
                .clone()
                .unwrap_or_else(|| provenance_from_files(&index.files))],
            attributes: std::collections::BTreeMap::new(),
        });
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-binder-native".into(),
            kind: "binder-to-native".into(),
            members: vec![
                "control-binder-method".into(),
                "native-size-sensitive".into(),
            ],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some("binder and native parser markers co-occur".into()),
        });
    }
    bundle
}

/// Package identity recovered from the JADX output tree itself.
///
/// JADX writes a decoded, plain-text `AndroidManifest.xml` under `resources/`
/// (or `resources/base.apk/` for a split-aware decompile), which carries the
/// `versionName`/`versionCode` that binary AXML hides from the APK-level
/// manifest reader. Split configuration APKs surface as sibling `*.apk`
/// directories under `resources/`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct JadxTargetIdentity {
    version_name: Option<String>,
    version_code: Option<String>,
    split_names: Vec<String>,
}

fn derive_target_identity_from_jadx_root(jadx_root: &Path) -> JadxTargetIdentity {
    let resources_root = jadx_root.join("resources");
    let mut identity = JadxTargetIdentity {
        split_names: collect_jadx_split_names(&resources_root),
        ..JadxTargetIdentity::default()
    };

    let Some(manifest_text) = read_jadx_decoded_manifest(&resources_root) else {
        return identity;
    };
    let Some(manifest_tag) = capture_manifest_open_tag(&manifest_text) else {
        return identity;
    };
    identity.version_name = capture_manifest_attr(&manifest_tag, "versionName");
    identity.version_code = capture_manifest_attr(&manifest_tag, "versionCode");
    identity
}

fn read_jadx_decoded_manifest(resources_root: &Path) -> Option<String> {
    for candidate in [
        resources_root.join("AndroidManifest.xml"),
        resources_root.join("base.apk").join("AndroidManifest.xml"),
    ] {
        if let Ok(text) = fs::read_to_string(&candidate) {
            if text.trim_start().starts_with('<') {
                return Some(text);
            }
        }
    }
    None
}

fn collect_jadx_split_names(resources_root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(resources_root) else {
        return Vec::new();
    };
    let mut split_names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".apk") && name != "base.apk")
        .collect();
    split_names.sort();
    split_names.dedup();
    split_names
}

fn capture_manifest_open_tag(text: &str) -> Option<String> {
    let start = text.find("<manifest")?;
    let end = text[start..].find('>')? + start;
    Some(text[start..=end].to_string())
}

fn capture_manifest_attr(manifest_tag: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"(?:android:)?{key}\s*=\s*"([^"]*)""#);
    let regex = Regex::new(&pattern).ok()?;
    let value = regex
        .captures(manifest_tag)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())?;
    (!value.is_empty()).then_some(value)
}

pub fn run_jadx(apk: &Path, output_dir: &Path) -> Result<(), String> {
    let output = Command::new("jadx")
        .args(["-d", &output_dir.display().to_string()])
        .arg(apk)
        .output()
        .map_err(|e| format!("failed to launch jadx: {e}"))?;
    if !output.status.success() {
        if jadx_output_looks_usable(output_dir) {
            fs::write(
                output_dir.join(".fat-jadx-nonzero"),
                "jadx exited non-zero but produced a usable output tree",
            )
            .map_err(|e| {
                format!(
                    "jadx exited non-zero and FAT could not write degraded marker {}: {e}",
                    output_dir.display()
                )
            })?;
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
            .unwrap_or("no additional jadx diagnostics");
        return Err(format!("jadx failed for {}: {}", apk.display(), detail));
    }
    Ok(())
}

fn jadx_output_looks_usable(output_dir: &Path) -> bool {
    let sources_dir = output_dir.join("sources");
    let resources_dir = output_dir.join("resources");
    sources_dir.is_dir() || resources_dir.is_dir()
}

fn collect_source_files(
    root: &Path,
    sink: &mut dyn AndroidProgressSink,
) -> Result<Vec<SourceFile>, String> {
    let mut candidate_paths: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or_default(),
                "java" | "kt" | "xml" | "json" | "txt" | "html" | "js"
            )
        })
        .collect();
    // Sort for deterministic traversal: WalkDir yields OS-native directory
    // order, which differs across filesystems (e.g. APFS vs ext4) and made
    // first-match-wins fact extraction non-reproducible across platforms.
    candidate_paths.sort();
    let total = candidate_paths.len();
    let progress_interval = std::cmp::max(total / 10, 200);
    let mut files = Vec::new();
    for (index, path) in candidate_paths.into_iter().enumerate() {
        if let Ok(text) = fs::read_to_string(&path) {
            let lower_text = text.to_ascii_lowercase();
            let package_name = parse_package_name(&text);
            let imports = parse_imports(&text);
            let import_families = imports
                .iter()
                .filter_map(|import| classify_import_family(import).map(str::to_string))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let class_names = parse_class_names(&text);
            let method_names = parse_method_names(&text);
            let interesting_method_names: Vec<String> = method_names
                .iter()
                .filter(|name| is_interesting_method_name(name))
                .cloned()
                .collect();
            let has_high_signal_method = interesting_method_names
                .iter()
                .any(|name| method_signal_score(name) >= 4);
            let loaded_libraries = parse_load_libraries(&text);
            let protocol_families =
                detect_protocol_families_from_parts(&lower_text, &imports, package_name.as_deref());
            let security_families = detect_security_families_from_parts(
                &lower_text,
                package_name.as_deref(),
                &class_names,
                &interesting_method_names,
            );
            let package_family = package_name
                .as_deref()
                .and_then(|name| {
                    classify_package_family_from_parts(name, !loaded_libraries.is_empty())
                })
                .map(str::to_string);
            files.push(SourceFile {
                path: path.clone(),
                text,
                lower_text,
                package_name,
                package_family,
                imports,
                import_families,
                protocol_families,
                security_families,
                class_names,
                interesting_method_names,
                has_high_signal_method,
                loaded_libraries,
            });
        }
        let completed = index + 1;
        if total > 0 && (completed == 1 || completed == total || completed % progress_interval == 0)
        {
            sink.phase_progress(
                AndroidProgressPhase::IndexJadxSources,
                &AndroidProgressSnapshot {
                    completed: Some(completed),
                    total: Some(total),
                    ..AndroidProgressSnapshot::default()
                },
            );
        }
    }
    if files.is_empty() {
        return Err(format!(
            "no readable source files found under {}",
            root.display()
        ));
    }
    Ok(files)
}

fn guess_class_name(text: &str) -> Option<String> {
    let package_name = parse_package_name(text).unwrap_or_else(|| "com.example".into());
    parse_class_names(text)
        .into_iter()
        .next()
        .map(|value| format!("{package_name}.{value}"))
}

fn guess_method_symbol(text: &str, method_name: &str) -> Option<String> {
    let class_name = guess_class_name(text)?;
    let method_re = Regex::new(&format!(
        r"([A-Za-z0-9_<>\[\]\.]+\s+)+{}\s*\(",
        regex::escape(method_name)
    ))
    .expect("method regex");
    if method_re.is_match(text) {
        Some(format!("{class_name}.{method_name}"))
    } else {
        None
    }
}

fn provenance_from_files(files: &[SourceFile]) -> AndroidProvenance {
    let artifact = files
        .first()
        .map(|file| file.path.display().to_string())
        .unwrap_or_else(|| "jadx-tree".into());
    AndroidProvenance {
        origin: "fat-android-heuristic-jadx".into(),
        artifact,
        location: None,
        detail: Some("heuristic extraction from decompiled tree".into()),
    }
}

fn provenance_from_path(path: &Path) -> AndroidProvenance {
    AndroidProvenance {
        origin: "fat-android-heuristic-jadx".into(),
        artifact: path.display().to_string(),
        location: None,
        detail: Some("heuristic extraction from decompiled file".into()),
    }
}

fn provenance_from_file(file: &SourceFile) -> AndroidProvenance {
    AndroidProvenance {
        origin: "fat-android-heuristic-jadx".into(),
        artifact: file.path.display().to_string(),
        location: None,
        detail: Some("heuristic extraction from decompiled file".into()),
    }
}

fn is_placeholder_symbol(symbol: &str) -> bool {
    matches!(
        symbol,
        "com.example.Router.dispatch"
            | "com.example.WebEntry.loadUrl"
            | "com.example.NotificationHandler.dispatch"
            | "com.example.NativeBridge.parseBlob"
    )
}

fn jni_symbol_name_for_method(symbol: &str) -> Option<String> {
    let (class_name, method_name) = symbol.rsplit_once('.')?;
    let encoded_class = class_name
        .chars()
        .map(|ch| match ch {
            '.' => "_".to_string(),
            '_' => "_1".to_string(),
            '$' => "_00024".to_string(),
            other => other.to_string(),
        })
        .collect::<String>();
    let encoded_method = method_name
        .chars()
        .map(|ch| match ch {
            '_' => "_1".to_string(),
            '$' => "_00024".to_string(),
            other => other.to_string(),
        })
        .collect::<String>();
    Some(format!("Java_{encoded_class}_{encoded_method}"))
}

fn detect_caller_validation_guards(lower_text: &str) -> BTreeSet<String> {
    let mut guards = BTreeSet::new();
    for (needle, label) in [
        ("getcallinguid(", "getCallingUid"),
        ("getcallingpackage(", "getCallingPackage"),
        ("checkcallingpermission(", "checkCallingPermission"),
        (
            "checkcallingorselfpermission(",
            "checkCallingOrSelfPermission",
        ),
        ("enforcecallingpermission(", "enforceCallingPermission"),
    ] {
        if lower_text.contains(needle) {
            guards.insert(label.to_string());
        }
    }
    guards
}

fn extract_javascript_interface_methods(text: &str) -> Vec<JavascriptInterfaceMethod> {
    let mut methods = Vec::new();
    for captures in javascript_interface_method_regex().captures_iter(text) {
        let Some(name_match) = captures.get(1) else {
            continue;
        };
        let params = captures
            .get(2)
            .map(|value| value.as_str())
            .unwrap_or_default();
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let open_brace_index = full_match.end().saturating_sub(1);
        let body = extract_braced_body(text, open_brace_index).unwrap_or_default();
        methods.push(JavascriptInterfaceMethod {
            name: name_match.as_str().to_string(),
            parameter_types: parse_parameter_types(params),
            sink_notes: classify_javascript_interface_sinks(&body),
        });
    }
    methods
}

fn encode_javascript_interface_method(method: &JavascriptInterfaceMethod) -> String {
    format!(
        "name={};params={};sinks={}",
        method.name,
        method.parameter_types.join(","),
        method.sink_notes.join(",")
    )
}

fn extract_braced_body(text: &str, open_brace_index: usize) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.get(open_brace_index).copied() != Some(b'{') {
        return None;
    }

    let mut depth = 0usize;
    let mut body_start = None;
    for (index, byte) in bytes.iter().enumerate().skip(open_brace_index) {
        match byte {
            b'{' => {
                depth += 1;
                if depth == 1 {
                    body_start = Some(index + 1);
                }
            }
            b'}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    let start = body_start.unwrap_or(open_brace_index + 1);
                    return text.get(start..index).map(str::to_string);
                }
            }
            _ => {}
        }
    }

    None
}

fn parse_parameter_types(params: &str) -> Vec<String> {
    params
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let declaration = value.split('=').next().unwrap_or(value).trim();
            let tokens: Vec<&str> = declaration.split_whitespace().collect();
            if tokens.len() >= 2 {
                tokens[..tokens.len() - 1].join(" ")
            } else {
                declaration.to_string()
            }
        })
        .collect()
}

fn classify_javascript_interface_sinks(body: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut sinks = Vec::new();

    if lower.contains("eventbus.getdefault().post(") || lower.contains("postmainevent(") {
        sinks.push("eventbus-post".to_string());
    }
    if lower.contains("sendgo2req")
        || lower.contains("req.topic")
        || lower.contains("api_id")
        || lower.contains("appsendcmd")
    {
        sinks.push("command-dispatch".to_string());
    }
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("retrofit")
        || lower.contains("okhttp")
        || lower.contains("httpclient.execute(")
    {
        sinks.push("http-request".to_string());
    }
    if lower.contains("filewriter")
        || lower.contains("filesoutputstream")
        || lower.contains("openfileoutput(")
        || (lower.contains(".write(") && (lower.contains("/tmp/") || lower.contains("program")))
    {
        sinks.push("file-write".to_string());
    }

    sinks
}

fn extract_command_catalog_signals(file: &SourceFile) -> Vec<ProtocolSignal> {
    let mut signals = Vec::new();
    let file_lower = file.lower_text.as_str();

    for captures in enum_block_regex().captures_iter(&file.text) {
        let Some(enum_name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(body) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        let enum_name_lower = enum_name.to_ascii_lowercase();
        let command_like_enum = ["api", "runner", "command", "action", "send", "request"]
            .iter()
            .any(|needle| enum_name_lower.contains(needle))
            || file_lower.contains("api_id")
            || file_lower.contains("sendgo2req")
            || file_lower.contains("topic");
        if !command_like_enum {
            continue;
        }
        for entry in parse_enum_entries(body) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::CommandCatalogEntry,
                detail: Some(format!("{enum_name}.{entry}")),
            });
        }
    }

    let command_like_container = file_lower.contains("sendgo2req")
        || file_lower.contains("api_id")
        || file_lower.contains("topic")
        || file.class_names.iter().any(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("req")
                || lower.contains("request")
                || lower.contains("command")
                || lower.contains("envelope")
                || lower.contains("send")
        });
    if command_like_container {
        for captures in field_declaration_regex().captures_iter(&file.text) {
            let Some(field_name) = captures.get(1).map(|value| value.as_str()) else {
                continue;
            };
            if matches!(field_name, "topic" | "api_id" | "id" | "data") {
                signals.push(ProtocolSignal {
                    kind: ProtocolSignalKind::CommandEnvelopeField,
                    detail: Some(field_name.to_string()),
                });
            }
        }
    }

    signals
}

fn extract_ble_security_signals(file: &SourceFile) -> Vec<ProtocolSignal> {
    let mut signals = Vec::new();
    let lower = file.lower_text.as_str();
    let ble_like = file
        .package_name
        .as_deref()
        .is_some_and(|package| package.to_ascii_lowercase().contains("ble"))
        || lower.contains("bluetooth")
        || lower.contains("uuid_")
        || lower.contains("gatt");
    if !ble_like && !lower.contains("aes/") {
        return signals;
    }

    let mut seen = BTreeSet::new();
    for captures in ble_uuid_constant_declaration_regex().captures_iter(&file.text) {
        let Some(name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if seen.insert(format!("uuid:{name}")) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleCharacteristicUuid,
                detail: Some(name.to_string()),
            });
        }
    }
    for captures in ble_uuid_name_regex().captures_iter(&file.text) {
        let Some(name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if seen.insert(format!("uuid:{name}")) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleCharacteristicUuid,
                detail: Some(name.to_string()),
            });
        }
    }
    for captures in ble_uuid_literal_regex().captures_iter(&file.text) {
        let Some(uuid) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if seen.insert(format!("uuid:{uuid}")) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleCharacteristicUuid,
                detail: Some(uuid.to_string()),
            });
        }
    }

    for mode in ["AES/CFB128/NoPadding", "AES/GCM/NoPadding"] {
        if lower.contains(&mode.to_ascii_lowercase()) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::BleCryptoMode,
                detail: Some(mode.to_string()),
            });
        }
    }

    if let Some(session_key) = first_regex_capture(ble_session_key_regex(), &file.text) {
        signals.push(ProtocolSignal {
            kind: ProtocolSignalKind::BleSessionKeyDerivation,
            detail: Some(session_key),
        });
    } else if lower.contains("sessionkey")
        || lower.contains("session_key")
        || lower.contains("wrappedkey")
        || lower.contains("exchangesessionkey")
        || lower.contains("secretkey")
    {
        // Canonical token so this heuristic fallback and a regex-captured
        // `"session_key"` literal collapse to the same fact deterministically
        // (they share a fact id after subject sanitization).
        signals.push(ProtocolSignal {
            kind: ProtocolSignalKind::BleSessionKeyDerivation,
            detail: Some("session_key".into()),
        });
    }

    signals
}

fn parse_enum_entries(body: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut in_constants = true;

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        if line.starts_with('@') {
            continue;
        }
        if line.contains(';') {
            in_constants = false;
        }
        if !in_constants && !line.ends_with(',') {
            break;
        }

        let candidate = line
            .split(['(', ',', ';'])
            .next()
            .unwrap_or_default()
            .trim();
        if candidate.is_empty() {
            continue;
        }
        if matches!(
            candidate,
            "public" | "private" | "protected" | "static" | "final"
        ) {
            continue;
        }
        if !candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            continue;
        }
        if !candidate
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        {
            continue;
        }
        entries.push(candidate.to_string());
    }

    entries
}

fn extract_http_api_signals(file: &SourceFile) -> Vec<ProtocolSignal> {
    let mut signals = Vec::new();

    for captures in retrofit_annotation_regex().captures_iter(&file.text) {
        let Some(method) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(path) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        signals.push(ProtocolSignal {
            kind: ProtocolSignalKind::HttpApiEndpoint,
            detail: Some(format!(
                "method={};path={};dynamic={}",
                method,
                path,
                path.contains('{') || path.contains('}')
            )),
        });
        if path.contains('{') || path.contains('}') {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::HttpDynamicPath,
                detail: Some(path.to_string()),
            });
        }
    }

    for captures in header_method_regex().captures_iter(&file.text) {
        let Some(header_name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if looks_like_auth_header(header_name) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::HttpAuthHeader,
                detail: Some(header_name.to_string()),
            });
        }
    }

    signals
}

fn looks_like_auth_header(header_name: &str) -> bool {
    let lower = header_name.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("auth")
        || lower.contains("sign")
        || lower.contains("nonce")
        || lower.contains("authorization")
        || lower.contains("cookie")
}

fn first_regex_capture(regex: &Regex, text: &str) -> Option<String> {
    regex
        .captures(text)
        .and_then(|caps| caps.get(1))
        .map(|value| value.as_str().to_string())
}

fn command_topic_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""(rt/api/[A-Za-z0-9_/\-]+)""#).expect("command topic regex"))
}

fn string_literal_regex(value: &str) -> &'static Regex {
    static SESSION_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    match value {
        "session-token" => SESSION_TOKEN_RE
            .get_or_init(|| Regex::new(r#""(session-token)""#).expect("session token regex")),
        _ => unreachable!("unsupported literal regex"),
    }
}

fn javascript_interface_method_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?s)@JavascriptInterface\s+public\s+(?:static\s+)?(?:final\s+)?[A-Za-z0-9_<>\[\]\.]+\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*\{"#,
        )
        .expect("javascript interface method regex")
    })
}

fn retrofit_annotation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"@(GET|POST|PUT|DELETE|PATCH)\("([^"]+)"\)"#)
            .expect("retrofit annotation regex")
    })
}

fn header_method_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:addHeader|header)\("([A-Za-z0-9_-]+)""#).expect("header method regex")
    })
}

fn enum_block_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)enum\s+([A-Za-z0-9_]+)\s*\{([^}]*)\}"#).expect("enum block regex")
    })
}

fn field_declaration_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)^\s*(?:public|private|protected)\s+[A-Za-z0-9_<>\[\]\.]+\s+([A-Za-z0-9_]+)\s*;"#,
        )
        .expect("field declaration regex")
    })
}

fn ble_uuid_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""(UUID_[A-Z0-9_]+)""#).expect("ble uuid name regex"))
}

fn ble_uuid_constant_declaration_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)\b([A-Z][A-Z0-9_]+)\s*=\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})""#,
        )
        .expect("ble uuid constant declaration regex")
    })
}

fn ble_uuid_literal_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#""([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})""#,
        )
        .expect("ble uuid literal regex")
    })
}

fn ble_session_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""(session[_-]?key)""#).expect("ble session key regex"))
}

fn parse_package_name(text: &str) -> Option<String> {
    package_regex()
        .captures(text)
        .and_then(|caps| caps.get(1))
        .map(|value| value.as_str().to_string())
}

fn parse_imports(text: &str) -> Vec<String> {
    import_regex()
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

fn parse_class_names(text: &str) -> Vec<String> {
    class_regex()
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

fn parse_method_names(text: &str) -> Vec<String> {
    method_regex()
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

fn parse_load_libraries(text: &str) -> Vec<String> {
    load_library_regex()
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

fn detect_protocol_families_from_parts(
    lower_text: &str,
    imports: &[String],
    package_name: Option<&str>,
) -> Vec<String> {
    let import_text = imports.join("\n").to_ascii_lowercase();
    let package_text = package_name.unwrap_or_default().to_ascii_lowercase();
    let mut protocols = BTreeSet::new();

    if has_positive_grpc_signal(lower_text, &import_text) {
        protocols.insert("grpc".to_string());
    }
    if lower_text.contains("webrtc") || import_text.contains("org.webrtc") {
        protocols.insert("webrtc".to_string());
    }
    if has_positive_weave_signal(lower_text, &import_text, &package_text) {
        protocols.insert("weave".to_string());
    }
    if lower_text.contains("matter") || import_text.contains("matter") {
        protocols.insert("matter".to_string());
    }
    if lower_text.contains("cast")
        || import_text.contains("chromecast")
        || import_text.contains("cast")
    {
        protocols.insert("cast".to_string());
    }
    if lower_text.contains("oauth")
        || lower_text.contains("authorization")
        || lower_text.contains("bearer ")
    {
        protocols.insert("auth".to_string());
    }

    protocols.into_iter().collect()
}

fn detect_security_families_from_parts(
    lower_text: &str,
    package_name: Option<&str>,
    class_names: &[String],
    method_names: &[String],
) -> Vec<String> {
    let package_text = package_name.unwrap_or_default().to_ascii_lowercase();
    let class_text = class_names.join("\n").to_ascii_lowercase();
    let method_text = method_names.join("\n").to_ascii_lowercase();
    let mut families = BTreeSet::new();

    if lower_text.contains("pairingcode")
        || lower_text.contains("manualpairingcode")
        || method_text.contains("pairingcode")
    {
        families.insert("pairing-code".to_string());
    }
    if lower_text.contains("fabric")
        || lower_text.contains("targetfabricid")
        || method_text.contains("createfabric")
        || method_text.contains("joinexistingfabric")
        || method_text.contains("leavefabric")
    {
        families.insert("fabric-membership".to_string());
    }
    if lower_text.contains("certificate")
        || lower_text.contains("x509")
        || lower_text.contains("attestation")
        || lower_text.contains("trustedrootcertificate")
        || lower_text.contains("operationalcredentials")
    {
        families.insert("certificate".to_string());
    }
    if lower_text.contains("keyexport")
        || lower_text.contains("groupkey")
        || lower_text.contains("rootkey")
        || lower_text.contains("keyid")
    {
        families.insert("key-export".to_string());
    }
    if lower_text.contains("commission")
        || lower_text.contains("rendezvous")
        || lower_text.contains("onboardingpayload")
        || lower_text.contains("shareddevicedata")
        || package_text.contains("matter.commissioning")
    {
        families.insert("commissioning".to_string());
    }
    if lower_text.contains("weavedevicedescriptor")
        || lower_text.contains("devicedescriptor")
        || method_text.contains("identifydevice")
        || class_text.contains("identifydevicecriteria")
    {
        families.insert("device-descriptor".to_string());
    }
    if lower_text.contains("accesstoken")
        || lower_text.contains("oauthtoken")
        || lower_text.contains("tokengetter")
        || method_text.contains("accesstoken")
    {
        families.insert("access-token".to_string());
    }

    families.into_iter().collect()
}

fn should_consider_default_heuristic_file(
    file: &SourceFile,
    target_package: &str,
    mode: AndroidSemanticMode,
) -> bool {
    if mode == AndroidSemanticMode::Dense {
        return true;
    }

    let Some(package_name) = file.package_name.as_deref() else {
        return !file.security_families.is_empty()
            || !file.protocol_families.is_empty()
            || !file.loaded_libraries.is_empty();
    };

    if is_app_owned_package(package_name, target_package) {
        return true;
    }

    if is_known_third_party_package(package_name) {
        return false;
    }

    is_semantically_relevant_file(file)
}

fn has_positive_grpc_signal(lower_text: &str, import_text: &str) -> bool {
    import_text.contains("io.grpc")
        || lower_text.contains("managedchannelbuilder")
        || lower_text.contains("managedchannel ")
        || lower_text.contains("grpc.newstub(")
        || lower_text.contains("newblockingstub(")
        || lower_text.contains("newfuturestub(")
}

fn has_positive_weave_signal(lower_text: &str, import_text: &str, package_text: &str) -> bool {
    is_weave_package(package_text)
        || import_text.contains(".weave.")
        || import_text.contains("nl.weave.")
        || import_text.contains("com.nestlabs.weave.")
        || lower_text.contains("package nl.weave.")
        || lower_text.contains("package com.nestlabs.weave.")
        || lower_text.contains("weavedevicemanager")
        || lower_text.contains("weavecertificatesupport")
        || lower_text.contains("weavedevicedescriptor")
        || lower_text.contains("targetfabricid")
        || lower_text.contains("identifydevicecriteria")
}

fn has_positive_mqtt_signal(lower_text: &str, import_text: &str, package_text: &str) -> bool {
    lower_text.contains("mqtt://")
        || ((lower_text.contains("tcp://") || lower_text.contains("ssl://"))
            && (lower_text.contains("mqttclient") || lower_text.contains("mqttconnectoptions")))
        || import_text.contains(".mqtt.")
        || import_text.contains("org.eclipse.paho")
        || import_text.contains("com.hivemq")
        || import_text.contains("io.netty.handler.codec.mqtt")
        || import_text.contains("mqttclient")
        || import_text.contains("mqttconnectoptions")
        || is_mqtt_package(package_text)
}

fn extract_security_constant_signals(file: &SourceFile) -> Vec<ProtocolSignal> {
    if !should_consider_security_constants_file(file) {
        return Vec::new();
    }

    let mut signals = Vec::new();
    let crypto_relevant = is_crypto_relevant_file(file);

    for capture in static_constant_regex().captures_iter(&file.text) {
        let Some(name_match) = capture.get(1) else {
            continue;
        };
        let Some(value_match) = capture.get(2) else {
            continue;
        };

        let name = name_match.as_str().trim();
        let value = value_match.as_str().trim();
        let name_lower = name.to_ascii_lowercase();
        let value_lower = value.to_ascii_lowercase();

        if looks_like_public_key(&name_lower, &value_lower) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::PublicKey,
                detail: Some(name.into()),
            });
            continue;
        }

        if looks_like_static_secret(&name_lower, &value_lower) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::StaticSecret,
                detail: Some(name.into()),
            });
            continue;
        }

        if looks_like_default_credential(&name_lower, &value_lower) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::DefaultCredential,
                detail: Some(name.into()),
            });
            continue;
        }

        if looks_like_network_endpoint(&name_lower, &value_lower) {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::NetworkStaticEndpoint,
                detail: Some(name.into()),
            });
            continue;
        }
    }

    if crypto_relevant {
        for capture in byte_material_assignment_regex().captures_iter(&file.text) {
            let Some(name_match) = capture.get(1) else {
                continue;
            };
            let name = name_match.as_str().trim();
            let normalized = normalize_symmetric_material_name(name);
            if normalized.is_empty() {
                continue;
            }
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::SymmetricKeyMaterial,
                detail: Some(normalized),
            });
        }

        for capture in static_block_byte_assignment_regex().captures_iter(&file.text) {
            let Some(name_match) = capture.get(1) else {
                continue;
            };
            let normalized = normalize_symmetric_material_name(name_match.as_str().trim());
            if normalized.is_empty() {
                continue;
            }
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::SymmetricKeyMaterial,
                detail: Some(normalized),
            });
        }

        if file
            .lower_text
            .contains("new secretkeyspec(new byte[16], \"aes\")")
            || file
                .lower_text
                .contains("new secretkeyspec(new byte [16], \"aes\")")
        {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::SymmetricKeyMaterial,
                detail: Some("zero-key-fallback".into()),
            });
        }
    }

    dedup_protocol_signals(signals)
}

fn extract_security_posture_signals(file: &SourceFile) -> Vec<ProtocolSignal> {
    if !should_consider_security_posture_file(file) {
        return Vec::new();
    }

    let mut signals = Vec::new();
    let lower = &file.lower_text;

    if lower.contains("hostnameverifier")
        && lower.contains("verify(")
        && lower.contains("return true;")
    {
        signals.push(ProtocolSignal {
            kind: ProtocolSignalKind::HostnameVerificationDisabled,
            detail: Some("HostnameVerifier#verify".into()),
        });
    }

    if lower.contains("x509trustmanager")
        && lower.contains("checkclienttrusted(")
        && lower.contains("checkservertrusted(")
        && (empty_trust_method_regex("checkClientTrusted").is_match(&file.text)
            || empty_trust_method_regex("checkServerTrusted").is_match(&file.text)
            || lower.contains("return new x509certificate[0];")
            || lower.contains("return null;"))
    {
        signals.push(ProtocolSignal {
            kind: ProtocolSignalKind::WeakTrustManager,
            detail: Some("X509TrustManager".into()),
        });
    }

    let token_store_keys = collect_plaintext_token_keys(file);
    let uses_default_mmkv = lower.contains("mmkv.defaultmmkv()");
    let has_crypto_key = lower.contains("cryptkey") || lower.contains("mmkvwithid(");

    if uses_default_mmkv {
        for key in token_store_keys {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::PlaintextTokenStore,
                detail: Some(key),
            });
        }

        if !has_crypto_key && lower.contains("encode(") && lower.contains("token") {
            signals.push(ProtocolSignal {
                kind: ProtocolSignalKind::AvailableEncryptionUnused,
                detail: Some("MMKV.defaultMMKV".into()),
            });
        }
    }

    dedup_protocol_signals(signals)
}

fn dedup_protocol_signals(signals: Vec<ProtocolSignal>) -> Vec<ProtocolSignal> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();

    for signal in signals {
        let key = (signal.kind, signal.detail.clone().unwrap_or_default());
        if seen.insert(key) {
            deduped.push(signal);
        }
    }

    deduped
}

fn is_crypto_relevant_file(file: &SourceFile) -> bool {
    file.imports.iter().any(|import| {
        let lower = import.to_ascii_lowercase();
        lower.starts_with("javax.crypto") || lower.starts_with("java.security")
    }) || file.lower_text.contains("cipher.getinstance(\"aes/")
        || file.lower_text.contains("secretkeyspec")
        || file.lower_text.contains("ivparameterspec")
}

fn should_consider_security_constants_file(file: &SourceFile) -> bool {
    if file.path.to_string_lossy().ends_with("/R.java") || file.path.ends_with("R.java") {
        return false;
    }

    let Some(package_name) = file.package_name.as_deref() else {
        return false;
    };

    if is_known_third_party_package(package_name) {
        return false;
    }

    is_crypto_relevant_file(file)
        || file.lower_text.contains("secret")
        || file.lower_text.contains("public_key")
        || file.lower_text.contains("server_address")
        || file.lower_text.contains("udp_ip")
        || file.lower_text.contains("udp_port")
        || file.lower_text.contains("default_ap_pwd")
        || file.lower_text.contains("dog_address")
}

fn should_consider_security_posture_file(file: &SourceFile) -> bool {
    if file.path.to_string_lossy().ends_with("/R.java") || file.path.ends_with("R.java") {
        return false;
    }

    let Some(package_name) = file.package_name.as_deref() else {
        return false;
    };

    if is_known_third_party_package(package_name) {
        return false;
    }

    let lower = &file.lower_text;
    lower.contains("hostnameverifier")
        || lower.contains("x509trustmanager")
        || lower.contains("mmkv.defaultmmkv()")
}

fn collect_plaintext_token_keys(file: &SourceFile) -> Vec<String> {
    let lower = &file.lower_text;
    let mut keys = Vec::new();

    for key in ["KEY_SP_TOKEN", "KEY_SP_REFRESH_TOKEN"] {
        if file.text.contains(key) && lower.contains("encode(") {
            keys.push(key.into());
        }
    }

    if lower.contains("accesstoken") && lower.contains("encode(") {
        keys.push("accessToken".into());
    }
    if lower.contains("refreshtoken") && lower.contains("encode(") {
        keys.push("refreshToken".into());
    }

    keys
}

fn looks_like_public_key(name_lower: &str, value_lower: &str) -> bool {
    let trimmed_value = value_lower.trim_matches('"');
    let public_key_named = name_lower.contains("public_key")
        || (name_has_token(name_lower, "public") && name_has_token(name_lower, "key"));
    let key_like_value = trimmed_value.contains("begin public key")
        || trimmed_value.starts_with("mii")
        || trimmed_value.len() >= 40;
    let ascii_key_alphabet = trimmed_value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'));

    public_key_named && key_like_value && ascii_key_alphabet
}

fn looks_like_static_secret(name_lower: &str, value_lower: &str) -> bool {
    let trimmed_value = value_lower.trim_matches('"');
    (name_has_token(name_lower, "secret") || name_lower.contains("sign_secret"))
        && !name_lower.contains("public")
        && !trimmed_value.is_empty()
        && !trimmed_value.chars().all(|ch| ch.is_ascii_digit())
}

fn looks_like_default_credential(name_lower: &str, value_lower: &str) -> bool {
    let trimmed_value = value_lower.trim_matches('"');
    let credential_named = (name_has_token(name_lower, "pwd")
        || name_has_token(name_lower, "password")
        || name_has_token(name_lower, "passcode")
        || name_has_token(name_lower, "credential"))
        && (name_has_token(name_lower, "default")
            || name_has_token(name_lower, "ap")
            || name_has_token(name_lower, "wifi"));
    let credential_value = trimmed_value.is_empty()
        || (trimmed_value.len() <= 64
            && trimmed_value.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '!' | '@' | '#')
            }));
    credential_named && credential_value
}

fn looks_like_network_endpoint(name_lower: &str, value_lower: &str) -> bool {
    let trimmed_value = value_lower.trim_matches('"');
    let endpoint_named = name_has_token(name_lower, "ip")
        || name_has_token(name_lower, "address")
        || name_has_token(name_lower, "host")
        || name_has_token(name_lower, "port");
    let endpoint_value = trimmed_value.starts_with("http://")
        || trimmed_value.starts_with("https://")
        || ipv4_literal_regex().is_match(trimmed_value)
        || trimmed_value.chars().all(|ch| ch.is_ascii_digit());
    endpoint_named && endpoint_value
}

fn name_has_token(name: &str, token: &str) -> bool {
    name == token
        || name.starts_with(&format!("{token}_"))
        || name.ends_with(&format!("_{token}"))
        || name.contains(&format!("_{token}_"))
}

fn normalize_symmetric_material_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains("publickey") {
        String::new()
    } else if lower == "iv"
        || lower.contains("secretkey")
        || lower.contains("keybytes")
        || lower.ends_with("_key")
        || lower == "key"
    {
        name.into()
    } else {
        String::new()
    }
}

fn is_grpc_package(package_name: &str) -> bool {
    package_name == "grpc" || package_name.ends_with(".grpc") || package_name.contains(".grpc.")
}

fn is_weave_package(package_name: &str) -> bool {
    package_name == "nl.weave"
        || package_name.starts_with("nl.weave.")
        || package_name == "com.nestlabs.weave"
        || package_name.starts_with("com.nestlabs.weave.")
        || package_name.contains(".weave.")
}

fn is_mqtt_package(package_name: &str) -> bool {
    package_name == "mqtt" || package_name.ends_with(".mqtt") || package_name.contains(".mqtt.")
}

fn is_app_owned_package(package_name: &str, target_package: &str) -> bool {
    package_name == target_package
        || package_name.starts_with(&format!("{target_package}."))
        || app_vendor_prefix(target_package).is_some_and(|prefix| {
            package_name == prefix || package_name.starts_with(&format!("{prefix}."))
        })
}

fn app_vendor_prefix(target_package: &str) -> Option<&str> {
    let mut parts = target_package.match_indices('.').map(|(index, _)| index);
    let _first = parts.next()?;
    let second = parts.next()?;
    Some(&target_package[..second])
}

fn is_known_third_party_package(package_name: &str) -> bool {
    [
        "android",
        "androidx",
        "cn.hotapk",
        "java",
        "javax",
        "kotlin",
        "kotlinx",
        "okhttp3",
        "okio",
        "retrofit2",
        "org.jetbrains",
        "com.alibaba",
        "com.blankj",
        "com.elvishew",
        "com.google.common",
        "com.google.android.exoplayer2",
        "com.iflytek",
        "com.just.agentweb",
        "com.luck.picture.lib",
        "com.lxj.xpopup",
        "com.nico",
        "com.ta",
        "com.taobao",
        "com.tencent",
        "io.microshow",
        "me.jessyan",
        "net.cachapa",
        "org.greenrobot",
        "top.zibin",
    ]
    .iter()
    .any(|prefix| package_name == *prefix || package_name.starts_with(&format!("{prefix}.")))
}

fn is_semantically_relevant_file(file: &SourceFile) -> bool {
    !file.loaded_libraries.is_empty()
        || !file.protocol_families.is_empty()
        || !file.import_families.is_empty()
        || file.has_high_signal_method
        || contains_semantic_keywords(&file.lower_text)
}

fn is_relevant_import(import: &str) -> bool {
    classify_import_family(import).is_some()
}

fn classify_import_family(import: &str) -> Option<&'static str> {
    let lower = import.to_ascii_lowercase();
    if lower.starts_with("io.grpc") {
        Some("grpc")
    } else if lower.starts_with("org.webrtc") {
        Some("webrtc")
    } else if lower.starts_with("okhttp3") {
        Some("okhttp")
    } else if lower.starts_with("retrofit2") {
        Some("retrofit")
    } else if lower.starts_with("android.webkit") || lower.contains("webview") {
        Some("webview")
    } else if lower.starts_with("android.bluetooth") {
        Some("bluetooth")
    } else if lower.starts_with("android.os.binder")
        || lower.starts_with("android.os.ibinder")
        || lower.starts_with("android.os.parcel")
        || lower.contains("binder")
    {
        Some("binder")
    } else if lower.starts_with("android.app.pendingintent") {
        Some("pending-intent")
    } else if is_weave_package(&lower) {
        Some("weave")
    } else if lower.contains("matter") {
        Some("matter")
    } else if lower.contains("chromecast") || lower.contains(".cast") {
        Some("cast")
    } else if lower.contains(".mqtt.")
        || lower.starts_with("org.eclipse.paho")
        || lower.starts_with("com.hivemq")
        || lower.starts_with("io.netty.handler.codec.mqtt")
    {
        Some("mqtt")
    } else if lower.contains("protobuf") {
        Some("protobuf")
    } else if lower.contains("contentresolver") {
        Some("content-resolver")
    } else if lower.contains("uri") {
        Some("uri")
    } else {
        None
    }
}

fn classify_package_family_from_parts(
    package_name: &str,
    has_loaded_libraries: bool,
) -> Option<&'static str> {
    let lower = package_name.to_ascii_lowercase();
    if is_weave_package(&lower) {
        Some("weave")
    } else if lower.contains("matter") {
        Some("matter")
    } else if lower.contains("webrtc") {
        Some("webrtc")
    } else if is_grpc_package(&lower) {
        Some("grpc")
    } else if lower.contains("chromecast") || lower.contains(".cast") || lower.contains("cast") {
        Some("cast")
    } else if is_mqtt_package(&lower) {
        Some("mqtt")
    } else if lower.contains("webview") {
        Some("webview")
    } else if lower.contains("binder") {
        Some("binder")
    } else if lower.contains("router") {
        Some("router")
    } else if has_loaded_libraries {
        Some("native-bridge")
    } else {
        None
    }
}

fn select_class_symbols(file: &SourceFile, mode: AndroidSemanticMode) -> Vec<String> {
    let mut scored: Vec<(i32, String)> = file
        .class_names
        .iter()
        .cloned()
        .map(|name| (class_signal_score(file, &name), name))
        .filter(|(score, _)| *score >= min_class_symbol_score(mode))
        .collect();
    scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    scored.truncate(max_class_symbols_per_file(mode));
    scored.into_iter().map(|(_, name)| name).collect()
}

fn class_signal_score(file: &SourceFile, class_name: &str) -> i32 {
    let class_lower = class_name.to_ascii_lowercase();
    let mut score = 0;
    if class_lower.contains("router")
        || class_lower.contains("manager")
        || class_lower.contains("provider")
        || class_lower.contains("bridge")
        || class_lower.contains("binder")
        || class_lower.contains("webview")
        || class_lower.contains("device")
    {
        score += 4;
    }
    if class_lower.contains("client")
        || class_lower.contains("service")
        || class_lower.contains("cast")
        || class_lower.contains("weave")
        || class_lower.contains("matter")
        || class_lower.contains("grpc")
    {
        score += 3;
    }
    if !file.loaded_libraries.is_empty() {
        score += 2;
    }
    if !file.protocol_families.is_empty() {
        score += 1;
    }
    if file.package_family.is_some() {
        score += 1;
    }
    if !file.import_families.is_empty() {
        score += 1;
    }
    if file.has_high_signal_method {
        score += 1;
    }
    score
}

fn select_method_symbols(file: &SourceFile, mode: AndroidSemanticMode) -> Vec<String> {
    let mut scored: Vec<(i32, String)> = file
        .interesting_method_names
        .iter()
        .cloned()
        .map(|name| (method_signal_score(&name), name))
        .filter(|(score, _)| *score >= min_method_symbol_score(mode))
        .collect();
    scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    scored.truncate(max_method_symbols_per_file(mode));
    scored.into_iter().map(|(_, name)| name).collect()
}

fn method_signal_score(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    let mut score = 0;
    if lower.starts_with("ondevice")
        || lower.starts_with("onnotify")
        || lower.starts_with("onidentify")
    {
        score += 5;
    }
    if lower.starts_with("dispatch")
        || lower.starts_with("connect")
        || lower.starts_with("bind")
        || lower.starts_with("start")
        || lower.starts_with("stop")
        || lower.starts_with("send")
        || lower.starts_with("execute")
        || lower.starts_with("auth")
    {
        score += 4;
    }
    if lower.starts_with("on") || lower.starts_with("load") || lower.starts_with("parse") {
        score += 3;
    }
    if lower.starts_with("query")
        || lower.starts_with("update")
        || lower.starts_with("insert")
        || lower.starts_with("delete")
        || lower.starts_with("write")
        || lower.starts_with("read")
    {
        score += 2;
    }
    score
}

fn rank_endpoint_templates(
    endpoint_templates: Vec<String>,
    mode: AndroidSemanticMode,
) -> Vec<(String, i32)> {
    let mut unique_endpoints = BTreeSet::new();
    let mut ranked = Vec::new();

    for template in endpoint_templates {
        if !is_endpoint_surface_candidate(&template) {
            continue;
        }
        if !unique_endpoints.insert(template.clone()) {
            continue;
        }
        let score = endpoint_surface_score(&template);
        if score < min_endpoint_surface_score(mode) {
            continue;
        }
        ranked.push((template, score));
    }

    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked.truncate(max_endpoint_control_surfaces(mode));
    ranked
}

fn is_endpoint_surface_candidate(template: &str) -> bool {
    let lower = template.to_ascii_lowercase();
    (lower.starts_with('/') || lower.starts_with("http://") || lower.starts_with("https://"))
        && (lower.contains("/api")
            || lower.contains("/devices")
            || lower.contains("/device")
            || lower.contains("/users/devices"))
        && !lower.ends_with(".webp")
        && !lower.ends_with(".png")
        && !lower.ends_with(".jpg")
        && !lower.ends_with(".jpeg")
        && !lower.ends_with(".svg")
        && !lower.ends_with(".gif")
        && !lower.ends_with(".html")
        && !lower.contains("/assets/")
        && !lower.contains("/images/")
}

fn endpoint_surface_score(template: &str) -> i32 {
    let lower = template.to_ascii_lowercase();
    let mut score = 0;

    if lower.contains("/api") {
        score += 1;
    }
    if lower.contains("/devices") || lower.contains("/device") {
        score += 3;
    }
    if lower.contains("{sn}") || lower.contains("{id}") || lower.contains("{uuid}") {
        score += 2;
    }
    if lower.contains("live")
        || lower.contains("stream")
        || lower.contains("control")
        || lower.contains("command")
        || lower.contains("activation")
        || lower.contains("bind")
        || lower.contains("pair")
        || lower.contains("token")
        || lower.contains("auth")
        || lower.contains("mode")
    {
        score += 4;
    }
    if lower.contains("start")
        || lower.contains("stop")
        || lower.contains("open")
        || lower.contains("enter")
        || lower.contains("exit")
        || lower.contains("dispatch")
        || lower.contains("reboot")
        || lower.contains("factory")
    {
        score += 3;
    }
    if lower.contains("jobs/") || lower.contains("/jobs") {
        score += 1;
    }
    if lower.ends_with("/faq")
        || lower.contains("/faq/")
        || lower.contains("maps/")
        || lower.contains("mapcontent")
        || lower.contains("status")
        || lower.contains("list")
        || lower.contains("modulefile")
        || lower.contains("analyze")
    {
        score -= 3;
    }
    if lower == "/api/v1/devices" || lower.ends_with("/devices") {
        score -= 1;
    }

    score
}

fn record_family_observation(
    families: &mut std::collections::BTreeMap<String, FamilyObservation>,
    family: &str,
    sample_subject: &str,
    provenance: AndroidProvenance,
) {
    let entry = families.entry(family.to_string()).or_default();
    if entry.sample_subject.is_empty() {
        entry.sample_subject = sample_subject.to_string();
    }
    entry.occurrences += 1;
    if entry.provenance.len() < 3 {
        entry.provenance.push(provenance);
    }
}

fn emit_family_facts(
    bundle: &mut AndroidSemanticBundle,
    kind: &str,
    id_prefix: &str,
    families: std::collections::BTreeMap<String, FamilyObservation>,
) {
    for (family, observation) in families {
        let mut attributes = std::collections::BTreeMap::new();
        if !observation.sample_subject.is_empty() {
            attributes.insert("sample".into(), observation.sample_subject);
        }
        attributes.insert("occurrences".into(), observation.occurrences.to_string());
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("{id_prefix}-{}", sanitize_id(&family)),
            kind: kind.into(),
            subject: family,
            support_level: AndroidSupportLevel::Observed,
            provenance: observation.provenance,
            attributes,
        });
    }
}

fn max_class_symbols_per_file(mode: AndroidSemanticMode) -> usize {
    match mode {
        AndroidSemanticMode::Default => 2,
        AndroidSemanticMode::Dense => 8,
    }
}

fn max_method_symbols_per_file(mode: AndroidSemanticMode) -> usize {
    match mode {
        AndroidSemanticMode::Default => 4,
        AndroidSemanticMode::Dense => 12,
    }
}

fn min_class_symbol_score(mode: AndroidSemanticMode) -> i32 {
    match mode {
        AndroidSemanticMode::Default => 5,
        AndroidSemanticMode::Dense => 2,
    }
}

fn min_method_symbol_score(mode: AndroidSemanticMode) -> i32 {
    match mode {
        AndroidSemanticMode::Default => 4,
        AndroidSemanticMode::Dense => 2,
    }
}

fn max_endpoint_control_surfaces(mode: AndroidSemanticMode) -> usize {
    match mode {
        AndroidSemanticMode::Default => 24,
        AndroidSemanticMode::Dense => 64,
    }
}

fn min_endpoint_surface_score(mode: AndroidSemanticMode) -> i32 {
    match mode {
        AndroidSemanticMode::Default => 4,
        AndroidSemanticMode::Dense => 2,
    }
}

fn contains_semantic_keywords(lower_text: &str) -> bool {
    lower_text.contains("/api/")
        || lower_text.contains("authorization")
        || lower_text.contains("bearer ")
        || lower_text.contains("x-device-token")
        || lower_text.contains("mqtt")
        || lower_text.contains("router")
        || lower_text.contains("deeplink")
        || lower_text.contains("webview")
        || lower_text.contains("binder")
        || lower_text.contains("contentresolver")
}

fn is_interesting_method_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("on")
        || lower.starts_with("begin")
        || lower.starts_with("dispatch")
        || lower.starts_with("load")
        || lower.starts_with("parse")
        || lower.starts_with("connect")
        || lower.starts_with("bind")
        || lower.starts_with("start")
        || lower.starts_with("stop")
        || lower.starts_with("send")
        || lower.starts_with("query")
        || lower.starts_with("update")
        || lower.starts_with("insert")
        || lower.starts_with("delete")
        || lower.starts_with("write")
        || lower.starts_with("read")
        || lower.starts_with("execute")
        || lower.starts_with("auth")
}

fn package_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*package\s+([A-Za-z0-9_\.]+)\s*;").expect("package regex")
    })
}

fn import_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*import\s+([A-Za-z0-9_\.]+)\s*;").expect("import regex"))
}

fn class_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)\bclass\s+([A-Za-z0-9_]+)").expect("class regex"))
}

fn method_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[A-Za-z0-9_<>\[\]\.]+\s+([A-Za-z0-9_]+)\s*\(",
        )
        .expect("method regex")
    })
}

fn load_library_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"System\.loadLibrary\("([A-Za-z0-9_\-\.]+)"\)"#).expect("load regex")
    })
}

fn endpoint_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"([A-Za-z0-9:/._-]*/(?:api|devices)[A-Za-z0-9/._{}-]*)"#)
            .expect("endpoint regex")
    })
}

fn static_constant_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)\b(?:public|private|protected)\s+static\s+final\s+(?:String|int|long|Integer|Long)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);"#,
        )
        .expect("static constant regex")
    })
}

fn byte_material_assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)\b(?:public|private|protected)\s+static\s+final\s+byte\[\]\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z0-9_\.]+\.[A-Za-z0-9_]+\([^;]*\)|[A-Za-z_][A-Za-z0-9_]*\([^;]*\)|new byte\[[^\]]+\][^;]*);"#,
        )
        .expect("byte material regex")
    })
}

fn static_block_byte_assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z0-9_\.]+\.[A-Za-z0-9_]+\([^;]*\)|[A-Za-z_][A-Za-z0-9_]*\([^;]*\));"#,
        )
        .expect("static block byte assignment regex")
    })
}

fn empty_trust_method_regex(method_name: &str) -> Regex {
    Regex::new(&format!(r#"(?s)\b{method_name}\s*\([^)]*\)\s*\{{\s*\}}"#))
        .expect("empty trust method regex")
}

fn ipv4_literal_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\d{1,3}(?:\.\d{1,3}){3}$"#).expect("ipv4 regex"))
}

fn merge_semantics(into: &mut AndroidSemanticBundle, other: AndroidSemanticBundle) {
    into.facts.extend(other.facts);
    into.symbol_identities.extend(other.symbol_identities);
    into.control_surfaces.extend(other.control_surfaces);
    into.transport_surfaces.extend(other.transport_surfaces);
    into.trust_boundaries.extend(other.trust_boundaries);
    into.resources.extend(other.resources);
    into.native_semantics.extend(other.native_semantics);
    into.revelations.extend(other.revelations);
    into.correlations.extend(other.correlations);
    into.warnings.extend(other.warnings);
}

pub fn merge_semantic_layers(
    mut base: AndroidSemanticBundle,
    other: AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    base.subsystems.clear();
    base.revelations.clear();
    merge_semantics(&mut base, other);
    dedupe_bundle(&mut base);
    base.subsystems = derive_subsystems(&base);
    dedupe_bundle(&mut base);
    let revelations = derive_revelations(&base);
    merge_semantics(&mut base, revelations);
    dedupe_bundle(&mut base);
    base
}

fn dedupe_bundle(bundle: &mut AndroidSemanticBundle) {
    dedupe_by_key(&mut bundle.facts, |value| value.fact_id.clone());
    dedupe_by_key(&mut bundle.symbol_identities, |value| {
        value.symbol_id.clone()
    });
    dedupe_by_key(&mut bundle.control_surfaces, |value| {
        value.surface_id.clone()
    });
    dedupe_by_key(&mut bundle.transport_surfaces, |value| {
        value.surface_id.clone()
    });
    dedupe_by_key(&mut bundle.trust_boundaries, |value| {
        value.boundary_id.clone()
    });
    dedupe_by_key(&mut bundle.native_semantics, |value| {
        value.native_id.clone()
    });
    dedupe_by_key(&mut bundle.subsystems, |value| value.subsystem_id.clone());
    dedupe_by_key(&mut bundle.revelations, |value| value.revelation_id.clone());
    dedupe_by_key(&mut bundle.correlations, |value| {
        value.correlation_id.clone()
    });
}

fn dedupe_by_key<T, F>(values: &mut Vec<T>, mut key: F)
where
    F: FnMut(&T) -> String,
{
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(key(value)));
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch,
            _ => '-',
        })
        .collect()
}

fn component_kind_label(kind: &AndroidComponentKind) -> &'static str {
    match kind {
        AndroidComponentKind::Activity => "activity",
        AndroidComponentKind::Service => "service",
        AndroidComponentKind::Receiver => "receiver",
        AndroidComponentKind::Provider => "provider",
    }
}

fn empty_bundle() -> AndroidSemanticBundle {
    AndroidSemanticBundle {
        bundle_version: String::new(),
        target: AndroidSemanticTarget {
            application_id: None,
            package_name: String::new(),
            version_code: None,
            version_name: None,
            split_names: Vec::new(),
        },
        extractor: AndroidExtractorMetadata {
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

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="123"
    android:versionName="1.2.3"
    package="com.example.androidmini">
    <uses-permission android:name="android.permission.INTERNET" />
</manifest>
"#;

    #[test]
    fn derives_version_identity_from_flat_jadx_resources_manifest() {
        let root = tempfile::tempdir().expect("tempdir");
        let resources = root.path().join("resources");
        fs::create_dir_all(&resources).expect("resources dir");
        fs::write(resources.join("AndroidManifest.xml"), MANIFEST).expect("manifest");

        let identity = derive_target_identity_from_jadx_root(root.path());
        assert_eq!(identity.version_name.as_deref(), Some("1.2.3"));
        assert_eq!(identity.version_code.as_deref(), Some("123"));
        assert!(identity.split_names.is_empty());
    }

    #[test]
    fn derives_version_identity_and_split_names_from_split_jadx_layout() {
        let root = tempfile::tempdir().expect("tempdir");
        let resources = root.path().join("resources");
        fs::create_dir_all(resources.join("base.apk")).expect("base.apk dir");
        fs::create_dir_all(resources.join("split_config.en.apk")).expect("split lang dir");
        fs::create_dir_all(resources.join("split_config.arm64_v8a.apk")).expect("split abi dir");
        fs::write(
            resources.join("base.apk").join("AndroidManifest.xml"),
            MANIFEST,
        )
        .expect("manifest");

        let identity = derive_target_identity_from_jadx_root(root.path());
        assert_eq!(identity.version_name.as_deref(), Some("1.2.3"));
        assert_eq!(identity.version_code.as_deref(), Some("123"));
        assert_eq!(
            identity.split_names,
            vec![
                "split_config.arm64_v8a.apk".to_string(),
                "split_config.en.apk".to_string(),
            ]
        );
    }

    #[test]
    fn target_identity_stays_empty_without_a_decoded_manifest() {
        let root = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(root.path().join("resources")).expect("resources dir");
        // Binary AXML that JADX failed to decode must not be mined for text.
        fs::write(
            root.path().join("resources").join("AndroidManifest.xml"),
            [0x03u8, 0x00, 0x08, 0x00, 0x64, 0x00],
        )
        .expect("binary manifest");

        assert_eq!(
            derive_target_identity_from_jadx_root(root.path()),
            JadxTargetIdentity::default()
        );
    }
}
