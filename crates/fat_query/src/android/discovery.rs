use crate::android::families::binder_native::derive_binder_native_boundary_leads;
use crate::android::families::capability_chain::derive_capability_chain_confused_deputy_leads;
use crate::android::families::commissioning_fabric::derive_commissioning_fabric_authority_leads;
use crate::android::families::device_authority::derive_device_authority_leads;
use crate::android::families::router::derive_remote_router_gadget_leads;
use crate::android::families::webview::derive_webview_bridge_uri_leads;
use crate::android::graph::{build_android_capability_graph, AndroidCapabilityGraphSummary};
use crate::android::locality::{build_locality_records, summarize_locality_records};
use crate::android::manifest::{parse_manifest, parse_manifest_via_apkanalyzer};
use crate::android::native::collect_native_libs;
use crate::android::resources::collect_resource_facts;
use crate::android::semantic::{AndroidSemanticBundle, AndroidSupportLevel};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ParseStatus;
use crate::result::ScoreTrace;
use fat_core::zip_preflight::{preflight_zip_file, ZipPreflightLimits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const MAX_APK_ENTRIES: usize = 65_536;
const MAX_ANDROID_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SELECTED_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_APK_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_APK_CENTRAL_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_APK_ENTRY_NAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidEntrySurface {
    DeepLink,
    Notification,
    IntentExtra,
    ProviderUri,
    PendingIntent,
    BinderMethod,
    WebViewUrl,
    JniEntry,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidLocalityClass {
    AppLocal,
    SplitFeatureLocal,
    BundledSdk,
    BundledNativeLib,
    VendoredLocal,
    LikelyUpstream,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidEvidenceBasis {
    ObservedManifest,
    ObservedSourceFact,
    ObservedResourceFact,
    ObservedNativeFact,
    InferredControlFlow,
    InferredCapabilityChain,
    InferredFromRepairedContext,
    InferredFromLocality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AndroidLeadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_surface: Option<AndroidEntrySurface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_transition: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_identity_or_permission: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<AndroidLocalityClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_basis: Vec<AndroidEvidenceBasis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_proof_signal: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidArtifactKind {
    Manifest,
    Dex,
    NativeLib,
    ResourceXml,
    Asset,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidContainerKind {
    BaseApk,
    SplitApk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidComponentKind {
    Activity,
    Service,
    Receiver,
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AndroidIntentFilterFact {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_schemes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_path_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidComponentFact {
    pub name: String,
    pub kind: AndroidComponentKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intent_filters: Vec<AndroidIntentFilterFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorities: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_uri_permissions: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidManifestFact {
    pub parse_status: ParseStatus,
    pub binary_xml: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default)]
    pub requested_permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debuggable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses_cleartext_traffic: Option<bool>,
    #[serde(default)]
    pub components: Vec<AndroidComponentFact>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidNativeLibFact {
    pub path: String,
    pub abi: String,
    pub library_name: String,
    pub provenance_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidResourceFact {
    #[serde(default)]
    pub xml_files: Vec<String>,
    #[serde(default)]
    pub html_assets: Vec<String>,
    #[serde(default)]
    pub route_like_assets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidArtifactFact {
    pub path: String,
    pub kind: AndroidArtifactKind,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidApkContainerInventory {
    pub kind: AndroidContainerKind,
    pub apk_path: String,
    pub entry_count: usize,
    #[serde(default)]
    pub dex_files: Vec<String>,
    pub manifest: AndroidManifestFact,
    #[serde(default)]
    pub native_libs: Vec<AndroidNativeLibFact>,
    pub resources: AndroidResourceFact,
    #[serde(default)]
    pub artifacts: Vec<AndroidArtifactFact>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidInventorySummary {
    pub container_count: usize,
    pub dex_file_count: usize,
    pub native_lib_count: usize,
    pub resource_xml_count: usize,
    pub html_asset_count: usize,
    pub route_like_asset_count: usize,
    pub component_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidInventoryReport {
    pub base_apk: String,
    #[serde(default)]
    pub split_apks: Vec<String>,
    #[serde(default)]
    pub containers: Vec<AndroidApkContainerInventory>,
    pub summary: AndroidInventorySummary,
    pub graph_summary: AndroidCapabilityGraphSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidLocalityRecord {
    pub apk_path: String,
    pub artifact_path: String,
    pub kind: AndroidArtifactKind,
    pub locality: AndroidLocalityClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidLocalitySummary {
    pub app_local: usize,
    pub split_feature_local: usize,
    pub bundled_sdk: usize,
    pub bundled_native_lib: usize,
    pub vendored_local: usize,
    pub likely_upstream: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidLocalityReport {
    pub base_apk: String,
    #[serde(default)]
    pub split_apks: Vec<String>,
    #[serde(default)]
    pub records: Vec<AndroidLocalityRecord>,
    pub summary: AndroidLocalitySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticBundleSummary {
    pub bundle_version: String,
    pub target_package_name: String,
    pub fact_count: usize,
    pub observed_fact_count: usize,
    pub inferred_fact_count: usize,
    pub revelation_count: usize,
    pub observed_revelation_count: usize,
    pub inferred_revelation_count: usize,
    pub symbol_identity_count: usize,
    pub control_surface_count: usize,
    pub transport_surface_count: usize,
    pub trust_boundary_count: usize,
    pub resource_count: usize,
    pub native_semantic_count: usize,
    pub correlation_count: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticExplainReport {
    pub bundle_version: String,
    pub target_package_name: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub revelations: Vec<AndroidSemanticExplainRevelation>,
    #[serde(default)]
    pub javascript_interface_methods: Vec<AndroidSemanticExplainSurface>,
    #[serde(default)]
    pub runtime_dart_packages: Vec<AndroidSemanticExplainSurface>,
    #[serde(default)]
    pub runtime_plugins: Vec<AndroidSemanticExplainSurface>,
    #[serde(default)]
    pub runtime_http_endpoints: Vec<AndroidSemanticExplainSurface>,
    #[serde(default)]
    pub runtime_chains: Vec<AndroidSemanticExplainSurface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticExplainRevelation {
    pub name: String,
    pub support_level: AndroidSupportLevel,
    pub rationale: String,
    #[serde(default)]
    pub subsystem_ids: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidSemanticExplainSurface {
    pub trigger: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AndroidDiscoverLead {
    pub lead_id: String,
    pub symbol: String,
    #[serde(default)]
    pub symbol_resolved: bool,
    pub family: String,
    pub family_confidence: f32,
    #[serde(default)]
    pub matched_roles: Vec<RoleMatch>,
    #[serde(default)]
    pub why_matched: Vec<String>,
    #[serde(default)]
    pub evidence_basis: Vec<AndroidEvidenceBasis>,
    pub locality: AndroidLocalityClass,
    #[serde(default)]
    pub suggested_trigger_recipe: Vec<TriggerRecipeStep>,
    #[serde(default)]
    pub expected_proof_signal: Vec<ProofSignal>,
    #[serde(default)]
    pub sibling_candidates: Vec<AndroidSiblingCandidate>,
    #[serde(default)]
    pub provenance_summary: Vec<String>,
    pub score_trace: ScoreTrace,
    #[serde(default)]
    pub metadata: AndroidLeadMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AndroidSiblingCandidate {
    pub symbol: String,
    pub family: String,
    pub family_confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AndroidDiscoverReport {
    pub status: String,
    pub base_apk: String,
    #[serde(default)]
    pub split_apks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_filter: Option<String>,
    pub top_k: usize,
    pub mode: String,
    pub inventory_summary: AndroidInventorySummary,
    pub graph_summary: AndroidCapabilityGraphSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<AndroidSemanticBundleSummary>,
    #[serde(default)]
    pub leads: Vec<AndroidDiscoverLead>,
    pub lead_count: usize,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub message: String,
}

pub fn inventory_apks(
    base_apk: &Path,
    split_apks: &[PathBuf],
) -> Result<AndroidInventoryReport, String> {
    let mut containers = Vec::new();
    let mut selected_manifest_bytes = 0_u64;
    let mut retained_entry_name_bytes = 0usize;
    containers.push(inspect_apk(
        base_apk,
        AndroidContainerKind::BaseApk,
        &mut selected_manifest_bytes,
        &mut retained_entry_name_bytes,
    )?);
    for split in split_apks {
        containers.push(inspect_apk(
            split,
            AndroidContainerKind::SplitApk,
            &mut selected_manifest_bytes,
            &mut retained_entry_name_bytes,
        )?);
    }

    let summary = AndroidInventorySummary {
        container_count: containers.len(),
        dex_file_count: containers.iter().map(|c| c.dex_files.len()).sum(),
        native_lib_count: containers.iter().map(|c| c.native_libs.len()).sum(),
        resource_xml_count: containers.iter().map(|c| c.resources.xml_files.len()).sum(),
        html_asset_count: containers
            .iter()
            .map(|c| c.resources.html_assets.len())
            .sum(),
        route_like_asset_count: containers
            .iter()
            .map(|c| c.resources.route_like_assets.len())
            .sum(),
        component_count: containers.iter().map(|c| c.manifest.components.len()).sum(),
    };
    let graph = build_android_capability_graph(&containers);

    Ok(AndroidInventoryReport {
        base_apk: base_apk.display().to_string(),
        split_apks: split_apks
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        containers,
        summary,
        graph_summary: graph.summary,
    })
}

pub fn build_locality_report(
    base_apk: &Path,
    split_apks: &[PathBuf],
) -> Result<AndroidLocalityReport, String> {
    let inventory = inventory_apks(base_apk, split_apks)?;
    let records = build_locality_records(&inventory.containers);
    let summary = summarize_locality_records(&records);
    Ok(AndroidLocalityReport {
        base_apk: inventory.base_apk,
        split_apks: inventory.split_apks,
        records,
        summary,
    })
}

pub fn build_semantic_explain_report(path: &Path) -> Result<AndroidSemanticExplainReport, String> {
    let bundle = load_semantic_bundle(path)?;
    let mut seen_javascript_methods = BTreeSet::new();
    let runtime_roles = collect_runtime_role_notes(&bundle);
    let runtime_prefixes = collect_runtime_package_prefixes(&bundle, &runtime_roles);
    Ok(AndroidSemanticExplainReport {
        bundle_version: bundle.bundle_version.clone(),
        target_package_name: bundle.target.package_name.clone(),
        warnings: bundle.warnings.clone(),
        revelations: bundle
            .revelations
            .iter()
            .map(|revelation| AndroidSemanticExplainRevelation {
                name: revelation.kind.clone(),
                support_level: revelation.support_level,
                rationale: revelation.rationale.clone().unwrap_or_default(),
                subsystem_ids: revelation.subsystem_ids.clone(),
                evidence: revelation.members.iter().take(3).cloned().collect(),
                members: revelation.members.clone(),
                member_summary: (revelation.members.len() > 3)
                    .then(|| format!("+{} more", revelation.members.len() - 3)),
            })
            .collect(),
        javascript_interface_methods: bundle
            .control_surfaces
            .iter()
            .filter(|surface| surface.kind == "javascript-interface-method")
            .filter(|surface| {
                let key = format!(
                    "{}::{}",
                    surface
                        .trigger
                        .clone()
                        .unwrap_or_else(|| surface.surface_id.clone()),
                    surface.notes.join("|")
                );
                seen_javascript_methods.insert(key)
            })
            .map(|surface| AndroidSemanticExplainSurface {
                trigger: surface
                    .trigger
                    .clone()
                    .unwrap_or_else(|| surface.surface_id.clone()),
                notes: surface.notes.clone(),
            })
            .collect(),
        runtime_dart_packages: explain_runtime_fact_group(
            &bundle,
            "source.dart-package",
            &runtime_roles,
            |subject| {
                runtime_roles.contains_key(subject)
                    || runtime_prefixes
                        .iter()
                        .any(|prefix| subject.starts_with(prefix))
            },
        ),
        runtime_plugins: explain_runtime_fact_group(
            &bundle,
            "runtime.plugin",
            &runtime_roles,
            |_| true,
        ),
        runtime_http_endpoints: explain_runtime_fact_group(
            &bundle,
            "http.api-endpoint",
            &runtime_roles,
            |subject| runtime_roles.contains_key(subject),
        ),
        runtime_chains: bundle
            .correlations
            .iter()
            .filter(|correlation| correlation.kind == "runtime-role-cluster")
            .map(|correlation| AndroidSemanticExplainSurface {
                trigger: runtime_chain_name(correlation),
                notes: summarize_runtime_chain_members(&bundle, correlation),
            })
            .collect(),
    })
}

fn collect_runtime_role_notes(bundle: &AndroidSemanticBundle) -> BTreeMap<String, Vec<String>> {
    let mut notes = BTreeMap::<String, Vec<String>>::new();
    for fact in &bundle.facts {
        let Some(role) = fact.attributes.get("role") else {
            continue;
        };
        if !fact.kind.starts_with("role.runtime-") {
            continue;
        }
        notes
            .entry(fact.subject.clone())
            .or_default()
            .push(format!("role={role}"));
    }
    for values in notes.values_mut() {
        values.sort();
        values.dedup();
    }
    notes
}

fn explain_runtime_fact_group(
    bundle: &AndroidSemanticBundle,
    kind: &str,
    runtime_roles: &BTreeMap<String, Vec<String>>,
    include: impl Fn(&str) -> bool,
) -> Vec<AndroidSemanticExplainSurface> {
    bundle
        .facts
        .iter()
        .filter(|fact| fact.kind == kind)
        .filter(|fact| include(&fact.subject))
        .map(|fact| AndroidSemanticExplainSurface {
            trigger: fact.subject.clone(),
            notes: runtime_roles
                .get(&fact.subject)
                .cloned()
                .unwrap_or_default(),
        })
        .collect()
}

fn collect_runtime_package_prefixes(
    bundle: &AndroidSemanticBundle,
    runtime_roles: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut prefixes = bundle
        .facts
        .iter()
        .filter(|fact| {
            fact.kind == "source.dart-package" && runtime_roles.contains_key(&fact.subject)
        })
        .filter_map(|fact| {
            fact.subject
                .strip_prefix("package:")
                .and_then(|rest| rest.split('/').next())
                .filter(|segment| !segment.is_empty())
                .map(|segment| format!("package:{segment}/"))
        })
        .collect::<Vec<_>>();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn runtime_chain_name(correlation: &crate::android::semantic::AndroidCorrelation) -> String {
    correlation
        .rationale
        .as_deref()
        .and_then(|text| text.split(':').nth(1))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(correlation.kind.as_str())
        .to_string()
}

fn member_subject(bundle: &AndroidSemanticBundle, member: &str) -> Option<String> {
    bundle
        .facts
        .iter()
        .find(|fact| fact.fact_id == member)
        .map(|fact| fact.subject.clone())
        .or_else(|| {
            bundle
                .control_surfaces
                .iter()
                .find(|surface| surface.surface_id == member)
                .and_then(|surface| {
                    surface
                        .trigger
                        .clone()
                        .or_else(|| Some(surface.kind.clone()))
                })
        })
}

fn summarize_runtime_chain_members(
    bundle: &AndroidSemanticBundle,
    correlation: &crate::android::semantic::AndroidCorrelation,
) -> Vec<String> {
    let role = runtime_chain_name(correlation);
    let mut members = correlation
        .members
        .iter()
        .filter_map(|member| member_subject(bundle, member))
        .collect::<Vec<_>>();
    members.sort();
    members.dedup();

    match role.as_str() {
        "embedded-web-content" => summarize_embedded_web_members(&members),
        _ => members,
    }
}

fn summarize_embedded_web_members(members: &[String]) -> Vec<String> {
    let mut selected = Vec::new();

    maybe_push_matching_member(members, &mut selected, |value| {
        value == "webview_flutter_android"
    });
    maybe_push_matching_member(members, &mut selected, |value| {
        value == "plugins.flutter.io/webview"
    });
    maybe_push_matching_member(members, &mut selected, |value| {
        value.contains("WebViewHostApi.loadUrl")
    });

    let generated_count = members
        .iter()
        .filter(|member| member.contains("dev.flutter.pigeon.webview_flutter_android."))
        .count();
    if generated_count > 1 {
        selected.push(format!(
            "+{} more generated webview channels",
            generated_count.saturating_sub(1)
        ));
    }

    if selected.is_empty() {
        members.iter().take(4).cloned().collect()
    } else {
        selected
    }
}

fn maybe_push_matching_member(
    members: &[String],
    selected: &mut Vec<String>,
    predicate: impl Fn(&str) -> bool,
) {
    if let Some(member) = members.iter().find(|member| predicate(member)) {
        if !selected.iter().any(|existing| existing == member) {
            selected.push(member.clone());
        }
    }
}
pub fn build_discover_report(
    base_apk: &Path,
    split_apks: &[PathBuf],
    semantic_bundle_path: Option<&Path>,
    family: Option<&str>,
    top_k: usize,
    mode: &str,
) -> Result<AndroidDiscoverReport, String> {
    let inventory = inventory_apks(base_apk, split_apks)?;
    let manifest_package_name = inventory
        .containers
        .iter()
        .find(|container| matches!(container.kind, AndroidContainerKind::BaseApk))
        .and_then(|container| container.manifest.package_name.clone());

    let semantic_bundle = match semantic_bundle_path {
        Some(path) => Some(load_semantic_bundle(path)?),
        None => None,
    };

    let mut warnings = Vec::new();
    let semantic = semantic_bundle.as_ref().map(|bundle| {
        if let Some(manifest_package_name) = manifest_package_name.as_deref() {
            if bundle.target.package_name != manifest_package_name {
                warnings.push(format!(
                    "semantic bundle target package {} does not match manifest package {}",
                    bundle.target.package_name, manifest_package_name
                ));
            }
        }
        summarize_semantic_bundle(bundle)
    });

    if semantic.is_none() {
        warnings.push(
            "no semantic bundle provided; discovery is limited to APK inventory and graph facts"
                .into(),
        );
    }

    let mut leads = Vec::new();
    let mut status = "consumer-ready".to_string();
    let mut message = "Android family discovery requires a semantic bundle; APK inventory and graph facts remain available."
        .to_string();

    if let Some(bundle) = semantic_bundle.as_ref() {
        status = "partial-family-ready".into();
        message = "Android family interpretation is available for the supported families.".into();
        match family {
            Some("commissioning-fabric-authority") => {
                leads.extend(derive_commissioning_fabric_authority_leads(bundle, top_k));
            }
            Some("remote-router-gadget") => {
                leads.extend(derive_remote_router_gadget_leads(bundle, &inventory, top_k));
            }
            Some("webview-bridge-uri") => {
                leads.extend(derive_webview_bridge_uri_leads(bundle));
            }
            Some("capability-chain-confused-deputy") => {
                leads.extend(derive_capability_chain_confused_deputy_leads(bundle));
            }
            Some("binder-native-boundary") => {
                leads.extend(derive_binder_native_boundary_leads(bundle));
            }
            Some("device-command-authority" | "device-binding-authority") => {
                leads.extend(derive_device_authority_leads(bundle, top_k));
                if let Some(family_name) = family {
                    leads.retain(|lead| lead.family == family_name);
                }
            }
            None => {
                leads.extend(derive_commissioning_fabric_authority_leads(bundle, top_k));
                leads.extend(derive_device_authority_leads(bundle, top_k));
                leads.extend(derive_remote_router_gadget_leads(bundle, &inventory, top_k));
                leads.extend(derive_webview_bridge_uri_leads(bundle));
                leads.extend(derive_capability_chain_confused_deputy_leads(bundle));
                leads.extend(derive_binder_native_boundary_leads(bundle));
            }
            Some(other) => {
                warnings.push(format!(
                    "family {other} is not implemented yet; available families are commissioning-fabric-authority, device-command-authority, device-binding-authority, remote-router-gadget, webview-bridge-uri, capability-chain-confused-deputy, and binder-native-boundary"
                ));
                message =
                    "Android family interpretation is available for the current Android families; requested family remains unimplemented."
                        .into();
            }
        }
        if family.is_none() {
            suppress_runtime_scaffolding_noise(&mut leads, bundle);
        }
        rank_and_attach_android_siblings(&mut leads, top_k);
        if leads.is_empty() {
            message = zero_lead_message(semantic.as_ref());
        } else if leads.len() < top_k {
            warnings.push(format!(
                "requested top_k={} but only {} leads surfaced after ranking and family de-duplication",
                top_k,
                leads.len()
            ));
        } else if family.is_none() {
            message =
                "Android family interpretation is available for the current Android families."
                    .into();
        }
    }

    Ok(AndroidDiscoverReport {
        status,
        base_apk: inventory.base_apk,
        split_apks: inventory.split_apks,
        manifest_package_name,
        family_filter: family.map(str::to_string),
        top_k,
        mode: mode.to_string(),
        inventory_summary: inventory.summary,
        graph_summary: inventory.graph_summary,
        semantic,
        lead_count: leads.len(),
        leads,
        warnings,
        message,
    })
}

fn zero_lead_message(semantic: Option<&AndroidSemanticBundleSummary>) -> String {
    let Some(semantic) = semantic else {
        return "No leads: semantic bundle missing, so discovery only saw APK inventory and graph facts.".into();
    };
    format!(
        "No leads: control_surface_count={}, trust_boundary_count={}. Likely cause: heuristic extraction did not find router/webview/capability/binder patterns. Try: check that JADX output contains decompiled Java sources, not just resource XML.",
        semantic.control_surface_count, semantic.trust_boundary_count
    )
}

fn inspect_apk(
    path: &Path,
    kind: AndroidContainerKind,
    selected_manifest_bytes: &mut u64,
    retained_entry_name_bytes: &mut usize,
) -> Result<AndroidApkContainerInventory, String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
    preflight_zip_file(
        &mut file,
        ZipPreflightLimits {
            max_file_bytes: MAX_APK_FILE_BYTES,
            max_entries: MAX_APK_ENTRIES as u64,
            max_central_directory_bytes: MAX_APK_CENTRAL_DIRECTORY_BYTES,
        },
    )
    .map_err(|error| format!("APK {} {error}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("failed to open apk zip {}: {}", path.display(), e))?;
    if archive.len() > MAX_APK_ENTRIES {
        return Err(format!(
            "APK {} has too many entries: {} exceeds {}",
            path.display(),
            archive.len(),
            MAX_APK_ENTRIES
        ));
    }

    let mut dex_files = Vec::new();
    let mut artifacts = Vec::new();
    let mut manifest_bytes = None;
    let mut manifest_notes = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|e| {
            format!(
                "failed to read zip entry {} in {}: {}",
                index,
                path.display(),
                e
            )
        })?;
        let name = entry.name().to_string();
        *retained_entry_name_bytes = retained_entry_name_bytes
            .checked_add(name.len())
            .ok_or_else(|| "APK retained entry-name byte count overflowed".to_string())?;
        if *retained_entry_name_bytes > MAX_APK_ENTRY_NAME_BYTES {
            return Err(format!(
                "APK retained entry names exceed byte limit of {MAX_APK_ENTRY_NAME_BYTES}"
            ));
        }
        let size_bytes = entry.size();
        let kind = classify_artifact_kind(&name);
        if matches!(kind, AndroidArtifactKind::Dex) {
            dex_files.push(name.clone());
        }
        if name == "AndroidManifest.xml" {
            let cumulative_remaining =
                MAX_SELECTED_MANIFEST_BYTES.saturating_sub(*selected_manifest_bytes);
            let allowed = MAX_ANDROID_MANIFEST_BYTES.min(cumulative_remaining);
            let mut buf = Vec::new();
            entry
                .take(allowed.saturating_add(1))
                .read_to_end(&mut buf)
                .map_err(|e| {
                    format!(
                        "failed to read AndroidManifest.xml from {}: {}",
                        path.display(),
                        e
                    )
                })?;
            if buf.len() as u64 > MAX_ANDROID_MANIFEST_BYTES {
                return Err(format!(
                    "AndroidManifest.xml in {} exceeds byte limit of {}",
                    path.display(),
                    MAX_ANDROID_MANIFEST_BYTES
                ));
            }
            if buf.len() as u64 > cumulative_remaining {
                return Err(format!(
                    "APK manifests exceed cumulative byte limit of {MAX_SELECTED_MANIFEST_BYTES}"
                ));
            }
            *selected_manifest_bytes = selected_manifest_bytes
                .checked_add(buf.len() as u64)
                .ok_or_else(|| "APK manifest byte count overflowed".to_string())?;
            manifest_bytes = Some(buf);
        }
        artifacts.push(AndroidArtifactFact {
            path: name,
            kind,
            size_bytes,
        });
    }

    if manifest_bytes.is_none() {
        manifest_notes.push("AndroidManifest.xml entry missing".into());
    }

    let manifest = match manifest_bytes {
        Some(bytes) => {
            let parsed = parse_manifest(&bytes);
            if parsed.binary_xml && parsed.package_name.is_none() && parsed.components.is_empty() {
                parse_manifest_via_apkanalyzer(path).unwrap_or(parsed)
            } else {
                parsed
            }
        }
        None => AndroidManifestFact {
            parse_status: ParseStatus::Failed,
            binary_xml: false,
            package_name: None,
            requested_permissions: Vec::new(),
            debuggable: None,
            uses_cleartext_traffic: None,
            components: Vec::new(),
            notes: manifest_notes,
        },
    };

    let resources = collect_resource_facts(&artifacts);
    let native_libs = collect_native_libs(&artifacts);

    Ok(AndroidApkContainerInventory {
        kind,
        apk_path: path.display().to_string(),
        entry_count: artifacts.len(),
        dex_files,
        manifest,
        native_libs,
        resources,
        artifacts,
        notes: Vec::new(),
    })
}

pub fn load_semantic_bundle(path: &Path) -> Result<AndroidSemanticBundle, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("failed to read semantic bundle {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse semantic bundle {}: {}", path.display(), e))
}

pub fn summarize_semantic_bundle(bundle: &AndroidSemanticBundle) -> AndroidSemanticBundleSummary {
    let observed_fact_count = bundle
        .facts
        .iter()
        .filter(|fact| matches!(fact.support_level, AndroidSupportLevel::Observed))
        .count();
    let inferred_fact_count = bundle
        .facts
        .iter()
        .filter(|fact| matches!(fact.support_level, AndroidSupportLevel::Inferred))
        .count();
    let observed_revelation_count = bundle
        .revelations
        .iter()
        .filter(|revelation| matches!(revelation.support_level, AndroidSupportLevel::Observed))
        .count();
    let inferred_revelation_count = bundle
        .revelations
        .iter()
        .filter(|revelation| matches!(revelation.support_level, AndroidSupportLevel::Inferred))
        .count();

    AndroidSemanticBundleSummary {
        bundle_version: bundle.bundle_version.clone(),
        target_package_name: bundle.target.package_name.clone(),
        fact_count: bundle.facts.len(),
        observed_fact_count,
        inferred_fact_count,
        revelation_count: bundle.revelations.len(),
        observed_revelation_count,
        inferred_revelation_count,
        symbol_identity_count: bundle.symbol_identities.len(),
        control_surface_count: bundle.control_surfaces.len(),
        transport_surface_count: bundle.transport_surfaces.len(),
        trust_boundary_count: bundle.trust_boundaries.len(),
        resource_count: bundle.resources.len(),
        native_semantic_count: bundle.native_semantics.len(),
        correlation_count: bundle.correlations.len(),
        warning_count: bundle.warnings.len(),
    }
}

fn rank_and_attach_android_siblings(leads: &mut Vec<AndroidDiscoverLead>, top_k: usize) {
    leads.sort_by(|left, right| {
        right
            .family_confidence
            .partial_cmp(&left.family_confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| lead_symbol_priority(right).cmp(&lead_symbol_priority(left)))
            .then_with(|| left.symbol.cmp(&right.symbol))
    });

    let all_leads = leads.clone();
    for lead in leads.iter_mut() {
        lead.sibling_candidates = all_leads
            .iter()
            .filter(|candidate| candidate.family == lead.family && candidate.symbol != lead.symbol)
            .take(3)
            .map(|candidate| AndroidSiblingCandidate {
                symbol: candidate.symbol.clone(),
                family: candidate.family.clone(),
                family_confidence: candidate.family_confidence,
            })
            .collect();
    }
    if top_k == 0 {
        leads.clear();
        return;
    }
    let mut selected = Vec::new();
    let mut seen_families = std::collections::BTreeSet::new();
    for lead in leads.iter() {
        if seen_families.insert(lead.family.clone()) {
            selected.push(lead.clone());
            if selected.len() == top_k {
                break;
            }
        }
    }
    *leads = selected;
}

fn suppress_runtime_scaffolding_noise(
    leads: &mut Vec<AndroidDiscoverLead>,
    bundle: &AndroidSemanticBundle,
) {
    let has_runtime_control_plane = bundle
        .revelations
        .iter()
        .any(|revelation| revelation.kind == "runtime-to-device-control-plane");
    let has_strong_runtime_authority = leads
        .iter()
        .any(|lead| lead.family == "device-command-authority" && lead.family_confidence >= 0.9);
    if !(has_runtime_control_plane && has_strong_runtime_authority) {
        return;
    }

    let package_path = bundle.target.package_name.replace('.', "/");
    leads.retain(|lead| match lead.family.as_str() {
        "webview-bridge-uri" => lead.symbol_resolved,
        "binder-native-boundary" => is_first_party_runtime_lead(lead, &package_path),
        _ => true,
    });
}

fn is_first_party_runtime_lead(lead: &AndroidDiscoverLead, package_path: &str) -> bool {
    lead.symbol.contains(package_path)
        || lead
            .provenance_summary
            .iter()
            .any(|summary| summary.contains(package_path))
}

fn lead_symbol_priority(lead: &AndroidDiscoverLead) -> usize {
    match lead.family.as_str() {
        "commissioning-fabric-authority" => commissioning_symbol_priority(&lead.symbol),
        _ => 0,
    }
}

fn commissioning_symbol_priority(symbol: &str) -> usize {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("completionhandler") || lower.contains("simpledevicemanagercallback") {
        0
    } else if lower.ends_with(".weavedevicemanager")
        || lower.ends_with(".devicemanagerimpl")
        || lower.ends_with(".mattersetupproxyactivity")
    {
        7
    } else if lower.contains("beginrendezvousdevicepairingcode")
        || lower.contains("beginrendezvousdeviceaccesstoken")
        || lower.contains("beginconnectblepairingcode")
        || lower.contains("beginconnectbleaccesstoken")
    {
        6
    } else if lower.contains("begincreatefabric")
        || lower.contains("beginjoinexistingfabric")
        || lower.contains("beginleavefabric")
    {
        5
    } else if lower.contains("commission")
        || lower.contains("setupproxy")
        || lower.contains("opencommissioningwindow")
    {
        4
    } else if lower.ends_with(".weavesecuritysupport")
        || lower.ends_with(".weavekeyexportclient")
        || lower.ends_with(".weavecertificatesupport")
    {
        3
    } else if lower.contains("identifydevice")
        || lower.contains("pairingcode")
        || lower.contains("deviceenumeration")
    {
        2
    } else if lower.contains("fabric") {
        1
    } else {
        0
    }
}

pub fn android_discovery_fingerprint(symbol: &str, family: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(symbol.as_bytes());
    hasher.update(b":");
    hasher.update(family.as_bytes());
    let digest = hasher.finalize();
    format!("android-{}", hex_prefix(&digest))
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn classify_artifact_kind(path: &str) -> AndroidArtifactKind {
    if path == "AndroidManifest.xml" {
        AndroidArtifactKind::Manifest
    } else if path.starts_with("classes") && path.ends_with(".dex") {
        AndroidArtifactKind::Dex
    } else if path.starts_with("lib/") && path.ends_with(".so") {
        AndroidArtifactKind::NativeLib
    } else if path.starts_with("res/") && path.ends_with(".xml") {
        AndroidArtifactKind::ResourceXml
    } else if path.starts_with("assets/") {
        AndroidArtifactKind::Asset
    } else {
        AndroidArtifactKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_name_heavy_apk(path: &Path, prefix: char) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for index in 0..70 {
            let name = format!("{prefix}{index:02}{}", "x".repeat(60_000));
            zip.start_file(name, options).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn inventory_rejects_oversized_android_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("oversized-manifest.apk");
        let file = File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(&vec![b'A'; 4 * 1024 * 1024 + 1]).unwrap();
        zip.finish().unwrap();

        let error = inventory_apks(&apk, &[]).expect_err("oversized manifest must fail");
        assert!(error.contains("AndroidManifest.xml"), "{error}");
        assert!(error.contains("byte limit"), "{error}");
    }

    #[test]
    fn inventory_caps_retained_entry_names_across_base_and_splits() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base.apk");
        let split = temp.path().join("split.apk");
        write_name_heavy_apk(&base, 'a');
        write_name_heavy_apk(&split, 'b');

        let error = inventory_apks(&base, &[split])
            .expect_err("the retained-name budget must cover the complete APK set");
        assert!(error.contains("retained entry names"), "{error}");
        assert!(error.contains("byte limit"), "{error}");
    }
}
