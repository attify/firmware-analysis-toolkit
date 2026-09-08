use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidIntentFilterFact,
    AndroidInventoryReport, AndroidLeadMetadata, AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidCorrelation, AndroidRevelation, AndroidSemanticBundle, AndroidSymbolIdentity,
    AndroidTrustBoundary,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;
use std::collections::BTreeSet;

pub fn derive_remote_router_gadget_leads(
    bundle: &AndroidSemanticBundle,
    inventory: &AndroidInventoryReport,
    top_k: usize,
) -> Vec<AndroidDiscoverLead> {
    let mut leads = Vec::new();
    leads.extend(explicit_router_leads(bundle, inventory));
    leads.extend(path_composition_leads(bundle, inventory));
    leads.extend(manifest_api_router_leads(bundle, inventory));

    leads.sort_by(|left, right| {
        right
            .family_confidence
            .partial_cmp(&left.family_confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });

    let mut seen = BTreeSet::new();
    leads.retain(|lead| seen.insert(lead.symbol.clone()));
    leads.truncate(top_k);
    leads
}

fn manifest_api_router_leads(
    bundle: &AndroidSemanticBundle,
    inventory: &AndroidInventoryReport,
) -> Vec<AndroidDiscoverLead> {
    let has_manifest_deeplink = bundle.control_surfaces.iter().any(|surface| {
        surface.kind == "manifest-exported-component"
            && surface
                .trigger
                .as_deref()
                .is_some_and(|trigger| trigger.contains("VIEW"))
    });
    let has_intent_boundary = bundle.trust_boundaries.iter().any(|boundary| {
        matches!(
            boundary.kind.as_str(),
            "deep-link-to-internal-router" | "service-entry-boundary" | "broadcast-entry-boundary"
        )
    });
    let has_intent_transport = bundle
        .transport_surfaces
        .iter()
        .any(|surface| surface.kind == "manifest-intent-filter");
    let has_start_activity = bundle
        .facts
        .iter()
        .any(|fact| fact.kind == "android-api.start-activity");
    let has_backend = bundle
        .facts
        .iter()
        .any(|fact| fact.kind == "environment.backend-url");

    let score = usize::from(has_manifest_deeplink)
        + usize::from(has_intent_boundary)
        + usize::from(has_intent_transport)
        + usize::from(has_start_activity)
        + usize::from(has_backend);
    if score < 2 {
        return Vec::new();
    }

    bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "manifest-exported-component")
        .filter(|surface| {
            surface
                .trigger
                .as_deref()
                .is_some_and(|trigger| trigger.contains("VIEW"))
        })
        .map(|surface| {
            let confidence = 0.45 + ((score.min(5) as f32 - 2.0) * 0.1);
            let mut penalties = Vec::new();
            if !has_start_activity {
                penalties.push("no-framework-startactivity".into());
            }
            if !has_backend {
                penalties.push("no-backend-signal".into());
            }
            let trigger_detail = best_manifest_deeplink_command(inventory)
                .unwrap_or_else(|| "adb shell am start -a android.intent.action.VIEW -d 'https://example.app/devices/FUZZ'".into());
            AndroidDiscoverLead {
                lead_id: format!("android-router:manifest:{}", surface.surface_id),
                symbol: surface
                    .exported_component
                    .clone()
                    .unwrap_or_else(|| surface.surface_id.clone()),
                symbol_resolved: true,
                family: "remote-router-gadget".into(),
                family_confidence: confidence,
                matched_roles: vec![
                    RoleMatch {
                        role: "manifest-exported-component".into(),
                        detail: surface.surface_id.clone(),
                    },
                    RoleMatch {
                        role: "framework-api".into(),
                        detail: if has_start_activity {
                            "android-api.start-activity".into()
                        } else {
                            "manifest-only".into()
                        },
                    },
                ],
                why_matched: vec![
                    "exported manifest surface accepts VIEW intents".into(),
                    "additive router scoring promoted partial deeplink evidence".into(),
                ],
                evidence_basis: vec![
                    AndroidEvidenceBasis::ObservedManifest,
                    AndroidEvidenceBasis::ObservedSourceFact,
                ],
                locality: AndroidLocalityClass::AppLocal,
                sibling_candidates: Vec::new(),
                suggested_trigger_recipe: vec![TriggerRecipeStep {
                    kind: "adb-deeplink".into(),
                    detail: trigger_detail,
                }],
                expected_proof_signal: vec![ProofSignal {
                    kind: "manifest-deeplink-reached".into(),
                    detail:
                        "exported VIEW surface is reachable even without explicit router naming"
                            .into(),
                }],
                provenance_summary: manifest_component_provenance(surface.exported_component.as_deref()),
                score_trace: ScoreTrace {
                    adapters: vec!["android-semantic-bundle".into()],
                    family_pack_hits: vec!["manifest-api-router-additive".into()],
                    penalties,
                    locality_notes: vec!["apk-app-local".into()],
                },
                metadata: AndroidLeadMetadata {
                    entry_surface: Some(AndroidEntrySurface::DeepLink),
                    capability_transition: vec![
                        "external-intent".into(),
                        "exported-component".into(),
                    ],
                    required_identity_or_permission: Vec::new(),
                    locality: Some(AndroidLocalityClass::AppLocal),
                    evidence_basis: vec![
                        AndroidEvidenceBasis::ObservedManifest,
                        AndroidEvidenceBasis::ObservedSourceFact,
                    ],
                    expected_proof_signal: vec!["manifest-deeplink-reached".into()],
                },
            }
        })
        .collect()
}

fn explicit_router_leads(
    bundle: &AndroidSemanticBundle,
    inventory: &AndroidInventoryReport,
) -> Vec<AndroidDiscoverLead> {
    let mut leads = Vec::new();
    let router_fact = bundle
        .facts
        .iter()
        .find(|fact| fact.kind == "control-surface.router-dispatch");
    let deep_link_boundary = bundle
        .trust_boundaries
        .iter()
        .find(|boundary| boundary.kind == "deep-link-to-internal-router");
    let deep_link_transport = bundle
        .transport_surfaces
        .iter()
        .find(|surface| surface.kind == "intent-parse" || surface.source == "external-deeplink");

    if let Some(surface) = bundle
        .control_surfaces
        .iter()
        .find(|surface| surface.kind == "router-dispatch")
    {
        let symbol = surface
            .entry_symbol
            .as_deref()
            .and_then(|id| resolve_symbol(bundle.symbol_identities.as_slice(), id))
            .unwrap_or_else(|| surface.surface_id.clone());
        let route_source = router_fact
            .and_then(|fact| fact.attributes.get("route_source"))
            .cloned()
            .unwrap_or_else(|| "untrusted-route".into());
        let deep_link_guard = deep_link_boundary.and_then(|boundary| boundary.guard.as_deref());
        let supporting_revelations = supporting_revelations(
            bundle,
            &[
                surface.surface_id.as_str(),
                surface.entry_symbol.as_deref().unwrap_or(""),
                deep_link_boundary
                    .map(|boundary| boundary.boundary_id.as_str())
                    .unwrap_or(""),
                deep_link_transport
                    .map(|transport| transport.surface_id.as_str())
                    .unwrap_or(""),
            ],
        );
        let mut score_trace = ScoreTrace {
            adapters: vec!["android-semantic-bundle".into()],
            family_pack_hits: vec!["remote-router-explicit".into()],
            penalties: Vec::new(),
            locality_notes: vec!["apk-app-local".into()],
        };
        if !supporting_revelations.is_empty() {
            score_trace
                .family_pack_hits
                .push("revelation-support".into());
        }
        if deep_link_transport.is_none() {
            score_trace
                .penalties
                .push("no-explicit-intent-parse".into());
        }
        if deep_link_guard.is_none() {
            score_trace.penalties.push("no-caller-validation".into());
        }
        let mut why_matched = vec![
            "router dispatch accepts external route material".into(),
            format!("route source is {route_source}"),
        ];
        if let Some(guard) = deep_link_guard {
            why_matched.push(format!("caller validation present: {guard}"));
        }
        why_matched.extend(
            supporting_revelations
                .iter()
                .take(2)
                .map(|revelation| supporting_revelation_note(revelation)),
        );
        let trigger_detail = best_manifest_deeplink_command(inventory).unwrap_or_else(|| {
            deep_link_boundary.map(route_detail).unwrap_or_else(|| {
                surface
                    .trigger
                    .clone()
                    .unwrap_or_else(|| "route://deeplink".into())
            })
        });
        leads.push(AndroidDiscoverLead {
            lead_id: format!("android-router:{}", surface.surface_id),
            symbol,
            symbol_resolved: resolve_symbol_metadata(
                bundle.symbol_identities.as_slice(),
                surface.entry_symbol.as_deref(),
            )
            .is_some_and(|(_, resolved)| resolved),
            family: "remote-router-gadget".into(),
            family_confidence: if deep_link_transport.is_some() {
                0.92
            } else {
                0.81
            } + supporting_revelation_boost(&supporting_revelations),
            matched_roles: vec![
                RoleMatch {
                    role: "router-dispatch".into(),
                    detail: surface.surface_id.clone(),
                },
                RoleMatch {
                    role: "deep-link-boundary".into(),
                    detail: deep_link_boundary
                        .map(|boundary| boundary.boundary_id.clone())
                        .unwrap_or_else(|| "implicit".into()),
                },
            ],
            why_matched,
            evidence_basis: vec![
                AndroidEvidenceBasis::ObservedSourceFact,
                AndroidEvidenceBasis::InferredCapabilityChain,
            ],
            locality: AndroidLocalityClass::AppLocal,
            sibling_candidates: Vec::new(),
            suggested_trigger_recipe: vec![TriggerRecipeStep {
                kind: "adb-deeplink".into(),
                detail: trigger_detail,
            }],
            expected_proof_signal: vec![ProofSignal {
                kind: "internal-navigation".into(),
                detail: "route dispatch reaches an internal target before validation is confirmed"
                    .into(),
            }],
            provenance_summary: summarize_fact_provenance(
                router_fact
                    .map(|fact| fact.provenance.as_slice())
                    .unwrap_or(&[]),
            ),
            score_trace,
            metadata: AndroidLeadMetadata {
                entry_surface: Some(AndroidEntrySurface::DeepLink),
                capability_transition: vec!["external-route".into(), "internal-router".into()],
                required_identity_or_permission: Vec::new(),
                locality: Some(AndroidLocalityClass::AppLocal),
                evidence_basis: vec![
                    AndroidEvidenceBasis::ObservedSourceFact,
                    AndroidEvidenceBasis::InferredCapabilityChain,
                ],
                expected_proof_signal: vec!["internal-navigation".into()],
            },
        });
    }

    leads
}

fn path_composition_leads(
    bundle: &AndroidSemanticBundle,
    inventory: &AndroidInventoryReport,
) -> Vec<AndroidDiscoverLead> {
    let has_backend = bundle
        .facts
        .iter()
        .any(|fact| fact.kind == "environment.backend-url");
    let has_auth = bundle
        .facts
        .iter()
        .any(|fact| fact.kind == "identity.auth-header");
    let auth_to_api = find_correlation(bundle.correlations.as_slice(), "auth-to-api");
    let api_to_mqtt = find_correlation(bundle.correlations.as_slice(), "api-to-mqtt");
    let rest_to_device_topic =
        find_correlation(bundle.correlations.as_slice(), "rest-to-device-topic");
    let mqtt_transport = bundle
        .transport_surfaces
        .iter()
        .any(|surface| surface.kind == "topic-root" || surface.kind == "mqtt-marker");

    if !(has_backend && (has_auth || auth_to_api.is_some())) {
        return Vec::new();
    }

    bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "endpoint-template")
        .filter(|surface| {
            surface
                .trigger
                .as_deref()
                .map(|trigger| trigger.contains('{') || trigger.contains("/devices/"))
                .unwrap_or(false)
        })
        .map(|surface| {
            let mut why_matched = vec![
                "path composition endpoint template feeds authenticated backend surface".into(),
            ];
            if auth_to_api.is_some() {
                why_matched.push("auth signal correlates with backend API surface".into());
            }
            if api_to_mqtt.is_some() || (mqtt_transport && rest_to_device_topic.is_some()) {
                why_matched
                    .push("authenticated API surface is adjacent to device transport".into());
            }

            let mut score_trace = ScoreTrace {
                adapters: vec!["android-semantic-bundle".into()],
                family_pack_hits: vec!["path-composition-owned-by-remote-router".into()],
                penalties: Vec::new(),
                locality_notes: vec![format!(
                    "containers={}",
                    inventory.summary.container_count
                )],
            };
            if !mqtt_transport {
                score_trace.penalties.push("no-device-transport-neighbor".into());
            }
            let mut evidence_basis = vec![AndroidEvidenceBasis::ObservedSourceFact];
            if auth_to_api.is_some() || api_to_mqtt.is_some() || rest_to_device_topic.is_some() {
                evidence_basis.push(AndroidEvidenceBasis::InferredCapabilityChain);
            }

            AndroidDiscoverLead {
                lead_id: format!("android-router:path:{}", surface.surface_id),
                symbol: surface
                    .trigger
                    .clone()
                    .unwrap_or_else(|| surface.surface_id.clone()),
                symbol_resolved: true,
                family: "remote-router-gadget".into(),
                family_confidence: if mqtt_transport { 0.79 } else { 0.68 },
                matched_roles: vec![
                    RoleMatch {
                        role: "path-template".into(),
                        detail: surface.surface_id.clone(),
                    },
                    RoleMatch {
                        role: "authenticated-api".into(),
                        detail: auth_to_api
                            .map(|correlation| correlation.correlation_id.clone())
                            .unwrap_or_else(|| "observed-auth-header".into()),
                    },
                ],
                why_matched,
                evidence_basis: evidence_basis.clone(),
                locality: AndroidLocalityClass::AppLocal,
                sibling_candidates: Vec::new(),
                suggested_trigger_recipe: vec![TriggerRecipeStep {
                    kind: "authenticated-api-request".into(),
                    detail: surface
                        .trigger
                        .clone()
                        .unwrap_or_else(|| surface.surface_id.clone()),
                }],
                expected_proof_signal: vec![ProofSignal {
                    kind: "authenticated-request-path".into(),
                    detail:
                        "templated path reaches an authenticated backend or adjacent device transport"
                            .into(),
                }],
                provenance_summary: Vec::new(),
                score_trace,
                metadata: AndroidLeadMetadata {
                    entry_surface: Some(AndroidEntrySurface::Unknown),
                    capability_transition: vec![
                        "path-template".into(),
                        "authenticated-api".into(),
                        "device-transport".into(),
                    ],
                    required_identity_or_permission: if has_auth {
                        vec!["x-device-token".into()]
                    } else {
                        Vec::new()
                    },
                    locality: Some(AndroidLocalityClass::AppLocal),
                    evidence_basis,
                    expected_proof_signal: vec!["authenticated-request-path".into()],
                },
            }
        })
        .collect()
}

fn resolve_symbol(symbols: &[AndroidSymbolIdentity], symbol_id: &str) -> Option<String> {
    resolve_symbol_metadata(symbols, Some(symbol_id)).map(|(name, _)| name)
}

fn resolve_symbol_metadata(
    symbols: &[AndroidSymbolIdentity],
    symbol_id: Option<&str>,
) -> Option<(String, bool)> {
    symbols
        .iter()
        .find(|symbol| Some(symbol.symbol_id.as_str()) == symbol_id)
        .map(|symbol| (symbol.qualified_name.clone(), !symbol.synthetic))
}

fn supporting_revelations<'a>(
    bundle: &'a AndroidSemanticBundle,
    members: &[&str],
) -> Vec<&'a AndroidRevelation> {
    bundle
        .revelations
        .iter()
        .filter(|revelation| {
            members.iter().any(|member| {
                !member.is_empty()
                    && revelation
                        .members
                        .iter()
                        .any(|candidate| candidate == member)
            })
        })
        .collect()
}

fn supporting_revelation_note(revelation: &AndroidRevelation) -> String {
    match revelation.rationale.as_deref() {
        Some(rationale) if !rationale.is_empty() => {
            format!("supporting revelation: {} ({rationale})", revelation.kind)
        }
        _ => format!("supporting revelation: {}", revelation.kind),
    }
}

fn supporting_revelation_boost(revelations: &[&AndroidRevelation]) -> f32 {
    (revelations.len().min(2) as f32) * 0.03
}

fn route_detail(boundary: &AndroidTrustBoundary) -> String {
    format!("{} -> {}", boundary.from_zone, boundary.to_zone)
}

fn summarize_fact_provenance(
    provenance: &[crate::android::semantic::AndroidProvenance],
) -> Vec<String> {
    provenance
        .iter()
        .take(3)
        .map(|entry| match (&entry.location, &entry.detail) {
            (Some(location), Some(detail)) => format!("{}:{} ({detail})", entry.artifact, location),
            (Some(location), None) => format!("{}:{}", entry.artifact, location),
            (None, Some(detail)) => format!("{} ({detail})", entry.artifact),
            (None, None) => entry.artifact.clone(),
        })
        .collect()
}

fn manifest_component_provenance(component_name: Option<&str>) -> Vec<String> {
    component_name
        .map(|name| vec![format!("AndroidManifest.xml ({name})")])
        .unwrap_or_default()
}

/// Score a single intent filter as a deeplink target and render its trigger
/// command. Returns `None` if the filter isn't a usable VIEW deeplink. The score
/// captures specificity so the *most specific* deeplink is preferred over the
/// first one encountered (a path-constrained, app-custom-scheme link is a far
/// better fuzz target than a bare `https://host` VIEW filter).
fn deeplink_candidate(filter: &AndroidIntentFilterFact) -> Option<(i32, String)> {
    let action_ok = filter
        .actions
        .iter()
        .any(|action| action == "android.intent.action.VIEW");
    if !action_ok {
        return None;
    }
    let scheme = filter.data_schemes.first()?;
    let host = filter.data_hosts.first()?;
    let path_prefix = filter.data_path_prefixes.first();
    let path = path_prefix
        .map(|prefix| {
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                "/FUZZ".to_string()
            } else {
                format!("{trimmed}/FUZZ")
            }
        })
        .unwrap_or_else(|| "/FUZZ".into());

    let mut score = 0;
    if let Some(prefix) = path_prefix {
        score += 4 + prefix.trim_end_matches('/').len() as i32;
    }
    // A custom (non-web) scheme is an app-specific deeplink surface.
    if !matches!(scheme.as_str(), "http" | "https") {
        score += 2;
    }

    let command =
        format!("adb shell am start -a android.intent.action.VIEW -d '{scheme}://{host}{path}'");
    Some((score, command))
}

fn best_manifest_deeplink_command(inventory: &AndroidInventoryReport) -> Option<String> {
    inventory
        .containers
        .iter()
        .flat_map(|container| container.manifest.components.iter())
        .flat_map(|component| component.intent_filters.iter())
        .filter_map(deeplink_candidate)
        // Highest specificity wins; ties break deterministically by command text.
        .max_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
        .map(|(_, command)| command)
}

fn find_correlation<'a>(
    correlations: &'a [AndroidCorrelation],
    kind: &str,
) -> Option<&'a AndroidCorrelation> {
    correlations
        .iter()
        .find(|correlation| correlation.kind == kind)
}

#[cfg(test)]
mod deeplink_tests {
    use super::*;

    fn filter(
        actions: &[&str],
        schemes: &[&str],
        hosts: &[&str],
        paths: &[&str],
    ) -> AndroidIntentFilterFact {
        AndroidIntentFilterFact {
            actions: actions.iter().map(|s| s.to_string()).collect(),
            categories: Vec::new(),
            data_schemes: schemes.iter().map(|s| s.to_string()).collect(),
            data_hosts: hosts.iter().map(|s| s.to_string()).collect(),
            data_path_prefixes: paths.iter().map(|s| s.to_string()).collect(),
        }
    }

    const VIEW: &str = "android.intent.action.VIEW";

    #[test]
    fn non_view_filter_is_not_a_candidate() {
        let f = filter(
            &["android.intent.action.MAIN"],
            &["https"],
            &["example.com"],
            &[],
        );
        assert!(deeplink_candidate(&f).is_none());
    }

    #[test]
    fn path_and_custom_scheme_raise_specificity() {
        let bare = deeplink_candidate(&filter(&[VIEW], &["https"], &["example.com"], &[]))
            .expect("bare https view");
        let with_path = deeplink_candidate(&filter(
            &[VIEW],
            &["https"],
            &["example.com"],
            &["/deep/link"],
        ))
        .expect("path-constrained");
        let custom = deeplink_candidate(&filter(&[VIEW], &["myapp"], &["open"], &["/deep/link"]))
            .expect("custom scheme + path");

        assert!(with_path.0 > bare.0, "a path constraint is more specific");
        assert!(custom.0 > with_path.0, "custom scheme adds specificity");
    }

    #[test]
    fn selection_prefers_the_most_specific_of_several_filters() {
        // A bare https VIEW filter appears first; the app's real deeplink
        // (custom scheme + path) appears second and must win.
        let filters = [
            filter(&[VIEW], &["https"], &["example.com"], &[]),
            filter(&[VIEW], &["myapp"], &["open"], &["/account/reset"]),
        ];
        let best = filters
            .iter()
            .filter_map(deeplink_candidate)
            .max_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)))
            .map(|(_, command)| command)
            .expect("a deeplink");
        assert!(
            best.contains("myapp://open/account/reset/FUZZ"),
            "expected the specific custom-scheme deeplink, got: {best}"
        );
    }
}
