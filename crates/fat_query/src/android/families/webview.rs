use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidLeadMetadata,
    AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidProvenance, AndroidRevelation, AndroidSemanticBundle, AndroidSymbolIdentity,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;

pub fn derive_webview_bridge_uri_leads(bundle: &AndroidSemanticBundle) -> Vec<AndroidDiscoverLead> {
    let weak_validation = bundle.facts.iter().find(|fact| {
        fact.kind == "webview.uri-validation"
            && fact
                .attributes
                .get("strength")
                .map(|value| value != "strong")
                .unwrap_or(true)
    });
    let bridge_boundary = bundle
        .trust_boundaries
        .iter()
        .find(|boundary| boundary.kind == "webview-to-bridge");
    let bridge_surface = bundle
        .control_surfaces
        .iter()
        .find(|surface| surface.kind == "javascript-bridge-method");
    let api_load = bundle.facts.iter().any(|fact| {
        matches!(
            fact.kind.as_str(),
            "android-api.webview-load-url" | "android-api.webview-load-data"
        )
    });
    let score = usize::from(weak_validation.is_some())
        + usize::from(bridge_boundary.is_some())
        + usize::from(bridge_surface.is_some())
        + usize::from(api_load);

    if score < 2 || (bridge_surface.is_none() && !api_load) {
        return Vec::new();
    }

    bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "webview-load-url")
        .filter(|surface| {
            bundle.transport_surfaces.iter().any(|transport| {
                transport.kind == "webview-uri-load" && transport.sink == surface.surface_id
            })
        })
        .map(|surface| {
            let resolved_symbol = resolve_symbol_metadata(
                bundle.symbol_identities.as_slice(),
                surface.entry_symbol.as_deref(),
            );
            let symbol = resolved_symbol
                .as_ref()
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| surface.surface_id.clone());
            let supporting_revelations = supporting_revelations(
                bundle,
                &[
                    surface.surface_id.as_str(),
                    surface.entry_symbol.as_deref().unwrap_or(""),
                    bridge_boundary
                        .map(|boundary| boundary.boundary_id.as_str())
                        .unwrap_or(""),
                    bridge_surface
                        .map(|bridge| bridge.surface_id.as_str())
                        .unwrap_or(""),
                ],
            );
            let mut penalties = Vec::new();
            if weak_validation.is_none() {
                penalties.push("no-explicit-weak-validation-fact".into());
            }
            if bridge_boundary.is_none() {
                penalties.push("no-webview-bridge-boundary".into());
            }
            let mut why_matched =
                vec!["remote URI reaches WebView bridge boundary with weak validation".into()];
            why_matched.extend(
                supporting_revelations
                    .iter()
                    .take(2)
                    .map(|revelation| supporting_revelation_note(revelation)),
            );
            AndroidDiscoverLead {
                lead_id: format!("android-webview:{}", surface.surface_id),
                symbol,
                symbol_resolved: resolved_symbol.is_some_and(|(_, resolved)| resolved),
                family: "webview-bridge-uri".into(),
                family_confidence: 0.55
                    + ((score.min(4) as f32 - 2.0) * 0.12)
                    + supporting_revelation_boost(&supporting_revelations),
                matched_roles: vec![
                    RoleMatch {
                        role: "webview-loader".into(),
                        detail: surface.surface_id.clone(),
                    },
                    RoleMatch {
                        role: "javascript-bridge".into(),
                        detail: bridge_surface
                            .map(|bridge| bridge.surface_id.clone())
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
                    kind: "hosted-web-page".into(),
                    detail: surface
                        .trigger
                        .clone()
                        .unwrap_or_else(|| "https://attacker.example/bridge.html".into()),
                }],
                expected_proof_signal: vec![ProofSignal {
                    kind: "bridge-reachable-from-uri".into(),
                    detail: "remote URI content can exercise a registered JavaScript bridge".into(),
                }],
                provenance_summary: summarize_fact_provenance(
                    weak_validation
                        .map(|fact| fact.provenance.as_slice())
                        .unwrap_or(&[]),
                ),
                score_trace: ScoreTrace {
                    adapters: vec!["android-semantic-bundle".into()],
                    family_pack_hits: {
                        let mut hits = vec!["webview-bridge-explicit".into()];
                        if !supporting_revelations.is_empty() {
                            hits.push("revelation-support".into());
                        }
                        hits
                    },
                    penalties,
                    locality_notes: vec!["apk-app-local".into()],
                },
                metadata: AndroidLeadMetadata {
                    entry_surface: Some(AndroidEntrySurface::WebViewUrl),
                    capability_transition: vec![
                        "remote-web-content".into(),
                        "javascript-bridge".into(),
                    ],
                    required_identity_or_permission: Vec::new(),
                    locality: Some(AndroidLocalityClass::AppLocal),
                    evidence_basis: vec![
                        AndroidEvidenceBasis::ObservedSourceFact,
                        AndroidEvidenceBasis::InferredCapabilityChain,
                    ],
                    expected_proof_signal: vec!["bridge-reachable-from-uri".into()],
                },
            }
        })
        .collect()
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

fn summarize_fact_provenance(provenance: &[AndroidProvenance]) -> Vec<String> {
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
