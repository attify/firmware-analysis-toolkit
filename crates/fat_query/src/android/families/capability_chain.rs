use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidLeadMetadata,
    AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidProvenance, AndroidRevelation, AndroidSemanticBundle, AndroidSymbolIdentity,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;

pub fn derive_capability_chain_confused_deputy_leads(
    bundle: &AndroidSemanticBundle,
) -> Vec<AndroidDiscoverLead> {
    let mutable_pending_intent = bundle
        .facts
        .iter()
        .find(|fact| fact.kind == "pending-intent.mutability" && fact.subject == "mutable");
    let has_mutable_pending_intent = mutable_pending_intent.is_some()
        || bundle
            .transport_surfaces
            .iter()
            .any(|surface| surface.kind == "mutable-pending-intent");
    let delegated_boundary = bundle
        .trust_boundaries
        .iter()
        .find(|boundary| boundary.kind == "delegated-identity-boundary");
    let delegated_path = bundle
        .correlations
        .iter()
        .find(|correlation| correlation.kind == "delegated-path-composition");
    let api_pending_intent = bundle.facts.iter().any(|fact| {
        matches!(
            fact.kind.as_str(),
            "android-api.pending-intent-get-activity"
                | "android-api.pending-intent-get-service"
                | "android-api.pending-intent-get-broadcast"
        )
    });
    let api_start_activity = bundle
        .facts
        .iter()
        .any(|fact| fact.kind == "android-api.start-activity");
    let score = usize::from(has_mutable_pending_intent)
        + usize::from(delegated_boundary.is_some())
        + usize::from(delegated_path.is_some())
        + usize::from(api_pending_intent)
        + usize::from(api_start_activity);

    if score < 2 || (!has_mutable_pending_intent && !api_pending_intent) {
        return Vec::new();
    }

    let surfaces: Vec<_> = bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "nested-intent-dispatch")
        .collect();
    if surfaces.is_empty() && delegated_boundary.is_none() && delegated_path.is_none() {
        return Vec::new();
    }
    let fallback_surface = if surfaces.is_empty() {
        vec![None]
    } else {
        surfaces.into_iter().map(Some).collect()
    };

    fallback_surface
        .into_iter()
        .map(|surface| {
            let resolved_symbol = resolve_symbol_metadata(
                bundle.symbol_identities.as_slice(),
                surface.and_then(|candidate| candidate.entry_symbol.as_deref()),
            );
            let symbol = resolved_symbol
                .as_ref()
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| "PendingIntent".into());
            let endpoint_template = bundle
                .control_surfaces
                .iter()
                .find(|candidate| candidate.kind == "endpoint-template");
            let supporting_revelations = supporting_revelations(
                bundle,
                &[
                    surface.map(|candidate| candidate.surface_id.as_str()).unwrap_or(""),
                    surface
                        .and_then(|candidate| candidate.entry_symbol.as_deref())
                        .unwrap_or(""),
                    delegated_boundary
                        .map(|boundary| boundary.boundary_id.as_str())
                        .unwrap_or(""),
                    delegated_path
                        .map(|correlation| correlation.correlation_id.as_str())
                        .unwrap_or(""),
                ],
            );
            let mut family_pack_hits = vec!["capability-chain-explicit".into()];
            if delegated_path.is_some() && endpoint_template.is_some() {
                family_pack_hits.push("path-composition-owned-by-capability-chain".into());
            }
            if api_pending_intent {
                family_pack_hits.push("framework-api-survival".into());
            }
            if !supporting_revelations.is_empty() {
                family_pack_hits.push("revelation-support".into());
            }
            let mut penalties = Vec::new();
            if delegated_boundary.is_none() {
                penalties.push("no-delegated-boundary".into());
            }
            if surface.is_none() {
                penalties.push("no-explicit-nested-dispatch-surface".into());
            }
            let mut why_matched = vec![
                "nested intent or mutable pending intent crosses delegated identity boundary"
                    .into(),
            ];
            why_matched.extend(
                supporting_revelations
                    .iter()
                    .take(2)
                    .map(|revelation| supporting_revelation_note(revelation)),
            );
            AndroidDiscoverLead {
                lead_id: format!(
                    "android-chain:{}",
                    surface
                        .map(|candidate| candidate.surface_id.as_str())
                        .unwrap_or("pending-intent")
                ),
                symbol,
                symbol_resolved: resolved_symbol.is_some_and(|(_, resolved)| resolved),
                family: "capability-chain-confused-deputy".into(),
                family_confidence: 0.5
                    + ((score.min(5) as f32 - 2.0) * 0.1)
                    + supporting_revelation_boost(&supporting_revelations),
                matched_roles: vec![
                    RoleMatch {
                        role: "nested-intent-dispatch".into(),
                        detail: surface
                            .map(|candidate| candidate.surface_id.clone())
                            .unwrap_or_else(|| "framework-api".into()),
                    },
                    RoleMatch {
                        role: "delegated-identity-boundary".into(),
                        detail: delegated_boundary
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
                    kind: "notification-action".into(),
                    detail: surface
                        .and_then(|candidate| candidate.trigger.clone())
                        .unwrap_or_else(|| "notification-action".into()),
                }],
                expected_proof_signal: vec![ProofSignal {
                    kind: "delegated-identity-action".into(),
                    detail:
                        "nested or pending-intent chain executes with authority different from the original caller"
                            .into(),
                }],
                provenance_summary: summarize_fact_provenance(
                    mutable_pending_intent
                        .map(|fact| fact.provenance.as_slice())
                        .unwrap_or(&[]),
                ),
                score_trace: ScoreTrace {
                    adapters: vec!["android-semantic-bundle".into()],
                    family_pack_hits,
                    penalties,
                    locality_notes: vec!["apk-app-local".into()],
                },
                metadata: AndroidLeadMetadata {
                    entry_surface: Some(AndroidEntrySurface::PendingIntent),
                    capability_transition: vec![
                        "notification-action".into(),
                        "delegated-component".into(),
                        "templated-endpoint".into(),
                    ],
                    required_identity_or_permission: Vec::new(),
                    locality: Some(AndroidLocalityClass::AppLocal),
                    evidence_basis: vec![
                        AndroidEvidenceBasis::ObservedSourceFact,
                        AndroidEvidenceBasis::InferredCapabilityChain,
                    ],
                    expected_proof_signal: vec!["delegated-identity-action".into()],
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
