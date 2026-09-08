use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidLeadMetadata,
    AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidProvenance, AndroidRevelation, AndroidSemanticBundle, AndroidSymbolIdentity,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;

pub fn derive_binder_native_boundary_leads(
    bundle: &AndroidSemanticBundle,
) -> Vec<AndroidDiscoverLead> {
    let binder_boundary = bundle
        .trust_boundaries
        .iter()
        .find(|boundary| boundary.kind == "binder-to-native");
    let binder_correlation = bundle
        .correlations
        .iter()
        .find(|correlation| correlation.kind == "binder-to-native");
    let size_sensitive = bundle
        .facts
        .iter()
        .find(|fact| fact.kind == "native.size-sensitive");
    let binder_surface_count = bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "binder-method")
        .count();
    let native_link_count = bundle.native_semantics.len();
    let score = usize::from(binder_boundary.is_some())
        + usize::from(binder_correlation.is_some())
        + usize::from(size_sensitive.is_some())
        + usize::from(binder_surface_count > 0)
        + usize::from(native_link_count > 0);

    if score < 2 || binder_surface_count == 0 {
        return Vec::new();
    }

    bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "binder-method")
        .filter(|surface| {
            bundle
                .native_semantics
                .iter()
                .any(|native| native.linked_symbol_id.as_deref() == surface.entry_symbol.as_deref())
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
                    binder_boundary
                        .map(|boundary| boundary.boundary_id.as_str())
                        .unwrap_or(""),
                    binder_correlation
                        .map(|correlation| correlation.correlation_id.as_str())
                        .unwrap_or(""),
                ],
            );
            let mut why_matched = vec![if binder_boundary.is_some()
                && binder_correlation.is_some()
                && size_sensitive.is_some()
            {
                "binder input reaches size-sensitive native boundary".into()
            } else {
                "binder input reaches or approaches a native boundary".into()
            }];
            why_matched.extend(
                supporting_revelations
                    .iter()
                    .take(2)
                    .map(|revelation| supporting_revelation_note(revelation)),
            );
            let guard = binder_boundary.and_then(|boundary| boundary.guard.as_deref());
            if let Some(guard) = guard {
                why_matched.push(format!("caller validation present: {guard}"));
            }
            let trigger_detail = surface
                .trigger
                .clone()
                .filter(|detail| detail != "TRANSACTION_parseBlob")
                .unwrap_or_else(|| {
                    resolved_symbol
                        .as_ref()
                        .map(|(name, resolved)| {
                            if *resolved {
                                format!("service call {} FUZZ", binder_service_name(name))
                            } else {
                                "TRANSACTION_parseBlob".into()
                            }
                        })
                        .unwrap_or_else(|| "TRANSACTION_parseBlob".into())
                });
            AndroidDiscoverLead {
                lead_id: format!("android-binder:{}", surface.surface_id),
                symbol,
                symbol_resolved: resolved_symbol.is_some_and(|(_, resolved)| resolved),
                family: "binder-native-boundary".into(),
                family_confidence: 0.52
                    + ((score.min(5) as f32 - 2.0) * 0.11)
                    + supporting_revelation_boost(&supporting_revelations),
                matched_roles: vec![
                    RoleMatch {
                        role: "binder-method".into(),
                        detail: surface.surface_id.clone(),
                    },
                    RoleMatch {
                        role: "native-boundary".into(),
                        detail: binder_correlation
                            .map(|correlation| correlation.correlation_id.clone())
                            .unwrap_or_else(|| "implicit".into()),
                    },
                ],
                why_matched,
                evidence_basis: vec![
                    AndroidEvidenceBasis::ObservedNativeFact,
                    AndroidEvidenceBasis::ObservedSourceFact,
                ],
                locality: AndroidLocalityClass::BundledNativeLib,
                sibling_candidates: Vec::new(),
                suggested_trigger_recipe: vec![TriggerRecipeStep {
                    kind: "binder-transaction".into(),
                    detail: trigger_detail,
                }],
                expected_proof_signal: vec![ProofSignal {
                    kind: "native-parser-reached".into(),
                    detail: "binder parcel input reaches a native copy or parse routine".into(),
                }],
                provenance_summary: summarize_fact_provenance(
                    size_sensitive
                        .map(|fact| fact.provenance.as_slice())
                        .unwrap_or(&[]),
                ),
                score_trace: ScoreTrace {
                    adapters: vec!["android-semantic-bundle".into()],
                    family_pack_hits: {
                        let mut hits = vec!["binder-native-explicit".into()];
                        if !supporting_revelations.is_empty() {
                            hits.push("revelation-support".into());
                        }
                        hits
                    },
                    penalties: [
                        binder_boundary.is_none().then_some("no-binder-boundary"),
                        binder_correlation
                            .is_none()
                            .then_some("no-binder-correlation"),
                        size_sensitive.is_none().then_some("no-size-sensitive-fact"),
                        guard.is_none().then_some("no-caller-validation"),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_string)
                    .collect(),
                    locality_notes: vec!["bundled-native-lib".into()],
                },
                metadata: AndroidLeadMetadata {
                    entry_surface: Some(AndroidEntrySurface::BinderMethod),
                    capability_transition: vec!["binder-caller".into(), "native-parser".into()],
                    required_identity_or_permission: Vec::new(),
                    locality: Some(AndroidLocalityClass::BundledNativeLib),
                    evidence_basis: vec![
                        AndroidEvidenceBasis::ObservedNativeFact,
                        AndroidEvidenceBasis::ObservedSourceFact,
                    ],
                    expected_proof_signal: vec!["native-parser-reached".into()],
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

fn binder_service_name(symbol: &str) -> String {
    symbol
        .rsplit_once('.')
        .map(|(class_name, _)| class_name)
        .unwrap_or(symbol)
        .to_string()
}
