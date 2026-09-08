use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidLeadMetadata,
    AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidProvenance, AndroidRevelation, AndroidSemanticBundle, AndroidSubsystem,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;

pub fn derive_commissioning_fabric_authority_leads(
    bundle: &AndroidSemanticBundle,
    top_k: usize,
) -> Vec<AndroidDiscoverLead> {
    let mut leads = Vec::new();
    for subsystem in &bundle.subsystems {
        if !matches!(
            subsystem.kind.as_str(),
            "weave-device-security" | "matter-commissioning"
        ) {
            continue;
        }

        let supporting_revelations: Vec<&AndroidRevelation> = bundle
            .revelations
            .iter()
            .filter(|revelation| {
                revelation
                    .subsystem_ids
                    .iter()
                    .any(|id| id == &subsystem.subsystem_id)
                    && matches!(
                        revelation.kind.as_str(),
                        "commissioning-plane" | "fabric-authority-plane" | "key-export-risk-plane"
                    )
            })
            .collect();

        if supporting_revelations.is_empty() {
            continue;
        }

        let mut candidate_symbols: Vec<_> = bundle
            .symbol_identities
            .iter()
            .filter(|symbol| {
                subsystem
                    .symbol_ids
                    .iter()
                    .any(|id| id == &symbol.symbol_id)
            })
            .filter(|symbol| is_authority_symbol(&symbol.qualified_name))
            .collect();
        candidate_symbols.sort_by(|left, right| {
            authority_rank(&right.qualified_name)
                .cmp(&authority_rank(&left.qualified_name))
                .then_with(|| left.qualified_name.cmp(&right.qualified_name))
        });

        if candidate_symbols.is_empty() {
            leads.push(build_lead(bundle, subsystem, None, &supporting_revelations));
        } else {
            for symbol in candidate_symbols.into_iter().take(top_k.max(1)) {
                leads.push(build_lead(
                    bundle,
                    subsystem,
                    Some(symbol.qualified_name.clone()),
                    &supporting_revelations,
                ));
            }
        }
    }

    leads.sort_by(|left, right| {
        right
            .family_confidence
            .partial_cmp(&left.family_confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| authority_rank(&right.symbol).cmp(&authority_rank(&left.symbol)))
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    leads.truncate(top_k);
    leads
}

fn build_lead(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    symbol: Option<String>,
    supporting_revelations: &[&AndroidRevelation],
) -> AndroidDiscoverLead {
    let symbol = symbol.unwrap_or_else(|| subsystem.kind.clone());
    let mut why_matched = vec![match subsystem.kind.as_str() {
        "weave-device-security" => {
            "commissioning and fabric authority signals converge in the Weave device security subsystem"
                .into()
        }
        "matter-commissioning" => {
            "commissioning authority signals converge in the Matter setup subsystem".into()
        }
        _ => "authority-bearing subsystem evidence is present".into(),
    }];
    why_matched.extend(
        supporting_revelations
            .iter()
            .map(|revelation| format!("supporting revelation: {}", revelation.kind)),
    );

    let trigger = bundle
        .control_surfaces
        .iter()
        .find(|surface| {
            subsystem
                .control_surface_ids
                .iter()
                .any(|id| id == &surface.surface_id)
        })
        .and_then(|surface| surface.trigger.clone())
        .unwrap_or_else(|| "authority-transition".into());

    let capability_transition = match subsystem.kind.as_str() {
        "weave-device-security" => vec![
            "pairing-or-token-auth".into(),
            "device-rendezvous".into(),
            "fabric-transition".into(),
        ],
        "matter-commissioning" => vec![
            "setup-proxy".into(),
            "commissioning-window".into(),
            "shared-device-state".into(),
        ],
        _ => vec!["authority-transition".into()],
    };

    let proof_detail = match subsystem.kind.as_str() {
        "weave-device-security" => {
            "rendezvous or fabric operation reaches an authority-bearing device-management path"
        }
        "matter-commissioning" => {
            "commissioning proxy or setup path reaches a device authority transition"
        }
        _ => "authority-bearing control path is reachable",
    };

    let locality = if subsystem.native_ids.is_empty() {
        AndroidLocalityClass::AppLocal
    } else {
        AndroidLocalityClass::BundledNativeLib
    };

    AndroidDiscoverLead {
        lead_id: format!("android-commissioning-fabric:{}", sanitize_id(&symbol)),
        symbol,
        symbol_resolved: true,
        family: "commissioning-fabric-authority".into(),
        family_confidence: authority_confidence(subsystem, supporting_revelations),
        matched_roles: vec![
            RoleMatch {
                role: "authority-subsystem".into(),
                detail: subsystem.subsystem_id.clone(),
            },
            RoleMatch {
                role: "semantic-revelation".into(),
                detail: supporting_revelations
                    .first()
                    .map(|revelation| revelation.revelation_id.clone())
                    .unwrap_or_else(|| "implicit".into()),
            },
        ],
        why_matched,
        evidence_basis: vec![
            AndroidEvidenceBasis::ObservedSourceFact,
            AndroidEvidenceBasis::ObservedNativeFact,
            AndroidEvidenceBasis::InferredCapabilityChain,
        ],
        locality: locality.clone(),
        sibling_candidates: Vec::new(),
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: "authority-path".into(),
            detail: trigger,
        }],
        expected_proof_signal: vec![ProofSignal {
            kind: "authority-transition".into(),
            detail: proof_detail.into(),
        }],
        provenance_summary: subsystem_provenance_summary(bundle, subsystem),
        score_trace: ScoreTrace {
            adapters: vec!["android-semantic-bundle".into()],
            family_pack_hits: vec![
                "commissioning-fabric-subsystem".into(),
                "revelation-backed-authority".into(),
            ],
            penalties: Vec::new(),
            locality_notes: vec![format!("{locality:?}").to_ascii_lowercase()],
        },
        metadata: AndroidLeadMetadata {
            entry_surface: Some(AndroidEntrySurface::Unknown),
            capability_transition,
            required_identity_or_permission: Vec::new(),
            locality: Some(locality),
            evidence_basis: vec![
                AndroidEvidenceBasis::ObservedSourceFact,
                AndroidEvidenceBasis::ObservedNativeFact,
                AndroidEvidenceBasis::InferredCapabilityChain,
            ],
            expected_proof_signal: vec!["authority-transition".into()],
        },
    }
}

fn authority_confidence(
    subsystem: &AndroidSubsystem,
    supporting_revelations: &[&AndroidRevelation],
) -> f32 {
    let mut confidence = 0.86;
    confidence += (supporting_revelations.len().min(3) as f32) * 0.03;
    if subsystem.kind == "weave-device-security" {
        confidence += 0.03;
    }
    confidence.min(0.99)
}

fn is_authority_symbol(qualified_name: &str) -> bool {
    authority_rank(qualified_name) > 0
}

fn authority_rank(qualified_name: &str) -> usize {
    let lower = qualified_name.to_ascii_lowercase();
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
    } else if lower.ends_with(".weavekeyexportclient")
        || lower.ends_with(".weavecertificatesupport")
        || lower.ends_with(".weavesecuritysupport")
        || lower.ends_with(".devicefilter")
        || lower.ends_with(".weavedevicedescriptor")
        || lower.ends_with(".identifydevicecriteria")
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

fn subsystem_provenance_summary(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
) -> Vec<String> {
    let provenance: Vec<AndroidProvenance> = bundle
        .facts
        .iter()
        .filter(|fact| subsystem.fact_ids.iter().any(|id| id == &fact.fact_id))
        .flat_map(|fact| fact.provenance.clone())
        .collect();
    summarize_provenance(&provenance)
}

fn summarize_provenance(provenance: &[AndroidProvenance]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    provenance
        .iter()
        .filter_map(|entry| {
            let summary = match (&entry.location, &entry.detail) {
                (Some(location), Some(detail)) => {
                    format!("{}:{} ({detail})", entry.artifact, location)
                }
                (Some(location), None) => format!("{}:{}", entry.artifact, location),
                (None, Some(detail)) => format!("{} ({detail})", entry.artifact),
                (None, None) => entry.artifact.clone(),
            };
            seen.insert(summary.clone()).then_some(summary)
        })
        .take(3)
        .collect()
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
