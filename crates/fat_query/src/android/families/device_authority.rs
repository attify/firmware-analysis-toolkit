use crate::android::discovery::{
    AndroidDiscoverLead, AndroidEntrySurface, AndroidEvidenceBasis, AndroidLeadMetadata,
    AndroidLocalityClass,
};
use crate::android::semantic::{
    AndroidProvenance, AndroidRevelation, AndroidSemanticBundle, AndroidSubsystem,
};
use crate::discovery::{ProofSignal, RoleMatch, TriggerRecipeStep};
use crate::result::ScoreTrace;

pub fn derive_device_authority_leads(
    bundle: &AndroidSemanticBundle,
    top_k: usize,
) -> Vec<AndroidDiscoverLead> {
    let mut leads = Vec::new();
    for subsystem in &bundle.subsystems {
        match subsystem.kind.as_str() {
            "web-command-bridge"
            | "session-command-control"
            | "local-device-control"
            | "local-device-runtime-control" => {
                let supporting: Vec<&AndroidRevelation> = bundle
                    .revelations
                    .iter()
                    .filter(|revelation| {
                        matches!(
                            revelation.kind.as_str(),
                            "web-to-command-plane" | "runtime-to-device-control-plane"
                        ) && revelation
                            .subsystem_ids
                            .iter()
                            .any(|id| id == &subsystem.subsystem_id)
                    })
                    .collect();
                if !supporting.is_empty() {
                    leads.push(build_device_command_lead(bundle, subsystem, &supporting));
                }
            }
            "account-device-binding" => {
                let supporting: Vec<&AndroidRevelation> = bundle
                    .revelations
                    .iter()
                    .filter(|revelation| {
                        revelation.kind == "account-to-device-authority-plane"
                            && revelation
                                .subsystem_ids
                                .iter()
                                .any(|id| id == &subsystem.subsystem_id)
                    })
                    .collect();
                if !supporting.is_empty() {
                    leads.push(build_device_binding_lead(bundle, subsystem, &supporting));
                }
            }
            _ => {}
        }
    }
    leads.sort_by(|left, right| {
        right
            .family_confidence
            .partial_cmp(&left.family_confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    leads.truncate(top_k.max(1));
    leads
}

fn build_device_command_lead(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    supporting: &[&AndroidRevelation],
) -> AndroidDiscoverLead {
    let symbol = best_symbol(bundle, subsystem, command_symbol_rank)
        .unwrap_or_else(|| subsystem.kind.clone());
    let trigger = best_surface_trigger(
        bundle,
        subsystem,
        &[
            "remote-command-dispatch",
            "web-command-bridge",
            "local-device-control-surface",
            "http-api-endpoint",
        ],
    )
    .unwrap_or_else(|| "command-envelope".into());
    let locality = AndroidLocalityClass::AppLocal;
    let entry_surface = if subsystem.kind == "local-device-runtime-control" {
        AndroidEntrySurface::Unknown
    } else {
        AndroidEntrySurface::WebViewUrl
    };
    let mut why_matched = vec![
        "web bridge, command envelope, and local device control evidence converge on the same control plane".into(),
        format!("supporting revelation: {}", supporting[0].kind),
    ];
    if subsystem.kind == "local-device-runtime-control" {
        if let Some(chain_summary) =
            runtime_role_chain_summary(bundle, subsystem, "local-device-control")
        {
            why_matched.insert(0, format!("runtime chain: {chain_summary}"));
        }
    }
    AndroidDiscoverLead {
        lead_id: format!("android-device-command:{}", sanitize_id(&symbol)),
        symbol,
        symbol_resolved: true,
        family: "device-command-authority".into(),
        family_confidence: 0.93,
        matched_roles: vec![
            RoleMatch {
                role: "authority-subsystem".into(),
                detail: subsystem.subsystem_id.clone(),
            },
            RoleMatch {
                role: "semantic-revelation".into(),
                detail: supporting[0].revelation_id.clone(),
            },
        ],
        why_matched,
        evidence_basis: vec![
            AndroidEvidenceBasis::ObservedSourceFact,
            AndroidEvidenceBasis::InferredCapabilityChain,
        ],
        locality: locality.clone(),
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: if subsystem.kind == "local-device-runtime-control" {
                "runtime-control".into()
            } else {
                "command-envelope".into()
            },
            detail: trigger,
        }],
        expected_proof_signal: vec![ProofSignal {
            kind: "command-dispatch".into(),
            detail: "web or session input reaches a command envelope and control path".into(),
        }],
        sibling_candidates: Vec::new(),
        provenance_summary: subsystem_provenance_summary(bundle, subsystem),
        score_trace: ScoreTrace {
            adapters: vec!["android-semantic-bundle".into()],
            family_pack_hits: vec![supporting[0].kind.clone()],
            penalties: Vec::new(),
            locality_notes: vec!["app_local".into()],
        },
        metadata: AndroidLeadMetadata {
            entry_surface: Some(entry_surface),
            capability_transition: if subsystem.kind == "local-device-runtime-control" {
                vec![
                    "flutter-runtime".into(),
                    "bundled-script".into(),
                    "local-device-control".into(),
                ]
            } else {
                vec![
                    "web-js-bridge".into(),
                    "session-offer".into(),
                    "command-envelope".into(),
                ]
            },
            required_identity_or_permission: Vec::new(),
            locality: Some(locality),
            evidence_basis: vec![
                AndroidEvidenceBasis::ObservedSourceFact,
                AndroidEvidenceBasis::InferredCapabilityChain,
            ],
            expected_proof_signal: vec!["command-dispatch".into()],
        },
    }
}

fn runtime_role_chain_summary(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    role: &str,
) -> Option<String> {
    let correlation = bundle.correlations.iter().find(|correlation| {
        correlation.kind == "runtime-role-cluster"
            && correlation
                .rationale
                .as_deref()
                .is_some_and(|text| text.contains(role))
    })?;

    let mut members = correlation
        .members
        .iter()
        .filter_map(|member| {
            bundle
                .facts
                .iter()
                .find(|fact| fact.fact_id == *member)
                .map(|fact| fact.subject.clone())
        })
        .filter(|subject| {
            subsystem
                .package_prefixes
                .iter()
                .any(|prefix| subject.contains(prefix))
                || subject.contains("package:")
                || subject.contains(".lua")
                || subject.contains("flutter_")
        })
        .collect::<Vec<_>>();
    members.sort();
    members.dedup();
    (!members.is_empty()).then(|| members.into_iter().take(4).collect::<Vec<_>>().join(" -> "))
}

fn build_device_binding_lead(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    supporting: &[&AndroidRevelation],
) -> AndroidDiscoverLead {
    let symbol = best_symbol(bundle, subsystem, binding_symbol_rank)
        .unwrap_or_else(|| subsystem.kind.clone());
    let trigger = best_surface_trigger(bundle, subsystem, &["account-device-bind-flow"])
        .unwrap_or_else(|| "oauth/bind".into());
    let locality = AndroidLocalityClass::AppLocal;
    AndroidDiscoverLead {
        lead_id: format!("android-device-binding:{}", sanitize_id(&symbol)),
        symbol,
        symbol_resolved: true,
        family: "device-binding-authority".into(),
        family_confidence: 0.91,
        matched_roles: vec![
            RoleMatch {
                role: "authority-subsystem".into(),
                detail: subsystem.subsystem_id.clone(),
            },
            RoleMatch {
                role: "semantic-revelation".into(),
                detail: supporting[0].revelation_id.clone(),
            },
        ],
        why_matched: vec![
            "account auth and device bind evidence converge on an account-to-device authority path"
                .into(),
            format!("supporting revelation: {}", supporting[0].kind),
        ],
        evidence_basis: vec![
            AndroidEvidenceBasis::ObservedSourceFact,
            AndroidEvidenceBasis::InferredCapabilityChain,
        ],
        locality: locality.clone(),
        suggested_trigger_recipe: vec![TriggerRecipeStep {
            kind: "http-bind".into(),
            detail: trigger,
        }],
        expected_proof_signal: vec![ProofSignal {
            kind: "account-device-bind".into(),
            detail: "oauth and bind operations converge on a device ownership transition".into(),
        }],
        sibling_candidates: Vec::new(),
        provenance_summary: subsystem_provenance_summary(bundle, subsystem),
        score_trace: ScoreTrace {
            adapters: vec!["android-semantic-bundle".into()],
            family_pack_hits: vec!["account-to-device-authority-plane".into()],
            penalties: Vec::new(),
            locality_notes: vec!["app_local".into()],
        },
        metadata: AndroidLeadMetadata {
            entry_surface: Some(AndroidEntrySurface::Unknown),
            capability_transition: vec!["oauth-token".into(), "device-bind".into()],
            required_identity_or_permission: Vec::new(),
            locality: Some(locality),
            evidence_basis: vec![
                AndroidEvidenceBasis::ObservedSourceFact,
                AndroidEvidenceBasis::InferredCapabilityChain,
            ],
            expected_proof_signal: vec!["account-device-bind".into()],
        },
    }
}

fn best_symbol(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    rank_fn: fn(&str) -> usize,
) -> Option<String> {
    let mut candidates: Vec<String> = bundle
        .symbol_identities
        .iter()
        .filter(|symbol| {
            subsystem
                .symbol_ids
                .iter()
                .any(|id| id == &symbol.symbol_id)
        })
        .map(|symbol| symbol.qualified_name.clone())
        .collect();
    candidates.sort_by(|left, right| {
        rank_fn(right)
            .cmp(&rank_fn(left))
            .then_with(|| left.cmp(right))
    });
    candidates.into_iter().next()
}

fn best_surface_trigger(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
    kinds: &[&str],
) -> Option<String> {
    bundle
        .control_surfaces
        .iter()
        .filter(|surface| {
            subsystem
                .control_surface_ids
                .iter()
                .any(|id| id == &surface.surface_id)
        })
        .find(|surface| kinds.iter().any(|kind| *kind == surface.kind))
        .and_then(|surface| surface.trigger.clone())
}

fn command_symbol_rank(symbol: &str) -> usize {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("bindagentwebsupport") {
        10
    } else if lower.contains("bluetooth.dart") {
        9
    } else if lower.contains("pairing.dart") {
        8
    } else if lower.contains("app_logic_model.dart") {
        7
    } else if lower.ends_with("main.lua") {
        6
    } else if lower.ends_with("androidinterface") {
        9
    } else if lower.contains("androidinterface.") {
        let mut score = 6usize;
        if [
            "send", "cmd", "command", "connect", "session", "sport", "patrol",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        {
            score += 3;
        }
        if [
            "backtoapp",
            "gotoalbum",
            "takephoto",
            "webserviceisok",
            "log",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        {
            score = score.saturating_sub(3);
        }
        score
    } else if lower.contains("webrtcfragment") {
        8
    } else if lower.contains("sendgo2req") {
        4
    } else if lower.contains("bluetoothservice") {
        3
    } else {
        1
    }
}

fn binding_symbol_rank(symbol: &str) -> usize {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("loginapi") {
        4
    } else if lower.contains("logindatabean") {
        3
    } else {
        1
    }
}

fn subsystem_provenance_summary(
    bundle: &AndroidSemanticBundle,
    subsystem: &AndroidSubsystem,
) -> Vec<String> {
    let mut summaries = Vec::new();
    for fact_id in &subsystem.fact_ids {
        if let Some(fact) = bundle.facts.iter().find(|fact| &fact.fact_id == fact_id) {
            summarize_fact_provenance(&fact.provenance, &mut summaries);
        }
    }
    summaries.truncate(4);
    summaries
}

fn summarize_fact_provenance(provenance: &[AndroidProvenance], summaries: &mut Vec<String>) {
    for entry in provenance {
        let summary = if let Some(location) = &entry.location {
            format!(
                "{}:{} ({})",
                entry.artifact,
                location,
                entry.detail.as_deref().unwrap_or("semantic evidence")
            )
        } else {
            format!(
                "{} ({})",
                entry.artifact,
                entry.detail.as_deref().unwrap_or("semantic evidence")
            )
        };
        if !summaries.iter().any(|existing| existing == &summary) {
            summaries.push(summary);
        }
    }
}

fn sanitize_id(symbol: &str) -> String {
    symbol
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}
