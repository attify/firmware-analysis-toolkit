use crate::derived::{fact_grouping_key, group_facts_by_subject};
use crate::result::{
    DerivedAnalysis, EvidenceBasis, FusedSourceEvidence, ReplayAnalysis, ReplayCandidate,
    ReplayRole, ScoreTrace,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn rank_replay_candidates(
    reference_symbols: &[String],
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    baseline_candidates: &[String],
) -> ReplayAnalysis {
    let grouped = group_facts_by_subject(derived);
    let mut required_roles = reference_symbols
        .iter()
        .flat_map(|symbol| roles_for_subject(symbol, &grouped))
        .collect::<Vec<_>>();
    let mut required_fact_kinds = reference_symbols
        .iter()
        .flat_map(|symbol| fact_kinds_for_subject(symbol, &grouped))
        .collect::<Vec<_>>();
    dedup_roles(&mut required_roles);
    dedup_strings(&mut required_fact_kinds);
    if required_roles.is_empty() {
        required_roles = baseline_candidates
            .iter()
            .flat_map(|symbol| roles_for_subject(symbol, &grouped))
            .collect::<Vec<_>>();
        dedup_roles(&mut required_roles);
    }
    if required_fact_kinds.is_empty() {
        required_fact_kinds = baseline_candidates
            .iter()
            .flat_map(|symbol| fact_kinds_for_subject(symbol, &grouped))
            .collect::<Vec<_>>();
        dedup_strings(&mut required_fact_kinds);
    }

    let references = reference_symbols.iter().cloned().collect::<BTreeSet<_>>();
    let baseline = baseline_candidates.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    let minimum_kind_overlap = required_fact_kinds.len().min(2);
    let minimum_role_overlap = required_roles.len().min(2);

    for method in &fused.methods {
        if references.contains(&method.qualified_name) {
            continue;
        }
        let candidate_roles = roles_for_subject(&method.qualified_name, &grouped);
        if candidate_roles.is_empty() && !baseline.contains(&method.qualified_name) {
            continue;
        }
        let matched_roles = candidate_roles
            .iter()
            .filter(|role| required_roles.contains(role))
            .cloned()
            .collect::<Vec<_>>();
        if minimum_role_overlap > 0
            && matched_roles.len() < minimum_role_overlap
            && !baseline.contains(&method.qualified_name)
        {
            continue;
        }
        let missing_roles = required_roles
            .iter()
            .filter(|role| !matched_roles.contains(role))
            .cloned()
            .collect::<Vec<_>>();
        let key = fact_grouping_key(&method.qualified_name, Some(&method.file));
        let facts = grouped
            .get(&key)
            .or_else(|| grouped.get(&method.qualified_name))
            .cloned()
            .unwrap_or_default();
        let candidate_fact_kinds = facts
            .iter()
            .map(|fact| fact.kind.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let matched_fact_kinds = candidate_fact_kinds
            .iter()
            .filter(|kind| required_fact_kinds.contains(kind))
            .cloned()
            .collect::<Vec<_>>();
        if minimum_kind_overlap > 0
            && matched_fact_kinds.len() < minimum_kind_overlap
            && !baseline.contains(&method.qualified_name)
        {
            continue;
        }
        let family_pack_hits = facts
            .iter()
            .map(|fact| fact.family_pack.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let observed_hits = facts
            .iter()
            .filter(|fact| matches!(fact.evidence_basis, EvidenceBasis::ObservedFromAstFacts))
            .count() as i32;
        let repaired_hits = facts
            .iter()
            .filter(|fact| {
                matches!(
                    fact.evidence_basis,
                    EvidenceBasis::InferredFromRepairedSlice
                )
            })
            .count() as i32;

        let mut score = (matched_roles.len() as i32 * 30)
            + (matched_fact_kinds.len() as i32 * 12)
            + (family_pack_hits.len() as i32 * 8)
            + (observed_hits * 4)
            + (baseline.contains(&method.qualified_name) as i32 * 10)
            - (missing_roles.len() as i32 * 7)
            - ((required_fact_kinds
                .len()
                .saturating_sub(matched_fact_kinds.len())) as i32
                * 6)
            - (repaired_hits * 2);

        if method.file
            == fused
                .methods
                .first()
                .map(|first| first.file.clone())
                .unwrap_or_default()
        {
            score += 2;
        }

        candidates.push(ReplayCandidate {
            symbol: method.qualified_name.clone(),
            file: Some(method.file.clone()),
            score,
            matched_roles,
            missing_roles,
            family_pack_hits,
            score_trace: ScoreTrace {
                adapters: fused.adapters.clone(),
                family_pack_hits: facts.iter().map(|fact| fact.kind.clone()).collect(),
                penalties: replay_penalties(
                    repaired_hits,
                    &required_fact_kinds,
                    &matched_fact_kinds,
                ),
                locality_notes: vec!["role-based replay ranking".into()],
            },
        });
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });

    ReplayAnalysis {
        reference_symbols: reference_symbols.to_vec(),
        required_roles,
        candidates,
        observed: vec![
            format!("reference_symbols={}", reference_symbols.len()),
            format!("baseline_candidates={}", baseline_candidates.len()),
        ],
        inferred: vec![
            "candidates ranked by matched roles, family packs, and evidence quality".into(),
        ],
    }
}

fn replay_penalties(
    repaired_hits: i32,
    required_fact_kinds: &[String],
    matched_fact_kinds: &[String],
) -> Vec<String> {
    let mut penalties = Vec::new();
    if repaired_hits > 0 {
        penalties.push("repaired-slice-evidence".into());
    }
    if !required_fact_kinds.is_empty() && matched_fact_kinds.len() < required_fact_kinds.len() {
        penalties.push("partial-fact-kind-overlap".into());
    }
    penalties
}

fn roles_for_subject(
    symbol: &str,
    grouped: &BTreeMap<String, Vec<crate::result::DerivedFact>>,
) -> Vec<ReplayRole> {
    let Some(facts) = lookup_facts_by_symbol(symbol, grouped) else {
        return Vec::new();
    };
    let has_gpu_protocol_context = facts.iter().any(|fact| {
        matches!(
            fact.kind.as_str(),
            "gpu_protocol_lifecycle_method"
                | "gpu_ordering_call_present"
                | "gpu_async_callback_present"
                | "explicit_state_guard"
        )
    });
    let mut roles = facts
        .iter()
        .filter_map(|fact| match fact.kind.as_str() {
            "allocation_call_present" | "buffer_or_subimage_method" => {
                Some(ReplayRole::AllocationSize)
            }
            "copy_call_present" => Some(ReplayRole::CopySize),
            "stride_pitch_depth_role" => Some(ReplayRole::PitchStrideDepth),
            "gpu_protocol_lifecycle_method" | "gpu_ordering_call_present" => {
                Some(ReplayRole::ProtocolOrdering)
            }
            "gpu_async_callback_present" => Some(ReplayRole::AsyncLifecycle),
            "permission_gate_present" | "override_permission_site" => {
                Some(match fact.kind.as_str() {
                    "override_permission_site" => ReplayRole::PermissionOverride,
                    _ => ReplayRole::GuardValidation,
                })
            }
            "callback_or_teardown_call_present" | "lifetime_sensitive_method" => {
                if has_gpu_protocol_context {
                    None
                } else {
                    Some(ReplayRole::CallbackTeardown)
                }
            }
            "ownership_transfer_call_present"
            | "deferred_or_pending_state_present"
            | "post_handoff_observer_present"
            | "stale_subject_reuse_risk" => Some(ReplayRole::PostHandoffObservation),
            _ => None,
        })
        .collect::<Vec<_>>();
    dedup_roles(&mut roles);
    roles
}

fn dedup_roles(roles: &mut Vec<ReplayRole>) {
    let mut seen = BTreeSet::new();
    roles.retain(|role| seen.insert(role.as_str().to_string()));
}

fn fact_kinds_for_subject(
    symbol: &str,
    grouped: &BTreeMap<String, Vec<crate::result::DerivedFact>>,
) -> Vec<String> {
    lookup_facts_by_symbol(symbol, grouped)
        .map(|facts| {
            facts
                .iter()
                .map(|fact| fact.kind.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Look up facts by bare symbol name, falling back to the first
/// file-qualified key (`symbol@file`) when a bare key is absent.
fn lookup_facts_by_symbol<'a>(
    symbol: &str,
    grouped: &'a BTreeMap<String, Vec<crate::result::DerivedFact>>,
) -> Option<&'a Vec<crate::result::DerivedFact>> {
    grouped.get(symbol).or_else(|| {
        let prefix = format!("{symbol}@");
        grouped
            .keys()
            .find(|key| key.starts_with(&prefix))
            .and_then(|key| grouped.get(key))
    })
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}
