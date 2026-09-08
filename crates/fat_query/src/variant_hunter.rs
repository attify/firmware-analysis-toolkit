use crate::derived::{fact_grouping_key, group_facts_by_subject};
use crate::result::{
    DerivedAnalysis, FusedSourceEvidence, LocalityStatus, ReplayAnalysis, RollResolution,
    ScoreTrace, VariantLead,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const LIFETIME_SUPPRESSOR_FACT_KINDS: &[&str] = &[
    "safe_invalidation_guard",
    "explicit_cancellation_guard",
    "cleanup_only_teardown",
    "explicit_shutdown_path",
    "single_shot_callback",
];

const SIZE_SUPPRESSOR_FACT_KINDS: &[&str] = &[
    "dominating_size_guard",
    "safe_math_wrapper",
    "bounds_checked_copy",
    "shape_consistent_copy",
];

pub fn hunt_variants(
    replay: &ReplayAnalysis,
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
    baseline_candidates: &[String],
    max_breadth: usize,
) -> Vec<VariantLead> {
    let grouped = group_facts_by_subject(derived);
    let baseline = baseline_candidates.iter().cloned().collect::<BTreeSet<_>>();
    let replay_window = replay
        .candidates
        .iter()
        .take(max_breadth.max(1))
        .collect::<Vec<_>>();
    let references = replay
        .reference_symbols
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if references.is_empty() && replay_window.is_empty() {
        return Vec::new();
    }
    let replay_files = replay_window
        .iter()
        .filter_map(|candidate| candidate.file.clone())
        .collect::<BTreeSet<_>>();
    let replay_family_hits = replay_window
        .iter()
        .flat_map(|candidate| candidate.family_pack_hits.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut leads = Vec::new();

    for method in &fused.methods {
        if references.contains(&method.qualified_name) {
            continue;
        }
        let key = fact_grouping_key(&method.qualified_name, Some(&method.file));
        let facts = grouped
            .get(&key)
            .or_else(|| grouped.get(&method.qualified_name))
            .cloned()
            .unwrap_or_default();
        if should_suppress_primary_family_variant(&facts) {
            continue;
        }
        let mut score = facts.len() as i32 * 10;
        let baseline_candidate = baseline.contains(&method.qualified_name);
        if facts.is_empty() && !baseline_candidate {
            continue;
        }
        let mut family_pack_hits = facts
            .iter()
            .map(|fact| fact.family_pack.as_str().to_string())
            .collect::<Vec<_>>();
        family_pack_hits.sort();
        family_pack_hits.dedup();
        let family_overlap = family_pack_hits
            .iter()
            .filter(|family| replay_family_hits.contains(*family))
            .count() as i32;
        let same_file_overlap = replay_files.contains(&method.file);
        let repaired_hits = facts
            .iter()
            .filter(|fact| {
                matches!(
                    fact.evidence_basis,
                    crate::result::EvidenceBasis::InferredFromRepairedSlice
                )
            })
            .count() as i32;
        score += family_overlap * 10;
        if same_file_overlap {
            score += 12;
        }
        if baseline_candidate {
            score -= 8;
            if locality.no_local_vulnerable_source_likely {
                score += 12;
            }
        }
        if method.qualified_name.contains("Override") {
            score += 2;
        }
        score -= repaired_hits * 3;
        let fingerprint = fingerprint(
            &method.qualified_name,
            Some(method.file.clone()),
            &family_pack_hits,
        );
        leads.push(VariantLead {
            symbol: method.qualified_name.clone(),
            file: Some(method.file.clone()),
            fingerprint,
            score,
            family_pack_hits,
            score_trace: ScoreTrace {
                adapters: fused.adapters.clone(),
                family_pack_hits: facts.iter().map(|fact| fact.kind.clone()).collect(),
                penalties: variant_penalties(repaired_hits, baseline_candidate),
                locality_notes: variant_locality_notes(
                    same_file_overlap,
                    family_overlap > 0,
                    baseline_candidate,
                    locality.no_local_vulnerable_source_likely,
                ),
            },
        });
    }

    if locality.allow_vendored_scan {
        if let Some(path) = &locality.vendored_nearby_path {
            let local_best_score = leads.iter().map(|lead| lead.score).max().unwrap_or(0);
            let vendored_score = local_best_score
                .saturating_add(20)
                .saturating_add(if locality.local_patch_touching_vendored_code {
                    5
                } else {
                    0
                })
                .saturating_add(if locality.no_local_vulnerable_source_likely {
                    3
                } else {
                    0
                });
            leads.push(VariantLead {
                symbol: format!("vendored-neighborhood:{}", path.display()),
                file: Some(path.clone()),
                fingerprint: fingerprint(
                    &format!("vendored-neighborhood:{}", path.display()),
                    Some(path.clone()),
                    &[locality_note(locality)],
                ),
                score: vendored_score,
                family_pack_hits: vec!["dependency-roll-upstream-hidden".into()],
                score_trace: ScoreTrace {
                    adapters: fused.adapters.clone(),
                    family_pack_hits: vec!["vendored_neighbor_candidate".into()],
                    penalties: vec!["vendored-expansion-candidate".into()],
                    locality_notes: vec!["vendored expansion allowed by resolved locality".into()],
                },
            });
        }
    }

    dedup_and_sort(leads)
}

fn should_suppress_primary_family_variant(facts: &[crate::result::DerivedFact]) -> bool {
    facts.iter().any(|fact| {
        let kind = fact.kind.as_str();
        matches!(
            fact.family_pack,
            crate::result::FamilyPack::LifetimeOwnership
        ) && LIFETIME_SUPPRESSOR_FACT_KINDS.contains(&kind)
            || matches!(
                fact.family_pack,
                crate::result::FamilyPack::BoundsSizeArithmetic
            ) && SIZE_SUPPRESSOR_FACT_KINDS.contains(&kind)
    })
}

fn dedup_and_sort(leads: Vec<VariantLead>) -> Vec<VariantLead> {
    let mut deduped = BTreeMap::new();
    for lead in leads {
        deduped
            .entry(lead.fingerprint.clone())
            .and_modify(|existing: &mut VariantLead| {
                if lead.score > existing.score {
                    *existing = lead.clone();
                }
            })
            .or_insert(lead);
    }
    let mut final_leads = deduped.into_values().collect::<Vec<_>>();
    final_leads.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    final_leads
}

fn fingerprint(symbol: &str, file: Option<PathBuf>, family_pack_hits: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(symbol.as_bytes());
    if let Some(file) = file {
        hasher.update(file.display().to_string().as_bytes());
    }
    for family in family_pack_hits {
        hasher.update(family.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn locality_note(locality: &RollResolution) -> String {
    match locality.locality {
        LocalityStatus::RepoLocal => "repo-local".into(),
        LocalityStatus::VendoredLocal => "vendored-local".into(),
        LocalityStatus::Generated => "generated".into(),
        LocalityStatus::UpstreamReferenced => "upstream-referenced".into(),
        LocalityStatus::UpstreamHidden => "upstream-hidden".into(),
        LocalityStatus::Unknown => "unknown".into(),
    }
}

fn variant_penalties(repaired_hits: i32, baseline_candidate: bool) -> Vec<String> {
    let mut penalties = Vec::new();
    if repaired_hits > 0 {
        penalties.push("repaired-slice-evidence".into());
    }
    if baseline_candidate {
        penalties.push("baseline-surface-candidate".into());
    }
    penalties
}

fn variant_locality_notes(
    same_file_overlap: bool,
    family_overlap: bool,
    baseline_candidate: bool,
    no_local_vulnerable_source_likely: bool,
) -> Vec<String> {
    let mut notes = vec!["local neighbor scan from replay hits + fused evidence".into()];
    if same_file_overlap {
        notes.push("same-file-with-replay-seed".into());
    }
    if family_overlap {
        notes.push("family-pack-overlap-with-replay-seed".into());
    }
    if baseline_candidate {
        notes.push("baseline-surface-retained-with-penalty".into());
        if no_local_vulnerable_source_likely {
            notes.push("baseline-surface-boosted-because-local-source-is-unlikely".into());
        }
    }
    notes
}
