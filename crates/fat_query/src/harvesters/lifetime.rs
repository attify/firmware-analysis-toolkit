use crate::derived::{fact_grouping_key, group_facts_by_subject};
use crate::discovery::BugFamily;
use crate::harvesters::{HarvestReport, HarvestedCandidate};
use crate::result::{DerivedAnalysis, FusedSourceEvidence, LocalityStatus, RollResolution};
use sha2::{Digest, Sha256};

const REQUIRED: &[&str] = &[
    "lifetime_sensitive_method",
    "callback_or_teardown_call_present",
];
const SUPPRESSORS: &[&str] = &[
    "cleanup_only_teardown",
    "safe_invalidation_guard",
    "explicit_cancellation_guard",
];

pub fn harvest(
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
) -> HarvestReport {
    let grouped = group_facts_by_subject(derived);
    let mut emitted = Vec::new();
    let mut suppressed = Vec::new();

    for method in &fused.methods {
        let key = fact_grouping_key(&method.qualified_name, Some(&method.file));
        let facts = grouped
            .get(&key)
            .or_else(|| grouped.get(&method.qualified_name))
            .cloned()
            .unwrap_or_default();
        let fact_kinds = facts
            .iter()
            .map(|fact| fact.kind.as_str())
            .collect::<Vec<_>>();
        if !REQUIRED.iter().all(|kind| fact_kinds.contains(kind)) {
            continue;
        }

        let suppression_reasons = SUPPRESSORS
            .iter()
            .filter(|kind| fact_kinds.contains(kind))
            .map(|kind| (*kind).to_string())
            .collect::<Vec<_>>();

        let mut role_overlap = vec![
            "lifetime-sensitive-method".to_string(),
            "callback-teardown".to_string(),
        ];
        if method
            .qualified_name
            .to_ascii_lowercase()
            .contains("observer")
        {
            role_overlap.push("observer-mutation".to_string());
        }

        let candidate = HarvestedCandidate {
            symbol: method.qualified_name.clone(),
            family: BugFamily::LifetimeReentrancy,
            score: 50 + (role_overlap.len() as i32 * 3),
            fingerprint: fingerprint(&method.qualified_name, &role_overlap),
            role_overlap,
            family_overlap: vec![BugFamily::LifetimeReentrancy.benchmark_family().to_string()],
            locality_notes: vec![locality_note(locality)],
            suppression_reasons,
        };

        if candidate.suppression_reasons.is_empty() {
            emitted.push(candidate);
        } else {
            suppressed.push(candidate);
        }
    }

    emitted.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    suppressed.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    HarvestReport {
        emitted,
        suppressed,
    }
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

fn fingerprint(symbol: &str, roles: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(symbol.as_bytes());
    for role in roles {
        hasher.update(role.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
