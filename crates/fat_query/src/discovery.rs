use crate::derived::{fact_grouping_key, group_facts_by_subject};
use crate::harvesters::harvest_family_candidates;
use crate::replay::rank_replay_candidates;
use crate::result::{
    DerivedAnalysis, DerivedFact, EvidenceBasis, FusedSourceEvidence, LocalityStatus,
    RollResolution, ScoreTrace, VariantLead,
};
use crate::variant_hunter::hunt_variants;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BugFamily {
    LifetimeReentrancy,
    SizeStrideArithmetic,
    GpuProtocolOrderLifecycle,
    ValidationTrustBoundary,
}

impl BugFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            BugFamily::LifetimeReentrancy => "lifetime-reentrancy",
            BugFamily::SizeStrideArithmetic => "size-stride-arithmetic",
            BugFamily::GpuProtocolOrderLifecycle => "gpu-protocol-order-lifecycle",
            BugFamily::ValidationTrustBoundary => "validation-trust-boundary",
        }
    }

    pub fn benchmark_family(&self) -> &'static str {
        match self {
            BugFamily::LifetimeReentrancy => "lifetime-ownership",
            BugFamily::SizeStrideArithmetic => "bounds-size-arithmetic",
            BugFamily::GpuProtocolOrderLifecycle => "gpu-protocol-order-lifecycle",
            BugFamily::ValidationTrustBoundary => "validation-policy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "lifetime-reentrancy" | "lifetime" | "lifetime-ownership" => {
                Some(BugFamily::LifetimeReentrancy)
            }
            "size-stride-arithmetic" | "size" | "bounds-size-arithmetic" => {
                Some(BugFamily::SizeStrideArithmetic)
            }
            "gpu-protocol-order-lifecycle" | "gpu-protocol-order" | "gpu-protocol" => {
                Some(BugFamily::GpuProtocolOrderLifecycle)
            }
            "validation-trust-boundary" | "validation" | "validation-policy" => {
                Some(BugFamily::ValidationTrustBoundary)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisScope {
    OriginalSlice,
    RepairedSlice,
    WholeTu,
    VendoredNeighbor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateStatus {
    Primary,
    Sibling,
    VendoredSibling,
    BlockedByLocality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleMatch {
    pub role: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingCandidate {
    pub symbol: String,
    pub fingerprint: String,
    pub score: i32,
    pub candidate_status: CandidateStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerRecipeStep {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredEnvironment {
    pub execution_mode: String,
    #[serde(default)]
    pub platform_constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSignal {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForbiddenTransitionRef {
    pub transition_id: String,
    pub expected_proof_class: String,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateHypothesis {
    pub hypothesis_id: String,
    pub machine_id: String,
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default)]
    pub active_regions: Vec<String>,
    #[serde(default)]
    pub key_states: Vec<String>,
    #[serde(default)]
    pub ghost_states: Vec<String>,
    #[serde(default)]
    pub invalidating_events: Vec<String>,
    #[serde(default)]
    pub required_guards: Vec<String>,
    #[serde(default)]
    pub forbidden_transitions: Vec<ForbiddenTransitionRef>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryLead {
    pub lead_id: String,
    pub symbol: String,
    pub family: BugFamily,
    pub family_confidence: f32,
    pub family_pack_version: String,
    pub analysis_scope: AnalysisScope,
    pub candidate_status: CandidateStatus,
    #[serde(default)]
    pub matched_roles: Vec<RoleMatch>,
    #[serde(default)]
    pub why_matched: Vec<String>,
    #[serde(default)]
    pub evidence_basis: Vec<EvidenceBasis>,
    pub locality: LocalityStatus,
    #[serde(default)]
    pub sibling_candidates: Vec<SiblingCandidate>,
    #[serde(default)]
    pub suggested_trigger_recipe: Vec<TriggerRecipeStep>,
    pub required_environment: RequiredEnvironment,
    #[serde(default)]
    pub expected_proof_signal: Vec<ProofSignal>,
    #[serde(default)]
    pub state_hypotheses: Vec<StateHypothesis>,
    pub score_trace: ScoreTrace,
}

struct FamilySpec<'a> {
    family: BugFamily,
    version: &'a str,
    primary_fact_kinds: &'a [&'a str],
    min_primary_matches: usize,
    booster_fact_kinds: &'a [&'a str],
    suppressor_fact_kinds: &'a [&'a str],
    role_map: &'a [(&'a str, &'a str)],
    trigger_recipes: &'a [(&'a str, &'a str)],
    proof_signals: &'a [(&'a str, &'a str)],
    execution_mode: &'a str,
    platform_constraints: &'a [&'a str],
    actors: &'a [&'a str],
    active_regions: &'a [&'a str],
    key_states: &'a [&'a str],
    ghost_states: &'a [&'a str],
    required_guards: &'a [&'a str],
}

pub fn build_discovery_leads(
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
) -> Vec<DiscoveryLead> {
    let grouped = group_facts_by_subject(derived);
    let mut leads = Vec::new();

    for method in &fused.methods {
        let key = fact_grouping_key(&method.qualified_name, Some(&method.file));
        let facts = grouped
            .get(&key)
            .or_else(|| grouped.get(&method.qualified_name))
            .cloned()
            .unwrap_or_default();

        for spec in family_specs() {
            if let Some(lead) = build_lead_for_method(method, &facts, locality, spec) {
                leads.push(lead);
            }
        }
    }

    leads.sort_by(|left, right| {
        right
            .family_confidence
            .partial_cmp(&left.family_confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });

    // Deduplicate by lead_id
    let mut seen = std::collections::HashSet::new();
    leads.retain(|lead| seen.insert(lead.lead_id.clone()));

    leads
}

pub fn attach_siblings(
    leads: &mut [DiscoveryLead],
    variant_leads: &[VariantLead],
    locality: &RollResolution,
    top_k: usize,
) {
    for lead in leads.iter_mut() {
        let siblings = variant_leads
            .iter()
            .filter(|candidate| candidate.symbol != lead.symbol)
            .take(top_k)
            .map(|candidate| SiblingCandidate {
                symbol: candidate.symbol.clone(),
                fingerprint: candidate.fingerprint.clone(),
                score: candidate.score,
                candidate_status: if candidate.symbol.starts_with("vendored-neighborhood:") {
                    CandidateStatus::VendoredSibling
                } else {
                    CandidateStatus::Sibling
                },
            })
            .collect::<Vec<_>>();

        if siblings.is_empty()
            && !locality.allow_vendored_scan
            && locality.no_local_vulnerable_source_likely
        {
            lead.candidate_status = CandidateStatus::BlockedByLocality;
            lead.score_trace
                .penalties
                .push("vendored-expansion-blocked".into());
        }

        if siblings
            .iter()
            .any(|candidate| candidate.candidate_status == CandidateStatus::VendoredSibling)
        {
            lead.score_trace
                .locality_notes
                .push("vendored-sibling-attached".into());
        }

        lead.sibling_candidates = siblings;
    }
}

pub fn populate_sibling_candidates(
    leads: &mut [DiscoveryLead],
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
    top_k: usize,
) {
    for lead in leads.iter_mut() {
        let replay = rank_replay_candidates(
            std::slice::from_ref(&lead.symbol),
            fused,
            derived,
            std::slice::from_ref(&lead.symbol),
        );
        let variants = hunt_variants(
            &replay,
            fused,
            derived,
            locality,
            std::slice::from_ref(&lead.symbol),
            1,
        );
        attach_siblings(std::slice::from_mut(lead), &variants, locality, top_k);
    }
}

pub fn populate_harvested_sibling_candidates(
    leads: &mut [DiscoveryLead],
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
    top_k: usize,
) {
    for lead in leads.iter_mut() {
        let report = harvest_family_candidates(lead.family.clone(), fused, derived, locality);
        let mut seen = lead
            .sibling_candidates
            .iter()
            .map(|candidate| candidate.symbol.clone())
            .collect::<BTreeSet<_>>();
        let mut harvested = report
            .emitted
            .into_iter()
            .filter(|candidate| candidate.symbol != lead.symbol)
            .filter(|candidate| seen.insert(candidate.symbol.clone()))
            .take(top_k)
            .map(|candidate| SiblingCandidate {
                symbol: candidate.symbol,
                fingerprint: candidate.fingerprint,
                score: candidate.score,
                candidate_status: CandidateStatus::Sibling,
            })
            .collect::<Vec<_>>();
        lead.sibling_candidates.append(&mut harvested);
        if !report.suppressed.is_empty() {
            lead.score_trace
                .penalties
                .push("suppressed-harvester-negative-present".into());
        }
    }
}

pub fn dedup_discovery_leads(leads: Vec<DiscoveryLead>) -> Vec<DiscoveryLead> {
    let mut seen = std::collections::HashSet::new();
    leads
        .into_iter()
        .filter(|lead| seen.insert(lead.lead_id.clone()))
        .collect()
}

pub fn filter_leads_by_family(
    leads: Vec<DiscoveryLead>,
    family: Option<BugFamily>,
) -> Vec<DiscoveryLead> {
    match family {
        Some(family) => leads
            .into_iter()
            .filter(|lead| lead.family == family)
            .collect(),
        None => leads,
    }
}

fn family_specs<'a>() -> [FamilySpec<'a>; 4] {
    [
        FamilySpec {
            family: BugFamily::LifetimeReentrancy,
            version: "lifetime-pack-v1",
            primary_fact_kinds: &[
                "lifetime_sensitive_method",
                "callback_or_teardown_call_present",
                "ownership_transfer_call_present",
                "post_handoff_observer_present",
            ],
            min_primary_matches: 2,
            booster_fact_kinds: &[
                "deferred_or_pending_state_present",
                "stale_subject_reuse_risk",
            ],
            suppressor_fact_kinds: &[
                "safe_invalidation_guard",
                "explicit_cancellation_guard",
                "cleanup_only_teardown",
                "explicit_shutdown_path",
                "single_shot_callback",
            ],
            role_map: &[
                ("lifetime_sensitive_method", "lifetime-sensitive-method"),
                ("callback_or_teardown_call_present", "callback-teardown"),
                ("ownership_transfer_call_present", "ownership-transfer"),
                ("post_handoff_observer_present", "post-handoff-observer"),
                ("deferred_or_pending_state_present", "deferred-pending"),
                ("stale_subject_reuse_risk", "stale-subject-risk"),
            ],
            trigger_recipes: &[
                (
                    "destroy-owner-during-callback",
                    "destroy or tear down the owner before callback completion",
                ),
                (
                    "observer-mutation-during-iteration",
                    "mutate the observer/container while callback iteration is still active",
                ),
                (
                    "handoff-then-report-stale-subject",
                    "hand off or defer the subject, then observe or report fields from the old subject view",
                ),
            ],
            proof_signals: &[
                (
                    "asan-use-after-free",
                    "callback path dereferences a stale owner",
                ),
                (
                    "stale-callback-context-crash",
                    "callback or completion path reaches torn-down state",
                ),
            ],
            execution_mode: "re-entrancy-state-machine",
            platform_constraints: &["asan"],
            actors: &["Owner", "Callback", "Request"],
            active_regions: &["lifecycle"],
            key_states: &["CallbackPending", "OwnerDestroyed"],
            ghost_states: &["OwnerAlive", "CallbackMayFire"],
            required_guards: &["safe_invalidation_guard", "explicit_cancellation_guard"],
        },
        FamilySpec {
            family: BugFamily::SizeStrideArithmetic,
            version: "size-pack-v1",
            primary_fact_kinds: &["allocation_call_present", "copy_call_present"],
            min_primary_matches: 2,
            booster_fact_kinds: &["stride_pitch_depth_role", "buffer_or_subimage_method"],
            suppressor_fact_kinds: &[
                "dominating_size_guard",
                "safe_math_wrapper",
                "bounds_checked_copy",
                "shape_consistent_copy",
            ],
            role_map: &[
                ("allocation_call_present", "allocation-size"),
                ("copy_call_present", "copy-size"),
                ("stride_pitch_depth_role", "pitch-stride-depth"),
                ("buffer_or_subimage_method", "buffer-shape-surface"),
            ],
            trigger_recipes: &[
                (
                    "pitch-depth-mismatch",
                    "make payload size smaller than metadata-implied pitch/depth copy size",
                ),
                (
                    "shape-channel-mismatch",
                    "vary logical shape/channels so allocation and copy paths diverge",
                ),
            ],
            proof_signals: &[
                (
                    "asan-heap-buffer-overflow",
                    "copy or upload path exceeds the allocation-sized backing store",
                ),
                (
                    "ubsan-integer-overflow",
                    "size arithmetic overflows before allocation or copy occurs",
                ),
            ],
            execution_mode: "shape-size-boundary",
            platform_constraints: &["asan", "ubsan"],
            actors: &["Buffer", "Shape", "Copy"],
            active_regions: &["allocation-vs-copy"],
            key_states: &["Allocated", "CopyPending"],
            ghost_states: &["AllocSizeKnown", "GuardDominatesCopy"],
            required_guards: &["dominating_size_guard", "safe_math_wrapper"],
        },
        FamilySpec {
            family: BugFamily::GpuProtocolOrderLifecycle,
            version: "protocol-pack-v1",
            primary_fact_kinds: &["gpu_protocol_lifecycle_method", "gpu_ordering_call_present"],
            min_primary_matches: 2,
            booster_fact_kinds: &["gpu_async_callback_present"],
            suppressor_fact_kinds: &["explicit_state_guard", "single_phase_cleanup"],
            role_map: &[
                ("gpu_protocol_lifecycle_method", "gpu-protocol-lifecycle"),
                ("gpu_ordering_call_present", "map-submit-destroy"),
                ("gpu_async_callback_present", "async-completion"),
            ],
            trigger_recipes: &[
                (
                    "map-then-destroy-before-completion",
                    "map or submit work, then destroy the owner before async completion drains",
                ),
                (
                    "device-loss-during-submit",
                    "force device loss or submission failure while async work is still pending",
                ),
            ],
            proof_signals: &[
                (
                    "guard-trip",
                    "protocol ordering or device lifecycle guard trips before completion",
                ),
                (
                    "asan-use-after-free",
                    "async completion reaches torn-down GPU state",
                ),
            ],
            execution_mode: "gpu-protocol-order",
            platform_constraints: &["asan", "gpu"],
            actors: &["Device", "Buffer", "EventManager"],
            active_regions: &["protocol-order"],
            key_states: &["Mapped", "CompletionPending"],
            ghost_states: &["MappedBufferStillValid", "DeviceAlive"],
            required_guards: &["explicit_state_guard"],
        },
        FamilySpec {
            family: BugFamily::ValidationTrustBoundary,
            version: "validation-pack-v1",
            primary_fact_kinds: &["validation_or_permission_method", "permission_gate_present"],
            min_primary_matches: 2,
            booster_fact_kinds: &["trust_boundary_action_present", "bad_message_path_present"],
            suppressor_fact_kinds: &["dominating_validation_guard", "origin_checked_action"],
            role_map: &[
                ("validation_or_permission_method", "validation-method"),
                ("permission_gate_present", "permission-gate"),
                ("trust_boundary_action_present", "trust-boundary-action"),
                ("bad_message_path_present", "bad-message-path"),
            ],
            trigger_recipes: &[
                (
                    "malformed-boundary-payload",
                    "send malformed input across the trust boundary and observe validation failure",
                ),
                (
                    "permission-state-mismatch",
                    "desynchronize permission or origin state before the trusted action runs",
                ),
            ],
            proof_signals: &[
                (
                    "bad-message",
                    "validation failure rejects the remote input as a bad message",
                ),
                (
                    "guard-trip",
                    "trust-boundary guard trips before the privileged action completes",
                ),
            ],
            execution_mode: "trust-boundary-validation",
            platform_constraints: &["asan", "ipc"],
            actors: &["Input", "Validator", "Action"],
            active_regions: &["validation"],
            key_states: &["Parsed", "ActuationPending"],
            ghost_states: &["ValidationDominatesUse", "PermissionFresh"],
            required_guards: &["dominating_validation_guard", "origin_checked_action"],
        },
    ]
}

fn build_lead_for_method(
    method: &crate::result::SourceMethodFact,
    facts: &[DerivedFact],
    locality: &RollResolution,
    spec: FamilySpec<'_>,
) -> Option<DiscoveryLead> {
    let matched_primary_kinds = spec
        .primary_fact_kinds
        .iter()
        .filter(|kind| facts.iter().any(|fact| fact.kind == **kind))
        .count();
    let matched_facts = facts
        .iter()
        .filter(|fact| spec.primary_fact_kinds.contains(&fact.kind.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let booster_facts = facts
        .iter()
        .filter(|fact| spec.booster_fact_kinds.contains(&fact.kind.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let suppressors = facts
        .iter()
        .filter(|fact| spec.suppressor_fact_kinds.contains(&fact.kind.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    if matched_facts.is_empty() {
        return None;
    }
    if matched_primary_kinds < spec.min_primary_matches {
        return None;
    }
    if !suppressors.is_empty() {
        return None;
    }

    let matched_roles = collect_role_matches(facts, spec.role_map);
    let trigger_recipe = spec
        .trigger_recipes
        .iter()
        .map(|(kind, detail)| TriggerRecipeStep {
            kind: (*kind).into(),
            detail: (*detail).into(),
        })
        .collect::<Vec<_>>();
    let proof_signals = spec
        .proof_signals
        .iter()
        .map(|(kind, detail)| ProofSignal {
            kind: (*kind).into(),
            detail: (*detail).into(),
        })
        .collect::<Vec<_>>();
    if matched_roles.is_empty() || trigger_recipe.is_empty() || proof_signals.is_empty() {
        return None;
    }

    let primary_count = matched_facts.len();
    let booster_count = booster_facts.len();
    let score = primary_count * 2 + booster_count;
    if score < 3 {
        return None;
    }

    let evidence_basis = dedup_evidence_basis(facts);
    let family_confidence = ((score as f32) / 10.0).min(0.99);
    let lead_id = discovery_fingerprint(&method.qualified_name, &method.file, &spec.family);
    let state_hypotheses =
        build_state_hypotheses(&lead_id, &spec, family_confidence, &matched_roles);

    Some(DiscoveryLead {
        lead_id: lead_id.clone(),
        symbol: method.qualified_name.clone(),
        family: spec.family.clone(),
        family_confidence,
        family_pack_version: spec.version.into(),
        analysis_scope: derive_analysis_scope(facts),
        candidate_status: CandidateStatus::Primary,
        matched_roles,
        why_matched: matched_facts
            .iter()
            .chain(booster_facts.iter())
            .map(|fact| fact.detail.clone())
            .collect(),
        evidence_basis,
        locality: locality.locality.clone(),
        sibling_candidates: Vec::new(),
        suggested_trigger_recipe: trigger_recipe,
        required_environment: RequiredEnvironment {
            execution_mode: spec.execution_mode.into(),
            platform_constraints: spec
                .platform_constraints
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        },
        expected_proof_signal: proof_signals,
        state_hypotheses,
        score_trace: ScoreTrace {
            adapters: Vec::new(),
            family_pack_hits: facts.iter().map(|fact| fact.kind.clone()).collect(),
            penalties: Vec::new(),
            locality_notes: vec![format!(
                "locality={}",
                locality_note(locality.locality.clone())
            )],
        },
    })
}

fn build_state_hypotheses(
    lead_id: &str,
    spec: &FamilySpec<'_>,
    confidence: f32,
    matched_roles: &[RoleMatch],
) -> Vec<StateHypothesis> {
    let forbidden_transitions = spec
        .trigger_recipes
        .iter()
        .zip(spec.proof_signals.iter().cycle())
        .map(
            |((transition_id, detail), (proof_class, _))| ForbiddenTransitionRef {
                transition_id: (*transition_id).to_string(),
                expected_proof_class: (*proof_class).to_string(),
                rationale: vec![(*detail).to_string()],
            },
        )
        .collect::<Vec<_>>();

    // Base ghost states from the family spec
    let mut ghost_states: Vec<String> = spec
        .ghost_states
        .iter()
        .map(|value| (*value).to_string())
        .collect();

    // Add role-derived ghost states for specificity
    for role in matched_roles {
        let ghost = format!("RolePresent:{}", role.role);
        if !ghost_states.contains(&ghost) {
            ghost_states.push(ghost);
        }
    }

    // Key states include matched role names for distinguishability
    let mut key_states: Vec<String> = spec
        .key_states
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    for role in matched_roles {
        if !key_states.contains(&role.role) {
            key_states.push(role.role.clone());
        }
    }

    vec![StateHypothesis {
        hypothesis_id: format!("{lead_id}::h0"),
        machine_id: spec.family.as_str().to_string(),
        actors: spec
            .actors
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        active_regions: spec
            .active_regions
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        key_states,
        ghost_states,
        invalidating_events: spec
            .trigger_recipes
            .iter()
            .map(|(kind, _)| (*kind).to_string())
            .collect(),
        required_guards: spec
            .required_guards
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        forbidden_transitions,
        confidence,
    }]
}

fn collect_role_matches(facts: &[DerivedFact], role_map: &[(&str, &str)]) -> Vec<RoleMatch> {
    let mut seen = BTreeSet::new();
    facts
        .iter()
        .filter_map(|fact| {
            role_map.iter().find_map(|(kind, role)| {
                if fact.kind == *kind && seen.insert((*role).to_string()) {
                    Some(RoleMatch {
                        role: (*role).into(),
                        detail: fact.detail.clone(),
                    })
                } else {
                    None
                }
            })
        })
        .collect()
}

fn dedup_evidence_basis(facts: &[DerivedFact]) -> Vec<EvidenceBasis> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for fact in facts {
        let key = format!("{:?}", fact.evidence_basis);
        if seen.insert(key) {
            values.push(fact.evidence_basis.clone());
        }
    }
    values
}

fn derive_analysis_scope(facts: &[DerivedFact]) -> AnalysisScope {
    if facts.iter().any(|fact| {
        matches!(
            fact.evidence_basis,
            EvidenceBasis::InferredFromRepairedSlice
        )
    }) {
        AnalysisScope::RepairedSlice
    } else {
        AnalysisScope::OriginalSlice
    }
}

fn discovery_fingerprint(symbol: &str, file: &Path, family: &BugFamily) -> String {
    let mut hasher = Sha256::new();
    hasher.update(symbol.as_bytes());
    hasher.update(file.to_string_lossy().as_bytes());
    hasher.update(format!("{family:?}").as_bytes());
    format!("{:x}", hasher.finalize())
}

fn locality_note(locality: LocalityStatus) -> &'static str {
    match locality {
        LocalityStatus::RepoLocal => "repo-local",
        LocalityStatus::VendoredLocal => "vendored-local",
        LocalityStatus::Generated => "generated",
        LocalityStatus::UpstreamReferenced => "upstream-referenced",
        LocalityStatus::UpstreamHidden => "upstream-hidden",
        LocalityStatus::Unknown => "unknown",
    }
}
