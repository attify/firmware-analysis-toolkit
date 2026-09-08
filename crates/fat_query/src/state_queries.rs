use crate::discovery::{BugFamily, DiscoveryLead, StateHypothesis};
use crate::result::LocalityStatus;
pub use crate::state_machines::{
    find_coexistence_candidates, find_counterfactual_transition_matches, find_event_path_matches,
    find_ghost_state_matches, find_invalidation_paths, find_lifetime_coexistence_candidates,
    find_lifetime_event_path_matches, find_lifetime_invalidation_paths,
    find_protocol_event_path_matches, find_protocol_invalidation_paths,
    find_size_event_path_matches, find_size_invalidation_paths, find_state_condition_matches,
    find_validation_event_path_matches, find_validation_invalidation_paths, CoexistenceMatch,
    CounterfactualTransitionMatch, EventPathMatch, GhostStateMatch, InvalidationPathMatch,
    LifetimeCoexistenceMatch, LifetimeEventPathMatch, LifetimeInvalidationPathMatch,
    ProtocolEventPathMatch, ProtocolInvalidationPathMatch, SizeEventPathMatch,
    SizeInvalidationPathMatch, StateConditionMatch, ValidationEventPathMatch,
    ValidationInvalidationPathMatch,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransitionMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub forbidden_transition_id: String,
    pub expected_proof_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalityPolicyMatch {
    pub lead_id: String,
    pub symbol: String,
    pub locality: String,
    pub hypothesis_id: String,
    pub blocked_widening: bool,
}

pub fn find_lifetime_invalidation_candidates(leads: &[DiscoveryLead]) -> Vec<StateTransitionMatch> {
    find_family_transition_matches(leads, BugFamily::LifetimeReentrancy)
}

pub fn find_size_mismatch_candidates(leads: &[DiscoveryLead]) -> Vec<StateTransitionMatch> {
    find_family_transition_matches(leads, BugFamily::SizeStrideArithmetic)
}

pub fn find_protocol_order_candidates(leads: &[DiscoveryLead]) -> Vec<StateTransitionMatch> {
    find_family_transition_matches(leads, BugFamily::GpuProtocolOrderLifecycle)
}

pub fn find_validation_gap_candidates(leads: &[DiscoveryLead]) -> Vec<StateTransitionMatch> {
    find_family_transition_matches(leads, BugFamily::ValidationTrustBoundary)
}

pub fn find_locality_policy_candidates(leads: &[DiscoveryLead]) -> Vec<LocalityPolicyMatch> {
    leads
        .iter()
        .flat_map(|lead| {
            lead.state_hypotheses.iter().filter_map(|hypothesis| {
                let blocked_widening = matches!(
                    lead.locality,
                    LocalityStatus::UpstreamHidden | LocalityStatus::UpstreamReferenced
                );
                if !blocked_widening {
                    return None;
                }
                Some(LocalityPolicyMatch {
                    lead_id: lead.lead_id.clone(),
                    symbol: lead.symbol.clone(),
                    locality: format!("{:?}", lead.locality),
                    hypothesis_id: hypothesis.hypothesis_id.clone(),
                    blocked_widening,
                })
            })
        })
        .collect()
}

fn find_family_transition_matches(
    leads: &[DiscoveryLead],
    family: BugFamily,
) -> Vec<StateTransitionMatch> {
    leads
        .iter()
        .filter(|lead| lead.family == family)
        .flat_map(|lead| {
            lead.state_hypotheses
                .iter()
                .flat_map(move |hypothesis| transition_matches_for_hypothesis(lead, hypothesis))
        })
        .collect()
}

fn transition_matches_for_hypothesis(
    lead: &DiscoveryLead,
    hypothesis: &StateHypothesis,
) -> Vec<StateTransitionMatch> {
    hypothesis
        .forbidden_transitions
        .iter()
        .map(|transition| StateTransitionMatch {
            lead_id: lead.lead_id.clone(),
            symbol: lead.symbol.clone(),
            machine_id: hypothesis.machine_id.clone(),
            hypothesis_id: hypothesis.hypothesis_id.clone(),
            forbidden_transition_id: transition.transition_id.clone(),
            expected_proof_class: transition.expected_proof_class.clone(),
        })
        .collect()
}
