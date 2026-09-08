use crate::discovery::DiscoveryLead;
use serde::{Deserialize, Serialize};

use super::registry::build_machine_for_hypothesis_entry;
use super::{StateMachine, StateMachineTransition};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoexistenceMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub transition_id: String,
    pub conflict_states: Vec<String>,
    pub event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationPathMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub source_actor: String,
    pub source_state: String,
    pub event_id: String,
    pub target_actor: String,
    pub invalidated_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPathMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub transition_id: String,
    pub source_state: String,
    pub target_state: String,
    pub event_id: String,
    pub expected_proof_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostStateMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub state_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateConditionMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub transition_id: String,
    pub required_state: String,
    pub event_id: String,
    pub target_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualTransitionMatch {
    pub lead_id: String,
    pub symbol: String,
    pub machine_id: String,
    pub hypothesis_id: String,
    pub transition_id: String,
    pub absent_guard: String,
    pub event_id: String,
    pub target_state: String,
}

pub type LifetimeCoexistenceMatch = CoexistenceMatch;
pub type LifetimeInvalidationPathMatch = InvalidationPathMatch;
pub type LifetimeEventPathMatch = EventPathMatch;
pub type ProtocolInvalidationPathMatch = InvalidationPathMatch;
pub type ProtocolEventPathMatch = EventPathMatch;
pub type SizeInvalidationPathMatch = InvalidationPathMatch;
pub type SizeEventPathMatch = EventPathMatch;
pub type ValidationInvalidationPathMatch = InvalidationPathMatch;
pub type ValidationEventPathMatch = EventPathMatch;

struct DerivedMachineMatch {
    lead_id: String,
    symbol: String,
    hypothesis_id: String,
    machine: StateMachine,
}

pub fn find_event_path_matches(
    leads: &[DiscoveryLead],
    machine_id: &str,
    event_id: &str,
) -> Vec<EventPathMatch> {
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            entry
                .machine
                .transitions
                .into_iter()
                .filter(|transition| transition.forbidden)
                .filter(|transition| transition.event_id == event_id)
                .map(move |transition| EventPathMatch {
                    lead_id: entry.lead_id.clone(),
                    symbol: entry.symbol.clone(),
                    machine_id: entry.machine.machine_id.clone(),
                    hypothesis_id: entry.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    source_state: transition.source_state.clone(),
                    target_state: transition.target_state.clone(),
                    event_id: transition.event_id.clone(),
                    expected_proof_class: transition.expected_proof_class.clone(),
                })
        })
        .collect()
}

pub fn find_ghost_state_matches(leads: &[DiscoveryLead], machine_id: &str) -> Vec<GhostStateMatch> {
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            let lead_id = entry.lead_id.clone();
            let symbol = entry.symbol.clone();
            let machine_id = entry.machine.machine_id.clone();
            let hypothesis_id = entry.hypothesis_id.clone();
            entry
                .machine
                .nodes
                .iter()
                .filter(|node| node.region_id == "ghost-states")
                .map(|node| GhostStateMatch {
                    lead_id: lead_id.clone(),
                    symbol: symbol.clone(),
                    machine_id: machine_id.clone(),
                    hypothesis_id: hypothesis_id.clone(),
                    state_id: node.state_id.clone(),
                    path: entry.machine.describe_state(&node.state_id),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn find_state_condition_matches(
    leads: &[DiscoveryLead],
    machine_id: &str,
    required_state: &str,
) -> Vec<StateConditionMatch> {
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            entry
                .machine
                .transitions
                .iter()
                .filter(|transition| {
                    transition
                        .required_states
                        .iter()
                        .any(|state| state == required_state)
                })
                .map(move |transition| StateConditionMatch {
                    lead_id: entry.lead_id.clone(),
                    symbol: entry.symbol.clone(),
                    machine_id: entry.machine.machine_id.clone(),
                    hypothesis_id: entry.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    required_state: required_state.to_string(),
                    event_id: transition.event_id.clone(),
                    target_state: transition.target_state.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn find_counterfactual_transition_matches(
    leads: &[DiscoveryLead],
    machine_id: &str,
    guard_id: Option<&str>,
) -> Vec<CounterfactualTransitionMatch> {
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            let lead_id = entry.lead_id.clone();
            let symbol = entry.symbol.clone();
            let machine_id = entry.machine.machine_id.clone();
            let hypothesis_id = entry.hypothesis_id.clone();
            entry
                .machine
                .transitions
                .iter()
                .filter(|transition| transition.forbidden)
                .flat_map(|transition| {
                    transition
                        .required_guards
                        .iter()
                        .filter(|guard| guard_id.map(|value| *guard == value).unwrap_or(true))
                        .map(|guard| CounterfactualTransitionMatch {
                            lead_id: lead_id.clone(),
                            symbol: symbol.clone(),
                            machine_id: machine_id.clone(),
                            hypothesis_id: hypothesis_id.clone(),
                            transition_id: transition.transition_id.clone(),
                            absent_guard: guard.clone(),
                            event_id: transition.event_id.clone(),
                            target_state: transition.target_state.clone(),
                        })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn find_invalidation_paths(
    leads: &[DiscoveryLead],
    machine_id: &str,
) -> Vec<InvalidationPathMatch> {
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            entry
                .machine
                .invalidation_edges
                .into_iter()
                .map(move |edge| InvalidationPathMatch {
                    lead_id: entry.lead_id.clone(),
                    symbol: entry.symbol.clone(),
                    machine_id: entry.machine.machine_id.clone(),
                    hypothesis_id: entry.hypothesis_id.clone(),
                    source_actor: edge.source_actor,
                    source_state: edge.source_state,
                    event_id: edge.event_id,
                    target_actor: edge.target_actor,
                    invalidated_state: edge.invalidated_state,
                })
        })
        .collect()
}

pub fn find_coexistence_candidates(
    leads: &[DiscoveryLead],
    machine_id: &str,
) -> Vec<CoexistenceMatch> {
    find_coexistence_candidates_with(leads, machine_id, |transition| {
        transition.forbidden && !transition.required_states.is_empty()
    })
}

pub fn find_lifetime_coexistence_candidates(
    leads: &[DiscoveryLead],
) -> Vec<LifetimeCoexistenceMatch> {
    find_coexistence_candidates_with(leads, "lifetime-reentrancy", |transition| {
        transition.forbidden
            && transition.target_state == "OwnerDestroyed"
            && !transition.required_states.is_empty()
    })
}

pub fn find_lifetime_invalidation_paths(
    leads: &[DiscoveryLead],
) -> Vec<LifetimeInvalidationPathMatch> {
    find_invalidation_paths(leads, "lifetime-reentrancy")
}

pub fn find_lifetime_event_path_matches(
    leads: &[DiscoveryLead],
    event_id: &str,
) -> Vec<LifetimeEventPathMatch> {
    find_event_path_matches(leads, "lifetime-reentrancy", event_id)
}

pub fn find_protocol_invalidation_paths(
    leads: &[DiscoveryLead],
) -> Vec<ProtocolInvalidationPathMatch> {
    find_invalidation_paths(leads, "gpu-protocol-order-lifecycle")
}

pub fn find_protocol_event_path_matches(
    leads: &[DiscoveryLead],
    event_id: &str,
) -> Vec<ProtocolEventPathMatch> {
    find_event_path_matches(leads, "gpu-protocol-order-lifecycle", event_id)
}

pub fn find_size_invalidation_paths(leads: &[DiscoveryLead]) -> Vec<SizeInvalidationPathMatch> {
    find_invalidation_paths(leads, "size-stride-arithmetic")
}

pub fn find_size_event_path_matches(
    leads: &[DiscoveryLead],
    event_id: &str,
) -> Vec<SizeEventPathMatch> {
    find_event_path_matches(leads, "size-stride-arithmetic", event_id)
}

pub fn find_validation_invalidation_paths(
    leads: &[DiscoveryLead],
) -> Vec<ValidationInvalidationPathMatch> {
    find_invalidation_paths(leads, "validation-trust-boundary")
}

pub fn find_validation_event_path_matches(
    leads: &[DiscoveryLead],
    event_id: &str,
) -> Vec<ValidationEventPathMatch> {
    find_event_path_matches(leads, "validation-trust-boundary", event_id)
}

fn derived_machines(leads: &[DiscoveryLead], machine_id: &str) -> Vec<DerivedMachineMatch> {
    leads
        .iter()
        .flat_map(|lead| {
            lead.state_hypotheses.iter().filter_map(|hypothesis| {
                let machine = build_machine_for_hypothesis_entry(hypothesis)?;
                if machine.machine_id != machine_id {
                    return None;
                }
                Some(DerivedMachineMatch {
                    lead_id: lead.lead_id.clone(),
                    symbol: lead.symbol.clone(),
                    hypothesis_id: hypothesis.hypothesis_id.clone(),
                    machine,
                })
            })
        })
        .collect()
}

fn find_coexistence_candidates_with<F>(
    leads: &[DiscoveryLead],
    machine_id: &str,
    predicate: F,
) -> Vec<CoexistenceMatch>
where
    F: Fn(&StateMachineTransition) -> bool,
{
    derived_machines(leads, machine_id)
        .into_iter()
        .flat_map(|entry| {
            entry
                .machine
                .transitions
                .iter()
                .filter(|transition| predicate(transition))
                .map(move |transition| CoexistenceMatch {
                    lead_id: entry.lead_id.clone(),
                    symbol: entry.symbol.clone(),
                    machine_id: entry.machine.machine_id.clone(),
                    hypothesis_id: entry.hypothesis_id.clone(),
                    transition_id: transition.transition_id.clone(),
                    conflict_states: transition.required_states.clone(),
                    event_id: transition.event_id.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
