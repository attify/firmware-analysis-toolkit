use serde::{Deserialize, Serialize};

use crate::discovery::{DiscoveryLead, StateHypothesis};

use super::core::{build_protocol_machine, StateMachine};
use super::families::{lifetime, size, validation};

pub struct MachineFamilyRegistration {
    pub machine_id: &'static str,
    pub build_machine: fn(&StateHypothesis) -> Option<StateMachine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineSnapshot {
    pub hypothesis_id: String,
    pub machine: StateMachine,
}

const REGISTERED_FAMILIES: &[MachineFamilyRegistration] = &[
    MachineFamilyRegistration {
        machine_id: lifetime::MACHINE_ID,
        build_machine: lifetime::build_machine,
    },
    MachineFamilyRegistration {
        machine_id: size::MACHINE_ID,
        build_machine: size::build_machine,
    },
    MachineFamilyRegistration {
        machine_id: validation::MACHINE_ID,
        build_machine: validation::build_machine,
    },
    MachineFamilyRegistration {
        machine_id: "gpu-protocol-order-lifecycle",
        build_machine: build_protocol_machine,
    },
];

pub fn build_machines_for_lead(lead: &DiscoveryLead) -> Vec<StateMachine> {
    lead.state_hypotheses
        .iter()
        .filter_map(build_machine_for_hypothesis_entry)
        .collect()
}

pub fn build_machine_snapshots_for_lead(lead: &DiscoveryLead) -> Vec<StateMachineSnapshot> {
    lead.state_hypotheses
        .iter()
        .filter_map(|hypothesis| {
            let machine = build_machine_for_hypothesis_entry(hypothesis)?;
            Some(StateMachineSnapshot {
                hypothesis_id: hypothesis.hypothesis_id.clone(),
                machine,
            })
        })
        .collect()
}

pub fn registered_machine_ids() -> Vec<&'static str> {
    REGISTERED_FAMILIES
        .iter()
        .map(|family| family.machine_id)
        .collect()
}

pub(crate) fn build_machine_for_hypothesis_entry(
    hypothesis: &StateHypothesis,
) -> Option<StateMachine> {
    for family in REGISTERED_FAMILIES {
        if hypothesis.machine_id == family.machine_id {
            return (family.build_machine)(hypothesis);
        }
    }
    None
}
