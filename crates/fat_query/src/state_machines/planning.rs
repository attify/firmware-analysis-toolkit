use crate::discovery::{DiscoveryLead, StateHypothesis};

use super::core::StateMachine;
use super::registry::build_machine_for_hypothesis_entry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTransitionSelection {
    pub machine_id: String,
    pub hypothesis_id: String,
    pub transition_id: String,
    pub event_id: String,
    pub source_state: String,
    pub target_state: String,
    pub required_states: Vec<String>,
    pub expected_proof_class: Option<String>,
    pub rationale: Vec<String>,
}

impl MachineTransitionSelection {
    pub fn attempted_transition_summary(&self) -> String {
        if self.required_states.is_empty() {
            return format!(
                "{} {} --{}--> {}",
                self.machine_id, self.source_state, self.event_id, self.target_state
            );
        }
        format!(
            "{} {} --{}--> {} while {}",
            self.machine_id,
            self.source_state,
            self.event_id,
            self.target_state,
            self.required_states.join(" + ")
        )
    }
}

pub fn select_transition_for_lead(
    lead: &DiscoveryLead,
    expected_proof_classes: &[String],
) -> Option<MachineTransitionSelection> {
    for hypothesis in &lead.state_hypotheses {
        if let Some(machine) = build_machine_for_hypothesis_entry(hypothesis) {
            if let Some(selection) =
                select_transition_from_machine(&machine, hypothesis, expected_proof_classes)
            {
                return Some(selection);
            }
        } else if let Some(first_transition) = hypothesis.forbidden_transitions.first() {
            return Some(MachineTransitionSelection {
                machine_id: hypothesis.machine_id.clone(),
                hypothesis_id: hypothesis.hypothesis_id.clone(),
                transition_id: first_transition.transition_id.clone(),
                event_id: "GenericEvent".into(),
                source_state: "Unknown".into(),
                target_state: "Unknown".into(),
                required_states: Vec::new(),
                expected_proof_class: Some(first_transition.expected_proof_class.clone()),
                rationale: first_transition.rationale.clone(),
            });
        }
    }
    None
}

fn select_transition_from_machine(
    machine: &StateMachine,
    hypothesis: &StateHypothesis,
    expected_proof_classes: &[String],
) -> Option<MachineTransitionSelection> {
    let matched = machine
        .transitions
        .iter()
        .filter(|transition| transition.forbidden)
        .find(|transition| {
            expected_proof_classes.is_empty()
                || transition
                    .expected_proof_class
                    .as_ref()
                    .is_some_and(|expected| {
                        expected_proof_classes.iter().any(|value| value == expected)
                    })
        })
        .or_else(|| {
            machine
                .transitions
                .iter()
                .find(|transition| transition.forbidden)
        })?;

    Some(MachineTransitionSelection {
        machine_id: machine.machine_id.clone(),
        hypothesis_id: hypothesis.hypothesis_id.clone(),
        transition_id: matched.transition_id.clone(),
        event_id: matched.event_id.clone(),
        source_state: machine.describe_state(&matched.source_state),
        target_state: machine.describe_state(&matched.target_state),
        required_states: matched
            .required_states
            .iter()
            .map(|state| machine.describe_state(state))
            .collect(),
        expected_proof_class: matched.expected_proof_class.clone(),
        rationale: matched.rationale.clone(),
    })
}
