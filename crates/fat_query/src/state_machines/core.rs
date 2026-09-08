use crate::discovery::{ForbiddenTransitionRef, StateHypothesis};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateRegionMode {
    Exclusive,
    Parallel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachine {
    pub machine_id: String,
    pub actors: Vec<String>,
    pub regions: Vec<StateRegion>,
    pub nodes: Vec<StateNode>,
    pub events: Vec<StateEvent>,
    pub transitions: Vec<StateMachineTransition>,
    pub invalidation_edges: Vec<InvalidationEdge>,
}

impl StateMachine {
    pub fn describe_state(&self, state_id: &str) -> String {
        let mut path = vec![state_id.to_string()];
        let mut current = self.nodes.iter().find(|node| node.state_id == state_id);
        let mut region_id = None;
        while let Some(node) = current {
            region_id = Some(node.region_id.clone());
            if let Some(parent_state) = node.parent_state.as_ref() {
                path.push(parent_state.clone());
                current = self
                    .nodes
                    .iter()
                    .find(|candidate| candidate.state_id == *parent_state);
            } else {
                break;
            }
        }
        path.reverse();
        match region_id {
            Some(region_id) => format!("{}/{}", region_id, path.join("/")),
            None => state_id.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRegion {
    pub region_id: String,
    pub mode: StateRegionMode,
    pub parallel_group: Option<String>,
    pub states: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateNode {
    pub state_id: String,
    pub region_id: String,
    pub parent_state: Option<String>,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEvent {
    pub event_id: String,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineTransition {
    pub transition_id: String,
    pub event_id: String,
    pub source_state: String,
    pub target_state: String,
    pub required_states: Vec<String>,
    pub required_guards: Vec<String>,
    pub expected_proof_class: Option<String>,
    pub rationale: Vec<String>,
    pub forbidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEdge {
    pub source_actor: String,
    pub source_state: String,
    pub event_id: String,
    pub target_actor: String,
    pub invalidated_state: String,
}

const PROTOCOL_MACHINE_ID: &str = "gpu-protocol-order-lifecycle";

pub fn build_protocol_machine(hypothesis: &StateHypothesis) -> Option<StateMachine> {
    if hypothesis.machine_id != PROTOCOL_MACHINE_ID {
        return None;
    }

    let mut regions = vec![
        StateRegion {
            region_id: "device-lifecycle".into(),
            mode: StateRegionMode::Exclusive,
            parallel_group: Some("protocol-lifecycle".into()),
            states: vec![
                "DeviceOperational".into(),
                "DeviceReady".into(),
                "DeviceLost".into(),
            ],
        },
        StateRegion {
            region_id: "mapping-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("protocol-lifecycle".into()),
            states: vec![
                "MapLifecycle".into(),
                "MapPending".into(),
                "MapCompleted".into(),
            ],
        },
        StateRegion {
            region_id: "completion-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("protocol-lifecycle".into()),
            states: vec![
                "CompletionLifecycle".into(),
                "CompletionPending".into(),
                "CompletionDrained".into(),
            ],
        },
    ];
    let mut nodes = vec![
        node(
            "DeviceOperational",
            "device-lifecycle",
            None,
            Some("Device"),
        ),
        node(
            "DeviceReady",
            "device-lifecycle",
            Some("DeviceOperational"),
            Some("Device"),
        ),
        node("DeviceLost", "device-lifecycle", None, Some("Device")),
        node("MapLifecycle", "mapping-status", None, Some("Mapping")),
        node(
            "MapPending",
            "mapping-status",
            Some("MapLifecycle"),
            Some("Mapping"),
        ),
        node(
            "MapCompleted",
            "mapping-status",
            Some("MapLifecycle"),
            Some("Mapping"),
        ),
        node(
            "CompletionLifecycle",
            "completion-status",
            None,
            Some("Completion"),
        ),
        node(
            "CompletionPending",
            "completion-status",
            Some("CompletionLifecycle"),
            Some("Completion"),
        ),
        node(
            "CompletionDrained",
            "completion-status",
            Some("CompletionLifecycle"),
            Some("Completion"),
        ),
    ];
    extend_with_ghost_region(&mut regions, &mut nodes, hypothesis, "protocol-lifecycle");

    Some(StateMachine {
        machine_id: hypothesis.machine_id.clone(),
        actors: fallback_actors(hypothesis, &["Device", "Mapping", "Completion"]),
        regions,
        nodes,
        events: vec![
            StateEvent {
                event_id: "DestroyDevice".into(),
                actor: Some("Device".into()),
            },
            StateEvent {
                event_id: "SubmitMapAsync".into(),
                actor: Some("Mapping".into()),
            },
            StateEvent {
                event_id: "DeviceLost".into(),
                actor: Some("Device".into()),
            },
        ],
        transitions: hypothesis
            .forbidden_transitions
            .iter()
            .map(map_protocol_transition)
            .collect(),
        invalidation_edges: vec![InvalidationEdge {
            source_actor: "Device".into(),
            source_state: "DeviceReady".into(),
            event_id: "DestroyDevice".into(),
            target_actor: "Mapping".into(),
            invalidated_state: "MapPending".into(),
        }],
    })
}

fn map_protocol_transition(transition: &ForbiddenTransitionRef) -> StateMachineTransition {
    match transition.transition_id.as_str() {
        "destroy-device-before-completion" | "map-then-destroy-before-completion" => {
            StateMachineTransition {
                transition_id: transition.transition_id.clone(),
                event_id: "DestroyDevice".into(),
                source_state: "MapPending".into(),
                target_state: "DeviceLost".into(),
                required_states: vec!["DeviceReady".into(), "CompletionPending".into()],
                required_guards: vec!["explicit_state_guard".into()],
                expected_proof_class: Some(transition.expected_proof_class.clone()),
                rationale: transition.rationale.clone(),
                forbidden: true,
            }
        }
        "device-loss-during-submit" => StateMachineTransition {
            transition_id: transition.transition_id.clone(),
            event_id: "DeviceLost".into(),
            source_state: "CompletionPending".into(),
            target_state: "DeviceLost".into(),
            required_states: vec!["DeviceReady".into(), "MapPending".into()],
            required_guards: vec![
                "device_loss_handler".into(),
                "completion_drain_guard".into(),
            ],
            expected_proof_class: Some(transition.expected_proof_class.clone()),
            rationale: transition.rationale.clone(),
            forbidden: true,
        },
        other => fallback_transition(other, transition),
    }
}

pub(crate) fn fallback_transition(
    transition_id: &str,
    transition: &ForbiddenTransitionRef,
) -> StateMachineTransition {
    StateMachineTransition {
        transition_id: transition_id.to_string(),
        event_id: "GenericEvent".into(),
        source_state: "Unknown".into(),
        target_state: "Unknown".into(),
        required_states: Vec::new(),
        required_guards: Vec::new(),
        expected_proof_class: Some(transition.expected_proof_class.clone()),
        rationale: transition.rationale.clone(),
        forbidden: true,
    }
}

pub(crate) fn fallback_actors(hypothesis: &StateHypothesis, defaults: &[&str]) -> Vec<String> {
    if hypothesis.actors.is_empty() {
        defaults.iter().map(|value| value.to_string()).collect()
    } else {
        hypothesis.actors.clone()
    }
}

pub(crate) fn node(
    state_id: &str,
    region_id: &str,
    parent_state: Option<&str>,
    actor: Option<&str>,
) -> StateNode {
    StateNode {
        state_id: state_id.into(),
        region_id: region_id.into(),
        parent_state: parent_state.map(str::to_string),
        actor: actor.map(str::to_string),
    }
}

pub(crate) fn extend_with_ghost_region(
    regions: &mut Vec<StateRegion>,
    nodes: &mut Vec<StateNode>,
    hypothesis: &StateHypothesis,
    parallel_group: &str,
) {
    if hypothesis.ghost_states.is_empty() {
        return;
    }

    regions.push(StateRegion {
        region_id: "ghost-states".into(),
        mode: StateRegionMode::Parallel,
        parallel_group: Some(parallel_group.into()),
        states: hypothesis.ghost_states.clone(),
    });

    nodes.extend(hypothesis.ghost_states.iter().map(|state_id| StateNode {
        state_id: state_id.clone(),
        region_id: "ghost-states".into(),
        parent_state: None,
        actor: None,
    }));
}
