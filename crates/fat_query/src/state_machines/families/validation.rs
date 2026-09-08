use crate::discovery::{ForbiddenTransitionRef, StateHypothesis};

use crate::state_machines::core::{
    extend_with_ghost_region, fallback_actors, fallback_transition, node, InvalidationEdge,
    StateEvent, StateMachine, StateMachineTransition, StateNode, StateRegion, StateRegionMode,
};

pub const MACHINE_ID: &str = "validation-trust-boundary";

pub fn build_machine(hypothesis: &StateHypothesis) -> Option<StateMachine> {
    if hypothesis.machine_id != MACHINE_ID {
        return None;
    }

    let mut regions = vec![
        StateRegion {
            region_id: "input-status".into(),
            mode: StateRegionMode::Exclusive,
            parallel_group: Some("validation-flow".into()),
            states: vec![
                "InputReceived".into(),
                "InputParsed".into(),
                "InputRejected".into(),
            ],
        },
        StateRegion {
            region_id: "validation-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("validation-flow".into()),
            states: vec![
                "ValidationPending".into(),
                "ValidationComplete".into(),
                "ValidationBypassed".into(),
            ],
        },
        StateRegion {
            region_id: "action-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("validation-flow".into()),
            states: vec![
                "ActionIdle".into(),
                "ActionReady".into(),
                "ActionExecuted".into(),
            ],
        },
    ];
    let mut nodes = validation_nodes();
    extend_with_ghost_region(&mut regions, &mut nodes, hypothesis, "validation-flow");

    Some(StateMachine {
        machine_id: hypothesis.machine_id.clone(),
        actors: fallback_actors(hypothesis, &["Input", "Validator", "Action"]),
        regions,
        nodes,
        events: vec![
            StateEvent {
                event_id: "UseBeforeValidation".into(),
                actor: Some("Action".into()),
            },
            StateEvent {
                event_id: "BadMessage".into(),
                actor: Some("Validator".into()),
            },
        ],
        transitions: hypothesis
            .forbidden_transitions
            .iter()
            .map(|transition| map_validation_transition(transition, &hypothesis.required_guards))
            .collect(),
        invalidation_edges: vec![InvalidationEdge {
            source_actor: "Validator".into(),
            source_state: "ValidationPending".into(),
            event_id: "UseBeforeValidation".into(),
            target_actor: "Action".into(),
            invalidated_state: "ActionReady".into(),
        }],
    })
}

fn validation_nodes() -> Vec<StateNode> {
    vec![
        node("InputReceived", "input-status", None, Some("Input")),
        node(
            "InputParsed",
            "input-status",
            Some("InputReceived"),
            Some("Input"),
        ),
        node("InputRejected", "input-status", None, Some("Input")),
        node(
            "ValidationPending",
            "validation-status",
            None,
            Some("Validator"),
        ),
        node(
            "ValidationComplete",
            "validation-status",
            Some("ValidationPending"),
            Some("Validator"),
        ),
        node(
            "ValidationBypassed",
            "validation-status",
            None,
            Some("Validator"),
        ),
        node("ActionIdle", "action-status", None, Some("Action")),
        node(
            "ActionReady",
            "action-status",
            Some("ActionIdle"),
            Some("Action"),
        ),
        node(
            "ActionExecuted",
            "action-status",
            Some("ActionReady"),
            Some("Action"),
        ),
    ]
}

fn map_validation_transition(
    transition: &ForbiddenTransitionRef,
    required_guards: &[String],
) -> StateMachineTransition {
    let guards = if required_guards.is_empty() {
        vec!["dominating_validation_guard".into()]
    } else {
        required_guards.to_vec()
    };
    match transition.transition_id.as_str() {
        "use-before-validation" | "permission-state-mismatch" => StateMachineTransition {
            transition_id: transition.transition_id.clone(),
            event_id: "UseBeforeValidation".into(),
            source_state: "InputReceived".into(),
            target_state: "ActionExecuted".into(),
            required_states: vec!["ValidationPending".into(), "ActionReady".into()],
            required_guards: guards,
            expected_proof_class: Some(transition.expected_proof_class.clone()),
            rationale: transition.rationale.clone(),
            forbidden: true,
        },
        "malformed-boundary-payload" => StateMachineTransition {
            transition_id: transition.transition_id.clone(),
            event_id: "BadMessage".into(),
            source_state: "InputParsed".into(),
            target_state: "InputRejected".into(),
            required_states: vec!["ValidationPending".into()],
            required_guards: guards,
            expected_proof_class: Some(transition.expected_proof_class.clone()),
            rationale: transition.rationale.clone(),
            forbidden: true,
        },
        other => fallback_transition(other, transition),
    }
}
