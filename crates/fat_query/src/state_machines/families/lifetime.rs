use crate::discovery::{ForbiddenTransitionRef, StateHypothesis};

use crate::state_machines::core::{
    extend_with_ghost_region, fallback_actors, fallback_transition, node, InvalidationEdge,
    StateEvent, StateMachine, StateMachineTransition, StateNode, StateRegion, StateRegionMode,
};

pub const MACHINE_ID: &str = "lifetime-reentrancy";

pub fn build_machine(hypothesis: &StateHypothesis) -> Option<StateMachine> {
    if hypothesis.machine_id != MACHINE_ID {
        return None;
    }

    let mut regions = vec![
        StateRegion {
            region_id: "owner-lifecycle".into(),
            mode: StateRegionMode::Exclusive,
            parallel_group: Some("lifetime-actors".into()),
            states: vec![
                "OwnerReachable".into(),
                "OwnerAlive".into(),
                "OwnerDestroying".into(),
                "OwnerDestroyed".into(),
            ],
        },
        StateRegion {
            region_id: "callback-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("lifetime-actors".into()),
            states: vec![
                "CallbackIdle".into(),
                "CallbackActive".into(),
                "CallbackPending".into(),
                "CallbackRunning".into(),
            ],
        },
    ];
    let mut nodes = lifetime_nodes();
    extend_with_ghost_region(&mut regions, &mut nodes, hypothesis, "lifetime-actors");

    Some(StateMachine {
        machine_id: hypothesis.machine_id.clone(),
        actors: fallback_actors(hypothesis, &["Owner", "Callback"]),
        regions,
        nodes,
        events: vec![
            StateEvent {
                event_id: "DestroyOwner".into(),
                actor: Some("Owner".into()),
            },
            StateEvent {
                event_id: "ObserverMutation".into(),
                actor: Some("Callback".into()),
            },
        ],
        transitions: hypothesis
            .forbidden_transitions
            .iter()
            .map(map_lifetime_transition)
            .collect(),
        invalidation_edges: vec![InvalidationEdge {
            source_actor: "Owner".into(),
            source_state: "OwnerAlive".into(),
            event_id: "DestroyOwner".into(),
            target_actor: "Callback".into(),
            invalidated_state: "CallbackPending".into(),
        }],
    })
}

fn lifetime_nodes() -> Vec<StateNode> {
    vec![
        node("OwnerReachable", "owner-lifecycle", None, Some("Owner")),
        node(
            "OwnerAlive",
            "owner-lifecycle",
            Some("OwnerReachable"),
            Some("Owner"),
        ),
        node(
            "OwnerDestroying",
            "owner-lifecycle",
            Some("OwnerReachable"),
            Some("Owner"),
        ),
        node("OwnerDestroyed", "owner-lifecycle", None, Some("Owner")),
        node("CallbackIdle", "callback-status", None, Some("Callback")),
        node("CallbackActive", "callback-status", None, Some("Callback")),
        node(
            "CallbackPending",
            "callback-status",
            Some("CallbackActive"),
            Some("Callback"),
        ),
        node(
            "CallbackRunning",
            "callback-status",
            Some("CallbackActive"),
            Some("Callback"),
        ),
    ]
}

fn map_lifetime_transition(transition: &ForbiddenTransitionRef) -> StateMachineTransition {
    match transition.transition_id.as_str() {
        "destroy-owner-during-callback" | "destroy-owner-while-callback-pending" => {
            StateMachineTransition {
                transition_id: transition.transition_id.clone(),
                event_id: "DestroyOwner".into(),
                source_state: "OwnerAlive".into(),
                target_state: "OwnerDestroyed".into(),
                required_states: vec!["CallbackPending".into(), "CallbackRunning".into()],
                required_guards: vec!["safe_invalidation_guard".into()],
                expected_proof_class: Some(transition.expected_proof_class.clone()),
                rationale: transition.rationale.clone(),
                forbidden: true,
            }
        }
        "observer-mutation-while-callback" | "observer-mutation-during-iteration" => {
            StateMachineTransition {
                transition_id: transition.transition_id.clone(),
                event_id: "ObserverMutation".into(),
                source_state: "CallbackPending".into(),
                target_state: "OwnerDestroying".into(),
                required_states: vec!["OwnerAlive".into(), "CallbackPending".into()],
                required_guards: vec!["safe_invalidation_guard".into()],
                expected_proof_class: Some(transition.expected_proof_class.clone()),
                rationale: transition.rationale.clone(),
                forbidden: true,
            }
        }
        other => fallback_transition(other, transition),
    }
}
