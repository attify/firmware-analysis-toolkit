use crate::discovery::{ForbiddenTransitionRef, StateHypothesis};

use crate::state_machines::core::{
    extend_with_ghost_region, fallback_actors, fallback_transition, node, InvalidationEdge,
    StateEvent, StateMachine, StateMachineTransition, StateNode, StateRegion, StateRegionMode,
};

pub const MACHINE_ID: &str = "size-stride-arithmetic";

pub fn build_machine(hypothesis: &StateHypothesis) -> Option<StateMachine> {
    if hypothesis.machine_id != MACHINE_ID {
        return None;
    }

    let mut regions = vec![
        StateRegion {
            region_id: "allocation-status".into(),
            mode: StateRegionMode::Exclusive,
            parallel_group: Some("size-safety".into()),
            states: vec![
                "AllocationUnknown".into(),
                "AllocationCommitted".into(),
                "OverflowObserved".into(),
            ],
        },
        StateRegion {
            region_id: "shape-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("size-safety".into()),
            states: vec![
                "ShapeMetadata".into(),
                "ShapeMetadataTrusted".into(),
                "ShapeMetadataDiverged".into(),
            ],
        },
        StateRegion {
            region_id: "copy-status".into(),
            mode: StateRegionMode::Parallel,
            parallel_group: Some("size-safety".into()),
            states: vec![
                "CopyLifecycle".into(),
                "CopyPending".into(),
                "CopyIssued".into(),
                "CopyCompleted".into(),
            ],
        },
    ];
    let mut nodes = size_nodes();
    extend_with_ghost_region(&mut regions, &mut nodes, hypothesis, "size-safety");

    Some(StateMachine {
        machine_id: hypothesis.machine_id.clone(),
        actors: fallback_actors(hypothesis, &["Buffer", "Shape", "Copy"]),
        regions,
        nodes,
        events: vec![
            StateEvent {
                event_id: "CopyWithMismatchedPitch".into(),
                actor: Some("Copy".into()),
            },
            StateEvent {
                event_id: "ShapeChannelMismatch".into(),
                actor: Some("Shape".into()),
            },
        ],
        transitions: hypothesis
            .forbidden_transitions
            .iter()
            .map(map_size_transition)
            .collect(),
        invalidation_edges: vec![InvalidationEdge {
            source_actor: "Shape".into(),
            source_state: "ShapeMetadataTrusted".into(),
            event_id: "ShapeChannelMismatch".into(),
            target_actor: "Buffer".into(),
            invalidated_state: "AllocationCommitted".into(),
        }],
    })
}

fn size_nodes() -> Vec<StateNode> {
    vec![
        node(
            "AllocationUnknown",
            "allocation-status",
            None,
            Some("Buffer"),
        ),
        node(
            "AllocationCommitted",
            "allocation-status",
            Some("AllocationUnknown"),
            Some("Buffer"),
        ),
        node(
            "OverflowObserved",
            "allocation-status",
            None,
            Some("Buffer"),
        ),
        node("ShapeMetadata", "shape-status", None, Some("Shape")),
        node(
            "ShapeMetadataTrusted",
            "shape-status",
            Some("ShapeMetadata"),
            Some("Shape"),
        ),
        node(
            "ShapeMetadataDiverged",
            "shape-status",
            Some("ShapeMetadata"),
            Some("Shape"),
        ),
        node("CopyLifecycle", "copy-status", None, Some("Copy")),
        node(
            "CopyPending",
            "copy-status",
            Some("CopyLifecycle"),
            Some("Copy"),
        ),
        node(
            "CopyIssued",
            "copy-status",
            Some("CopyLifecycle"),
            Some("Copy"),
        ),
        node(
            "CopyCompleted",
            "copy-status",
            Some("CopyLifecycle"),
            Some("Copy"),
        ),
    ]
}

fn map_size_transition(transition: &ForbiddenTransitionRef) -> StateMachineTransition {
    match transition.transition_id.as_str() {
        "copy-size-exceeds-allocation" | "pitch-depth-mismatch" => StateMachineTransition {
            transition_id: transition.transition_id.clone(),
            event_id: "CopyWithMismatchedPitch".into(),
            source_state: "CopyPending".into(),
            target_state: "OverflowObserved".into(),
            required_states: vec!["AllocationCommitted".into(), "ShapeMetadataTrusted".into()],
            required_guards: vec!["dominating_size_guard".into(), "safe_math_wrapper".into()],
            expected_proof_class: Some(transition.expected_proof_class.clone()),
            rationale: transition.rationale.clone(),
            forbidden: true,
        },
        "shape-channel-mismatch" => StateMachineTransition {
            transition_id: transition.transition_id.clone(),
            event_id: "ShapeChannelMismatch".into(),
            source_state: "ShapeMetadataTrusted".into(),
            target_state: "CopyIssued".into(),
            required_states: vec!["AllocationCommitted".into()],
            required_guards: vec!["dominating_size_guard".into()],
            expected_proof_class: Some(transition.expected_proof_class.clone()),
            rationale: transition.rationale.clone(),
            forbidden: true,
        },
        other => fallback_transition(other, transition),
    }
}
