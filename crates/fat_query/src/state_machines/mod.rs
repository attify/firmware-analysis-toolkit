pub mod core;
mod families;
pub mod planning;
pub mod queries;
pub mod registry;

pub use core::{
    build_protocol_machine, InvalidationEdge, StateEvent, StateMachine, StateMachineTransition,
    StateNode, StateRegion, StateRegionMode,
};
pub use families::lifetime::build_machine as build_lifetime_machine;
pub use families::size::build_machine as build_size_machine;
pub use families::validation::build_machine as build_validation_machine;
pub use planning::{select_transition_for_lead, MachineTransitionSelection};
pub use queries::{
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
pub use registry::{
    build_machine_snapshots_for_lead, build_machines_for_lead, registered_machine_ids,
    StateMachineSnapshot,
};
