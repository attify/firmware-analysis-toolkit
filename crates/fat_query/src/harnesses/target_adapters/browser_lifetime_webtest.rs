use crate::attempt_generation::{GenerationStrategy, ParamDomain, ParamKind};
use crate::discovery::DiscoveryLead;
use crate::harnesses::{ArgTemplate, HarnessPlan, InputBinding};
use crate::target_lanes::TargetLaneRecord;

pub fn configure(plan: &mut HarnessPlan, _lead: &DiscoveryLead, lane: &TargetLaneRecord) {
    if supports_direct_runtime_lane(lane) {
        plan.base_command = vec![lane.binary_or_driver.clone()];
        plan.argv_template = vec![
            ArgTemplate::Literal {
                value: "--callback-count".into(),
            },
            ArgTemplate::Binding {
                key: "callback_count".into(),
            },
            ArgTemplate::Literal {
                value: "--teardown-mode".into(),
            },
            ArgTemplate::Binding {
                key: "teardown_mode".into(),
            },
            ArgTemplate::Literal {
                value: "--cancellation-mode".into(),
            },
            ArgTemplate::Binding {
                key: "cancellation_mode".into(),
            },
            ArgTemplate::Literal {
                value: "--observer-mutation-mode".into(),
            },
            ArgTemplate::Binding {
                key: "observer_mutation_mode".into(),
            },
            ArgTemplate::Literal {
                value: "--navigation-mode".into(),
            },
            ArgTemplate::Binding {
                key: "navigation_mode".into(),
            },
        ];
    }
    configure_bindings(plan, lane);
}

fn configure_bindings(plan: &mut HarnessPlan, lane: &TargetLaneRecord) {
    if !supports_attempt_generation(lane) {
        return;
    }
    let profile = transition_profile(plan);
    plan.input_bindings = vec![
        InputBinding {
            key: "callback_count".into(),
            value: profile.callback_count_seed.into(),
        },
        InputBinding {
            key: "teardown_mode".into(),
            value: profile.teardown_mode_seed.into(),
        },
        InputBinding {
            key: "cancellation_mode".into(),
            value: profile.cancellation_mode_seed.into(),
        },
        InputBinding {
            key: "observer_mutation_mode".into(),
            value: profile.observer_mutation_mode_seed.into(),
        },
        InputBinding {
            key: "navigation_mode".into(),
            value: profile.navigation_mode_seed.into(),
        },
    ];
    plan.param_domains = vec![
        ParamDomain {
            name: "callback_count".into(),
            kind: ParamKind::Integer,
            seeds: vec![profile.callback_count_seed.into()],
            edge_cases: profile
                .callback_count_edge_cases
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
        ParamDomain {
            name: "teardown_mode".into(),
            kind: ParamKind::Enum,
            seeds: vec![profile.teardown_mode_seed.into()],
            edge_cases: profile
                .teardown_mode_edge_cases
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
        ParamDomain {
            name: "cancellation_mode".into(),
            kind: ParamKind::Enum,
            seeds: vec![profile.cancellation_mode_seed.into()],
            edge_cases: profile
                .cancellation_mode_edge_cases
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
        ParamDomain {
            name: "observer_mutation_mode".into(),
            kind: ParamKind::Enum,
            seeds: vec![profile.observer_mutation_mode_seed.into()],
            edge_cases: profile
                .observer_mutation_mode_edge_cases
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
        ParamDomain {
            name: "navigation_mode".into(),
            kind: ParamKind::Enum,
            seeds: vec![profile.navigation_mode_seed.into()],
            edge_cases: profile
                .navigation_mode_edge_cases
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
    ];
    plan.generation_strategy = profile.generation_strategy;
}

fn supports_attempt_generation(lane: &TargetLaneRecord) -> bool {
    lane.runtime_capabilities.accepts_callback_count
        && lane.runtime_capabilities.accepts_teardown_mode
        && lane.runtime_capabilities.accepts_cancellation_mode
        && lane.runtime_capabilities.accepts_observer_mutation_mode
        && lane.runtime_capabilities.accepts_navigation_mode
}

fn supports_direct_runtime_lane(lane: &TargetLaneRecord) -> bool {
    lane.runtime_capabilities.honors_callback_count
        && lane.runtime_capabilities.honors_teardown_mode
        && lane.runtime_capabilities.honors_cancellation_mode
        && lane.runtime_capabilities.honors_observer_mutation_mode
        && lane.runtime_capabilities.honors_navigation_mode
}

struct LifetimeTransitionProfile {
    callback_count_seed: &'static str,
    callback_count_edge_cases: &'static [&'static str],
    teardown_mode_seed: &'static str,
    teardown_mode_edge_cases: &'static [&'static str],
    cancellation_mode_seed: &'static str,
    cancellation_mode_edge_cases: &'static [&'static str],
    observer_mutation_mode_seed: &'static str,
    observer_mutation_mode_edge_cases: &'static [&'static str],
    navigation_mode_seed: &'static str,
    navigation_mode_edge_cases: &'static [&'static str],
    generation_strategy: GenerationStrategy,
}

fn transition_profile(plan: &HarnessPlan) -> LifetimeTransitionProfile {
    match plan.forbidden_transition_id.as_deref() {
        Some("observer-mutation-while-callback") => LifetimeTransitionProfile {
            callback_count_seed: "2",
            callback_count_edge_cases: &["1"],
            teardown_mode_seed: "release-observer",
            teardown_mode_edge_cases: &["destroy-owner"],
            cancellation_mode_seed: "none",
            cancellation_mode_edge_cases: &["cancel-before-completion"],
            observer_mutation_mode_seed: "mutate-during-callback",
            observer_mutation_mode_edge_cases: &["none"],
            navigation_mode_seed: "none",
            navigation_mode_edge_cases: &["navigate-frame"],
            generation_strategy: GenerationStrategy::FocusedEdgeSweep,
        },
        _ => LifetimeTransitionProfile {
            callback_count_seed: "1",
            callback_count_edge_cases: &["2"],
            teardown_mode_seed: "destroy-owner",
            teardown_mode_edge_cases: &["release-observer"],
            cancellation_mode_seed: "none",
            cancellation_mode_edge_cases: &["cancel-before-completion"],
            observer_mutation_mode_seed: "none",
            observer_mutation_mode_edge_cases: &["mutate-during-callback"],
            navigation_mode_seed: "none",
            navigation_mode_edge_cases: &["navigate-frame"],
            generation_strategy: GenerationStrategy::FocusedEdgeSweep,
        },
    }
}
