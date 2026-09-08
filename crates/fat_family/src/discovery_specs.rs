pub use crate::model::{
    DiscoveryFamilySpec, LocalityPolicy, ProofClass, RequiredRoleGroup, Suppressor,
    TargetPreference, TriggerTemplate,
};

const LIFETIME_REENTRANCY_ROLE_GROUPS: &[RequiredRoleGroup] = &[
    RequiredRoleGroup {
        name: "callback_delivery",
        roles: &["callback registration", "callback invocation"],
    },
    RequiredRoleGroup {
        name: "observer_mutation",
        roles: &["observer mutation", "iteration"],
    },
    RequiredRoleGroup {
        name: "owner_teardown",
        roles: &["destroy", "release", "teardown"],
    },
    RequiredRoleGroup {
        name: "async_cancellation",
        roles: &["posted task", "cancellation", "stale owner capture"],
    },
];

const LIFETIME_REENTRANCY_SUPPRESSORS: &[Suppressor] = &[
    Suppressor {
        name: "cleanup_only_teardown",
        signals: &["cleanup-only path", "destructor-only flow"],
    },
    Suppressor {
        name: "explicit_shutdown_path",
        signals: &["explicit shutdown", "pre-arranged teardown"],
    },
    Suppressor {
        name: "single_shot_callback",
        signals: &["one-shot callback", "no re-entry"],
    },
];

const LIFETIME_REENTRANCY_TRIGGER_TEMPLATES: &[TriggerTemplate] = &[
    TriggerTemplate {
        name: "callback_then_teardown",
        description: "deliver a callback and destroy the owner before the callback returns",
    },
    TriggerTemplate {
        name: "observer_mutation_during_iteration",
        description: "mutate the observer list while it is being iterated",
    },
    TriggerTemplate {
        name: "posted_task_then_owner_destruction",
        description: "post work to the queue and tear down the owner before dispatch",
    },
    TriggerTemplate {
        name: "cancellation_before_completion",
        description: "interrupt or cancel the request before completion and reuse stale state",
    },
];

const LIFETIME_REENTRANCY_TARGET_PREFERENCES: &[TargetPreference] = &[
    TargetPreference {
        kind: "source_surface",
        value: "blink",
    },
    TargetPreference {
        kind: "source_surface",
        value: "content",
    },
    TargetPreference {
        kind: "source_surface",
        value: "components",
    },
    TargetPreference {
        kind: "source_surface",
        value: "base",
    },
    TargetPreference {
        kind: "source_surface",
        value: "device",
    },
    TargetPreference {
        kind: "execution_lane",
        value: "asan-fd-cr-race-002-quick2",
    },
];

const SIZE_STRIDE_ARITHMETIC_ROLE_GROUPS: &[RequiredRoleGroup] = &[
    RequiredRoleGroup {
        name: "alloc_copy_divergence",
        roles: &["alloc size", "copy size"],
    },
    RequiredRoleGroup {
        name: "stride_geometry",
        roles: &["stride", "pitch", "depth"],
    },
    RequiredRoleGroup {
        name: "truncation_paths",
        roles: &["truncation", "narrowing", "size path"],
    },
    RequiredRoleGroup {
        name: "alignment_mismatch",
        roles: &["aligned copy", "raw copy", "rounded size"],
    },
];

const SIZE_STRIDE_ARITHMETIC_SUPPRESSORS: &[Suppressor] = &[
    Suppressor {
        name: "bounds_checked_copy",
        signals: &["correct bounds check", "copy length guarded"],
    },
    Suppressor {
        name: "safe_math_wrapper",
        signals: &["safe integer math", "saturating arithmetic"],
    },
    Suppressor {
        name: "shape_consistent_copy",
        signals: &["matching metadata", "matching payload size"],
    },
];

const SIZE_STRIDE_ARITHMETIC_TRIGGER_TEMPLATES: &[TriggerTemplate] = &[
    TriggerTemplate {
        name: "payload_smaller_than_metadata_implied_size",
        description: "send a payload that is smaller than the size implied by its metadata",
    },
    TriggerTemplate {
        name: "pitch_stride_depth_divergence",
        description: "diverge pitch, stride, or depth from the actual payload layout",
    },
    TriggerTemplate {
        name: "aligned_vs_raw_copy_mismatch",
        description: "mix aligned copies with raw copies on the same buffer path",
    },
    TriggerTemplate {
        name: "narrowing_on_size_paths",
        description: "force narrowing or truncation on a path that later uses the wide size",
    },
];

const SIZE_STRIDE_ARITHMETIC_TARGET_PREFERENCES: &[TargetPreference] = &[
    TargetPreference {
        kind: "source_surface",
        value: "angle-standalone-cl",
    },
    TargetPreference {
        kind: "source_surface",
        value: "angle-replay-466192044",
    },
    TargetPreference {
        kind: "source_surface",
        value: "angle-replay-487208468",
    },
    TargetPreference {
        kind: "source_surface",
        value: "third_party/angle",
    },
    TargetPreference {
        kind: "source_surface",
        value: "media",
    },
    TargetPreference {
        kind: "source_surface",
        value: "gpu",
    },
    TargetPreference {
        kind: "execution_lane",
        value: "cl-vk-asan",
    },
];

const GPU_PROTOCOL_ORDER_LIFECYCLE_ROLE_GROUPS: &[RequiredRoleGroup] = &[
    RequiredRoleGroup {
        name: "map_unmap_destroy",
        roles: &["map", "unmap", "destroy"],
    },
    RequiredRoleGroup {
        name: "device_loss_submit",
        roles: &["device lost", "submit", "queue"],
    },
    RequiredRoleGroup {
        name: "async_completion",
        roles: &["callback", "completion", "async"],
    },
];

const GPU_PROTOCOL_ORDER_LIFECYCLE_SUPPRESSORS: &[Suppressor] = &[
    Suppressor {
        name: "explicit_state_guard",
        signals: &["explicit state guard", "guarded cleanup"],
    },
    Suppressor {
        name: "single_phase_cleanup",
        signals: &["single phase cleanup", "no async re-entry"],
    },
];

const GPU_PROTOCOL_ORDER_LIFECYCLE_TRIGGER_TEMPLATES: &[TriggerTemplate] = &[
    TriggerTemplate {
        name: "map_then_destroy_before_completion",
        description: "map or submit work, then destroy the owner before async completion",
    },
    TriggerTemplate {
        name: "device_loss_during_submit",
        description: "trigger device loss or submission failure while work is still in flight",
    },
];

const GPU_PROTOCOL_ORDER_LIFECYCLE_TARGET_PREFERENCES: &[TargetPreference] = &[
    TargetPreference {
        kind: "source_surface",
        value: "third_party/dawn",
    },
    TargetPreference {
        kind: "source_surface",
        value: "gpu",
    },
    TargetPreference {
        kind: "execution_lane",
        value: "dawn-webgpu-asan",
    },
];

const VALIDATION_TRUST_BOUNDARY_ROLE_GROUPS: &[RequiredRoleGroup] = &[
    RequiredRoleGroup {
        name: "permission_or_validation_gate",
        roles: &["permission", "validate", "origin"],
    },
    RequiredRoleGroup {
        name: "trust_boundary_action",
        roles: &["dispatch", "remote action", "privileged action"],
    },
    RequiredRoleGroup {
        name: "bad_message_path",
        roles: &["bad message", "deny", "reject"],
    },
];

const VALIDATION_TRUST_BOUNDARY_SUPPRESSORS: &[Suppressor] = &[
    Suppressor {
        name: "dominating_validation_guard",
        signals: &["dominating validation guard", "validated before dispatch"],
    },
    Suppressor {
        name: "origin_checked_action",
        signals: &["origin checked action", "trusted origin only"],
    },
];

const VALIDATION_TRUST_BOUNDARY_TRIGGER_TEMPLATES: &[TriggerTemplate] = &[
    TriggerTemplate {
        name: "malformed_mojo_or_webidl_payload",
        description: "send malformed Mojo or WebIDL input across the trust boundary",
    },
    TriggerTemplate {
        name: "permission_state_mismatch",
        description: "mutate permission or origin state so the action runs under stale validation",
    },
];

const VALIDATION_TRUST_BOUNDARY_TARGET_PREFERENCES: &[TargetPreference] = &[
    TargetPreference {
        kind: "source_surface",
        value: "services",
    },
    TargetPreference {
        kind: "source_surface",
        value: "ipc",
    },
    TargetPreference {
        kind: "source_surface",
        value: "content",
    },
    TargetPreference {
        kind: "execution_lane",
        value: "mojo-validation-asan",
    },
];

const DISCOVERY_FAMILY_SPECS: &[DiscoveryFamilySpec] = &[
    DiscoveryFamilySpec {
        family_id: "lifetime-reentrancy",
        required_role_groups: LIFETIME_REENTRANCY_ROLE_GROUPS,
        suppressors: LIFETIME_REENTRANCY_SUPPRESSORS,
        trigger_templates: LIFETIME_REENTRANCY_TRIGGER_TEMPLATES,
        expected_proof_classes: &[
            ProofClass::AsanUseAfterFree,
            ProofClass::GuardTrip,
            ProofClass::BadMessage,
        ],
        locality_policy: LocalityPolicy::RepoLocalOnly,
        target_preferences: LIFETIME_REENTRANCY_TARGET_PREFERENCES,
    },
    DiscoveryFamilySpec {
        family_id: "size-stride-arithmetic",
        required_role_groups: SIZE_STRIDE_ARITHMETIC_ROLE_GROUPS,
        suppressors: SIZE_STRIDE_ARITHMETIC_SUPPRESSORS,
        trigger_templates: SIZE_STRIDE_ARITHMETIC_TRIGGER_TEMPLATES,
        expected_proof_classes: &[
            ProofClass::AsanHeapBufferOverflow,
            ProofClass::UbsanIntegerOverflow,
            ProofClass::GuardTrip,
        ],
        locality_policy: LocalityPolicy::VendoredAllowed,
        target_preferences: SIZE_STRIDE_ARITHMETIC_TARGET_PREFERENCES,
    },
    DiscoveryFamilySpec {
        family_id: "gpu-protocol-order-lifecycle",
        required_role_groups: GPU_PROTOCOL_ORDER_LIFECYCLE_ROLE_GROUPS,
        suppressors: GPU_PROTOCOL_ORDER_LIFECYCLE_SUPPRESSORS,
        trigger_templates: GPU_PROTOCOL_ORDER_LIFECYCLE_TRIGGER_TEMPLATES,
        expected_proof_classes: &[ProofClass::GuardTrip, ProofClass::AsanUseAfterFree],
        locality_policy: LocalityPolicy::VendoredAllowed,
        target_preferences: GPU_PROTOCOL_ORDER_LIFECYCLE_TARGET_PREFERENCES,
    },
    DiscoveryFamilySpec {
        family_id: "validation-trust-boundary",
        required_role_groups: VALIDATION_TRUST_BOUNDARY_ROLE_GROUPS,
        suppressors: VALIDATION_TRUST_BOUNDARY_SUPPRESSORS,
        trigger_templates: VALIDATION_TRUST_BOUNDARY_TRIGGER_TEMPLATES,
        expected_proof_classes: &[ProofClass::BadMessage, ProofClass::GuardTrip],
        locality_policy: LocalityPolicy::BlockWhenUpstreamHidden,
        target_preferences: VALIDATION_TRUST_BOUNDARY_TARGET_PREFERENCES,
    },
];

pub fn discovery_family_specs() -> &'static [DiscoveryFamilySpec] {
    DISCOVERY_FAMILY_SPECS
}

pub fn discovery_family_spec(family_id: &str) -> Option<&'static DiscoveryFamilySpec> {
    DISCOVERY_FAMILY_SPECS
        .iter()
        .find(|spec| spec.family_id == family_id)
}
