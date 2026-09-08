use fat_family::discovery_specs::{
    discovery_family_spec, discovery_family_specs, LocalityPolicy, ProofClass,
};
use fat_family::runtime_hints_for_family;

#[test]
fn test_phase_2b_discovery_family_specs_expose_all_promoted_families() {
    let family_ids: Vec<_> = discovery_family_specs()
        .iter()
        .map(|spec| spec.family_id)
        .collect();

    assert_eq!(
        family_ids,
        vec![
            "lifetime-reentrancy",
            "size-stride-arithmetic",
            "gpu-protocol-order-lifecycle",
            "validation-trust-boundary",
        ]
    );
    assert!(discovery_family_spec("gpu-protocol-order-lifecycle").is_some());
    assert!(discovery_family_spec("validation-trust-boundary").is_some());
}

#[test]
fn test_lifetime_reentrancy_discovery_family_spec_is_complete() {
    let spec = discovery_family_spec("lifetime-reentrancy").expect("missing lifetime spec");

    assert_eq!(spec.family_id, "lifetime-reentrancy");
    assert_eq!(spec.locality_policy, LocalityPolicy::RepoLocalOnly);
    assert_eq!(
        spec.expected_proof_classes,
        &[
            ProofClass::AsanUseAfterFree,
            ProofClass::GuardTrip,
            ProofClass::BadMessage,
        ]
    );

    assert_eq!(spec.required_role_groups.len(), 4);
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "callback_delivery"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "observer_mutation"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "owner_teardown"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "async_cancellation"));

    assert_eq!(spec.suppressors.len(), 3);
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "cleanup_only_teardown"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "explicit_shutdown_path"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "single_shot_callback"));

    assert_eq!(spec.trigger_templates.len(), 4);
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "callback_then_teardown"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "observer_mutation_during_iteration"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "posted_task_then_owner_destruction"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "cancellation_before_completion"));

    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.kind == "execution_lane"));
    assert!(spec
        .target_preferences
        .iter()
        .all(|preference| { !preference.value.starts_with("/Users/") }));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.kind == "source_surface"));
}

#[test]
fn test_size_stride_arithmetic_discovery_family_spec_is_complete() {
    let spec = discovery_family_spec("size-stride-arithmetic").expect("missing size spec");

    assert_eq!(spec.family_id, "size-stride-arithmetic");
    assert_eq!(spec.locality_policy, LocalityPolicy::VendoredAllowed);
    assert_eq!(
        spec.expected_proof_classes,
        &[
            ProofClass::AsanHeapBufferOverflow,
            ProofClass::UbsanIntegerOverflow,
            ProofClass::GuardTrip,
        ]
    );

    assert_eq!(spec.required_role_groups.len(), 4);
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "alloc_copy_divergence"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "stride_geometry"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "truncation_paths"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "alignment_mismatch"));

    assert_eq!(spec.suppressors.len(), 3);
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "bounds_checked_copy"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "safe_math_wrapper"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "shape_consistent_copy"));

    assert_eq!(spec.trigger_templates.len(), 4);
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "payload_smaller_than_metadata_implied_size"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "pitch_stride_depth_divergence"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "aligned_vs_raw_copy_mismatch"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "narrowing_on_size_paths"));

    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.kind == "execution_lane"));
    assert!(spec
        .target_preferences
        .iter()
        .all(|preference| { !preference.value.starts_with("/Users/") }));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.kind == "source_surface"));
}

#[test]
fn test_phase_2a_discovery_families_use_discovery_runtime_hints() {
    let lifetime = runtime_hints_for_family("lifetime-reentrancy");
    assert_eq!(lifetime.family_id, "lifetime-reentrancy");
    assert_eq!(lifetime.required_actions.len(), 1);
    assert_eq!(lifetime.required_actions[0].path, "/analysis");
    assert_eq!(
        lifetime.required_actions[0].detail,
        "mount the discovery workspace before launch"
    );
    assert_eq!(lifetime.recommended_actions.len(), 1);
    assert_eq!(lifetime.recommended_actions[0].path, "/analysis/tmp");

    let size = runtime_hints_for_family("size-stride-arithmetic");
    assert_eq!(size.family_id, "size-stride-arithmetic");
    assert_eq!(size.required_actions.len(), 1);
    assert_eq!(size.required_actions[0].path, "/analysis");
    assert_eq!(
        size.required_actions[0].detail,
        "mount the discovery workspace before launch"
    );
    assert_eq!(size.recommended_actions.len(), 1);
    assert_eq!(size.recommended_actions[0].path, "/analysis/tmp");

    let protocol = runtime_hints_for_family("gpu-protocol-order-lifecycle");
    assert_eq!(protocol.family_id, "gpu-protocol-order-lifecycle");
    assert_eq!(protocol.required_actions.len(), 1);
    assert_eq!(protocol.required_actions[0].path, "/analysis");
    assert_eq!(protocol.recommended_actions.len(), 1);
    assert_eq!(protocol.recommended_actions[0].path, "/analysis/tmp");

    let validation = runtime_hints_for_family("validation-trust-boundary");
    assert_eq!(validation.family_id, "validation-trust-boundary");
    assert_eq!(validation.required_actions.len(), 1);
    assert_eq!(validation.required_actions[0].path, "/analysis");
    assert_eq!(validation.recommended_actions.len(), 1);
    assert_eq!(validation.recommended_actions[0].path, "/analysis/tmp");
}

#[test]
fn test_gpu_protocol_order_lifecycle_discovery_family_spec_is_complete() {
    let spec = discovery_family_spec("gpu-protocol-order-lifecycle")
        .expect("missing gpu protocol-order spec");

    assert_eq!(spec.family_id, "gpu-protocol-order-lifecycle");
    assert_eq!(spec.locality_policy, LocalityPolicy::VendoredAllowed);
    assert_eq!(
        spec.expected_proof_classes,
        &[ProofClass::GuardTrip, ProofClass::AsanUseAfterFree]
    );
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "map_unmap_destroy"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "device_loss_submit"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "async_completion"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "explicit_state_guard"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "map_then_destroy_before_completion"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "device_loss_during_submit"));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.value == "third_party/dawn"));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.value == "dawn-webgpu-asan"));
}

#[test]
fn test_validation_trust_boundary_discovery_family_spec_is_complete() {
    let spec = discovery_family_spec("validation-trust-boundary").expect("missing validation spec");

    assert_eq!(spec.family_id, "validation-trust-boundary");
    assert_eq!(
        spec.locality_policy,
        LocalityPolicy::BlockWhenUpstreamHidden
    );
    assert_eq!(
        spec.expected_proof_classes,
        &[ProofClass::BadMessage, ProofClass::GuardTrip]
    );
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "permission_or_validation_gate"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "trust_boundary_action"));
    assert!(spec
        .required_role_groups
        .iter()
        .any(|group| group.name == "bad_message_path"));
    assert!(spec
        .suppressors
        .iter()
        .any(|suppressor| suppressor.name == "dominating_validation_guard"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "malformed_mojo_or_webidl_payload"));
    assert!(spec
        .trigger_templates
        .iter()
        .any(|template| template.name == "permission_state_mismatch"));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.value == "services"));
    assert!(spec
        .target_preferences
        .iter()
        .any(|preference| preference.value == "mojo-validation-asan"));
}
