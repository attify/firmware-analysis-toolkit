use fat_backend::BackendRegistry;
use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_emulate::plan::{create_emulation_bundle_from_request, EmulationBundleRequest};
use fat_emulate::strategy::EmulationAutomationMode;
use fat_emulate::substrate_selection::{select_runner, RunnerKind};

#[test]
fn substrate_selection_prefers_service_runner_when_service_is_viable() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-service", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "web:uhttpd".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_substrate_preference(SubstratePreference::Auto)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let selected = select_runner(&plan, &BackendRegistry::with_test_backends()).expect("runner");
    assert_eq!(selected.kind, RunnerKind::Service);
    assert_eq!(selected.logical_substrate, SubstrateKind::Service);
}

#[test]
fn substrate_selection_honors_system_first_when_managed_vm_is_viable() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "web:uhttpd".to_string(),
            ])
            .with_host_capabilities(vec![
                "native-host".to_string(),
                "managed-linux-vm".to_string(),
            ])
            .with_substrate_preference(SubstratePreference::SystemFirst)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let selected = select_runner(&plan, &BackendRegistry::with_test_backends()).expect("runner");
    assert_eq!(selected.kind, RunnerKind::System);
    assert_eq!(selected.logical_substrate, SubstrateKind::System);
}

#[test]
fn substrate_selection_honors_reference_only() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-reference", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "generated:reference-rootfs".to_string(),
            ])
            .with_host_capabilities(vec!["docker-engine".to_string()])
            .with_substrate_preference(SubstratePreference::ReferenceOnly)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let selected = select_runner(&plan, &BackendRegistry::with_test_backends()).expect("runner");
    assert_eq!(selected.kind, RunnerKind::Reference);
    assert_eq!(selected.logical_substrate, SubstrateKind::Reference);
}
