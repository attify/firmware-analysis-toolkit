use fat_backend::{
    BackendDriverPhase, BackendRegistry, BackendSubstrateKind, BackendSubstrateStatus,
};

#[test]
fn backend_driver_contract_exposes_phases_and_substrates() {
    let registry = BackendRegistry::with_test_backends();
    let contracts = registry.driver_contracts();
    let qemu_direct = contracts
        .iter()
        .find(|contract| contract.backend_id == "qemu-direct")
        .expect("qemu-direct contract missing");

    assert_eq!(
        qemu_direct.phases,
        vec![
            BackendDriverPhase::Suitability,
            BackendDriverPhase::Provisioning,
            BackendDriverPhase::Preparation,
            BackendDriverPhase::Execution,
            BackendDriverPhase::Observation,
            BackendDriverPhase::Diagnostics,
        ]
    );
    assert_eq!(
        qemu_direct.supported_substrates,
        vec![BackendSubstrateKind::NativeHost]
    );
    assert_eq!(qemu_direct.substrates.len(), 1);
    assert!(qemu_direct
        .substrates
        .iter()
        .all(|substrate| substrate.capability.is_supported));
    assert!(qemu_direct
        .substrates
        .iter()
        .all(|substrate| substrate.health.status == BackendSubstrateStatus::Healthy));
}

#[test]
fn backend_registry_rankings_still_work() {
    let registry = BackendRegistry::with_test_backends();
    let scores = registry.rank_family("linux-router-arm");
    assert!(!scores.is_empty());
    assert_eq!(scores[0].backend_id, "firmae");
}

#[test]
fn firmae_prefers_managed_linux_vm_over_native_host() {
    let registry = BackendRegistry::with_test_backends();
    let contracts = registry.driver_contracts();
    let firmae = contracts
        .iter()
        .find(|contract| contract.backend_id == "firmae")
        .expect("firmae contract missing");

    assert_eq!(
        firmae.supported_substrates,
        vec![
            BackendSubstrateKind::ManagedLinuxVm,
            BackendSubstrateKind::DockerEngine,
        ]
    );
}

#[test]
fn emux_is_a_docker_backed_reference_backend_candidate() {
    let registry = BackendRegistry::with_test_backends();
    let contracts = registry.driver_contracts();
    let emux = contracts
        .iter()
        .find(|contract| contract.backend_id == "emux")
        .expect("emux contract missing");

    assert_eq!(
        emux.phases,
        vec![
            BackendDriverPhase::Suitability,
            BackendDriverPhase::Provisioning,
            BackendDriverPhase::Preparation,
            BackendDriverPhase::Execution,
            BackendDriverPhase::Observation,
            BackendDriverPhase::Diagnostics,
        ]
    );
    assert_eq!(
        emux.supported_substrates,
        vec![BackendSubstrateKind::DockerEngine]
    );
    assert_eq!(emux.substrates.len(), 1);
    assert!(emux
        .substrates
        .iter()
        .all(|substrate| substrate.capability.is_supported));
    assert!(emux
        .substrates
        .iter()
        .all(|substrate| substrate.health.status == BackendSubstrateStatus::Healthy));

    let scores = registry.rank_family("linux-router-mips");
    assert!(
        scores.iter().any(|score| score.backend_id == "emux"),
        "emux should appear as a ranked backend candidate for router-mips"
    );
}
