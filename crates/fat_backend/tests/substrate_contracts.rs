use fat_backend::{
    logical_substrate_for_backend, BackendLogicalSubstrateContract, BackendRegistry,
    BackendSubstrateKind,
};
use fat_core::rehosting_policy::SubstrateKind as LogicalSubstrateKind;

#[test]
fn backend_registry_derives_service_logical_contracts_from_service_evidence() {
    let registry = BackendRegistry::with_test_backends();
    let contracts = registry.logical_substrate_contracts_for_evidence(&[
        "arch:armel".to_string(),
        "web:uhttpd".to_string(),
        "generated:reference-rootfs".to_string(),
    ]);

    let qemu_direct = find_contract(&contracts, "qemu-direct");
    assert_eq!(qemu_direct.logical_kind, LogicalSubstrateKind::Service);
    assert!(qemu_direct
        .supported_physical_substrates
        .iter()
        .any(|substrate| substrate.kind == BackendSubstrateKind::NativeHost));
    assert_eq!(qemu_direct.supported_physical_substrates.len(), 1);

    let emux = find_contract(&contracts, "emux");
    assert_eq!(emux.logical_kind, LogicalSubstrateKind::Reference);
    assert!(emux
        .fidelity_caveats
        .iter()
        .any(|caveat| caveat.contains("reference device")));
}

#[test]
fn backend_registry_derives_system_logical_contracts_when_service_evidence_is_absent() {
    let registry = BackendRegistry::with_test_backends();
    let contracts = registry.logical_substrate_contracts_for_evidence(&[
        "arch:armel".to_string(),
        "fs:squashfs".to_string(),
        "init:busybox".to_string(),
    ]);

    let qemu_direct = find_contract(&contracts, "qemu-direct");
    assert_eq!(qemu_direct.logical_kind, LogicalSubstrateKind::System);
    assert!(qemu_direct
        .fidelity_caveats
        .iter()
        .any(|caveat| caveat.contains("kernel")));
}

#[test]
fn logical_substrate_mapping_for_qemu_direct_depends_on_service_signals() {
    assert_eq!(
        logical_substrate_for_backend("qemu-direct", &["web:cgi".to_string()]),
        LogicalSubstrateKind::Service
    );
    assert_eq!(
        logical_substrate_for_backend("qemu-direct", &["init:busybox".to_string()]),
        LogicalSubstrateKind::System
    );
}

fn find_contract<'a>(
    contracts: &'a [BackendLogicalSubstrateContract],
    backend_id: &str,
) -> &'a BackendLogicalSubstrateContract {
    contracts
        .iter()
        .find(|contract| contract.backend_id == backend_id)
        .unwrap_or_else(|| panic!("missing contract for {backend_id}"))
}
