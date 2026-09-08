use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};

#[test]
fn substrate_preference_auto_orders_service_system_reference() {
    assert_eq!(
        SubstratePreference::Auto.default_order(),
        vec![
            SubstrateKind::Service,
            SubstrateKind::System,
            SubstrateKind::Reference,
        ]
    );
}
