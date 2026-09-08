use fat_family::mcu_packs::{resolve_mcu_pack, PeripheralRole};

#[test]
fn stm32h7_pack_resolves_mmio_irq_and_memory_hints() {
    let pack = resolve_mcu_pack(Some("STM32H7"), None).expect("stm32h7 pack");

    assert_eq!(pack.family_id, "stm32h7");
    assert_eq!(pack.display_name, "STM32H7");
    assert_eq!(pack.flash_base, 0x0800_0000);
    assert_eq!(pack.total_vector_entries, Some(166));

    let mmio = pack.lookup_mmio(0x5800_1C00).expect("i2c4 mmio");
    assert_eq!(mmio.peripheral_name, "I2C4");
    assert!(mmio.roles.contains(&PeripheralRole::CommsBridge));
    assert!(!mmio.roles.contains(&PeripheralRole::HostSidecarLink));

    let irq = pack.lookup_irq(22).expect("irq 22 label");
    assert_eq!(irq.name, "EXTI0");

    assert!(pack
        .sram_ranges
        .iter()
        .any(|range| range.start == 0x2400_0000 && range.end == 0x2408_0000));
}

#[test]
fn stm32h7_pack_exposes_role_hints_and_alias_lookup() {
    let pack = resolve_mcu_pack(Some("stm32h7"), None).expect("stm32h7 alias");

    assert!(pack.aliases.contains(&"stm32h743"));
    assert!(pack.aliases.contains(&"stm32h7xx"));

    let hint = pack.role_hint_for_peripheral("CRC").expect("crc role hint");
    assert!(hint.roles.contains(&PeripheralRole::ErrorDetection));

    let flash = pack
        .lookup_mmio(0x5200_2000)
        .expect("flash controller mmio");
    assert_eq!(flash.peripheral_name, "FLASH");
    assert!(flash.roles.contains(&PeripheralRole::FlashWritePath));
}

#[test]
fn stm32h7_pack_does_not_assign_board_specific_roles() {
    let pack = resolve_mcu_pack(Some("STM32H7"), None).expect("stm32h7 pack");
    let board_specific = [
        PeripheralRole::UpdateTransport,
        PeripheralRole::HostSidecarLink,
        PeripheralRole::Actuation,
    ];

    for (address, name) in [
        (0x4000_1000, "TIM6"),
        (0x4000_3C00, "SPI3"),
        (0x4000_4C00, "UART4"),
        (0x4000_5400, "I2C1"),
        (0x4000_7800, "UART7"),
        (0x4000_7C00, "UART8"),
        (0x4001_1000, "USART1"),
        (0x4002_8000, "ETH_MAC"),
        (0x5800_1C00, "I2C4"),
    ] {
        let mmio = pack.lookup_mmio(address).expect("mmio range");
        assert_eq!(mmio.peripheral_name, name);
        for role in board_specific {
            assert!(
                !mmio.roles.contains(&role),
                "generic STM32H7 {name} range contains board-specific role {role:?}"
            );
        }

        if let Some(hint) = pack.role_hint_for_peripheral(name) {
            for role in board_specific {
                assert!(
                    !hint.roles.contains(&role),
                    "generic STM32H7 {name} hint contains board-specific role {role:?}"
                );
            }
        }
    }
}

#[test]
fn stm32h743_irq_labels_match_cmsis_vector_indices() {
    let pack = resolve_mcu_pack(Some("STM32H743"), None).expect("stm32h743 pack");
    for (vector_index, expected_label) in [
        (22, "EXTI0"),
        (27, "DMA1_Stream0"),
        (28, "DMA1_Stream1"),
        (29, "DMA1_Stream2"),
        (30, "DMA1_Stream3"),
        (31, "DMA1_Stream4"),
        (32, "DMA1_Stream5"),
        (33, "DMA1_Stream6"),
        (47, "I2C1_EV"),
        (48, "I2C1_ER"),
        (63, "DMA1_Stream7"),
        (67, "SPI3"),
        (68, "UART4"),
        (70, "TIM6_DAC"),
        (72, "DMA2_Stream0"),
        (73, "DMA2_Stream1"),
        (98, "UART7"),
        (99, "UART8"),
        (111, "I2C4_EV"),
        (112, "I2C4_ER"),
        (145, "BDMA_Channel0"),
        (146, "BDMA_Channel1"),
    ] {
        let label = pack.lookup_irq(vector_index).expect("IRQ label");
        assert_eq!(
            label.name,
            expected_label,
            "wrong CMSIS label for vector {vector_index} (IRQ {})",
            vector_index - 16
        );
    }
}

#[test]
fn generic_cortex_m_pack_is_fallback() {
    let pack = resolve_mcu_pack(None, None).expect("fallback pack");

    assert_eq!(pack.family_id, "cortex-m");
    assert!(pack.lookup_mmio(0x1234_5678).is_none());
    assert!(pack.lookup_irq(999).is_none());
}
