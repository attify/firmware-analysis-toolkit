use fat_analyze::mcu::detect_cortex_m_ivt;

// ---------- Helper: build a minimal valid IVT byte buffer ----------

/// Build a 1024-byte buffer with a valid Cortex-M IVT at the start.
/// `sp`: initial stack pointer (word 0)
/// `reset`: reset vector (word 1) -- must have Thumb bit set
/// `nmi`: NMI handler (word 2)
/// `hardfault`: HardFault handler (word 3)
/// Remaining 252 vector slots are filled with `fill`.
fn build_ivt(sp: u32, reset: u32, nmi: u32, hardfault: u32, fill: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    for &word in &[sp, reset, nmi, hardfault] {
        buf.extend_from_slice(&word.to_le_bytes());
    }
    // Fill slots 4..256 with the fill value
    for _ in 4..256 {
        buf.extend_from_slice(&fill.to_le_bytes());
    }
    assert_eq!(buf.len(), 1024);
    buf
}

// ===================================================================
// Test 1: Valid STM32H7 IVT is detected
// ===================================================================
#[test]
fn test_valid_stm32h7_ivt_detected() {
    // Real values from the Unitree STM32H743 binary:
    //   SP    = 0x2401A058  (AXI SRAM, 0x24xx range -> STM32H7)
    //   Reset = 0x080002AD  (flash, Thumb bit set)
    //   NMI   = 0x0800947B  (flash, Thumb bit set)
    //   HF    = 0x08007B81  (flash, Thumb bit set)
    let bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(profile.is_some(), "should detect valid STM32H7 IVT");

    let p = profile.unwrap();
    assert_eq!(p.architecture, "ARM Cortex-M");
    assert_eq!(p.chip_family, "STM32H7");
    assert!(
        p.chip_family_confidence >= 90,
        "confidence should be >= 90 for STM32H7, got {}",
        p.chip_family_confidence
    );
    assert_eq!(p.initial_sp, 0x2401_A058);
    assert_eq!(p.reset_vector, 0x0800_02AD);
    assert_eq!(p.flash_base, 0x0800_0000);
}

#[test]
fn test_stm32h7_axi_sram_end_stack_pointer_is_detected() {
    // A descending Cortex-M stack may start one byte past the last SRAM byte.
    // STM32H743 AXI SRAM spans 0x2400_0000..=0x2407_FFFF, so 0x2408_0000
    // is a valid initial SP even though it is not itself an addressable byte.
    let bytes = build_ivt(
        0x2408_0000,
        0x0804_0299,
        0x0804_42FF,
        0x0804_55B1,
        0x0000_0000,
    );

    let profile = detect_cortex_m_ivt(&bytes).expect("should accept the top of STM32H7 AXI SRAM");

    assert_eq!(profile.chip_family, "STM32H7");
    assert_eq!(profile.initial_sp, 0x2408_0000);
    assert_eq!(profile.reset_vector, 0x0804_0299);
}

// ===================================================================
// Test 2: Valid STM32F4 IVT is detected (SP in 0x20xx range)
// ===================================================================
#[test]
fn test_valid_stm32f4_ivt_detected() {
    // Typical STM32F4 values:
    //   SP    = 0x20010000  (SRAM1, 0x20xx range)
    //   Reset = 0x08000101  (flash, Thumb bit set)
    let bytes = build_ivt(
        0x2001_0000,
        0x0800_0101,
        0x0800_0201,
        0x0800_0301,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(profile.is_some(), "should detect valid STM32F4 IVT");

    let p = profile.unwrap();
    assert_eq!(p.architecture, "ARM Cortex-M");
    assert!(
        p.chip_family.starts_with("STM32"),
        "chip_family should start with STM32, got {}",
        p.chip_family
    );
    assert_eq!(p.initial_sp, 0x2001_0000);
    assert_eq!(p.reset_vector, 0x0800_0101);
    assert_eq!(p.flash_base, 0x0800_0000);
}

// ===================================================================
// Test 3: Reset vector without Thumb bit is rejected
// ===================================================================
#[test]
fn test_reset_without_thumb_bit_rejected() {
    // Reset = 0x08000100  (bit 0 = 0, no Thumb)
    let bytes = build_ivt(
        0x2001_0000,
        0x0800_0100,
        0x0800_0201,
        0x0800_0301,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(
        profile.is_none(),
        "should reject IVT when reset vector has no Thumb bit"
    );
}

// ===================================================================
// Test 4: Non-MCU binary (ELF magic) is rejected
// ===================================================================
#[test]
fn test_elf_binary_rejected() {
    // ELF magic: 0x7F 'E' 'L' 'F' = 0x464C457F in LE
    let mut bytes = vec![0u8; 1024];
    bytes[0] = 0x7F;
    bytes[1] = b'E';
    bytes[2] = b'L';
    bytes[3] = b'F';
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(profile.is_none(), "should reject ELF binary");
}

// ===================================================================
// Test 5: All zeros is rejected
// ===================================================================
#[test]
fn test_all_zeros_rejected() {
    let bytes = vec![0u8; 1024];
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(profile.is_none(), "should reject all-zeros input");
}

// ===================================================================
// Test 6: Input too short (< 16 bytes) is rejected
// ===================================================================
#[test]
fn test_too_short_rejected() {
    let bytes = vec![0xFFu8; 12];
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(
        profile.is_none(),
        "should reject input shorter than 16 bytes"
    );
}

// ===================================================================
// Test 7: Active interrupt count is computed correctly
// ===================================================================
#[test]
fn test_active_interrupt_count() {
    // Reset, NMI, HF + 4 more non-zero handlers; SP is not a handler.
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    // Set slots 4..8 to non-zero handler addresses
    for i in 4..8 {
        let addr: u32 = 0x0800_1001;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&addr.to_le_bytes());
    }
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert_eq!(profile.active_interrupt_count, 7);
    assert_eq!(profile.total_interrupt_slots, 166);
}

#[test]
fn test_stm32h7_vector_count_is_bounded_to_family_ivt_size() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.resize(256 * 4, 0x00);
    for i in 166..256 {
        let addr: u32 = 0x0800_2001;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&addr.to_le_bytes());
    }

    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert_eq!(profile.total_interrupt_slots, 166);
    assert_eq!(
        profile.active_interrupt_count, 3,
        "SP should not count as a handler, and suffix words past the STM32H7 IVT boundary must be ignored"
    );
}

// ===================================================================
// Test 8: Flash padding is detected
// ===================================================================
#[test]
fn test_flash_padding_detected() {
    // Build a buffer: 512 bytes of code + 1536 bytes of 0xFF padding = 2048 bytes
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    // Extend to 2048 with 0xFF
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    // code_size should be around 1024 (the last non-0xFF byte is at the end of the IVT)
    // since the IVT is 1024 bytes with the last active data being the hardfault at byte 15
    // but we have zeros for the rest of the IVT, and zeros != 0xFF
    // The last non-0xFF byte position depends on what's in the IVT.
    // Slots 4..256 are 0x00000000, so the last non-0xFF byte is at position 15 (end of hardfault).
    // Actually, 0x00 != 0xFF, so the last non-0xFF is at position 1023 (last byte of a zero word).
    // Wait -- zero bytes are not 0xFF, so rposition will find them.
    // Let's think: the IVT has zero-filled slots 4..256. Those are 0x00 bytes.
    // So the last non-0xFF byte is at 1023 (the last 0x00 in the IVT).
    // code_size = 1024, total = 2048, padding = 50%
    assert!(profile.padding_percent.is_some(), "should detect padding");
    assert_eq!(profile.padding_percent.unwrap(), 50);
    assert_eq!(profile.code_size, Some(1024));
}

// ===================================================================
// Test 9: SDK/RTOS fingerprinting detects FreeRTOS
// ===================================================================
#[test]
fn test_freertos_detection() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    // Append FreeRTOS strings after the IVT
    bytes.extend_from_slice(b"vTaskDelete xQueueCreate pvPortMalloc");
    // Pad to reasonable size
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert_eq!(profile.detected_rtos.as_deref(), Some("FreeRTOS"));
}

// ===================================================================
// Test 10: SDK/RTOS fingerprinting detects STM32CubeMX
// ===================================================================
#[test]
fn test_stm32cubemx_sdk_detection() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"Drivers/STM32H7xx_HAL_Driver some other stuff");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert_eq!(profile.detected_sdk.as_deref(), Some("STM32CubeMX"));
}

// ===================================================================
// Test 11: Peripheral hint detection
// ===================================================================
#[test]
fn test_peripheral_hints_detected() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"UART SPI I2C Ethernet DMA");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(profile.peripheral_hints.contains(&"UART".to_string()));
    assert!(profile.peripheral_hints.contains(&"SPI".to_string()));
    assert!(profile.peripheral_hints.contains(&"I2C".to_string()));
    assert!(profile.peripheral_hints.contains(&"Ethernet".to_string()));
    assert!(profile.peripheral_hints.contains(&"DMA".to_string()));
}

// ===================================================================
// Test 12: LwIP stack detection
// ===================================================================
#[test]
fn test_lwip_stack_detection() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"dhcp.c tcp.c lwip something");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(profile.detected_stacks.contains(&"LwIP".to_string()));
}

// ===================================================================
// Test 13: Power-of-two size detection
// ===================================================================
#[test]
fn test_power_of_two_size() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.resize(2048, 0xFF); // 2048 = 2^11
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(profile.is_power_of_two_size, "2048 bytes is a power of two");
    assert_eq!(profile.total_size, 2048);
}

// ===================================================================
// Test 14: Zephyr RTOS detection
// ===================================================================
#[test]
fn test_zephyr_rtos_detection() {
    let mut bytes = build_ivt(
        0x2001_0000,
        0x0800_0101,
        0x0800_0201,
        0x0800_0301,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"__device_dts_ord_something");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert_eq!(profile.detected_rtos.as_deref(), Some("Zephyr"));
}

// ===================================================================
// Test 15: NXP LPC4300 family detection (SP in 0x0200xxxx range)
// ===================================================================
#[test]
fn test_nxp_lpc4300_detection() {
    // LPC4300: SP in 0x0200_xxxx range, reset in 0x0000_xxxx flash
    let bytes = build_ivt(
        0x0200_8000,
        0x0000_0401,
        0x0000_0501,
        0x0000_0601,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(profile.is_some(), "should detect NXP LPC4300");
    let p = profile.unwrap();
    assert_eq!(p.chip_family, "NXP LPC4300");
    assert_eq!(p.flash_base, 0x0000_0000);
}

// ===================================================================
// Test 16: mbed TLS stack detection
// ===================================================================
#[test]
fn test_mbedtls_detection() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"mbedtls_ssl_handshake MBEDTLS_SSL_VERIFY_REQUIRED");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(profile.detected_stacks.contains(&"mbed TLS".to_string()));
}

// ===================================================================
// Test 17: Bare-metal (no RTOS) leaves detected_rtos as None
// ===================================================================
#[test]
fn test_bare_metal_no_rtos() {
    let bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(
        profile.detected_rtos.is_none(),
        "bare-metal should have no RTOS detected"
    );
}

// ===================================================================
// Test 18: SP outside any known SRAM range is rejected
// ===================================================================
#[test]
fn test_sp_outside_sram_rejected() {
    // SP = 0x5000_0000 -- not in any known SRAM range
    let bytes = build_ivt(
        0x5000_0000,
        0x0800_0101,
        0x0800_0201,
        0x0800_0301,
        0x0000_0000,
    );
    let profile = detect_cortex_m_ivt(&bytes);
    assert!(
        profile.is_none(),
        "should reject SP outside known SRAM range"
    );
}

// ===================================================================
// Test 19: Lowercase "ethernet" in paths is detected as Ethernet peripheral
// ===================================================================
#[test]
fn test_lowercase_ethernet_detection() {
    let mut bytes = build_ivt(
        0x2401_A058,
        0x0800_02AD,
        0x0800_947B,
        0x0800_7B81,
        0x0000_0000,
    );
    bytes.extend_from_slice(b"../Middlewares/Third_Party/LwIP/src/netif/ethernet.c");
    bytes.resize(2048, 0xFF);
    let profile = detect_cortex_m_ivt(&bytes).expect("should detect valid IVT");
    assert!(
        profile.peripheral_hints.contains(&"Ethernet".to_string()),
        "lowercase 'ethernet' in paths should be detected; got: {:?}",
        profile.peripheral_hints
    );
}
