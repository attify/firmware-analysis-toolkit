use fat_core::mcu_inspection::McuProfile;
use fat_family::mcu_packs::resolve_mcu_pack;

/// Attempt to detect and characterize a bare-metal ARM Cortex-M firmware image
/// by validating the interrupt vector table at the start of `bytes`.
///
/// Returns `Some(McuProfile)` if the first bytes look like a valid Cortex-M IVT,
/// or `None` if validation fails.
pub fn detect_cortex_m_ivt(bytes: &[u8]) -> Option<McuProfile> {
    if bytes.len() < 16 {
        return None;
    }

    let sp = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let reset = u32::from_le_bytes(bytes[4..8].try_into().ok()?);

    // Reset vector must have Thumb bit set (bit 0 = 1).
    if reset & 1 == 0 {
        return None;
    }
    let reset_addr = reset & !1u32;

    // SP must be in a known SRAM range; use it + reset to identify chip family.
    let (chip_family, confidence) = identify_chip_family(sp, reset_addr)?;

    // Reset must be in known flash.
    let flash_base = infer_flash_base(reset_addr)?;
    if reset_addr < flash_base || reset_addr.wrapping_sub(flash_base) > 16 * 1024 * 1024 {
        return None;
    }

    // Validate NMI (word 2) and HardFault (word 3) — at least one must look
    // like a valid Thumb code pointer in flash.
    let nmi = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let hf = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    let nmi_valid = (nmi & 1 == 1) && (nmi & !1u32) >= flash_base;
    let hf_valid = (hf & 1 == 1) && (hf & !1u32) >= flash_base;
    if !nmi_valid && !hf_valid {
        return None;
    }

    let family_vector_limit = resolve_mcu_pack(Some(chip_family), None)
        .and_then(|pack| pack.total_vector_entries.map(|count| count as usize))
        .unwrap_or(256);
    let max_vectors = std::cmp::min(bytes.len() / 4, family_vector_limit);

    let mut words = Vec::with_capacity(max_vectors);
    let mut address_counts = std::collections::HashMap::<u32, usize>::new();
    for i in 0..max_vectors {
        let off = i * 4;
        if off + 4 > bytes.len() {
            break;
        }
        let word = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap_or([0; 4]));
        words.push(word);
        if i >= 2 && word != 0 && word != 0xFFFF_FFFF {
            *address_counts.entry(word).or_insert(0) += 1;
        }
    }

    let default_handler = address_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .and_then(|(address, count)| (*count >= 8).then_some(*address));

    let active = words
        .iter()
        .enumerate()
        .filter(|(index, word)| {
            if *index == 0 {
                return false;
            }
            if **word == 0 || **word == 0xFFFF_FFFF {
                return false;
            }
            if let Some(default_handler) = default_handler {
                if *index >= 2 && **word == default_handler {
                    return false;
                }
            }
            true
        })
        .count();

    // Flash padding characterization.
    let (code_size, padding_pct) = characterize_flash_padding(bytes);

    // SDK / RTOS / stack / peripheral fingerprinting.
    let fingerprint = fingerprint_stacks(bytes);

    Some(McuProfile {
        architecture: "ARM Cortex-M".to_string(),
        chip_family: chip_family.to_string(),
        chip_family_confidence: confidence,
        initial_sp: sp,
        reset_vector: reset,
        flash_base,
        active_interrupt_count: active,
        total_interrupt_slots: max_vectors,
        code_size,
        total_size: bytes.len() as u64,
        padding_percent: padding_pct,
        is_power_of_two_size: bytes.len().is_power_of_two(),
        detected_sdk: fingerprint.sdk,
        detected_rtos: fingerprint.rtos,
        detected_stacks: fingerprint.stacks,
        peripheral_hints: fingerprint.peripherals,
    })
}

// ------------------------------------------------------------------
// Chip family identification from SP and reset address ranges
// ------------------------------------------------------------------

fn identify_chip_family(sp: u32, reset_addr: u32) -> Option<(&'static str, u8)> {
    // Cortex-M stacks descend, so the initial SP may point one byte past the
    // last addressable SRAM byte. STM32H7 AXI SRAM ends at 0x2407_FFFF.
    if (0x2400_0000..=0x2408_0000).contains(&sp) {
        return Some(("STM32H7", 95));
    }

    match sp >> 16 {
        // STM32H7: DTCM-RAM at 0x3000_0000 .. 0x3003_FFFF
        0x3000..=0x3003 => Some(("STM32H7", 85)),
        // CCM or NXP LPC1xxx at 0x1000_xxxx
        0x1000 => {
            if reset_addr >= 0x0800_0000 {
                Some(("STM32 (CCM)", 70))
            } else {
                Some(("NXP LPC1xxx", 70))
            }
        }
        // NXP LPC4300: local SRAM at 0x0200_0000 .. 0x0203_FFFF
        0x0200..=0x0203 => Some(("NXP LPC4300", 80)),
        _ => {
            let sp_top = sp >> 24;
            if sp_top == 0x20 {
                // Generic SRAM at 0x20xx_xxxx — typical of many Cortex-M parts.
                if (0x0800_0000..0x0900_0000).contains(&reset_addr) {
                    Some((guess_stm32_subfamily(sp), 75))
                } else if reset_addr < 0x0010_0000 {
                    Some(("Cortex-M (NXP/Nordic/TI)", 40))
                } else {
                    Some(("Cortex-M (unknown vendor)", 30))
                }
            } else {
                None
            }
        }
    }
}

fn guess_stm32_subfamily(sp: u32) -> &'static str {
    match sp & 0x00FF_FFFF {
        0..=0x4000 => "STM32 (small, F0/L0/G0)",
        0x4001..=0x2_0000 => "STM32 (medium, F1/F3/L4/G4)",
        0x2_0001..=0x8_0000 => "STM32 (large, F4/F7/U5)",
        _ => "STM32 (unknown)",
    }
}

fn infer_flash_base(reset_addr: u32) -> Option<u32> {
    match reset_addr >> 24 {
        0x08 => Some(0x0800_0000), // STM32 internal flash
        0x00 => Some(0x0000_0000), // NXP, Nordic, TI — flash at 0
        0x01 => Some(0x0100_0000), // some NXP parts
        0x04 => Some(0x0040_0000), // some NXP FlexSPI
        _ => None,
    }
}

// ------------------------------------------------------------------
// Flash padding characterization
// ------------------------------------------------------------------

fn characterize_flash_padding(bytes: &[u8]) -> (Option<u64>, Option<u8>) {
    if bytes.len() < 1024 {
        return (None, None);
    }
    let last_nonff = match bytes.iter().rposition(|&b| b != 0xFF) {
        Some(pos) => pos,
        None => return (None, None),
    };
    let code_size = (last_nonff + 1) as u64;
    let total = bytes.len() as u64;
    let padding_pct = ((total - code_size) * 100 / total) as u8;
    if padding_pct < 10 {
        return (Some(code_size), None);
    }
    (Some(code_size), Some(padding_pct))
}

// ------------------------------------------------------------------
// SDK / RTOS / stack / peripheral fingerprinting
// ------------------------------------------------------------------

struct StackFingerprint {
    sdk: Option<String>,
    rtos: Option<String>,
    stacks: Vec<String>,
    peripherals: Vec<String>,
}

fn fingerprint_stacks(bytes: &[u8]) -> StackFingerprint {
    let mut fp = StackFingerprint {
        sdk: None,
        rtos: None,
        stacks: Vec::new(),
        peripherals: Vec::new(),
    };

    let text = String::from_utf8_lossy(bytes);

    // SDK detection
    if text.contains("Middlewares/Third_Party") || text.contains("Drivers/STM32") {
        fp.sdk = Some("STM32CubeMX".to_string());
    }
    if fp.sdk.is_none() && text.contains("CMSIS") {
        fp.sdk = Some("ARM CMSIS".to_string());
    }

    // RTOS detection
    if text.contains("vTaskDelete")
        || text.contains("xQueueCreate")
        || text.contains("pvPortMalloc")
    {
        fp.rtos = Some("FreeRTOS".to_string());
    } else if text.contains("__device_dts_ord_") {
        fp.rtos = Some("Zephyr".to_string());
    } else if text.contains("tx_thread_") {
        fp.rtos = Some("ThreadX".to_string());
    } else if text.contains("rt_thread_") {
        fp.rtos = Some("RT-Thread".to_string());
    }

    // Network / middleware stacks
    if text.contains("dhcp.c") || text.contains("tcp.c") || text.contains("lwip") {
        fp.stacks.push("LwIP".to_string());
    }
    if text.contains("mbedtls_") || text.contains("MBEDTLS_") {
        fp.stacks.push("mbed TLS".to_string());
    }
    if text.contains("FATFS") || text.contains("f_open") {
        fp.stacks.push("FatFS".to_string());
    }
    if text.contains("tinyusb") || text.contains("USBD_") {
        fp.stacks.push("USB Device".to_string());
    }

    // Peripheral hints
    let peripheral_patterns: &[(&str, &str)] = &[
        ("EEPROM", "EEPROM"),
        ("UART", "UART"),
        ("Uart", "UART"),
        ("SPI", "SPI"),
        ("I2C", "I2C"),
        ("CAN", "CAN"),
        ("FDCAN", "FDCAN"),
        ("Ethernet", "Ethernet"),
        ("ethernet", "Ethernet"),
        ("DMA", "DMA"),
        ("ADC", "ADC"),
        ("TFTP", "TFTP"),
        ("tftp", "TFTP"),
    ];
    for &(pattern, name) in peripheral_patterns {
        if text.contains(pattern) && !fp.peripherals.contains(&name.to_string()) {
            fp.peripherals.push(name.to_string());
        }
    }

    fp
}
