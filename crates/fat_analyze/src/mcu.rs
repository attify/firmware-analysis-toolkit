use fat_core::mcu_inspection::{
    InterruptHandlerKind, InterruptVectorEntry, InterruptVectorReport, McuIdentification,
    McuIdentityString, McuProfile, McuVectorCandidate, RepeatedVectorTarget,
};
use fat_family::mcu_packs::{resolve_mcu_pack, McuFamilyPack};

/// Attempt to detect and characterize a bare-metal ARM Cortex-M firmware image
/// by validating the interrupt vector table at the start of `bytes`.
///
/// Returns `Some(McuProfile)` if the first bytes look like a valid Cortex-M IVT,
/// or `None` if validation fails.
pub fn detect_cortex_m_ivt(bytes: &[u8]) -> Option<McuProfile> {
    detect_cortex_m_ivt_with_base(bytes, None)
}

/// Compatibility profile for consumers that require a code mapping. Structural
/// recognition is available independently through `identify_mcu` even when the
/// code base is unknown. An explicit base is an assumption, not family evidence.
pub fn detect_cortex_m_ivt_with_base(bytes: &[u8], user_base: Option<u32>) -> Option<McuProfile> {
    let candidate = probe_vectors_with_base(bytes, 0, user_base)?;
    if !candidate.accepted {
        return None;
    }
    let sp = candidate.initial_sp;
    let reset = candidate.reset_vector;
    let reset_addr = reset & !1;
    let (chip_family, confidence) =
        identify_chip_family(sp, reset_addr).unwrap_or(("Cortex-M (unknown vendor)", 0));
    let flash_base = user_base.or_else(|| infer_code_base(reset_addr))?;
    if reset_addr < flash_base {
        return None;
    }

    let table = scan_vector_table(
        bytes,
        Some(flash_base),
        resolve_mcu_pack(Some(chip_family), None),
    )?;

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
        active_interrupt_count: table.active_count,
        total_interrupt_slots: table.entry_count,
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

/// Recover observed vector entries with one set of bounds and counting rules.
/// `vector_address` maps byte zero of this slice, not byte zero of its container.
/// A populated entry is a candidate handler, never proof of runtime activity.
pub(crate) fn scan_vector_table(
    bytes: &[u8],
    vector_address: Option<u32>,
    pack: Option<&McuFamilyPack>,
) -> Option<InterruptVectorReport> {
    if bytes.len() < 8 {
        return None;
    }
    let word_at = |index: usize| {
        bytes
            .get(index * 4..index * 4 + 4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
    };
    let reset = word_at(1)?;
    let reserved = |index: usize| {
        matches!(index, 7..=10 | 13)
            || pack.is_some_and(|pack| pack.reserved_vector_indices.contains(&(index as u16)))
    };
    let plausible = |word: u32| plausible_handler(word, reset, pack);
    let available_words = bytes.len() / 4;
    let family_limit = pack
        .and_then(|pack| pack.total_vector_entries)
        .map(usize::from);
    // Resource bound only: this is not a guessed hardware IRQ capacity.
    let requested_limit = family_limit.unwrap_or(256);
    let max_entries = available_words.min(requested_limit);
    let mut handler_boundary = None;
    // Even before walking external vectors, core handler addresses can prove
    // that executable bytes begin before an otherwise plausible pointer word.
    for index in 1..available_words.min(16) {
        let word = word_at(index)?;
        if !reserved(index) && plausible(word) {
            if let Some(relative) = vector_address.and_then(|base| (word & !1).checked_sub(base)) {
                if relative >= 16 && (relative as usize) < bytes.len() {
                    handler_boundary = Some(
                        handler_boundary
                            .map_or(relative as usize, |old: usize| old.min(relative as usize)),
                    );
                }
            }
        }
    }
    let mut entries = Vec::new();
    let mut boundary = None;
    for index in 0..max_entries {
        if handler_boundary.is_some_and(|offset| index * 4 + 4 > offset) {
            boundary = Some(("mapped-handler", format!(
                "stopped before mapped handler code at vector-relative offset 0x{:X}; intervening zero words may be alignment padding",
                handler_boundary.unwrap()
            )));
            break;
        }
        let word = word_at(index)?;
        let is_reserved = reserved(index);
        if index > 1 && !is_reserved && word == u32::MAX {
            boundary = Some((
                "empty-vector-sentinel",
                format!("stopped before word {index} at the first 0xffffffff vector sentinel"),
            ));
            break;
        }
        if index > 1 && !is_reserved && word != 0 && !plausible(word) {
            boundary = Some((
                "implausible-handler-word",
                format!(
                "stopped before word {index}: not a Thumb pointer in a compatible executable region"
            ),
            ));
            break;
        }
        let handler_kind = match index {
            0 => InterruptHandlerKind::InitialStackPointer,
            1 => InterruptHandlerKind::ResetHandler,
            _ if is_reserved => InterruptHandlerKind::Reserved,
            _ if word == 0 || word == u32::MAX => InterruptHandlerKind::Unpopulated,
            _ => InterruptHandlerKind::Interrupt,
        };
        if matches!(
            handler_kind,
            InterruptHandlerKind::ResetHandler | InterruptHandlerKind::Interrupt
        ) {
            if let Some(relative) = vector_address.and_then(|base| (word & !1).checked_sub(base)) {
                if (relative as usize) < (index + 1) * 4 {
                    boundary = Some(("overlapping-handler-target", format!(
                        "stopped before word {index}: mapped handler target 0x{:08X} overlaps already scanned vector words; table extent or mapping is unresolved", word & !1
                    )));
                    break;
                }
                if (relative as usize) < bytes.len() {
                    handler_boundary = Some(
                        handler_boundary
                            .map_or(relative as usize, |old| old.min(relative as usize)),
                    );
                }
            }
        }
        entries.push(InterruptVectorEntry {
            index: index as u16,
            address: word,
            handler_kind,
            core_exception: core_exception_name(index).map(str::to_string),
            external_irq_number: (index >= 16).then_some(index.saturating_sub(16) as u16),
            family_label: None,
            evidence_ids: Vec::new(),
        });
    }
    let scanned_word_count = entries.len();
    let (scan_boundary, mut scan_boundary_rationale) = if let Some((kind, reason)) = boundary {
        (kind.to_string(), vec![reason])
    } else if family_limit == Some(max_entries) {
        ("family-vector-limit".into(), vec![format!(
            "family profile {} bounds the table at {max_entries} words; this is a profile bound, not a measurement of enabled interrupts",
            pack.map(|p| p.family_id).unwrap_or("unknown")
        )])
    } else if available_words <= requested_limit {
        ("available-bytes".into(), vec![format!(
            "artifact contains {available_words} complete words from the selected vector offset; a partial table cannot establish hardware IRQ capacity"
        )])
    } else {
        ("fallback-vector-limit".into(), vec![format!(
            "no documented family bound was available; stopped at the {requested_limit}-word safety cap without establishing table completeness"
        )])
    };
    // Without a reached profile bound, trailing zero words cannot distinguish
    // absent IRQ vectors from alignment padding. Keep holes between observed
    // handlers, but do not report trailing fill as additional external IRQs.
    if scan_boundary != "family-vector-limit" {
        let retained = entries
            .iter()
            .rposition(|entry| entry.address != 0)
            .map_or(0, |index| index + 1)
            .max(entries.len().min(16));
        if retained < entries.len() {
            scan_boundary_rationale.push(format!(
                "omitted {} trailing zero words because external-vector extent versus padding is unresolved", entries.len() - retained
            ));
            entries.truncate(retained);
        }
    }
    scan_boundary_rationale.push(
        "populated handler entries do not establish enabled interrupts, hardware IRQ capacity, or a shared target's runtime role".into()
    );
    let is_handler = |entry: &InterruptVectorEntry| {
        matches!(
            entry.handler_kind,
            InterruptHandlerKind::ResetHandler | InterruptHandlerKind::Interrupt
        )
    };
    let core_exception_count = entries
        .iter()
        .filter(|entry| entry.index < 16 && is_handler(entry))
        .count();
    let external_irq_count = entries
        .iter()
        .filter(|entry| entry.index >= 16 && is_handler(entry))
        .count();
    let reserved_entry_count = entries
        .iter()
        .filter(|entry| entry.handler_kind == InterruptHandlerKind::Reserved)
        .count();
    let unpopulated_entry_count = entries
        .iter()
        .filter(|entry| entry.handler_kind == InterruptHandlerKind::Unpopulated)
        .count();
    let mut targets = std::collections::HashMap::<u32, usize>::new();
    for entry in entries.iter().filter(|entry| is_handler(entry)) {
        *targets.entry(entry.address & !1).or_default() += 1;
    }
    let unique_aligned_target_count = targets.len();
    let mut repeated_targets = targets
        .into_iter()
        .filter_map(|(aligned_address, reference_count)| {
            (reference_count > 1).then_some(RepeatedVectorTarget {
                aligned_address,
                reference_count,
            })
        })
        .collect::<Vec<_>>();
    repeated_targets.sort_by(|left, right| {
        right
            .reference_count
            .cmp(&left.reference_count)
            .then_with(|| left.aligned_address.cmp(&right.aligned_address))
    });
    Some(InterruptVectorReport {
        entry_count: entries.len(),
        active_count: core_exception_count + external_irq_count,
        core_exception_count,
        external_irq_count,
        reserved_entry_count,
        unpopulated_entry_count,
        // Aliases alone cannot prove a default-handler loop or inactivity.
        default_handler_count: 0,
        scanned_word_count,
        handler_candidate_count: core_exception_count + external_irq_count,
        unique_aligned_target_count,
        repeated_targets,
        scan_boundary,
        scan_boundary_rationale,
        entries,
        provenance: None,
    })
}

fn plausible_handler(word: u32, reset: u32, pack: Option<&McuFamilyPack>) -> bool {
    word != u32::MAX
        && word & 1 == 1
        && (word >> 24 == reset >> 24
            || pack.is_some_and(|pack| {
                pack.executable_regions
                    .iter()
                    .any(|region| region.contains(word & !1))
            }))
}

fn core_exception_name(index: usize) -> Option<&'static str> {
    match index {
        1 => Some("Reset"),
        2 => Some("NMI"),
        3 => Some("HardFault"),
        4 => Some("MemManage"),
        5 => Some("BusFault"),
        6 => Some("UsageFault"),
        11 => Some("SVCall"),
        12 => Some("DebugMonitor"),
        14 => Some("PendSV"),
        15 => Some("SysTick"),
        _ => None,
    }
}

// ------------------------------------------------------------------
// Chip family identification from SP and reset address ranges
// ------------------------------------------------------------------

fn identify_chip_family(sp: u32, reset_addr: u32) -> Option<(&'static str, u8)> {
    fat_family::mcu_packs::identify_address_family(sp, reset_addr)
}

pub(crate) fn infer_code_base(reset_addr: u32) -> Option<u32> {
    fat_family::mcu_packs::infer_code_base(reset_addr)
}

/// Structural probe: address-family assumptions never veto the vector evidence.
pub fn probe_cortex_m_vectors(bytes: &[u8], offset: usize) -> Option<McuVectorCandidate> {
    probe_vectors_with_base(bytes, offset, None)
}

fn probe_vectors_with_base(
    bytes: &[u8],
    offset: usize,
    user_base: Option<u32>,
) -> Option<McuVectorCandidate> {
    let data = bytes.get(offset..)?;
    if data.len() < 16 {
        return None;
    }
    let word = |slot: usize| u32::from_le_bytes(data[slot * 4..slot * 4 + 4].try_into().unwrap());
    let sp = word(0);
    // Cortex-M implementations have SRAM in several architectural regions.
    // This is candidate plausibility, not a claim that a chip owns that RAM.
    let plausible_sp = (0x2000_0000..=0x4000_0000).contains(&sp)
        || (0x1000_0000..=0x1001_0000).contains(&sp)
        || (0x0200_0000..=0x0204_0000).contains(&sp);
    if !plausible_sp && offset != 0 {
        return None;
    }
    let reset = word(1);
    let mut candidate = McuVectorCandidate {
        offset: offset as u64,
        initial_sp: sp,
        reset_vector: reset,
        confidence: "insufficient".into(),
        ..Default::default()
    };
    if !plausible_sp {
        candidate
            .contradictions
            .push("initial stack pointer is outside plausible SRAM regions".into());
        return Some(candidate);
    }
    if data[..16].iter().all(|b| (0x20..=0x7e).contains(b)) {
        candidate
            .contradictions
            .push("candidate vector words consist entirely of printable text".into());
        return Some(candidate);
    }
    if sp & 3 != 0 {
        candidate
            .contradictions
            .push("initial stack pointer is not word-aligned".into());
    }
    if reset & 1 == 0 || reset == u32::MAX {
        candidate
            .contradictions
            .push("reset vector is not a valid Thumb pointer".into());
    }
    if !candidate.contradictions.is_empty() {
        return Some(candidate);
    }
    let pack = identify_chip_family(sp, reset & !1)
        .and_then(|(family, _)| resolve_mcu_pack(Some(family), None));
    let compatible = |value: u32| plausible_handler(value, reset, pack);
    if !compatible(word(2)) && !compatible(word(3)) {
        candidate
            .contradictions
            .push("neither NMI nor HardFault corroborates a compatible executable region".into());
        return Some(candidate);
    }
    let mut corroborating = 0;
    let mut contradictory = 0;
    // Small compiled images may contain only a partial table followed by code.
    // A mapped handler can bound the table; words at/after that address must
    // not be interpreted as additional exception vectors.
    let table_end = user_base
        .or_else(|| infer_code_base(reset & !1))
        .and_then(|base| {
            (1..4)
                .map(word)
                .filter(|v| compatible(*v))
                .filter_map(|v| (v & !1).checked_sub(base))
                .filter(|n| *n >= 16)
                .min()
        })
        .map(|n| n as usize)
        .unwrap_or(64)
        .min(64)
        .min(data.len());
    // Reserved core slots are excluded: some vendors store a checksum there.
    for slot in [2, 3, 4, 5, 6, 11, 12, 14, 15] {
        if slot * 4 + 4 > table_end {
            continue;
        }
        let value = word(slot);
        if value == 0 || value == u32::MAX {
            continue;
        }
        if compatible(value) {
            corroborating += 1;
        } else {
            contradictory += 1;
        }
    }
    candidate.evidence = vec![
        "word-aligned initial stack pointer in a plausible SRAM region".into(),
        "reset vector has the Thumb bit set".into(),
        format!("{corroborating} core exception vectors point into compatible executable regions"),
    ];
    if table_end < 64 {
        candidate.evidence.push(format!("partial vector table: checked {table_end} bytes before a mapped handler or end of input"));
    }
    if let Some(base) = user_base {
        candidate.evidence.push(format!(
            "table boundary evaluated using user-specified base 0x{base:08X}"
        ));
    }
    if contradictory > 0 {
        candidate.contradictions.push(format!(
            "{contradictory} core exception words contradict the address pattern"
        ));
    }
    candidate.accepted =
        contradictory <= 3 && corroborating >= 1 && (contradictory <= 1 || corroborating >= 2);
    if candidate.accepted {
        candidate.confidence = if corroborating >= 3 && contradictory == 0 && table_end == 64 {
            "high"
        } else {
            "medium"
        }
        .into();
    }
    Some(candidate)
}

pub fn vector_candidates(bytes: &[u8]) -> Vec<McuVectorCandidate> {
    vector_candidates_with_base(bytes, None)
}

pub(crate) fn vector_candidates_with_base(
    bytes: &[u8],
    user_base: Option<u32>,
) -> Vec<McuVectorCandidate> {
    let mut candidates = Vec::new();
    if bytes.len() < 16 {
        return candidates;
    }
    for offset in (0..=bytes.len().min(0x2000) - 16).step_by(4) {
        if let Some(candidate) = probe_vectors_with_base(bytes, offset, user_base) {
            if candidate.accepted {
                candidates.push(candidate);
                if offset == 0 || candidates.iter().filter(|c| c.accepted).count() >= 4 {
                    break;
                }
            } else if offset == 0 {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

pub fn identify_mcu(bytes: &[u8]) -> McuIdentification {
    identify_mcu_with_base(bytes, None)
}

pub(crate) fn identify_mcu_with_base(bytes: &[u8], user_base: Option<u32>) -> McuIdentification {
    let candidates = vector_candidates_with_base(bytes, user_base);
    let strings = identity_strings(bytes);
    let mut result = McuIdentification {
        architecture_confidence: "insufficient".into(),
        family_confidence: "unresolved".into(),
        vector_candidates: candidates,
        identity_strings: strings,
        ..Default::default()
    };
    let Some(candidate) = result.vector_candidates.iter().find(|c| c.accepted) else {
        result.notes.push(
            "no consistent Cortex-M vector table found in the first 8 KiB; architecture unresolved"
                .into(),
        );
        return result;
    };
    result.architecture = Some("ARM Cortex-M".into());
    result.architecture_confidence = candidate.confidence.clone();
    let sp = candidate.initial_sp;
    let reset = candidate.reset_vector & !1;
    if infer_code_base(reset).is_some() {
        if let Some((family, _)) =
            identify_chip_family(sp, reset).filter(|(f, _)| !f.starts_with("Cortex-M"))
        {
            result.family = Some(family.into());
            result.family_confidence = "tentative".into();
            result
                .family_evidence
                .push("stack and reset address ranges match a family heuristic".into());
        }
    }
    for hit in &result.identity_strings {
        if let Some(pack) = fat_family::mcu_packs::compatible_identity_pack(&hit.value, sp, reset) {
            result.family = Some(
                fat_family::mcu_packs::identity_display_name(&hit.value)
                    .unwrap_or(pack.display_name)
                    .into(),
            );
            result.family_confidence = "corroborated".into();
            result.family_evidence.push(format!(
                "{} identity at file offset 0x{:X}, compatible SRAM and executable region ({})",
                hit.encoding, hit.offset, pack.family_id
            ));
            if pack
                .executable_regions
                .iter()
                .any(|region| region.kind == "boot-rom" && region.contains(reset))
            {
                result.image_role = Some("boot-rom-likely".into());
            }
            // Prefer a narrower marker when both series and subfamily occur.
            if result.family.as_deref() != Some(pack.display_name) {
                break;
            }
        }
    }
    if infer_code_base(reset).is_none() && user_base.is_none() {
        result.notes.push(
            "code mapping unresolved; vector recognition does not establish the load address"
                .into(),
        );
    }
    if let Some(base) = user_base {
        result.notes.push(format!(
            "load address 0x{base:08X} is a user-specified assumption"
        ));
    }
    result
        .notes
        .push("identity strings and address ranges do not establish an exact device model".into());
    result
}

fn identity_strings(bytes: &[u8]) -> Vec<McuIdentityString> {
    let mut hits = Vec::new();
    for wide in [false, true] {
        let step = if wide { 2 } else { 1 };
        let mut offset = 0;
        while offset < bytes.len() && hits.len() < 32 {
            let start = offset;
            let mut text = String::new();
            while offset < bytes.len()
                && (0x20..=0x7e).contains(&bytes[offset])
                && (!wide || bytes.get(offset + 1) == Some(&0))
                && text.len() < 256
            {
                text.push(bytes[offset] as char);
                offset += step;
            }
            if text.len() >= 6 && fat_family::mcu_packs::identity_pack(&text).is_some() {
                hits.push(McuIdentityString {
                    offset: start as u64,
                    encoding: if wide { "utf-16le" } else { "ascii" }.into(),
                    value: text,
                });
            }
            if offset == start {
                offset += 1;
            }
        }
    }
    hits.sort_by_key(|hit| hit.offset);
    hits
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
