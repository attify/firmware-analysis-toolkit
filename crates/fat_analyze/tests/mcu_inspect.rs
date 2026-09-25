use std::fs;

use fat_analyze::mcu_family::{
    resolve_family_pack, resolve_family_resolution, FamilyResolutionMode,
};
use fat_analyze::mcu_inspect::{
    build_address_hypotheses, classify_image_layout, extract_execution_model,
    extract_integrity_controls, extract_mmio_clusters, extract_peripheral_surface,
    extract_shared_state_edges, extract_shared_state_risk, extract_startup_chain,
    extract_vector_table, extract_write_authority, inspect_file, summarize_security_surface,
    McuInspectRequest,
};
use fat_core::mcu_inspection::{
    EvidenceHeuristicKind, ExecutionModelKind, ExecutionModelReport, ImageLayoutKind,
    InspectionDegradation, PeripheralEvidenceSource, PeripheralRole, PeripheralUse,
    SectionProvenance, SharedAccessPattern, StartupRole,
};
use tempfile::NamedTempFile;

fn write_temp_blob(bytes: &[u8]) -> NamedTempFile {
    let temp = NamedTempFile::new().expect("create temp blob");
    fs::write(temp.path(), bytes).expect("write temp blob");
    temp
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn thumb_b(from: u32, to: u32) -> [u8; 2] {
    let pc = from.wrapping_add(4);
    let offset = to.wrapping_sub(pc) as i32;
    assert_eq!(offset & 1, 0, "Thumb B targets must be halfword aligned");
    let imm11 = ((offset >> 1) as u16) & 0x07ff;
    (0xe000u16 | imm11).to_le_bytes()
}

fn build_vector_table_image(reset: u32, second_step: Option<u32>, total_size: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, reset | 1);
    write_u32(&mut bytes, 0x0800_2001);
    write_u32(&mut bytes, 0x0800_3001);
    for _ in 4..32 {
        write_u32(&mut bytes, 0x0800_4001);
    }

    while bytes.len() < 0x100 {
        bytes.push(0x00);
    }

    let reset_offset = (reset - 0x0800_0000) as usize;
    if bytes.len() < reset_offset + 8 {
        bytes.resize(reset_offset + 8, 0x00);
    }
    bytes[reset_offset..reset_offset + 2].copy_from_slice(&thumb_b(reset, reset + 0x10));
    bytes[reset_offset + 2..reset_offset + 4].copy_from_slice(&[0x00, 0xBF]);

    let step1 = reset + 0x10;
    let step1_offset = (step1 - 0x0800_0000) as usize;
    if bytes.len() < step1_offset + 4 {
        bytes.resize(step1_offset + 4, 0x00);
    }
    match second_step {
        Some(target) => {
            bytes[step1_offset..step1_offset + 2].copy_from_slice(&thumb_b(step1, target));
            bytes[step1_offset + 2..step1_offset + 4].copy_from_slice(&[0x00, 0xBF]);
            let target_offset = (target - 0x0800_0000) as usize;
            if bytes.len() < target_offset + 4 {
                bytes.resize(target_offset + 4, 0x00);
            }
            bytes[target_offset..target_offset + 2].copy_from_slice(&[0x00, 0xBF]);
            bytes[target_offset + 2..target_offset + 4].copy_from_slice(&[0x70, 0x47]);
        }
        None => {
            bytes[step1_offset..step1_offset + 2].copy_from_slice(&[0x70, 0x47]);
            bytes[step1_offset + 2..step1_offset + 4].copy_from_slice(&[0x00, 0xBF]);
        }
    }

    if bytes.len() < total_size {
        bytes.resize(total_size, 0xFF);
    }
    bytes
}

fn build_stage1_security_blob() -> Vec<u8> {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x900);
    let mmio_words = [0x5200_2000u32, 0x5200_2004, 0x5800_1c00, 0x5800_1c04];
    let mmio_offset = 0x180;
    for (index, word) in mmio_words.iter().enumerate() {
        let start = mmio_offset + index * 4;
        bytes[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }

    let payload = b"shared_flag irq main update ota crc32 checksum erase program uart comms flash";
    let payload_offset = 0x300;
    bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

    bytes
}

fn build_relocated_vector_image() -> Vec<u8> {
    // The original fixture put code at file offset 0x4200, which actually
    // supports base 0x08000000. An app loaded at 0x08004000 has it at 0x200.
    let full = build_vector_table_image(0x0800_4200, Some(0x0800_4220), 2048);
    let mut bytes = vec![0u8; 2048];
    bytes[..128].copy_from_slice(&full[..128]);
    bytes[0x200..0x224].copy_from_slice(&full[0x4200..0x4224]);
    bytes
}

#[test]
fn regression_inferred_mapping_does_not_change_selected_vector_table() {
    let mut bytes = vec![0u8; 0x400];
    let base = 0x0804_0000u32;
    for (i, word) in [
        0x2000_2000,
        base + 0x21,
        base + 0x25,
        base + 0x29,
        base + 0x25,
        base + 0x25,
        base + 0x25,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[0x80 + i * 4..0x84 + i * 4].copy_from_slice(&word.to_le_bytes());
    }
    for i in 0..8 {
        bytes[0xa0 + i * 4..0xa4 + i * 4].copy_from_slice(&0x4770_d100u32.to_le_bytes());
    }
    for (i, word) in [0x2000_2000, base + 0x101, base + 0x201, base + 0x301]
        .into_iter()
        .enumerate()
    {
        bytes[0x100 + i * 4..0x104 + i * 4].copy_from_slice(&word.to_le_bytes());
    }
    let file = write_temp_blob(&bytes);
    let report = inspect_file(&McuInspectRequest {
        file: file.path().into(),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .unwrap();
    let selected = report
        .identification
        .as_ref()
        .unwrap()
        .vector_candidates
        .iter()
        .find(|candidate| candidate.accepted)
        .unwrap()
        .offset;
    assert_eq!(selected, 0x100);
    assert_eq!(
        report.image_layout.as_ref().unwrap().candidate_offsets[0] as u64,
        selected
    );
    assert_eq!(
        report.vector_table.unwrap().entries[1].address,
        base + 0x101
    );
    let hypotheses = build_address_hypotheses(&bytes);
    assert_eq!(
        classify_image_layout(&bytes, &hypotheses).candidate_offsets[0],
        0x100
    );
}

#[test]
fn regression_unknown_mapping_is_not_borrowed_from_a_later_vector_table() {
    let mut bytes = vec![0u8; 0x400];
    for (offset, words) in [
        (
            0x80,
            [0x2000_2000u32, 0x6000_0105, 0x6000_0201, 0x6000_0301],
        ),
        (
            0x100,
            [0x2000_2000u32, 0x0800_0105, 0x0800_0201, 0x0800_0301],
        ),
    ] {
        for (i, word) in words.into_iter().enumerate() {
            bytes[offset + i * 4..offset + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    let file = write_temp_blob(&bytes);
    let report = inspect_file(&McuInspectRequest {
        file: file.path().into(),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .unwrap();
    let identification = report.identification.unwrap();
    assert_eq!(
        identification
            .vector_candidates
            .iter()
            .find(|c| c.accepted)
            .unwrap()
            .offset,
        0x80
    );
    assert!(
        report.address_hypotheses.is_none(),
        "the later table's mapping must not be applied to the primary candidate"
    );
    assert!(report.startup_chain.is_none());
}

fn build_peripheral_surface_blob() -> Vec<u8> {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x900);
    let literals = [0x4000_4C00u32, 0x2400_21D0];
    let mmio_offset = 0x180;
    for (index, word) in literals.iter().enumerate() {
        let start = mmio_offset + index * 4;
        bytes[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[test]
fn resolve_family_pack_prefers_forced_family() {
    let resolution = resolve_family_pack(Some("STM32H7"), Some("generic"));
    assert_eq!(resolution.pack.family_id, "stm32h7");
}

#[test]
fn resolve_family_resolution_distinguishes_exact_hint_from_fallback() {
    let exact = resolve_family_resolution(Some("STM32H7"), Some("generic"));
    assert_eq!(exact.mode, FamilyResolutionMode::UserExact);
    assert_eq!(exact.pack.family_id, "stm32h7");

    let fallback = resolve_family_resolution(Some("unknown-hint"), Some("STM32H7"));
    assert_eq!(fallback.mode, FamilyResolutionMode::FastProfileExact);
    assert_eq!(fallback.pack.family_id, "stm32h7");
}

#[test]
fn inspect_file_marks_weak_signal_blob_as_degraded() {
    let temp = write_temp_blob(&[0x41; 64]);
    let path = temp.path().to_path_buf();
    let request = McuInspectRequest {
        file: path.clone(),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: Some("bogus-backend".to_string()),
    };

    let report = inspect_file(&request).expect("report");
    assert_eq!(report.artifact_path, path.display().to_string());
    assert_eq!(
        report
            .artifact_identity
            .as_ref()
            .expect("identity")
            .total_bytes,
        64
    );
    assert_eq!(
        report
            .byte_measurements
            .as_ref()
            .expect("byte measurements")
            .content_prefix_bytes,
        0
    );
    assert!(report.fast_profile.is_none());
    assert_eq!(report.analysis_provenance.backend, "native-mcu-inspect");
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "bundle_root=absent"));
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "backend_preference=bogus-backend"));
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "backend_preference_rejected=bogus-backend"));
    assert!(report
        .degradations
        .as_ref()
        .expect("degradations")
        .contains(&InspectionDegradation::WeakSignal));
}

#[test]
fn inspect_file_returns_typed_report_for_valid_cortex_m_blob() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x2401_A058u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_02ADu32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_947Bu32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_7B81u32.to_le_bytes());
    bytes.resize(2048, 0xFF);

    let temp = write_temp_blob(&bytes);
    let path = temp.path().to_path_buf();
    let request = McuInspectRequest {
        file: path.clone(),
        user_base: Some(0x0800_0000),
        user_family: Some("STM32H7".to_string()),
        bundle_root: None,
        backend_preference: Some("native-mcu-inspect".to_string()),
    };

    let report = inspect_file(&request).expect("report");
    let identity = report.artifact_identity.as_ref().expect("identity");
    assert_eq!(identity.total_bytes, bytes.len() as u64);
    assert_eq!(identity.sha256.len(), 64);

    let measurements = report
        .byte_measurements
        .as_ref()
        .expect("byte measurements");
    assert_eq!(measurements.content_prefix_bytes, 16);
    assert_eq!(measurements.trailing_uniform_byte, Some(0xff));
    assert_eq!(measurements.trailing_uniform_bytes, 2032);

    let evidence = report.evidence.as_ref().expect("measurement evidence");
    for evidence_id in [
        "artifact-identity",
        "content-prefix",
        "trailing-uniform-run",
        "vector-word-0",
        "vector-word-1",
    ] {
        assert!(
            evidence
                .iter()
                .any(|record| record.evidence_id == evidence_id),
            "missing evidence {evidence_id}"
        );
    }
    let profile = report.fast_profile.as_ref().expect("fast profile");
    assert_eq!(profile.chip_family, "STM32H7");
    assert_eq!(report.analysis_provenance.user_base, Some(0x0800_0000));
    assert_eq!(
        report.analysis_provenance.user_family.as_deref(),
        Some("STM32H7")
    );
    assert_eq!(report.analysis_provenance.backend, "native-mcu-inspect");
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "bundle_root=absent"));
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "user_family_exact=STM32H7"));
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "backend_preference=native-mcu-inspect"));
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note == "backend_alias=native-mcu-inspect"));
    assert!(report.degradations.is_none());
}

#[test]
fn address_hypothesis_extractor_prefers_flash_base_for_full_flash_image() {
    let bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 4096);
    let hypotheses = build_address_hypotheses(&bytes);
    assert!(!hypotheses.is_empty());
    assert_eq!(hypotheses[0].base, 0x0800_0000);
    assert!(hypotheses[0].is_primary);
}

#[test]
fn address_hypothesis_extractor_handles_relocated_app_only_sample() {
    let bytes = build_relocated_vector_image();
    let hypotheses = build_address_hypotheses(&bytes);
    assert!(!hypotheses.is_empty());
    assert_eq!(hypotheses[0].base, 0x0800_4000);
}

#[test]
fn image_layout_extractor_distinguishes_full_flash_app_only_and_concat() {
    let full_flash = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 8192);
    let full_hypotheses = build_address_hypotheses(&full_flash);
    let full_layout = classify_image_layout(&full_flash, &full_hypotheses);
    assert_eq!(full_layout.kind.value, ImageLayoutKind::FullFlashDump);

    let app_only = build_relocated_vector_image();
    let app_hypotheses = build_address_hypotheses(&app_only);
    let app_layout = classify_image_layout(&app_only, &app_hypotheses);
    assert_eq!(app_layout.kind.value, ImageLayoutKind::AppOnlyImage);

    let mut concat = vec![0xAA; 0x200];
    let mut app = build_vector_table_image(0x0800_6200, Some(0x0800_6220), 2048);
    concat.append(&mut app);
    let concat_hypotheses = build_address_hypotheses(&concat);
    let concat_layout = classify_image_layout(&concat, &concat_hypotheses);
    assert_eq!(
        concat_layout.kind.value,
        ImageLayoutKind::BootloaderPlusAppConcat
    );
}

#[test]
fn vector_table_extractor_counts_handlers_without_treating_aliases_as_defaults() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    for _ in 4..20 {
        write_u32(&mut bytes, 0x0800_2001);
    }
    bytes.resize(4096, 0xFF);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    assert_eq!(vector_table.active_count, 14);
    assert_eq!(vector_table.default_handler_count, 0);
    assert_eq!(vector_table.repeated_targets[0].reference_count, 11);
}

/// The scan used to run past the end of a short table and report
/// whatever followed -- startup code, init-table words, MMIO constants -- as
/// named IRQ handlers.
#[test]
fn vector_table_scan_stops_at_the_first_word_that_cannot_be_a_handler() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058); // initial SP
    write_u32(&mut bytes, 0x0800_0201); // reset
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    // Real Thumb instruction words captured from a compiled startup routine.
    // Every one of these was previously reported as an active IRQ handler.
    for word in [0xD100_4291u32, 0xF841_4770, 0xE9D4_68E3, 0x5200_2000] {
        write_u32(&mut bytes, word);
    }
    bytes.resize(4096, 0x00);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert_eq!(vector_table.entry_count, 4);
    assert_eq!(vector_table.scan_boundary, "implausible-handler-word");
    assert!(vector_table
        .entries
        .iter()
        .all(|entry| entry.address != 0xD100_4291));
}

/// An even word is never a Cortex-M handler, even when it is in the right
/// region -- this is how misread init-table pointers used to leak in.
#[test]
fn vector_table_scan_rejects_an_in_region_word_with_no_thumb_bit() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_00B4); // in-region, Thumb bit clear
    bytes.resize(4096, 0x00);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert_eq!(vector_table.entry_count, 3);
    assert_eq!(vector_table.scan_boundary, "implausible-handler-word");
}

/// A zero slot is a legitimate reserved vector position and must not be
/// mistaken for the end of the table.
#[test]
fn vector_table_scan_treats_a_zero_slot_as_unpopulated_not_as_the_table_end() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0); // reserved
    write_u32(&mut bytes, 0x0800_1101);
    bytes.resize(4096, 0x00);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert!(
        vector_table.entry_count >= 5,
        "zero slot ended the scan early: {} entries",
        vector_table.entry_count
    );
    assert!(vector_table
        .entries
        .iter()
        .any(|entry| entry.address == 0x0800_1101));
}

#[test]
fn vector_table_extractor_reports_candidate_and_repeated_target_measurements() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    for _ in 0..12 {
        write_u32(&mut bytes, 0x0800_2001);
    }
    for _ in 0..4 {
        write_u32(&mut bytes, 0);
    }

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert_eq!(vector_table.scanned_word_count, 20);
    assert_eq!(vector_table.handler_candidate_count, 10);
    assert_eq!(vector_table.unique_aligned_target_count, 4);
    assert_eq!(
        vector_table.repeated_targets[0].aligned_address,
        0x0800_2000
    );
    assert_eq!(vector_table.repeated_targets[0].reference_count, 7);
    assert_eq!(vector_table.scan_boundary, "available-bytes");
    assert!(!vector_table.scan_boundary_rationale.is_empty());
}

#[test]
fn vector_table_extractor_respects_stm32h7_ivt_boundary_and_ignores_suffix_words() {
    // Keep mapped code beyond the full 166-word table rather than inside it.
    let mut bytes = build_vector_table_image(0x0800_0400, Some(0x0800_0420), 4096);
    for index in 32..166 {
        let start = index * 4;
        bytes[start..start + 4].copy_from_slice(&0x0800_2001u32.to_le_bytes());
    }
    for index in 166..256 {
        let start = index * 4;
        bytes[start..start + 4].copy_from_slice(&0x0800_6001u32.to_le_bytes());
    }

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert_eq!(vector_table.entry_count, 166);
    assert_eq!(vector_table.scanned_word_count, 166);
    assert_eq!(vector_table.handler_candidate_count, 160);
    assert_eq!(vector_table.unique_aligned_target_count, 4);
    assert_eq!(vector_table.scan_boundary, "family-vector-limit");
    assert!(vector_table
        .repeated_targets
        .iter()
        .all(|target| target.aligned_address != 0x0800_6000));
    assert!(vector_table
        .entries
        .iter()
        .all(|entry| usize::from(entry.index) < 166));
}

#[test]
fn startup_chain_extractor_keeps_partial_chain_when_only_some_edges_are_recoverable() {
    let bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x260);
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    assert_eq!(chain.steps[0].role, StartupRole::ResetStub);
    assert!(chain.steps.len() >= 2);
    assert!(chain.confidence < 1.0);
}

#[test]
fn execution_model_extractor_identifies_superloop_and_unknown() {
    let mut superloop = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let loop_head = 0x0800_0240u32;
    let reset_offset = (0x0800_0200 - 0x0800_0000) as usize;
    superloop[reset_offset + 0x40..reset_offset + 0x42]
        .copy_from_slice(&thumb_b(loop_head, loop_head));
    superloop[0x240..0x242].copy_from_slice(&thumb_b(loop_head, loop_head));

    let hypotheses = build_address_hypotheses(&superloop);
    let layout = classify_image_layout(&superloop, &hypotheses);
    let vector_table =
        extract_vector_table(&superloop, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&superloop, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&superloop, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");
    assert_eq!(execution_model.model.value, ExecutionModelKind::Superloop);

    let weak = vec![0xFFu8; 128];
    let weak_hypotheses = build_address_hypotheses(&weak);
    let weak_layout = classify_image_layout(&weak, &weak_hypotheses);
    let weak_vector = extract_vector_table(&weak, &weak_layout, &weak_hypotheses);
    let weak_chain =
        extract_startup_chain(&weak, weak_vector.as_ref(), &weak_layout, &weak_hypotheses);
    let weak_model = extract_execution_model(
        &weak,
        weak_chain.as_ref(),
        weak_vector.as_ref(),
        &weak_layout,
    )
    .expect("weak execution model");
    assert_eq!(weak_model.model.value, ExecutionModelKind::Unknown);
}

#[test]
fn execution_model_reports_bare_metal_supporting_evidence() {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let loop_head = 0x0800_0240u32;
    let reset_offset = (0x0800_0200 - 0x0800_0000) as usize;
    bytes[reset_offset + 0x40..reset_offset + 0x42].copy_from_slice(&thumb_b(loop_head, loop_head));
    bytes[0x240..0x242].copy_from_slice(&thumb_b(loop_head, loop_head));

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");

    assert_eq!(execution_model.model.value, ExecutionModelKind::Superloop);
    assert!(!execution_model.supporting_evidence.is_empty());
    let absent = execution_model
        .supporting_evidence
        .iter()
        .filter(|item| matches!(item.kind, EvidenceHeuristicKind::RtosMarkerAbsent { .. }))
        .count();
    assert!(absent >= 4, "expected all RTOS families reported absent");
    assert!(!execution_model
        .supporting_evidence
        .iter()
        .any(|item| item.kind == EvidenceHeuristicKind::SysTickHandlerDefault));
    // the reconstructed chain ends before Main: explicit degradation entry
    assert!(execution_model
        .anti_evidence
        .iter()
        .any(|item| item.kind == EvidenceHeuristicKind::MainDominatingLoopUnknown));
    assert!(
        execution_model.metrics.vector_table_entries >= 16,
        "expected the systick vector index to be covered"
    );
    assert_eq!(execution_model.metrics.non_default_irq_handlers, 0);
    assert_eq!(
        execution_model.metrics.loop_heads_total,
        execution_model.loop_heads.len() as u32
    );
}

#[test]
fn execution_model_rtos_marker_forces_rtos_classification() {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let marker = b"pxCurrentTCB";
    let marker_offset = 0x300;
    bytes[marker_offset..marker_offset + marker.len()].copy_from_slice(marker);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");

    assert_eq!(execution_model.model.value, ExecutionModelKind::Rtos);
    let present = execution_model
        .anti_evidence
        .iter()
        .find(|item| matches!(item.kind, EvidenceHeuristicKind::RtosMarkerPresent { .. }))
        .expect("rtos marker anti-evidence");
    assert_eq!(present.artifact_ref, Some(marker_offset as u32));
    // FreeRTOS is scanned first and hit: no family is reported absent
    assert!(execution_model
        .supporting_evidence
        .iter()
        .all(|item| !matches!(item.kind, EvidenceHeuristicKind::RtosMarkerAbsent { .. })));
}

#[test]
fn execution_model_populated_systick_does_not_prove_isr_driven_execution() {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let systick_handler = 0x0800_5001u32;
    let word_offset = 15 * 4;
    bytes[word_offset..word_offset + 4].copy_from_slice(&systick_handler.to_le_bytes());
    let handler_offset = (0x0800_5000 - 0x0800_0000) as usize;
    if bytes.len() < handler_offset + 4 {
        bytes.resize(handler_offset + 4, 0x00);
    }
    bytes[handler_offset..handler_offset + 4].copy_from_slice(&[0x00, 0xBF, 0x70, 0x47]);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");

    assert!(!execution_model
        .anti_evidence
        .iter()
        .any(|item| item.kind == EvidenceHeuristicKind::SysTickHandlerCustom));
    assert_eq!(execution_model.model.value, ExecutionModelKind::Unknown);
}

#[test]
fn execution_model_report_json_round_trip_keeps_evidence() {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let loop_head = 0x0800_0240u32;
    let reset_offset = (0x0800_0200 - 0x0800_0000) as usize;
    bytes[reset_offset + 0x40..reset_offset + 0x42].copy_from_slice(&thumb_b(loop_head, loop_head));
    bytes[0x240..0x242].copy_from_slice(&thumb_b(loop_head, loop_head));

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");

    let serialized = serde_json::to_string(&execution_model).expect("serialize");
    let deserialized: ExecutionModelReport =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized, execution_model);
    assert!(serialized.contains("supporting_evidence"));
    assert!(serialized.contains("anti_evidence"));
    assert!(serialized.contains("rtos-marker-absent"));
    assert!(!serialized.contains("sys-tick-handler-default"));
}

#[test]
fn address_hypothesis_extractor_scans_minimum_valid_vector_table() {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);

    let hypotheses = build_address_hypotheses(&bytes);
    assert_eq!(hypotheses.len(), 1);
    assert_eq!(hypotheses[0].base, 0x0800_0000);
}

#[test]
fn mmio_cluster_extractor_emits_raw_mmio_evidence() {
    let bytes = build_stage1_security_blob();
    let peripheral_map = extract_mmio_clusters(&bytes);

    assert!(
        peripheral_map
            .uses
            .iter()
            .any(|use_| use_.source == PeripheralEvidenceSource::Mmio),
        "expected at least one raw MMIO-backed use"
    );
    assert!(peripheral_map
        .uses
        .iter()
        .any(|use_| use_.base == 0x5200_2000 && use_.source == PeripheralEvidenceSource::Mmio));
}

#[test]
fn mmio_cluster_extractor_rejects_unaligned_ascii_false_positive_words() {
    let bytes = vec![0x41u8; 128];
    let peripheral_map = extract_mmio_clusters(&bytes);

    assert!(
        peripheral_map.uses.is_empty(),
        "expected weak-signal ASCII blob to avoid invented MMIO clusters"
    );
}

#[test]
fn isr_shared_state_extractor_emits_shared_state_edge_on_synthetic_irq_main_shared_flag_pattern() {
    let bytes = build_stage1_security_blob();
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let edges =
        extract_shared_state_edges(&bytes, Some(&vector_table), Some(0x0800_0220), None, None);

    assert!(!edges.is_empty(), "expected a shared-state edge");
    assert!(edges
        .iter()
        .any(|edge| edge.access_pattern == SharedAccessPattern::PollingFlag));
    assert!(edges
        .iter()
        .any(|edge| edge.irq_handler == 0x0800_2000 && edge.consumer == 0x0800_0220));
}

#[test]
fn peripheral_surface_extractor_does_not_invent_config_writes_from_adjacent_literals() {
    let bytes = build_peripheral_surface_blob();
    let resolution = resolve_family_pack(Some("STM32H7"), Some("STM32H7"));
    let peripheral_map = fat_analyze::mcu_inspect::extract_peripheral_map(&bytes, &resolution);
    let surface = extract_peripheral_surface(&bytes, &peripheral_map, &resolution);

    assert!(surface
        .register_blocks
        .iter()
        .any(|block| block.peripheral_name == "UART4"
            && block.observed_registers.iter().any(|name| name == "CR1")));
    assert!(
        surface.recovered_configs.is_empty(),
        "an adjacent RAM handle pointer is not evidence of a register write: {:?}",
        surface.recovered_configs
    );
    assert!(surface
        .provenance
        .as_ref()
        .is_some_and(|provenance| provenance
            .notes
            .iter()
            .any(|note| note.contains("address literals do not prove register writes"))));
}

#[test]
fn shared_state_risk_report_ranks_async_findings() {
    let bytes = build_stage1_security_blob();
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");
    let temp = write_temp_blob(&bytes);
    let main_entry = fat_analyze::mcu_inspect::inspect_file(&McuInspectRequest {
        file: temp.path().to_path_buf(),
        user_base: Some(0x0800_0000),
        user_family: Some("STM32H7".to_string()),
        bundle_root: None,
        backend_preference: None,
    })
    .expect("report")
    .main_entry
    .expect("main entry");
    let resolution = resolve_family_pack(Some("STM32H7"), Some("STM32H7"));
    let peripheral_map = fat_analyze::mcu_inspect::extract_peripheral_map(&bytes, &resolution);
    let surface = extract_peripheral_surface(&bytes, &peripheral_map, &resolution);
    let risk = extract_shared_state_risk(
        &bytes,
        Some(&vector_table),
        Some(&main_entry),
        Some(&execution_model),
        Some(&peripheral_map),
        Some(&surface),
    )
    .expect("risk");

    assert!(!risk.edges.is_empty());
    assert!(!risk.ranked_findings.is_empty());
}

#[test]
fn security_surface_extractor_summarizes_likely_update_flash_and_comms_surface() {
    let bytes = build_stage1_security_blob();
    let peripheral_map = extract_mmio_clusters(&bytes);
    let integrity = extract_integrity_controls(&bytes, Some(&peripheral_map));
    let write_authority = extract_write_authority(&bytes, Some(&peripheral_map));
    let surface = summarize_security_surface(&bytes, &peripheral_map, &integrity, &write_authority);

    assert!(
        surface
            .update_surface
            .iter()
            .any(|item| item.contains("update") || item.contains("ota")),
        "expected update surface summary"
    );
    assert!(
        surface
            .flash_surface
            .iter()
            .any(|item| item.contains("flash") || item.contains("erase")),
        "expected flash surface summary"
    );
    assert!(
        surface
            .comms_surface
            .iter()
            .any(|item| item.contains("uart") || item.contains("comms")),
        "expected comms surface summary"
    );
}

#[test]
fn integrity_primitive_extractor_keeps_crc_checksum_in_integrity_checks_and_no_false_signature_evidence_in_authenticity_checks(
) {
    let bytes = build_stage1_security_blob();
    let peripheral_map = extract_mmio_clusters(&bytes);
    let (integrity_checks, authenticity_checks) =
        extract_integrity_controls(&bytes, Some(&peripheral_map));

    assert!(
        integrity_checks.iter().any(
            |check| check.description.contains("CRC") || check.description.contains("checksum")
        ),
        "expected CRC/checksum integrity evidence"
    );
    assert!(
        authenticity_checks.is_empty(),
        "CRC/checksum evidence must not turn into signature evidence"
    );
}

#[test]
fn flash_write_extractor_emits_write_authority_candidates_when_erase_program_primitives_are_detected(
) {
    let bytes = build_stage1_security_blob();
    let peripheral_map = extract_mmio_clusters(&bytes);
    let write_authority = extract_write_authority(&bytes, Some(&peripheral_map));

    assert!(
        !write_authority.is_empty(),
        "expected write-authority candidates from erase/program primitives"
    );
    assert!(write_authority
        .iter()
        .any(|entry| entry.description.contains("erase") || entry.description.contains("program")));
}

#[test]
fn stm32h7_enrichment_labels_i2c4_mmio_hit() {
    let resolution = resolve_family_pack(Some("STM32H7"), None);
    let generic_name = "mmio-cluster@0x58001c00".to_string();
    let use_ = PeripheralUse {
        family: None,
        peripheral_name: generic_name.clone(),
        base: 0x5800_1c00,
        roles: Vec::new(),
        source: PeripheralEvidenceSource::Mmio,
        confidence: 0.42,
        evidence_ids: Vec::new(),
    };
    let enriched = fat_analyze::mcu_family::enrich_peripheral_map(
        fat_core::mcu_inspection::PeripheralMapReport {
            uses: vec![use_],
            provenance: Some(SectionProvenance::default()),
        },
        &resolution,
    );

    assert!(enriched
        .uses
        .iter()
        .any(|use_| use_.peripheral_name == generic_name));
    let i2c4 = enriched
        .uses
        .iter()
        .find(|use_| use_.peripheral_name == "I2C4")
        .expect("enriched I2C4 entry");
    assert!(i2c4.roles.contains(&PeripheralRole::CommsBridge));
    assert!(!i2c4.roles.contains(&PeripheralRole::HostSidecarLink));
    assert_eq!(
        enriched
            .provenance
            .as_ref()
            .and_then(|prov| prov.family_pack.as_deref()),
        Some("stm32h7")
    );
}

#[test]
fn stm32h7_enrichment_labels_irq_name() {
    let resolution = resolve_family_pack(Some("STM32H7"), None);
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    for i in 4..120 {
        let value = if i == 111 { 0x0800_2201 } else { 0x0800_2001 };
        write_u32(&mut bytes, value);
    }
    bytes.resize(4096, 0xFF);
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let enriched = fat_analyze::mcu_family::enrich_vector_table(vector_table, &resolution);

    let irq = enriched
        .entries
        .iter()
        .find(|entry| entry.index == 111)
        .expect("vector entry 111");
    assert_eq!(irq.family_label.as_deref(), Some("I2C4_EV"));
}

#[test]
fn weak_family_match_does_not_invent_labels() {
    let resolution = resolve_family_pack(Some("unknown-family"), None);
    let enriched = fat_analyze::mcu_family::enrich_peripheral_map(
        fat_core::mcu_inspection::PeripheralMapReport {
            uses: vec![PeripheralUse {
                family: None,
                peripheral_name: "mmio-cluster@0x58001c00".to_string(),
                base: 0x5800_1c00,
                roles: Vec::new(),
                source: PeripheralEvidenceSource::Mmio,
                confidence: 0.42,
                evidence_ids: Vec::new(),
            }],
            provenance: Some(SectionProvenance::default()),
        },
        &resolution,
    );

    assert_eq!(enriched.uses.len(), 1);
    assert_eq!(enriched.uses[0].peripheral_name, "mmio-cluster@0x58001c00");
    assert!(enriched.uses[0].roles.is_empty());
}

#[test]
fn exact_family_match_records_family_pack_even_without_mmio_hit() {
    let resolution = resolve_family_pack(Some("STM32H7"), None);
    let enriched = fat_analyze::mcu_family::enrich_peripheral_map(
        fat_core::mcu_inspection::PeripheralMapReport {
            uses: vec![PeripheralUse {
                family: None,
                peripheral_name: "mmio-cluster@0x40022000".to_string(),
                base: 0x4002_2000,
                roles: Vec::new(),
                source: PeripheralEvidenceSource::Mmio,
                confidence: 0.42,
                evidence_ids: Vec::new(),
            }],
            provenance: Some(SectionProvenance::default()),
        },
        &resolution,
    );

    assert_eq!(
        enriched
            .provenance
            .as_ref()
            .and_then(|prov| prov.family_pack.as_deref()),
        Some("stm32h7")
    );
}

#[test]
fn inspect_file_recovers_named_stm32h7_peripherals_from_exact_mmio_literals() {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x800);
    let literals = [0x5800_1C00u32, 0x5200_2000, 0x4000_4C00, 0x4000_7800];
    let mut offset = 0x300usize;
    for literal in literals {
        bytes[offset..offset + 4].copy_from_slice(&literal.to_le_bytes());
        offset += 0x20;
    }

    let temp = write_temp_blob(&bytes);
    let report = inspect_file(&McuInspectRequest {
        file: temp.path().to_path_buf(),
        user_base: Some(0x0800_0000),
        user_family: Some("STM32H7".to_string()),
        bundle_root: None,
        backend_preference: None,
    })
    .expect("report");

    let uses = report
        .peripheral_map
        .as_ref()
        .expect("peripheral map")
        .uses
        .iter()
        .map(|use_| use_.peripheral_name.as_str())
        .collect::<Vec<_>>();

    assert!(uses.contains(&"I2C4"));
    assert!(uses.contains(&"FLASH"));
    assert!(uses.contains(&"UART4"));
    assert!(uses.contains(&"UART7"));
}

#[test]
fn shared_state_findings_are_deduplicated_and_avoid_reset_stub() {
    use fat_core::mcu_inspection::{Interpretation, MainEntryReport};

    let bytes = build_stage1_security_blob();
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");
    let execution_model =
        extract_execution_model(&bytes, Some(&chain), Some(&vector_table), &layout)
            .expect("execution model");
    let resolution = resolve_family_pack(Some("STM32H7"), Some("STM32H7"));
    let peripheral_map = fat_analyze::mcu_inspect::extract_peripheral_map(&bytes, &resolution);
    let surface = extract_peripheral_surface(&bytes, &peripheral_map, &resolution);

    let reset_stub = vector_table
        .entries
        .get(1)
        .map(|e| e.address & !1)
        .expect("reset");

    // A real main entry (not the reset stub) yields deduplicated findings.
    let real_main = MainEntryReport {
        entrypoint: Interpretation {
            value: 0x0800_0220,
            ..Default::default()
        },
        provenance: None,
    };
    let risk = extract_shared_state_risk(
        &bytes,
        Some(&vector_table),
        Some(&real_main),
        Some(&execution_model),
        Some(&peripheral_map),
        Some(&surface),
    )
    .expect("risk");
    let mut titles: Vec<_> = risk
        .ranked_findings
        .iter()
        .map(|f| f.title.clone())
        .collect();
    let count = titles.len();
    titles.sort();
    titles.dedup();
    assert_eq!(titles.len(), count, "findings must not contain duplicates");
    assert!(
        !risk
            .ranked_findings
            .iter()
            .any(|f| f.title.contains(&format!("0x{reset_stub:08x}"))),
        "no finding should point at the reset stub"
    );

    // When main-entry detection collapses onto the reset stub, suppress entirely.
    let reset_main = MainEntryReport {
        entrypoint: Interpretation {
            value: reset_stub,
            ..Default::default()
        },
        provenance: None,
    };
    let suppressed = extract_shared_state_risk(
        &bytes,
        Some(&vector_table),
        Some(&reset_main),
        Some(&execution_model),
        Some(&peripheral_map),
        Some(&surface),
    );
    assert!(
        suppressed.is_none(),
        "risk report must be suppressed when the consumer is the reset stub"
    );
}

#[test]
fn peripheral_map_detects_base_address_literals_for_system_init_peripherals() {
    // Embed RCC (0x58024400) and a CPACR write target inside the SCB block
    // (0xE000ED88) as little-endian base-address literals.
    let mut bytes = vec![0u8; 256];
    bytes[0..4].copy_from_slice(&0x5802_4400u32.to_le_bytes());
    bytes[64..68].copy_from_slice(&0xE000_ED88u32.to_le_bytes());
    bytes[128..132].copy_from_slice(&0x5800_0400u32.to_le_bytes()); // SYSCFG

    let resolution = resolve_family_pack(Some("STM32H7"), Some("STM32H7"));
    let map = fat_analyze::mcu_inspect::extract_peripheral_map(&bytes, &resolution);

    for name in ["RCC", "SCB", "SYSCFG"] {
        assert!(
            map.uses.iter().any(|u| u.peripheral_name == name),
            "{name} not detected from its base-address literal; got: {:?}",
            map.uses
                .iter()
                .map(|u| &u.peripheral_name)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn regression_shared_systick_does_not_prove_default_role_or_isr_driven_model() {
    let bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x320);
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let table = extract_vector_table(&bytes, &layout, &hypotheses).unwrap();
    assert!(table
        .repeated_targets
        .iter()
        .any(|target| target.aligned_address == (table.entries[15].address & !1)));
    let model = extract_execution_model(&bytes, None, Some(&table), &layout).unwrap();
    assert_eq!(model.model.value, ExecutionModelKind::Unknown);
    assert!(!model
        .supporting_evidence
        .iter()
        .any(|e| e.kind == EvidenceHeuristicKind::SysTickHandlerDefault));
    assert!(!model
        .anti_evidence
        .iter()
        .any(|e| e.kind == EvidenceHeuristicKind::SysTickHandlerCustom));
}
