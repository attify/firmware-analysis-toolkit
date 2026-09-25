//! Startup init-descriptor table recovery.
//!
//! Every fixture here is real `arm-none-eabi-gcc` / `ld` output — see
//! `tests/fixtures/mcu/init-table/Makefile` for the exact toolchain and
//! flags. Hand-assembled bytes would not exercise the literal-pool ordering,
//! the loop placement after the return path, or the stride encodings the
//! compiler actually emits, which is where this parser has to be correct.

use std::fs;
use std::path::PathBuf;

use fat_analyze::mcu_init_table::{
    classify_init_handler, detect_init_tables, extract_runtime_init_table, ImageAddressing,
};
use fat_analyze::mcu_inspect::{
    build_address_hypotheses, classify_image_layout, extract_startup_chain, extract_vector_table,
    inspect_file, McuInspectRequest,
};
use fat_core::mcu_inspection::{
    InitHandlerKind, InitTableFormat, InitTableReport, McuInspectionReport, StartupRole,
};

/// Every CMSIS build variant: `-Os`/`-O0`/`-O2` on Cortex-M4 plus `-Os` on
/// Cortex-M0. The descriptor *contents* are identical across all four; only
/// the table address moves, so nothing here may hardcode a table address.
const CMSIS_VARIANTS: [&str; 4] = [
    "cmsis-copy-zero-os.bin",
    "cmsis-copy-zero-o0.bin",
    "cmsis-copy-zero-o2.bin",
    "cmsis-copy-zero-m0.bin",
];

const SCATTER_VARIANT: &str = "scatter-load.bin";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mcu/init-table")
        .join(name)
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("read mcu init-table fixture")
}

fn inspect(name: &str) -> McuInspectionReport {
    inspect_file(&McuInspectRequest {
        file: fixture_path(name),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .expect("mcu inspection report")
}

fn init_table(name: &str) -> InitTableReport {
    inspect(name).init_table.expect("init descriptor table")
}

fn roles(name: &str) -> Vec<StartupRole> {
    inspect(name)
        .startup_chain
        .expect("startup chain")
        .steps
        .iter()
        .map(|step| step.role)
        .collect()
}

#[test]
fn cmsis_copy_and_zero_tables_are_recovered_as_separate_segments() {
    let table = init_table("cmsis-copy-zero-os.bin");

    // Two tables, not one: a 12-byte-stride copy table and an 8-byte-stride
    // zero table. Assuming a single stride would mis-parse one of them.
    assert_eq!(table.segments.len(), 2, "{table:#?}");
    assert_eq!(table.segments[0].format, InitTableFormat::CmsisCopyTable);
    assert_eq!(table.segments[0].record_stride, 12);
    assert_eq!(table.segments[0].record_count, 1);
    assert_eq!(table.segments[1].format, InitTableFormat::CmsisZeroTable);
    assert_eq!(table.segments[1].record_stride, 8);
    assert_eq!(table.segments[1].record_count, 1);
    assert!(table.segments.iter().all(|segment| segment.stride_observed));

    assert_eq!(table.records.len(), 2);
    let copy = &table.records[0];
    assert_eq!(copy.dst, 0x2000_0000);
    assert_eq!(copy.size, 4);
    assert_eq!(copy.handler, None);
    assert_eq!(copy.handler_kind, InitHandlerKind::WordCopy);

    let zero = &table.records[1];
    assert_eq!(zero.src, None);
    assert_eq!(zero.dst, 0x2000_0004);
    assert_eq!(zero.size, 0x100);
    assert_eq!(zero.handler, None);
    assert_eq!(zero.handler_kind, InitHandlerKind::ZeroInit);

    assert_eq!(table.total_dst_coverage, 0x104);
    assert_eq!(table.max_dst_end, 0x2000_0104);
}

#[test]
fn cmsis_copy_source_points_at_the_data_load_region_in_flash() {
    for variant in CMSIS_VARIANTS {
        let bytes = fixture_bytes(variant);
        let table = init_table(variant);
        // `.data` is the last thing in the image and is exactly one word, so
        // its load address is the final word of flash.
        let expected_src = 0x0800_0000 + (bytes.len() as u32 - 4);
        assert_eq!(
            table.records[0].src,
            Some(expected_src),
            "{variant}: copy source should be the trailing .data load region"
        );
    }
}

#[test]
fn descriptor_contents_are_stable_across_optimisation_levels_and_cores() {
    let mut observed_bases = Vec::new();
    for variant in CMSIS_VARIANTS {
        let table = init_table(variant);
        observed_bases.push(table.base_address);

        let shape: Vec<(Option<u32>, u32, u32, InitHandlerKind)> = table
            .records
            .iter()
            .map(|record| {
                (
                    record.src.map(|_| 0),
                    record.dst,
                    record.size,
                    record.handler_kind,
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                (Some(0), 0x2000_0000, 4, InitHandlerKind::WordCopy),
                (None, 0x2000_0004, 0x100, InitHandlerKind::ZeroInit),
            ],
            "{variant}: descriptor contents should not depend on the build"
        );
    }

    observed_bases.sort_unstable();
    observed_bases.dedup();
    assert!(
        observed_bases.len() > 1,
        "expected the table address to move across build variants, saw {observed_bases:?}"
    );
}

#[test]
fn scatter_load_records_carry_classified_handlers() {
    let table = init_table(SCATTER_VARIANT);

    assert_eq!(table.format, InitTableFormat::ScatterLoad);
    assert_eq!(table.record_stride, 16);
    assert_eq!(table.segments.len(), 1);
    assert_eq!(table.segments[0].record_count, 2);
    assert!(table.segments[0].stride_observed);
    assert_eq!(table.end_address - table.base_address, 32);

    assert_eq!(table.records.len(), 2);
    let copy = &table.records[0];
    assert_eq!(copy.src, Some(table.end_address));
    assert_eq!(copy.dst, 0x2400_0000);
    assert_eq!(copy.size, 4);
    assert_eq!(copy.handler, Some(0x0800_0022));
    assert_eq!(copy.handler_kind, InitHandlerKind::WordCopy);

    let zero = &table.records[1];
    // The handler word for a zero-init record has src == 0; the startup loop
    // supplies the Thumb bit (`r3 = [r4 + 0xC] | 1`), so handlers are stored
    // in the table without it.
    assert_eq!(zero.src, None);
    assert_eq!(zero.dst, 0x2400_0004);
    assert_eq!(zero.size, 0x100);
    assert_eq!(zero.handler, Some(0x0800_0038));
    assert_eq!(zero.handler_kind, InitHandlerKind::ZeroInit);
    assert_eq!(zero.handler.unwrap() & 1, 0);
}

#[test]
fn sp_consistency_is_reported_per_layout() {
    // Scatter-load fixture: __StackTop == ADDR(.bss) + SIZEOF(.bss), so the
    // descriptor coverage lands exactly on the initial SP. This is the same
    // invariant that holds on the Unitree Go1 image
    // (0xB80 + 0x194D8 == 0x1A058 == SP 0x2401A058 - 0x24000000).
    let scatter = init_table(SCATTER_VARIANT);
    assert_eq!(scatter.initial_sp, Some(0x2400_0104));
    assert_eq!(scatter.max_dst_end, 0x2400_0104);
    assert!(scatter.matches_initial_sp);
    assert!(scatter.confidence > 0.9);

    // CMSIS fixture: the stack sits at the top of a 64 KiB SRAM, well above
    // .bss, so the check legitimately does not hold and must not be claimed.
    let cmsis = init_table("cmsis-copy-zero-os.bin");
    assert_eq!(cmsis.initial_sp, Some(0x2001_0000));
    assert_eq!(cmsis.max_dst_end, 0x2000_0104);
    assert!(!cmsis.matches_initial_sp);
    assert!(cmsis.confidence < scatter.confidence);
}

#[test]
fn a_copy_triple_is_not_re_read_as_a_spurious_zero_pair() {
    // A bare memory scan finds a second, non-existent "zero pair" in the
    // trailing {dst, size} words of every copy triple. Bounds come from the
    // startup literal pool instead, so exactly two records exist and each one
    // starts at a table base.
    let table = init_table("cmsis-copy-zero-os.bin");
    let bases: Vec<u32> = table
        .segments
        .iter()
        .map(|segment| segment.base_address)
        .collect();
    assert_eq!(table.records.len(), 2);
    for record in &table.records {
        assert!(
            bases.contains(&record.record_address),
            "record at 0x{:08X} is not at a recovered table base {bases:?}",
            record.record_address
        );
    }
    // The phantom pair would be at copy_table_base + 4.
    let phantom = table.segments[0].base_address + 4;
    assert!(table
        .records
        .iter()
        .all(|record| record.record_address != phantom));
}

#[test]
fn startup_chain_walks_past_the_reset_stub() {
    // CMSIS inlines the copy/zero walk into Reset_Handler, so the chain is
    // reset -> SystemInit -> main with no separate runtime-init step.
    assert_eq!(
        roles("cmsis-copy-zero-os.bin"),
        vec![
            StartupRole::ResetStub,
            StartupRole::SystemInit,
            StartupRole::Main
        ]
    );

    // The scatter-load fixture calls out to a dedicated table walker, which
    // is identified as RuntimeInit by the table it walks, not by position.
    assert_eq!(
        roles(SCATTER_VARIANT),
        vec![
            StartupRole::ResetStub,
            StartupRole::SystemInit,
            StartupRole::RuntimeInit,
            StartupRole::Main
        ]
    );

    let chain = inspect(SCATTER_VARIANT).startup_chain.expect("chain");
    let runtime = chain
        .steps
        .iter()
        .find(|step| step.role == StartupRole::RuntimeInit)
        .expect("runtime init step");
    assert_eq!(runtime.address, 0x0800_004C);
    let main = chain
        .steps
        .iter()
        .find(|step| step.role == StartupRole::Main)
        .expect("main step");
    assert_eq!(main.address, 0x0800_00A0);
}

#[test]
fn main_entry_follows_the_recovered_main_step() {
    let report = inspect(SCATTER_VARIANT);
    let main_entry = report.main_entry.expect("main entry");
    assert_eq!(main_entry.entrypoint.value, 0x0800_00A0);
}

#[test]
fn handler_classifier_separates_copy_loops_from_fill_loops() {
    let bytes = fixture_bytes(SCATTER_VARIANT);
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let addressing =
        ImageAddressing::from_layout(0x0800_0090, &layout, bytes.len()).expect("addressing");

    // copy_fn: word load + word store, no zero immediate.
    assert_eq!(
        classify_init_handler(&bytes, 0x0800_0022, &addressing),
        InitHandlerKind::WordCopy
    );
    // zero_fn: word store fed by `movs r3, #0`, no loads.
    assert_eq!(
        classify_init_handler(&bytes, 0x0800_0038, &addressing),
        InitHandlerKind::ZeroInit
    );
    // The vector table is data, not a handler body.
    assert_eq!(
        classify_init_handler(&bytes, 0x0800_0000, &addressing),
        InitHandlerKind::Unknown
    );
}

#[test]
fn detection_is_anchored_on_the_walking_function() {
    let bytes = fixture_bytes(SCATTER_VARIANT);
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let addressing =
        ImageAddressing::from_layout(0x0800_0090, &layout, bytes.len()).expect("addressing");

    // RuntimeInit's literal pool carries the bounds.
    let from_walker = detect_init_tables(&bytes, 0x0800_004C, &addressing);
    assert_eq!(from_walker.len(), 1);
    assert_eq!(from_walker[0].records.len(), 2);

    // Reset_Handler only issues calls, so no bounds are available there.
    assert!(detect_init_tables(&bytes, 0x0800_0090, &addressing).is_empty());
    // main's literal pool holds RAM pointers, which are never table bounds.
    assert!(detect_init_tables(&bytes, 0x0800_00A0, &addressing).is_empty());
}

#[test]
fn images_without_a_descriptor_table_report_none() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x2001_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_0201u32.to_le_bytes());
    for _ in 2..32 {
        bytes.extend_from_slice(&0x0800_1001u32.to_le_bytes());
    }
    bytes.resize(0x200, 0);
    // Reset stub: `bx lr`.
    bytes.extend_from_slice(&[0x70, 0x47]);
    bytes.resize(0x400, 0xFF);

    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");
    let chain = extract_startup_chain(&bytes, Some(&vector_table), &layout, &hypotheses)
        .expect("startup chain");

    assert!(extract_runtime_init_table(
        &bytes,
        Some(&chain),
        &layout,
        &hypotheses,
        Some(0x2001_0000)
    )
    .is_none());
    assert!(chain
        .steps
        .iter()
        .all(|step| step.role != StartupRole::Main));
}

#[test]
fn absence_of_a_table_is_explained_in_analysis_provenance() {
    let present = inspect(SCATTER_VARIANT);
    assert!(present
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note.starts_with("init_table=present")));

    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("no-table.bin");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x2001_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_0201u32.to_le_bytes());
    for _ in 2..32 {
        bytes.extend_from_slice(&0x0800_1001u32.to_le_bytes());
    }
    bytes.resize(0x200, 0);
    bytes.extend_from_slice(&[0x70, 0x47]);
    bytes.resize(0x400, 0xFF);
    fs::write(&blob, &bytes).expect("write blob");

    let report = inspect_file(&McuInspectRequest {
        file: blob,
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .expect("report");
    assert!(report.init_table.is_none());
    assert!(
        report
            .analysis_provenance
            .notes
            .iter()
            .any(|note| note.starts_with("init_table=absent")),
        "{:?}",
        report.analysis_provenance.notes
    );
}

/// Vector-table boundary regression against real toolchain output.
///
/// `scatter-load.bin` declares an 8-entry vector table and is followed
/// immediately by compiled startup code. The scan used to read 54 entries out
/// of the 216-byte image and report Thumb instruction words and the flash
/// controller's MMIO base as named STM32H7 IRQ handlers.
#[test]
fn a_short_vector_table_is_not_extended_into_the_code_that_follows_it() {
    let bytes = fixture_bytes("scatter-load.bin");
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let vector_table = extract_vector_table(&bytes, &layout, &hypotheses).expect("vector table");

    assert_eq!(vector_table.entry_count, 8, "declared table is 8 entries");
    assert_eq!(vector_table.scan_boundary, "mapped-handler");
    // The flash-controller MMIO base SystemInit writes; never a handler.
    assert!(vector_table
        .entries
        .iter()
        .all(|entry| entry.address != 0x5200_2000));
}

#[test]
fn init_table_report_survives_a_json_round_trip() {
    let table = init_table(SCATTER_VARIANT);
    let serialized = serde_json::to_string(&table).expect("serialize");
    assert!(serialized.contains("scatter-load"));
    assert!(serialized.contains("zero-init"));
    assert!(serialized.contains("word-copy"));
    let restored: InitTableReport = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(restored, table);
}
