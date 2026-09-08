//! `SystemInit` side-effect recovery.
//!
//! `system-init-rich.bin` is real `arm-none-eabi-gcc` 16.2.0 output — see
//! `tests/fixtures/mcu/init-table/Makefile`. Its `SystemInit` performs every
//! side effect this analysis classifies plus one write to a peripheral it
//! deliberately does not model, so the "preserved, not dropped" contract for
//! unclassified writes is exercised by a real store rather than a synthetic
//! one.
//!
//! The `-Os` compiler output is what makes these tests worth having: the flash
//! wait-state write is a `bic #0xF` / `orr #7` read-modify-write that never
//! produces a concrete word, the RCC base is folded to `0x58024000` with the
//! register reached through a `#0x400` displacement, and the FPU enable goes
//! through `mov.w r3, #0xE000E000` rather than a literal `0xE000ED88`. A
//! matcher over literal pool constants would miss all three.

use std::fs;
use std::path::PathBuf;

use fat_analyze::mcu_inspect::{inspect_file, McuInspectRequest};
use fat_core::mcu_inspection::{
    CacheEffectKind, ClockEffectKind, FpuStatus, McuInspectionReport, SystemInitEffectsReport,
};

const RICH: &str = "system-init-rich.bin";
const PLAIN: &str = "scatter-load.bin";
const CMSIS: &str = "cmsis-copy-zero-os.bin";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mcu/init-table")
        .join(name)
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

fn effects(name: &str) -> SystemInitEffectsReport {
    inspect(name)
        .system_init_effects
        .expect("system init effects")
}

#[test]
fn a_full_system_init_yields_every_classified_effect() {
    let report = effects(RICH);

    assert_eq!(report.function_address, 0x0800_0074);
    assert!(report.function_size > 0);
    assert_eq!(report.fpu, FpuStatus::Enabled);
    assert_eq!(report.flash_latency, Some(7));
    assert!(
        report.clock_effects.len() >= 2,
        "{:?}",
        report.clock_effects
    );
    assert!(report.mpu_configured);
    assert_eq!(report.art_accel, Some(true));

    let check = report
        .vtor_relocation_check
        .expect("vtor relocation sentinel check");
    assert_eq!(check.sentinel_value, 0x2000_0000);
    assert_eq!(
        report.vtor_write.expect("vtor write").value,
        Some(0x0800_0000)
    );
    assert!(report.confidence >= 0.9, "{}", report.confidence);
}

#[test]
fn a_read_modify_write_still_pins_the_flash_wait_state_count() {
    // `-Os` compiles `acr &= ~0xF; acr |= 7;` into `bic #0xF` then `orr #7` on
    // a value loaded from the register. The stored word is never concrete, but
    // its low nibble is, which is the whole fact.
    let report = effects(RICH);
    assert_eq!(report.flash_latency, Some(7));
    assert!(report
        .evidence
        .iter()
        .any(|item| item.label == "flash-latency" && item.detail.contains("7 wait states")));
}

#[test]
fn clock_writes_are_classified_by_register_and_bit() {
    let report = effects(RICH);
    let kinds: Vec<ClockEffectKind> = report
        .clock_effects
        .iter()
        .map(|effect| effect.kind)
        .collect();

    assert!(kinds.contains(&ClockEffectKind::HsiEnable), "{kinds:?}");
    assert!(
        kinds.contains(&ClockEffectKind::HseBypassClear),
        "{kinds:?}"
    );
    assert!(kinds.contains(&ClockEffectKind::SysclkSwitch), "{kinds:?}");

    // The RCC base is folded into a `#0x400` displacement by the compiler, so
    // the register offset has to come from the resolved target rather than
    // from a literal.
    let cr_writes = report
        .clock_effects
        .iter()
        .filter(|effect| effect.register_offset == 0x00)
        .count();
    assert_eq!(cr_writes, 2, "{:?}", report.clock_effects);
}

#[test]
fn cache_enable_bits_are_reported_individually() {
    let report = effects(RICH);
    let kinds: Vec<CacheEffectKind> = report
        .cache_effects
        .iter()
        .map(|effect| effect.kind)
        .collect();
    assert!(kinds.contains(&CacheEffectKind::ICacheEnable), "{kinds:?}");
    assert!(kinds.contains(&CacheEffectKind::DCacheEnable), "{kinds:?}");
}

#[test]
fn an_unmodelled_peripheral_write_is_preserved_rather_than_dropped() {
    let report = effects(RICH);
    let write = report
        .unclassified_writes
        .iter()
        .find(|write| write.target == 0x5802_4C0C)
        .unwrap_or_else(|| panic!("{:?}", report.unclassified_writes));
    assert_eq!(write.value, Some(2));
    assert!((0x0800_0000..0x0800_1000).contains(&write.at));
}

#[test]
fn a_minimal_system_init_reports_what_it_did_not_find() {
    // The plain scatter-load fixture only enables the FPU and sets latency.
    // Everything else must be listed as looked-for-and-absent, not silently
    // omitted, so a reader can tell "absent" from "not checked".
    let report = effects(PLAIN);

    assert_eq!(report.fpu, FpuStatus::Enabled);
    assert_eq!(report.flash_latency, Some(4));
    assert!(report.clock_effects.is_empty());
    assert!(!report.mpu_configured);
    assert_eq!(report.art_accel, None);
    assert!(report.vtor_relocation_check.is_none());

    for expected in [
        "clock tree setup",
        "I-cache enable",
        "D-cache enable",
        "MPU configuration",
        "VTOR relocation check",
        "vendor flash accelerator",
    ] {
        assert!(
            report.not_observed.iter().any(|item| item == expected),
            "{expected} missing from {:?}",
            report.not_observed
        );
    }

    let rich = effects(RICH);
    assert!(
        report.confidence < rich.confidence,
        "a thinner SystemInit must not report the same confidence"
    );
}

#[test]
fn a_foreign_family_register_map_is_not_applied_to_the_wrong_chip() {
    // The CMSIS fixture is an STM32F4-shaped build: its flash controller lives
    // at 0x40023C00, not the H7's 0x52002000. The write must survive as an
    // unclassified peripheral write rather than being read as a wait-state
    // count through the wrong register map.
    let report = effects(CMSIS);

    assert_eq!(report.fpu, FpuStatus::Enabled);
    assert_eq!(report.flash_latency, None);
    assert!(report
        .not_observed
        .iter()
        .any(|item| item == "flash latency"));
    assert!(
        report
            .unclassified_writes
            .iter()
            .any(|write| write.target == 0x4002_3C00 && write.value == Some(5)),
        "{:?}",
        report.unclassified_writes
    );
}

#[test]
fn a_startup_chain_without_a_system_init_step_reports_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("stub-only.bin");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x2001_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_0201u32.to_le_bytes());
    for _ in 2..32 {
        bytes.extend_from_slice(&0x0800_1001u32.to_le_bytes());
    }
    bytes.resize(0x200, 0);
    // Reset stub: `bx lr`, so the walk finds no second step at all.
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

    assert!(report.system_init_effects.is_none());
    assert!(
        report
            .analysis_provenance
            .notes
            .iter()
            .any(|note| note.starts_with("system_init_effects=absent")),
        "{:?}",
        report.analysis_provenance.notes
    );
}

#[test]
fn the_analysis_records_how_much_of_the_function_it_understood() {
    let report = effects(RICH);
    let provenance = report.provenance.expect("provenance");

    assert_eq!(provenance.extractor, "system-init-extractor");
    assert_eq!(provenance.family_pack.as_deref(), Some("stm32h7"));
    assert!(provenance
        .notes
        .iter()
        .any(|note| note.starts_with("decoded_bytes=") && note.contains("terminated=true")));
    assert!(provenance
        .notes
        .iter()
        .any(|note| note.contains("rather than guessed")));

    let present = inspect(RICH);
    assert!(present
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note.starts_with("system_init_effects=present")));
}

#[test]
fn the_effects_report_survives_a_json_round_trip() {
    let report = effects(RICH);
    let serialized = serde_json::to_string(&report).expect("serialize");
    assert!(serialized.contains("\"fpu\":\"enabled\""));
    assert!(serialized.contains("hse-bypass-clear"));
    assert!(serialized.contains("d-cache-enable"));
    let restored: SystemInitEffectsReport = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(restored, report);
}
