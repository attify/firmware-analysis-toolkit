use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_vector_word(buf: &mut [u8], index: usize, value: u32) {
    let start = index * 4;
    buf[start..start + 4].copy_from_slice(&value.to_le_bytes());
}

fn thumb_b(from: u32, to: u32) -> [u8; 2] {
    let pc = from.wrapping_add(4);
    let offset = to.wrapping_sub(pc) as i32;
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

fn build_mcu_blob() -> Vec<u8> {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x900);
    let mmio_words = [0x5800_1C00u32, 0x5800_1C04, 0x4001_1000, 0x4001_1004];
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

fn build_many_peripheral_blob() -> Vec<u8> {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x900);
    let peripheral_literals = [
        0x5200_2000u32,
        0x5802_4400,
        0x5802_4C00,
        0xE000_ED00,
        0x5800_1C00,
        0x4000_4C00,
        0x4000_7800,
        0x4000_7C00,
        0x4000_3C00,
        0x4000_1000,
    ];
    for (index, literal) in peripheral_literals.iter().enumerate() {
        let start = 0x500 + index * 0x10;
        bytes[start..start + 4].copy_from_slice(&literal.to_le_bytes());
    }
    bytes
}

fn build_labeled_vector_table_blob() -> Vec<u8> {
    let mut bytes = vec![0xFF; 0x900];
    write_vector_word(&mut bytes, 0, 0x2401_A058);
    write_vector_word(&mut bytes, 1, 0x0800_0301);

    write_vector_word(&mut bytes, 2, 0x0800_0401);
    write_vector_word(&mut bytes, 3, 0x0800_0401);
    for index in 4..16 {
        write_vector_word(&mut bytes, index, 0);
    }
    for index in 16..166 {
        write_vector_word(&mut bytes, index, 0x0800_0401);
    }

    for (index, handler) in [(70, 0x0800_0501), (98, 0x0800_0511), (99, 0x0800_0521)] {
        write_vector_word(&mut bytes, index, handler);
    }

    for offset in [0x300usize, 0x400, 0x500, 0x510, 0x520] {
        bytes[offset..offset + 2].copy_from_slice(&[0x70, 0x47]);
    }
    bytes
}

fn build_relocated_stm32h7_blob_with_stack_at_sram_end() -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [
        0x2408_0000u32,
        0x0804_0299,
        0x0804_42FF,
        0x0804_55B1,
        0x0804_42FF,
        0x0804_42FF,
        0x0804_42FF,
        0x0000_0000,
    ] {
        write_u32(&mut bytes, word);
    }
    bytes.resize(22_152, 0xFF);
    bytes
}

#[test]
fn fat_inspect_mcu_help_mentions_base_and_family() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "mcu", "--help"])
        .output()
        .expect("fat inspect mcu help runs");

    assert!(output.status.success(), "inspect mcu help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--base"),
        "missing --base in help: {stdout}"
    );
    assert!(
        stdout.contains("--family"),
        "missing --family in help: {stdout}"
    );
}

#[test]
fn fat_inspect_mcu_json_emits_evidence_report_and_provenance() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--base",
            "0x08000000",
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "mcu-inspection/v1");
    assert_eq!(report["analysis_provenance"]["user_base"], 0x0800_0000u64);
    assert_eq!(report["analysis_provenance"]["user_family"], "STM32H7");
    assert!(report.get("address_hypotheses").is_some());
    assert!(report.get("startup_chain").is_some());
    assert!(report.get("execution_model").is_some());
    assert!(report.get("integrity_checks").is_some());
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
}

#[test]
fn fat_inspect_mcu_human_output_renders_evidence_sections() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "mcu", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat inspect mcu runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "MCU inspection",
        "Architecture",
        "Address hypotheses",
        "Startup chain",
        "Execution model",
        "Peripheral map",
        "Security controls",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_inspect_mcu_human_output_renders_every_json_peripheral() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_many_peripheral_blob()).expect("blob");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");
    assert!(json_output.status.success());
    let report: Value = serde_json::from_slice(&json_output.stdout).expect("json");
    let peripherals = report["peripheral_map"]["uses"]
        .as_array()
        .expect("peripheral uses");
    assert!(
        peripherals.len() > 5,
        "fixture must exercise the former top-five truncation: {report}"
    );

    let text_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
        ])
        .output()
        .expect("fat inspect mcu text runs");
    assert!(text_output.status.success());
    let stdout = String::from_utf8_lossy(&text_output.stdout);

    for peripheral in peripherals {
        let name = peripheral["peripheral_name"].as_str().expect("name");
        let base = peripheral["base"].as_u64().expect("base");
        let expected = format!("{name} @ 0x{base:08X}");
        assert!(
            stdout.contains(&expected),
            "text output omitted JSON peripheral {expected}:\n{stdout}"
        );
    }
    assert!(stdout.contains("TIM6 @"), "stdout:\n{stdout}");
}

#[test]
fn fat_inspect_mcu_human_output_renders_vector_summary_and_every_active_external_irq() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_labeled_vector_table_blob()).expect("blob");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");
    assert!(json_output.status.success());
    let report: Value = serde_json::from_slice(&json_output.stdout).expect("json");
    let vector_table = &report["vector_table"];
    assert_eq!(vector_table["entry_count"], 166);
    let active_irqs = vector_table["entries"]
        .as_array()
        .expect("vector entries")
        .iter()
        .filter(|entry| {
            entry["index"].as_u64().is_some_and(|index| index >= 16)
                && entry["handler_kind"] == "interrupt"
        })
        .collect::<Vec<_>>();
    assert_eq!(active_irqs.len(), 3);

    let text_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
        ])
        .output()
        .expect("fat inspect mcu text runs");
    assert!(text_output.status.success());
    let stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(stdout.contains("Vector table"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("Entries scanned:     166"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Default-handler positions:"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Default target:      0x08000400 (147 positions)"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Active external IRQs: 3"),
        "stdout:\n{stdout}"
    );

    for entry in active_irqs {
        let index = entry["index"].as_u64().expect("index");
        let irq = index - 16;
        let label = entry["family_label"].as_str().expect("family label");
        let address = entry["address"].as_u64().expect("address");
        let expected = format!("IRQ {irq} (vector {index}) {label} @ 0x{address:08X}");
        assert!(
            stdout.contains(&expected),
            "text output omitted active IRQ {expected}:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_mcu_recovers_relocated_stm32h7_with_stack_at_sram_end() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("firmware_blinky.bin");
    std::fs::write(&blob, build_relocated_stm32h7_blob_with_stack_at_sram_end()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["fast_profile"]["architecture"], "ARM Cortex-M");
    assert_eq!(report["fast_profile"]["chip_family"], "STM32H7");
    assert_eq!(report["fast_profile"]["initial_sp"], 0x2408_0000u64);
    assert_eq!(report["fast_profile"]["reset_vector"], 0x0804_0299u64);
    assert_eq!(report["address_hypotheses"][0]["base"], 0x0804_0000u64);
    assert!(
        report.get("degradations").is_none(),
        "valid STM32H7 image should not be degraded: {report}"
    );
}

#[test]
fn fat_inspect_mcu_weak_signal_returns_degraded_well_formed_json() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("weak.bin");
    std::fs::write(&blob, vec![0x41u8; 128]).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "mcu-inspection/v1");
    assert!(report.get("degradations").is_some());
    assert_eq!(
        report["degradations"],
        serde_json::json!(["weak-signal", "non-cortex-m-likely"])
    );
    assert!(
        report.get("peripheral_map").is_none(),
        "weak-signal blobs should not invent peripheral evidence: {report}"
    );
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
}

#[test]
fn fat_inspect_mcu_rejects_malformed_base_override() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--base",
            "not-a-number",
        ])
        .output()
        .expect("fat inspect mcu runs");

    assert!(
        !output.status.success(),
        "expected malformed --base to fail, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid --base"),
        "expected malformed-base error, got:\n{stderr}"
    );
}

fn init_table_fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mcu/init-table")
        .join(name)
}

#[test]
fn fat_inspect_mcu_json_reports_the_scatter_load_init_table() {
    let fixture = init_table_fixture("scatter-load.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            fixture.to_str().expect("fixture path"),
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let table = report
        .get("init_table")
        .expect("init_table section present");
    assert_eq!(table["format"], "scatter-load");
    assert_eq!(table["record_stride"], 16);
    assert_eq!(table["matches_initial_sp"], true);
    assert_eq!(table["total_dst_coverage"], 0x104);

    let records = table["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["dst"], 0x2400_0000u64);
    assert_eq!(records[0]["size"], 4);
    assert_eq!(records[0]["handler"], 0x0800_0022u64);
    assert_eq!(records[0]["handler_kind"], "word-copy");
    assert_eq!(records[1]["dst"], 0x2400_0004u64);
    assert_eq!(records[1]["size"], 0x100);
    assert_eq!(records[1]["handler"], 0x0800_0038u64);
    assert_eq!(records[1]["handler_kind"], "zero-init");
    assert!(
        records[1]["src"].is_null(),
        "zero-init records carry no src"
    );
}

#[test]
fn fat_inspect_mcu_human_output_renders_the_cmsis_init_table() {
    let fixture = init_table_fixture("cmsis-copy-zero-os.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            fixture.to_str().expect("fixture path"),
        ])
        .output()
        .expect("fat inspect mcu runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Init descriptor table"), "{stdout}");
    assert!(stdout.contains("cmsis-copy-table"), "{stdout}");
    assert!(stdout.contains("cmsis-zero-table"), "{stdout}");
    assert!(stdout.contains("0x20000000 - 0x20000004"), "{stdout}");
    assert!(stdout.contains("0x20000004 - 0x20000104"), "{stdout}");
    assert!(stdout.contains("zero-fill"), "{stdout}");
    // The stack sits above .bss here, so the SP check must not claim a match.
    assert!(
        stdout.contains("differs from dst end 0x20000104"),
        "{stdout}"
    );
    // Walking past the reset stub is the point of the change.
    assert!(stdout.contains("1: SystemInit"), "{stdout}");
    assert!(stdout.contains("2: Main"), "{stdout}");
}

#[test]
fn fat_inspect_mcu_human_output_notes_a_missing_init_table() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "mcu", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat inspect mcu runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no init descriptor table recovered"),
        "{stdout}"
    );
}
