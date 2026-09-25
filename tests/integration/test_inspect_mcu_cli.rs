use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn build_profile_register_blob(dereference: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    for (index, value) in [0x1000_1000, 0x1fff_0105, 0x1fff_0121, 0x1fff_0121]
        .into_iter()
        .enumerate()
    {
        write_vector_word(&mut bytes, index, value);
    }
    for (offset, instruction) in [
        (0x104, 0x4801u16), // ldr r0, [pc, #4] -> pool at 0x10c
        (0x106, if dereference { 0x6801 } else { 0xbf00 }),
        (0x108, 0x4770), // bx lr
        (0x10a, 0xbf00),
        (0x120, 0x4770),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&instruction.to_le_bytes());
    }
    bytes[0x10c..0x110].copy_from_slice(&0xe000_e010u32.to_le_bytes());
    let marker = b"NXP LPC134X IFLASH";
    bytes[0x300..0x300 + marker.len()].copy_from_slice(marker);
    bytes
}

#[test]
fn fat_inspect_mcu_exposes_bounded_code_and_profile_register_evidence() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_profile_register_blob(true)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", file.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["code_analysis"].is_object(),
        "missing code evidence: {report}"
    );
    assert!(
        report["register_annotations"].is_object(),
        "missing register evidence: {report}"
    );
    assert_eq!(
        report["fast_profile"]["active_interrupt_count"],
        report["vector_table"]["active_count"]
    );
    assert_eq!(report["vector_table"]["default_handler_count"], 0);
    let accesses = report["code_analysis"]["memory_accesses"]
        .as_array()
        .unwrap();
    assert!(accesses
        .iter()
        .any(|access| access["instruction_offset"] == 0x106 && access["target"] == 0xe000_e010u32));
    assert_eq!(report["register_annotations"]["core_name"], "ARM Cortex-M3");
    let annotated = report["register_annotations"]["accesses"]
        .as_array()
        .unwrap();
    assert!(annotated
        .iter()
        .any(|access| access["instruction_offset"] == 0x106
            && access["names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name["peripheral"] == "SysTick" && name["register"] == "CTRL")));
    let ranges = report["code_analysis"]["instruction_ranges"]
        .as_array()
        .unwrap();
    assert!(
        ranges.iter().all(|range| {
            let start = range["file_offset"].as_u64().unwrap();
            let end = start + range["length"].as_u64().unwrap();
            end <= 0x10c || start >= 0x110
        }),
        "literal pool was classified as code: {ranges:?}"
    );
}

#[test]
fn fat_inspect_mcu_human_output_separates_code_registers_and_constants() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_profile_register_blob(true)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", file.to_str().unwrap()])
        .arg("--details")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Code analysis",
        "Function candidate",
        "Hardware",
        "Entries scanned",
        "Entries retained",
        "ARM Cortex-M3",
        "read",
        "4 B",
        "0xE000E010",
        "SysTick.CTRL",
        "Hardware registers accessed",
        "Address constants",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[test]
fn fat_inspect_mcu_literal_reference_is_not_a_register_access() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_profile_register_blob(false)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", file.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["code_analysis"]["memory_accesses"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!report["code_analysis"]["literal_references"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(report["register_annotations"]["accesses"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!report["register_annotations"]["address_references"]
        .as_array()
        .unwrap()
        .is_empty());
}

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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
    assert!(stdout.contains("--details"), "{stdout}");
}

#[test]
fn fat_inspect_mcu_json_emits_evidence_report_and_provenance() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", blob.to_str().expect("blob")])
        .arg("--details")
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
        "Cortex-M",
        "Address hypotheses",
        "Startup chain",
        "Peripheral candidates",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
    for removed in ["Security controls", "Evidence type", "Observation"] {
        assert!(!stdout.contains(removed), "unexpected {removed}:\n{stdout}");
    }
}

#[test]
fn fat_inspect_mcu_human_output_renders_every_json_peripheral() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_many_peripheral_blob()).expect("blob");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .arg("--details")
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
        ])
        .arg("--details")
        .output()
        .expect("fat inspect mcu text runs");
    assert!(text_output.status.success());
    let stdout = String::from_utf8_lossy(&text_output.stdout);

    for peripheral in peripherals {
        let name = peripheral["peripheral_name"].as_str().expect("name");
        let base = peripheral["base"].as_u64().expect("base");
        let expected = format!("{name}|0x{base:08X}");
        assert!(
            stdout.lines().any(|line| line
                .trim()
                .trim_matches('│')
                .split('│')
                .take(2)
                .map(str::trim)
                .collect::<Vec<_>>()
                .join("|")
                == expected),
            "text output omitted JSON peripheral {expected}:\n{stdout}"
        );
    }
    assert!(stdout.contains("TIM6"), "stdout:\n{stdout}");
}

#[test]
fn fat_inspect_mcu_human_output_renders_vector_summary_and_every_populated_external_irq() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_labeled_vector_table_blob()).expect("blob");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .arg("--details")
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
    assert_eq!(active_irqs.len(), 150);
    assert_eq!(vector_table["default_handler_count"], 0);
    assert_eq!(vector_table["external_irq_count"], 150);

    let text_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
        ])
        .arg("--details")
        .output()
        .expect("fat inspect mcu text runs");
    assert!(text_output.status.success());
    let stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(stdout.contains("Vector table"), "stdout:\n{stdout}");
    assert!(
        stdout.lines().any(|line| line
            .split_once(':')
            .is_some_and(|(key, value)| key.trim() == "Entries scanned" && value.trim() == "166")),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("150 external IRQs"), "stdout:\n{stdout}");

    assert!(!stdout.contains("Default/custom IRQ handler roles: unresolved"));
    assert!(!stdout.contains("non-default IRQ handlers: 0"));

    for entry in active_irqs {
        let index = entry["index"].as_u64().expect("index");
        let irq = index - 16;
        let label = entry["family_label"]
            .as_str()
            .map(|label| format!(" {label}"))
            .unwrap_or_default();
        let address = entry["address"].as_u64().expect("address");
        let handler = address & !1;
        let expected = format!("{index}: IRQ {irq}{label}|0x{handler:08X}|0x{address:08X}");
        assert!(
            stdout.lines().any(|line| line
                .trim()
                .trim_matches('│')
                .split('│')
                .map(str::trim)
                .collect::<Vec<_>>()
                .join("|")
                == expected),
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
    assert_eq!(report["degradations"], serde_json::json!(["weak-signal"]));
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
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
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args([
            "inspect",
            "mcu",
            "--file",
            fixture.to_str().expect("fixture path"),
        ])
        .arg("--details")
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
    assert!(stdout.contains("2: main"), "{stdout}");
}

#[test]
fn fat_inspect_mcu_human_output_omits_a_missing_init_table() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat inspect mcu runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Init descriptor table"), "{stdout}");
    assert!(
        !stdout.contains("no init descriptor table recovered"),
        "{stdout}"
    );
}

fn inspect_output(path: &std::path::Path, json: bool, details: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "120")])
        .args(["inspect", "mcu", "--file", path.to_str().unwrap()]);
    if json {
        command.arg("--json");
    }
    if details {
        command.arg("--details");
    }
    let output = command.output().expect("inspect runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn fat_inspect_mcu_concise_report_keeps_findings_and_json_diagnostics() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_profile_register_blob(true)).unwrap();
    let before: Value = serde_json::from_str(&inspect_output(&file, true, false)).unwrap();
    let text = inspect_output(&file, false, true);
    let after: Value = serde_json::from_str(&inspect_output(&file, true, false)).unwrap();
    assert_eq!(before, after, "human rendering changed the JSON report");
    assert!(!before["code_analysis"]["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!before["register_annotations"]["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(before["init_table"].is_null());
    assert!(before["system_init_effects"].is_null());
    assert!(
        before["peripheral_map"].is_null()
            || before["peripheral_map"]["uses"]
                .as_array()
                .is_some_and(Vec::is_empty)
    );
    for finding in [
        "Vector table",
        "Code analysis",
        "Hardware",
        "NXP LPC134x",
        "0x1FFF0105",
        "0xE000E010",
        "SysTick.CTRL",
        "Hardware registers accessed",
        "Address constants",
    ] {
        assert!(text.contains(finding), "lost finding {finding}: {text}");
    }
    for absent in [
        "Evidence notes & limits",
        "Degradations",
        "Init descriptor table",
        "SystemInit effects",
        "Peripheral candidates",
        "Initialization descriptors",
        "Analysis stops",
    ] {
        assert!(
            !text.contains(absent),
            "unexpected empty/diagnostic content {absent}: {text}"
        );
    }
}

#[test]
fn fat_inspect_mcu_concise_unmatched_report_omits_empty_sections_but_json_keeps_reasons() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("unrecognized.bin");
    std::fs::write(&file, [0x41u8; 128]).unwrap();
    let before: Value = serde_json::from_str(&inspect_output(&file, true, false)).unwrap();
    let text = inspect_output(&file, false, false);
    let after: Value = serde_json::from_str(&inspect_output(&file, true, true)).unwrap();
    assert_eq!(before, after);
    assert_eq!(before["degradations"], serde_json::json!(["weak-signal"]));
    assert!(before["code_analysis"].is_null());
    assert!(before["vector_table"].is_null());
    assert!(text.contains("unrecognized.bin"), "{text}");
    assert!(text.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(key, value)| key.trim() == "Size" && value.contains("128"))
    }));
    for absent in [
        "Architecture",
        "Family",
        "Evidence notes & limits",
        "Degradations",
        "Address hypotheses",
        "Vector table",
        "Startup chain",
        "Code analysis",
        "Hardware",
        "Init descriptor table",
        "SystemInit effects",
        "SRAM partition",
        "Execution model",
        "Peripheral candidates",
        "Peripheral surface",
        "Security controls",
        "ISR / shared state",
    ] {
        assert!(
            !text.contains(absent),
            "unexpected unmatched section {absent}: {text}"
        );
    }
}

#[test]
fn fat_inspect_mcu_concise_literal_only_report_keeps_constants_separate_from_accesses() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("literal-only.bin");
    std::fs::write(&file, build_profile_register_blob(false)).unwrap();
    let report: Value = serde_json::from_str(&inspect_output(&file, true, false)).unwrap();
    assert!(report["register_annotations"]["accesses"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        report["register_annotations"]["address_references"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let text = inspect_output(&file, false, true);
    assert!(text.contains("Hardware"), "{text}");
    assert!(text.contains("Address constants"), "{text}");
    assert!(text.contains("0xE000E010"), "{text}");
    assert!(text.contains("SysTick.CTRL"), "{text}");
    assert!(!text.contains("Hardware registers accessed"), "{text}");
    assert!(!text.contains("Evidence notes & limits"), "{text}");
}

#[test]
fn fat_inspect_mcu_overview_keeps_entry_and_accesses_while_details_expand_sites() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_profile_register_blob(true)).unwrap();
    let overview = inspect_output(&file, false, false);
    let details = inspect_output(&file, false, true);
    for text in [&overview, &details] {
        for value in [
            "anonymous.bin",
            "NXP LPC134x",
            "0x1FFF0104",
            "0xE000E010",
            "SysTick.CTRL",
        ] {
            assert!(text.contains(value), "missing {value}: {text}");
        }
    }
    // The overview has an aligned entry; the raw vector and instruction site
    // are available in the expanded reference view.
    assert!(!overview.contains("0x1FFF0105"), "{overview}");
    assert!(!overview.contains("0x1FFF0106"), "{overview}");
    assert!(details.contains("0x1FFF0105"), "{details}");
    assert!(details.contains("0x1FFF0106"), "{details}");
    assert!(overview.lines().count() <= 35, "{overview}");
    assert!(
        details.lines().count() > overview.lines().count(),
        "{details}"
    );
    let json: Value = serde_json::from_str(&inspect_output(&file, true, false)).unwrap();
    let json_details: Value = serde_json::from_str(&inspect_output(&file, true, true)).unwrap();
    assert_eq!(json, json_details);
}

#[test]
fn fat_inspect_mcu_overview_groups_large_vector_tables() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("vectors.bin");
    std::fs::write(&file, build_labeled_vector_table_blob()).unwrap();
    let overview = inspect_output(&file, false, false);
    let details = inspect_output(&file, false, true);
    assert!(overview.contains("150"), "{overview}");
    assert!(overview.contains("0x08000400"), "{overview}");
    assert!(
        overview.lines().count() <= 40,
        "unbounded overview: {overview}"
    );
    assert!(
        details.contains("IRQ 149"),
        "last populated IRQ missing: {details}"
    );
}
