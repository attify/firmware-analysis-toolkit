use std::fs;

use fat_analyze::svd_rank::{rank_svd_corpus, SvdRankRequest};
use tempfile::tempdir;

fn write_firmware(path: &std::path::Path, words: &[u32]) {
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    fs::write(path, bytes).expect("write firmware");
}

fn write_svd(path: &std::path::Path, device: &str, peripherals: &[(&str, u32, &[(&str, u32)])]) {
    let mut xml = format!("<device><name>{device}</name><peripherals>");
    for (peripheral, base, registers) in peripherals {
        xml.push_str(&format!(
            "<peripheral><name>{peripheral}</name><baseAddress>0x{base:08x}</baseAddress><registers>"
        ));
        for (register, offset) in *registers {
            xml.push_str(&format!(
                "<register><name>{register}</name><addressOffset>0x{offset:x}</addressOffset></register>"
            ));
        }
        xml.push_str("</registers></peripheral>");
    }
    xml.push_str("</peripherals></device>");
    fs::write(path, xml).expect("write svd");
}

fn write_bytes(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write firmware bytes");
}

#[test]
fn svd_rank_orders_candidate_devices_by_exact_register_hits() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    let corpus = dir.path().join("svds");
    fs::create_dir(&corpus).expect("corpus dir");

    write_firmware(
        &firmware,
        &[
            0x4001_1000,
            0x4001_100C,
            0x4001_1010,
            0x4001_1400,
            0x5800_1C00,
            0x5800_1C10,
            0x2000_1000,
        ],
    );
    write_svd(
        &corpus.join("stm32h7_demo.svd"),
        "STM32H7_DEMO",
        &[
            (
                "USART1",
                0x4001_1000,
                &[("CR1", 0x00), ("BRR", 0x0C), ("CR2", 0x10)],
            ),
            ("I2C4", 0x5800_1C00, &[("CR1", 0x00), ("TIMEOUTR", 0x10)]),
        ],
    );
    write_svd(
        &corpus.join("other_demo.svd"),
        "OTHER_DEMO",
        &[("UART0", 0x4000_0000, &[("DR", 0x00), ("CR", 0x04)])],
    );

    let report = rank_svd_corpus(&SvdRankRequest {
        firmware: firmware.clone(),
        svd_corpus: corpus,
        max_results: 10,
    })
    .expect("rank report");

    assert_eq!(report.schema_version, "svd-rank/v1");
    assert_eq!(report.artifact_path, firmware.display().to_string());
    assert_eq!(report.observed_mmio_literals, 6);
    assert_eq!(report.candidates.len(), 2);
    assert_eq!(report.candidates[0].device, "STM32H7_DEMO");
    assert_eq!(report.candidates[0].matched_register_count, 5);
    assert_eq!(report.candidates[0].score, 5.0);
    assert!(report.candidates[0]
        .matched_registers
        .iter()
        .any(|matched| matched.peripheral == "USART1" && matched.register == "BRR"));
    assert_eq!(report.candidates[1].device, "OTHER_DEMO");
    assert_eq!(report.candidates[1].matched_register_count, 0);
}

#[test]
fn svd_rank_expands_derived_peripherals_and_dimmed_register_arrays() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    let corpus = dir.path().join("svds");
    fs::create_dir(&corpus).expect("corpus dir");

    write_firmware(&firmware, &[0x4001_3000, 0x4001_3020, 0x4001_3800]);
    fs::write(
        corpus.join("derived_dim.svd"),
        r#"<device><name>DERIVED_DIM_DEVICE</name><peripherals>
<peripheral><name>USART1</name><baseAddress>0x40011000</baseAddress><registers>
<register><name>CR1</name><addressOffset>0x00</addressOffset></register>
<register><dim>2</dim><dimIncrement>0x20</dimIncrement><name>FIFO%s</name><addressOffset>0x20</addressOffset></register>
</registers></peripheral>
<peripheral derivedFrom="USART1"><name>USART3</name><baseAddress>0x40013000</baseAddress></peripheral>
<peripheral derivedFrom="USART1"><name>UART5</name><baseAddress>0x40013800</baseAddress></peripheral>
</peripherals></device>"#,
    )
    .expect("svd");

    let report = rank_svd_corpus(&SvdRankRequest {
        firmware,
        svd_corpus: corpus,
        max_results: 10,
    })
    .expect("rank report");

    assert_eq!(report.candidates[0].device, "DERIVED_DIM_DEVICE");
    assert_eq!(report.candidates[0].matched_register_count, 3);
    assert!(report.candidates[0]
        .matched_registers
        .iter()
        .any(|matched| matched.peripheral == "USART3" && matched.register == "FIFO0"));
    assert!(report.candidates[0]
        .matched_registers
        .iter()
        .any(|matched| matched.peripheral == "UART5" && matched.register == "CR1"));
}

#[test]
fn svd_rank_uses_strings_and_vector_metadata_to_break_mmio_ties() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    let corpus = dir.path().join("svds");
    fs::create_dir(&corpus).expect("corpus dir");

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x2001_A058u32.to_le_bytes());
    bytes.extend_from_slice(&0x0800_0201u32.to_le_bytes());
    for _ in 2..48 {
        bytes.extend_from_slice(&0x0800_0401u32.to_le_bytes());
    }
    bytes.extend_from_slice(&0x4001_1000u32.to_le_bytes());
    bytes.extend_from_slice(&0x4001_100Cu32.to_le_bytes());
    bytes.extend_from_slice(b"/build/acme/stm32f407_demo/main.c\0STM32F407 HAL UART");
    write_bytes(&firmware, &bytes);

    write_svd(
        &corpus.join("stm32f103.svd"),
        "STM32F103",
        &[("USART1", 0x4001_1000, &[("CR1", 0x00), ("BRR", 0x0C)])],
    );
    write_svd(
        &corpus.join("stm32f407.svd"),
        "STM32F407",
        &[("USART1", 0x4001_1000, &[("CR1", 0x00), ("BRR", 0x0C)])],
    );

    let report = rank_svd_corpus(&SvdRankRequest {
        firmware,
        svd_corpus: corpus,
        max_results: 10,
    })
    .expect("rank report");

    assert_eq!(report.candidates[0].device, "STM32F407");
    assert_eq!(report.candidates[0].matched_register_count, 2);
    assert!(report.candidates[0].string_hint_score > report.candidates[1].string_hint_score);
    assert!(report.candidates[0].vector_hint_score > 0.0);
    assert!(report.candidates[0].score > report.candidates[1].score);
}
