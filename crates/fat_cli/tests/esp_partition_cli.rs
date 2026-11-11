use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0x77; 0x123];
    let mut entry = [0; 32];
    entry[..4].copy_from_slice(&[0xaa, 0x50, 1, 2]);
    entry[4..8].copy_from_slice(&0x9000_u32.to_le_bytes());
    entry[8..12].copy_from_slice(&0x6000_u32.to_le_bytes());
    entry[12..15].copy_from_slice(b"nvs");
    entry[28..32].copy_from_slice(&0x80000003_u32.to_le_bytes());
    bytes.extend(entry);
    bytes.extend([0xff; 32]);
    bytes
}

#[test]
fn identify_and_headers_share_native_partition_evidence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("firmware.bin");
    std::fs::write(&path, fixture()).unwrap();
    let mut reports = Vec::new();
    for command in [vec!["identify"], vec!["inspect", "headers"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .args(&command)
            .arg("--file")
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        let scan = if command[0] == "identify" {
            assert_eq!(json["likely_class"], "esp-idf-partitioned-image");
            &json["structure"]["esp_partitions"]
        } else {
            &json["esp_partitions"]
        };
        assert_eq!(scan["tables"][0]["file_offset"], 0x123);
        assert_eq!(scan["tables"][0]["partitions"][0]["flash_offset"], 0x9000);
        reports.push(scan.clone());
        for columns in ["48", "120"] {
            let output = Command::new(env!("CARGO_BIN_EXE_fat"))
                .args(&command)
                .arg("--file")
                .arg(&path)
                .env("NO_COLOR", "1")
                .env("COLUMNS", columns)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let text = String::from_utf8_lossy(&output.stdout);
            for value in [
                "ESP-IDF",
                "0x00000123",
                "0x00009000",
                "0x00006000",
                "nvs",
                "0x80000003",
            ] {
                assert!(text.contains(value), "missing {value} in {text}");
            }
        }
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn rejected_table_is_diagnostic_not_identification() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad-table.bin");
    let mut bytes = fixture();
    bytes[0x123 + 8..0x123 + 12].fill(0);
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "headers", "--file"])
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["esp_partitions"]["tables"], serde_json::json!([]));
    assert!(!report["esp_partitions"]["diagnostics"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn embedded_table_does_not_override_an_outer_uimage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("linux-uimage.bin");
    let payload = fixture();
    let mut header = vec![0; 64];
    header[..4].copy_from_slice(&0x27051956_u32.to_be_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[24..28].copy_from_slice(&crc32(&payload).to_be_bytes());
    header[28..32].copy_from_slice(&[5, 5, 2, 0]); // Linux, MIPS, kernel, uncompressed
    let crc = crc32(&header);
    header[4..8].copy_from_slice(&crc.to_be_bytes());
    header.extend(payload);
    std::fs::write(&path, header).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file"])
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["likely_class"], "structured-firmware-container");
    assert_eq!(
        report["structure"]["esp_partitions"]["tables"][0]["file_offset"],
        0x123 + 64
    );
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320_u32 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
