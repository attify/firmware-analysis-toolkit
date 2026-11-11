use fat_analyze::bootloader::{analyze_firmware_bytes, analyze_layout_bytes, merge_snapshots};
use md5::{Digest, Md5};
use serde_json::Value;

fn entry(label: &str, kind: u8, subtype: u8, offset: u32, size: u32, flags: u32) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..2].copy_from_slice(&[0xaa, 0x50]);
    bytes[2] = kind;
    bytes[3] = subtype;
    bytes[4..8].copy_from_slice(&offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&size.to_le_bytes());
    bytes[12..12 + label.len()].copy_from_slice(label.as_bytes());
    bytes[28..32].copy_from_slice(&flags.to_le_bytes());
    bytes
}

fn table(checksum: bool) -> Vec<u8> {
    let mut bytes = entry("settings", 1, 2, 0x9000, 0x6000, 0);
    bytes.extend(entry("radio", 1, 1, 0xf000, 0x1000, 0));
    bytes.extend(entry("slot_a", 0, 0x10, 0x10000, 0x100000, 0));
    finish(bytes, checksum)
}

fn finish(mut bytes: Vec<u8>, checksum: bool) -> Vec<u8> {
    if checksum {
        let digest = Md5::digest(&bytes);
        bytes.extend([0xeb, 0xeb]);
        bytes.extend([0xff; 14]);
        bytes.extend(digest);
    }
    bytes.extend([0xff; 32]);
    bytes
}

fn scan(bytes: &[u8]) -> Value {
    let snapshot = analyze_firmware_bytes(bytes).unwrap();
    let json = serde_json::to_value(snapshot).unwrap();
    assert!(
        json["esp_partitions"].is_object(),
        "ESP-IDF scan missing: {json}"
    );
    json["esp_partitions"].clone()
}

#[test]
fn discovers_relocated_table_without_assuming_flash_base() {
    let mut bytes = vec![0x77; 0x5123];
    bytes.extend(table(true));
    let report = scan(&bytes);
    assert_eq!(report["tables"].as_array().unwrap().len(), 1);
    let table = &report["tables"][0];
    assert_eq!(table["file_offset"], 0x5123);
    assert_eq!(table["size"], 160);
    assert_eq!(
        table["checksum"]["stored_hex"],
        table["checksum"]["computed_hex"]
    );
    assert_eq!(table["partitions"][0]["label"], "settings");
    assert_eq!(table["partitions"][0]["entry_file_offset"], 0x5123);
    assert_eq!(table["partitions"][0]["flash_offset"], 0x9000);
    assert_eq!(table["partitions"][0]["size"], 0x6000);
    assert!(table["partitions"][0].get("file_offset").is_none());
    assert_eq!(table["partitions"][2]["subtype_name"], "ota_0");
}

#[test]
fn standalone_legacy_table_preserves_custom_codes_flags_and_full_label() {
    let bytes = finish(
        entry("abcdefghijklmnop", 0x40, 0xa5, 0x2000, 0x1000, 0x80000003),
        false,
    );
    let report = scan(&bytes);
    let table = &report["tables"][0];
    assert_eq!(table["file_offset"], 0);
    assert!(table["checksum"].is_null());
    let partition = &table["partitions"][0];
    assert_eq!(partition["label"], "abcdefghijklmnop");
    assert_eq!(partition["partition_type"], 0x40);
    assert_eq!(partition["subtype"], 0xa5);
    assert_eq!(partition["flags"], 0x80000003_u32);
    assert!(partition["type_name"].is_null());
    assert!(partition["subtype_name"].is_null());
}

#[test]
fn rejects_corrupt_checksum_without_accepting_a_table_suffix() {
    let mut bytes = table(true);
    bytes[112] ^= 1;
    let report = scan(&bytes);
    assert!(report["tables"].as_array().unwrap().is_empty());
    assert!(report["diagnostics"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("MD5"));
}

#[test]
fn rejects_invalid_entries_without_accepting_valid_suffixes() {
    for range in [8..12, 40..44] {
        let mut bytes = table(false);
        bytes[range].fill(0);
        let report = scan(&bytes);
        assert!(report["tables"].as_array().unwrap().is_empty(), "{report}");
    }
}

#[test]
fn rejects_truncated_records_and_missing_terminator() {
    let bytes = table(true);
    for length in [1, 12, 31, 32, 63, 96, 120, 128, 159] {
        assert!(scan(&bytes[..length])["tables"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn rejects_overlaps_duplicate_names_and_invalid_alignment() {
    for second in [
        entry("overlap", 1, 2, 0xa000, 0x6000, 0),
        entry("settings", 1, 2, 0x20000, 0x6000, 0),
        entry("unaligned", 1, 2, 0x20001, 0x6000, 0),
        entry("app", 0, 0, 0x21000, 0x10000, 0),
        entry("overflow", 1, 0x80, 0xfffff000, 0x2000, 0),
    ] {
        let mut bytes = entry("settings", 1, 2, 0x9000, 0x6000, 0);
        bytes.extend(second);
        assert!(scan(&finish(bytes, false))["tables"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn rejects_invalid_utf8_and_empty_labels() {
    for label in [[0xff; 16], [0; 16]] {
        let mut bytes = table(false);
        bytes[12..28].copy_from_slice(&label);
        assert!(scan(&bytes)["tables"].as_array().unwrap().is_empty());
    }
}

#[test]
fn retains_multiple_distinct_tables_and_deduplicates_merged_scans() {
    let mut bytes = table(true);
    bytes.resize(0x4000, 0xff);
    bytes.extend(table(false));
    let report = scan(&bytes);
    assert_eq!(report["tables"].as_array().unwrap().len(), 2);
    assert_eq!(report["tables"][1]["file_offset"], 0x4000);
    let snapshot = analyze_firmware_bytes(&bytes).unwrap();
    let merged = serde_json::to_value(merge_snapshots(snapshot.clone(), snapshot)).unwrap();
    assert_eq!(
        merged["esp_partitions"]["tables"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn accepts_bootloader_and_partition_table_entries_at_low_flash_addresses() {
    let mut bytes = entry("boot", 2, 0, 0, 0x8000, 0);
    bytes.extend(entry("table", 3, 0, 0x8000, 0x1000, 0));
    let report = scan(&finish(bytes, true));
    assert_eq!(
        report["tables"][0]["partitions"][0]["type_name"],
        "bootloader"
    );
    assert_eq!(
        report["tables"][0]["partitions"][1]["type_name"],
        "partition_table"
    );
}

#[test]
fn enforces_maximum_table_length() {
    let mut entries = Vec::new();
    for n in 0..95 {
        entries.extend(entry(&format!("p{n}"), 0x40, 0, n * 0x1000, 0x1000, 0));
    }
    assert_eq!(
        scan(&finish(entries.clone(), false))["tables"][0]["partitions"]
            .as_array()
            .unwrap()
            .len(),
        95
    );
    entries.extend(entry("too_many", 0x40, 0, 0x100000, 0x1000, 0));
    assert!(scan(&finish(entries, false))["tables"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn unrelated_data_and_magic_alone_are_not_tables() {
    for bytes in [vec![0xff; 4096], vec![0; 4096], vec![0xaa, 0x50, 0, 0]] {
        assert!(scan(&bytes)["tables"].as_array().unwrap().is_empty());
    }
}

#[test]
fn layout_maps_only_table_bytes_not_unresolved_flash_payloads() {
    let mut bytes = vec![0x77; 0x123];
    bytes.extend(table(true));
    let layout = analyze_layout_bytes(&bytes).unwrap();
    let region = layout
        .regions
        .iter()
        .find(|region| region.format == "esp-idf-partition-table")
        .expect("partition table region");
    assert_eq!(region.kind.as_str(), "partition-table");
    assert_eq!(region.offset, 0x123);
    assert_eq!(region.size, Some(160));
    assert!(region.span_is_exact);
    assert!(!layout.regions.iter().any(|region| region.offset == 0x9000));
}

#[test]
fn older_snapshots_remain_readable() {
    let snapshot = analyze_firmware_bytes(&[]).unwrap();
    let mut json = serde_json::to_value(snapshot).unwrap();
    json.as_object_mut().unwrap().remove("esp_partitions");
    let restored: fat_core::bootloader::BootloaderSnapshot = serde_json::from_value(json).unwrap();
    assert!(restored.esp_partitions.tables.is_empty());
}

#[test]
fn corrupt_middle_magic_does_not_promote_a_legacy_suffix() {
    let mut bytes = table(false);
    bytes[32] = 0;
    let report = scan(&bytes);
    assert!(report["tables"].as_array().unwrap().is_empty(), "{report}");
}

#[test]
fn incidental_magic_does_not_hide_an_independently_valid_table() {
    for prefix in [
        vec![0xaa, 0x50, b'a', b'b', b'c'],
        [vec![0xaa, 0x50], vec![b'x'; 30]].concat(),
    ] {
        let mut bytes = prefix.clone();
        bytes.extend(table(true));
        let report = scan(&bytes);
        assert_eq!(report["tables"].as_array().unwrap().len(), 1, "{report}");
        assert_eq!(report["tables"][0]["file_offset"], prefix.len());
    }
}

#[test]
fn rejected_framing_does_not_hide_a_legacy_table_on_another_alignment() {
    let mut bytes = entry("damaged", 1, 2, 0x9000, 0x6000, 0);
    bytes.extend([0x77; 5]);
    bytes.extend(finish(
        entry("independent", 1, 2, 0x20000, 0x6000, 0),
        false,
    ));
    bytes.resize(256, 0xff);
    let report = scan(&bytes);
    assert_eq!(report["tables"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["tables"][0]["file_offset"], 37);
}
