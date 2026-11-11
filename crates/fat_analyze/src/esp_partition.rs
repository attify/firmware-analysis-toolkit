//! Native ESP-IDF table discovery, independent of chip architecture and flash base.
//!
//! Format reference: Espressif ESP-IDF components/partition_table/gen_esp32part.py
//! https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/partition-tables.html
use std::collections::BTreeSet;

use fat_core::esp_partition::{
    EspPartition, EspPartitionChecksum, EspPartitionDiagnostic, EspPartitionScan, EspPartitionTable,
};
use md5::{Digest, Md5};
use memchr::memmem;

const ENTRY_SIZE: usize = 32;
const MAX_TABLE_SIZE: usize = 0xc00;
const MAGIC: &[u8] = &[0xaa, 0x50];

pub fn scan(bytes: &[u8]) -> EspPartitionScan {
    let mut report = EspPartitionScan::default();
    let mut accepted_end = 0;
    let mut rejected_ends = [0; ENTRY_SIZE];
    for start in memmem::find_iter(bytes, MAGIC) {
        if start < accepted_end {
            continue;
        }
        let phase = start % ENTRY_SIZE;
        let (end, framed, result) = parse_at(bytes, start);
        match result {
            // A valid MD5 independently establishes the beginning of a table,
            // even when an earlier incidental signature covered this position.
            Ok(table) if table.checksum.is_some() || start >= rejected_ends[phase] => {
                accepted_end = end;
                report.tables.push(table);
            }
            Ok(_) => {} // Do not promote a legacy suffix of a rejected table.
            Err(reason) => {
                if start >= rejected_ends[phase] {
                    report.diagnostics.push(EspPartitionDiagnostic {
                        file_offset: start as u64,
                        reason,
                    });
                }
                if framed {
                    rejected_ends[phase] = rejected_ends[phase].max(end);
                }
            }
        }
    }
    report
}

fn parse_at(bytes: &[u8], start: usize) -> (usize, bool, Result<EspPartitionTable, String>) {
    let mut partitions = Vec::new();
    let mut checksum = None;
    let mut error = None;
    let mut cursor = start;
    for _ in 0..MAX_TABLE_SIZE / ENTRY_SIZE {
        let Some(record) = bytes.get(cursor..).and_then(|tail| tail.get(..ENTRY_SIZE)) else {
            return (
                bytes.len(),
                !partitions.is_empty(),
                Err("truncated table or missing end marker".into()),
            );
        };
        let record_offset = cursor;
        cursor += ENTRY_SIZE;
        if record == [0xff; ENTRY_SIZE] {
            let framed = !partitions.is_empty();
            let result = if let Some(error) = error {
                Err(error)
            } else {
                validate_partitions(&partitions).map(|()| EspPartitionTable {
                    file_offset: start as u64,
                    size: (cursor - start) as u64,
                    checksum,
                    partitions,
                })
            };
            return (cursor, framed, result);
        }
        if record[..2] == [0xeb, 0xeb] {
            if checksum.is_some() || partitions.is_empty() || record[2..16] != [0xff; 14] {
                error
                    .get_or_insert_with(|| "invalid MD5 record placement or reserved bytes".into());
            }
            let digest = Md5::digest(&bytes[start..record_offset]);
            if record[16..] != digest[..] {
                error.get_or_insert_with(|| "MD5 checksum mismatch".into());
            }
            checksum = Some(EspPartitionChecksum {
                stored_hex: hex(&record[16..]),
                computed_hex: hex(&digest),
            });
        } else if &record[..2] == MAGIC {
            if checksum.is_some() {
                error.get_or_insert_with(|| "partition entry follows MD5 record".into());
            }
            match parse_entry(record, record_offset) {
                Ok(partition) => partitions.push(partition),
                Err(reason) => {
                    error.get_or_insert(reason);
                }
            }
        } else {
            let reason = format!("invalid record magic at file offset 0x{record_offset:x}");
            if partitions.is_empty() {
                return (cursor, false, Err(reason));
            }
            // Once entries establish framing, retain the rejected continuation
            // through its terminator. A damaged middle record must not turn the
            // following legacy entries into a new, apparently valid table.
            error.get_or_insert(reason);
        }
    }
    (
        cursor,
        !partitions.is_empty(),
        Err("table exceeds 0xc00 bytes or is missing its end marker".into()),
    )
}

fn parse_entry(bytes: &[u8], file_offset: usize) -> Result<EspPartition, String> {
    let label_bytes = bytes[12..28]
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    let label = std::str::from_utf8(label_bytes).map_err(|_| "invalid UTF-8 partition label")?;
    if label.is_empty() || label.chars().any(char::is_control) {
        return Err("empty partition label or control character in label".into());
    }
    let partition_type = bytes[2];
    if partition_type == 0xff {
        return Err("partition type 0xff is reserved for erased entries".into());
    }
    let subtype = bytes[3];
    let flash_offset = u64::from(read_u32(bytes, 4));
    let size = u64::from(read_u32(bytes, 8));
    let alignment = if partition_type == 0 { 0x10000 } else { 0x1000 };
    if !flash_offset.is_multiple_of(alignment) {
        return Err(format!("partition {label:?} has an unaligned flash offset"));
    }
    if size == 0 || flash_offset + size > 1_u64 << 32 {
        return Err(format!(
            "partition {label:?} has an invalid size or exceeds 32-bit flash addressing"
        ));
    }
    if partition_type == 0 && !size.is_multiple_of(0x1000) {
        return Err(format!(
            "app partition {label:?} size is not aligned to 0x1000"
        ));
    }
    Ok(EspPartition {
        entry_file_offset: file_offset as u64,
        label: label.to_string(),
        partition_type,
        subtype,
        type_name: match partition_type {
            0 => Some("app".into()),
            1 => Some("data".into()),
            2 => Some("bootloader".into()),
            3 => Some("partition_table".into()),
            _ => None,
        },
        subtype_name: subtype_name(partition_type, subtype),
        flash_offset,
        size,
        flags: read_u32(bytes, 28),
    })
}

fn validate_partitions(partitions: &[EspPartition]) -> Result<(), String> {
    if partitions.is_empty() {
        return Err("table contains no partitions".into());
    }
    let mut labels = BTreeSet::new();
    for partition in partitions {
        if !labels.insert(&partition.label) {
            return Err(format!("duplicate partition label {:?}", partition.label));
        }
    }
    let mut ordered = partitions.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|partition| partition.flash_offset);
    for pair in ordered.windows(2) {
        if pair[0].flash_offset + pair[0].size > pair[1].flash_offset {
            return Err(format!(
                "overlapping partitions {:?} and {:?}",
                pair[0].label, pair[1].label
            ));
        }
    }
    Ok(())
}

fn subtype_name(kind: u8, subtype: u8) -> Option<String> {
    let name = match (kind, subtype) {
        (0, 0) => "factory",
        (0, 0x10..=0x1f) => return Some(format!("ota_{}", subtype - 0x10)),
        (0, 0x20) => "test",
        (1, 0) => "ota",
        (1, 1) => "phy",
        (1, 2) => "nvs",
        (1, 3) => "coredump",
        (1, 4) => "nvs_keys",
        (1, 5) => "efuse",
        (1, 6) => "undefined",
        (1, 0x80) => "esphttpd",
        (1, 0x81) => "fat",
        (1, 0x82) => "spiffs",
        (1, 0x83) => "littlefs",
        (2 | 3, 0) => "primary",
        (2 | 3, 1) => "ota",
        (2, 2) => "recovery",
        _ => return None,
    };
    Some(name.into())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded entry field"),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
