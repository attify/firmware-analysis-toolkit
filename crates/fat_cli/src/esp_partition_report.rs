use fat_core::esp_partition::EspPartitionTable;

use crate::report::Report;

pub fn append_tables(view: &mut Report, tables: &[EspPartitionTable]) {
    for table in tables {
        view.section("ESP-IDF partitions");
        view.kv("Table file offset", format!("0x{:08x}", table.file_offset));
        view.kv(
            "MD5",
            if table.checksum.is_some() {
                "valid"
            } else {
                "not present"
            },
        );
        let rows = table
            .partitions
            .iter()
            .map(|partition| {
                vec![
                    partition.label.clone(),
                    partition
                        .type_name
                        .clone()
                        .unwrap_or_else(|| format!("0x{:02x}", partition.partition_type)),
                    partition
                        .subtype_name
                        .clone()
                        .unwrap_or_else(|| format!("0x{:02x}", partition.subtype)),
                    format!("0x{:08x}", partition.flash_offset),
                    format!("0x{:08x}", partition.size),
                    format!("0x{:08x}", partition.flags),
                ]
            })
            .collect::<Vec<_>>();
        view.table(
            &["Name", "Type", "Subtype", "Flash offset", "Size", "Flags"],
            &rows,
        );
        view.text("Flash offsets are device addresses; mapping them into this file requires its flash base.");
    }
}
