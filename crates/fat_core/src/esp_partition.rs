//! ESP-IDF partition metadata. Flash addresses do not imply input-file mappings.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EspPartitionScan {
    pub tables: Vec<EspPartitionTable>,
    pub diagnostics: Vec<EspPartitionDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspPartitionTable {
    pub file_offset: u64,
    /// Bytes through the end marker, not an assumed 4 KiB flash-sector extent.
    pub size: u64,
    pub checksum: Option<EspPartitionChecksum>,
    pub partitions: Vec<EspPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspPartitionChecksum {
    pub stored_hex: String,
    pub computed_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspPartition {
    pub entry_file_offset: u64,
    pub label: String,
    pub partition_type: u8,
    pub subtype: u8,
    pub type_name: Option<String>,
    pub subtype_name: Option<String>,
    pub flash_offset: u64,
    pub size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspPartitionDiagnostic {
    pub file_offset: u64,
    pub reason: String,
}
