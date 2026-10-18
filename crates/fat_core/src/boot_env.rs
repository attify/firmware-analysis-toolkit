//! Located U-Boot environment evidence. CRC validity does not select the active copy.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEnvScan {
    pub environments: Vec<BootEnvironment>,
    pub scanned_bytes: u64,
    pub alignment: u64,
    pub candidate_sizes: Vec<u64>,
    pub explicit_region: bool,
    pub search_limited: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEnvironment {
    pub offset: u64,
    /// Total stored region length, including CRC and optional redundant-copy flag.
    pub size: u64,
    pub format: String,
    pub crc_endianness: String,
    pub crc_valid: bool,
    pub stored_crc32: String,
    pub redundancy_flag: Option<u8>,
    pub variables: Vec<EnvironmentVariable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    pub key: String,
    pub value: String,
    pub offset: u64,
}
