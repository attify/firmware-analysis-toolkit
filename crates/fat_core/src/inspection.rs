use serde::{Deserialize, Serialize};

use crate::bootloader::BootImageHeader;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InspectionReport {
    #[serde(default)]
    pub container_headers: Vec<ContainerHeader>,
    #[serde(default)]
    pub image_headers: Vec<BootImageHeader>,
    #[serde(default)]
    pub compression_members: Vec<CompressionMember>,
    #[serde(default)]
    pub filesystem_headers: Vec<FilesystemHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ContainerHeader {
    pub format: String,
    pub offset: u64,
    pub header_size: u64,
    pub magic: String,
    pub vendor: Option<String>,
    pub package_name: Option<String>,
    pub timestamp_unix: Option<u64>,
    pub declared_payload_size: Option<u64>,
    pub actual_payload_size: Option<u64>,
    pub payload_type: Option<String>,
    pub payload_marker: Option<String>,
    pub seed_hex: Option<String>,
    pub integrity_algorithm: Option<String>,
    pub stored_digest_hex: Option<String>,
    pub computed_digest_hex: Option<String>,
    pub integrity_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CompressionMember {
    pub format: String,
    pub offset: u64,
    pub properties_hex: Option<String>,
    pub dictionary_size: Option<u32>,
    pub uncompressed_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_architecture: Option<String>,
    pub operating_system: Option<String>,
    pub timestamp_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FilesystemHeader {
    pub format: String,
    pub offset: u64,
    pub endianness: Option<String>,
    pub version: Option<String>,
    pub compression: Option<String>,
    pub inode_count: Option<u32>,
    pub block_size: Option<u32>,
    pub image_size: Option<u64>,
    pub created_unix: Option<u64>,
}
