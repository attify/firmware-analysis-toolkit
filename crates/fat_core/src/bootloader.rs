use serde::{Deserialize, Serialize};

use crate::inspection::{CompressionMember, ContainerHeader, FilesystemHeader};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootloaderSnapshot {
    pub family: Option<String>,
    pub version_hint: Option<String>,
    #[serde(default)]
    pub kernel_cmdline: Option<KernelCmdline>,
    #[serde(default)]
    pub partition_map: Option<MtdPartitionMap>,
    pub env_variables: Vec<BootEnvVariable>,
    pub flow_hints: Vec<BootFlowHint>,
    pub secure_boot_hints: Vec<SecureBootHint>,
    #[serde(default)]
    pub container_headers: Vec<ContainerHeader>,
    #[serde(default)]
    pub image_headers: Vec<BootImageHeader>,
    #[serde(default)]
    pub compression_members: Vec<CompressionMember>,
    #[serde(default)]
    pub filesystem_headers: Vec<FilesystemHeader>,
    #[serde(default)]
    pub embedded_signatures: Vec<EmbeddedSignature>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KernelCmdline {
    pub value: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MtdPartitionMap {
    pub source: String,
    pub device: String,
    pub root_device: Option<String>,
    pub root_fstype: Option<String>,
    #[serde(default)]
    pub partitions: Vec<MtdPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MtdPartition {
    pub index: u32,
    pub name: String,
    pub size_bytes: u64,
    pub flash_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootImageHeader {
    pub format: String,
    pub offset: u64,
    pub header_size: u64,
    pub magic_hex: String,
    pub data_size: u64,
    pub load_address_hex: String,
    pub entry_point_hex: String,
    pub header_crc32_hex: String,
    pub data_crc32_hex: String,
    pub timestamp_unix: u64,
    pub name: Option<String>,
    pub os_code_hex: Option<String>,
    pub operating_system: Option<String>,
    pub architecture_code_hex: Option<String>,
    pub architecture: Option<String>,
    pub image_type_code_hex: Option<String>,
    pub image_type: Option<String>,
    pub compression_code_hex: Option<String>,
    pub compression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EmbeddedSignature {
    pub format: String,
    pub offset: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootEnvVariable {
    pub key: String,
    pub value: String,
    pub source: BootValueSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootFlowHint {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecureBootHint {
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BootValueSource {
    #[default]
    Imported,
    Observed,
    Derived,
}
