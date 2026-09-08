use crate::bootplan::{BootArtifact, BootArtifactSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootloaderImage {
    pub family: String,
    pub path: String,
    pub source_path: String,
    pub format: String,
    pub architecture: String,
    pub endianness: Option<String>,
    pub load_address: Option<String>,
    pub entry_address: Option<String>,
    pub container_kind: Option<String>,
    pub provenance: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootloaderCompatibility {
    pub mode: String,
    pub machine: Option<String>,
    pub qemu_binary: Option<String>,
    pub compatible: bool,
    pub confidence: f32,
    pub reasons: Vec<String>,
    pub blocking_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootChainPlan {
    pub mode: String,
    pub bootloader_image: Option<BootloaderImage>,
    pub selected_artifacts: Option<BootArtifactSet>,
    pub kernel: Option<BootArtifact>,
    pub dtb: Option<BootArtifact>,
    pub rootfs: Option<BootArtifact>,
    pub compatibility: Option<BootloaderCompatibility>,
    pub flash_layout: Vec<String>,
    pub storage_layout: Vec<String>,
    pub env_source: Option<String>,
    pub boot_commands: Vec<String>,
    pub rejection_reason: Option<String>,
}
