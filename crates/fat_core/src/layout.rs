use serde::{Deserialize, Serialize};

use crate::bootloader::MtdPartitionMap;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayoutReport {
    pub summary: LayoutSummary,
    #[serde(default)]
    pub partition_map: Option<MtdPartitionMap>,
    #[serde(default)]
    pub regions: Vec<LayoutRegion>,
    #[serde(default)]
    pub overlaps: Vec<LayoutOverlap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutOverlap {
    pub left_offset: u64,
    pub right_offset: u64,
    pub start_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayoutSummary {
    pub top_level_region_count: usize,
    pub nested_region_count: usize,
    pub dominant_boot_image_offset: Option<u64>,
    pub dominant_rootfs_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutRegion {
    pub offset: u64,
    pub kind: LayoutRegionKind,
    pub format: String,
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncompressed_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_offset: Option<u64>,
    #[serde(default)]
    pub span_is_exact: bool,
    #[serde(default)]
    pub fills_to_eof: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_format: Option<String>,
    pub role: LayoutRegionRole,
    #[serde(default)]
    pub partition: Option<LayoutRegionPartition>,
    pub scope: LayoutRegionScope,
    pub depth: u32,
    pub parent_offset: Option<u64>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutRegionPartition {
    pub mtdblock: u32,
    pub name: String,
    pub flash_offset: u64,
    pub size_bytes: u64,
    pub firmware_offset_delta: i64,
    #[serde(default)]
    pub mount_point: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutRegionKind {
    #[serde(rename = "container")]
    Container,
    #[serde(rename = "boot-image")]
    BootImage,
    #[serde(rename = "compression")]
    Compression,
    #[serde(rename = "filesystem")]
    Filesystem,
    #[serde(rename = "padding")]
    Padding,
}

impl LayoutRegionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutRegionKind::Container => "container",
            LayoutRegionKind::BootImage => "boot-image",
            LayoutRegionKind::Compression => "compression",
            LayoutRegionKind::Filesystem => "filesystem",
            LayoutRegionKind::Padding => "padding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutRegionRole {
    #[serde(rename = "firmware container")]
    FirmwareContainer,
    #[serde(rename = "likely boot image")]
    LikelyBootImage,
    #[serde(rename = "likely kernel payload")]
    LikelyKernelPayload,
    #[serde(rename = "likely rootfs")]
    LikelyRootfs,
    #[serde(rename = "likely app partition")]
    LikelyAppPartition,
    #[serde(rename = "likely compressed payload")]
    LikelyCompressedPayload,
    #[serde(rename = "likely archive tail")]
    LikelyArchiveTail,
    #[serde(rename = "padding")]
    Padding,
    #[serde(rename = "unknown role")]
    UnknownRole,
}

impl LayoutRegionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutRegionRole::FirmwareContainer => "firmware container",
            LayoutRegionRole::LikelyBootImage => "likely boot image",
            LayoutRegionRole::LikelyKernelPayload => "likely kernel payload",
            LayoutRegionRole::LikelyRootfs => "likely rootfs",
            LayoutRegionRole::LikelyAppPartition => "likely app partition",
            LayoutRegionRole::LikelyCompressedPayload => "likely compressed payload",
            LayoutRegionRole::LikelyArchiveTail => "likely archive tail",
            LayoutRegionRole::Padding => "padding",
            LayoutRegionRole::UnknownRole => "unknown role",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutRegionScope {
    #[serde(rename = "top-level")]
    TopLevel,
    #[serde(rename = "nested")]
    Nested,
}

impl LayoutRegionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutRegionScope::TopLevel => "top-level",
            LayoutRegionScope::Nested => "nested",
        }
    }
}
