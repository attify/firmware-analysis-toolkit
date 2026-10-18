//! Static BMC inspection evidence shared by text, JSON, and SARIF presentation.
use crate::{boot_env::BootEnvScan, fit::FitScanReport, layout::LayoutReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcInspectionReport {
    pub schema_version: String,
    pub artifact_path: String,
    pub image_size: u64,
    pub sha256: String,
    pub identity: Vec<BmcIdentityEvidence>,
    pub bootloader_versions: Vec<LocatedMarker>,
    pub layout: LayoutReport,
    pub fit: FitScanReport,
    pub environment_scan: BootEnvScan,
    pub trust_markers: Vec<LocatedMarker>,
    pub findings: Vec<BmcFinding>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcIdentityEvidence {
    pub category: String,
    pub value: String,
    pub offset: u64,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocatedMarker {
    pub kind: String,
    pub name: String,
    pub offset: u64,
    pub length: u64,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcFinding {
    pub rule_id: String,
    pub level: String,
    pub message: String,
    pub offset: u64,
    pub length: u64,
    pub node_path: Option<String>,
}
