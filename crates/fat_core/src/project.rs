use serde::{Deserialize, Serialize};

use crate::fingerprint::FirmwareFingerprint;

pub const PROJECT_LAYOUT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLayoutMarker {
    pub layout_version: u32,
}

impl Default for ProjectLayoutMarker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectLayoutMarker {
    pub fn new() -> Self {
        Self {
            layout_version: PROJECT_LAYOUT_VERSION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectStatus {
    Created,
    Extracting,
    Extracted,
    Analyzing,
    Analyzed,
    Emulating,
    Error,
}

impl ProjectStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectStatus::Created => "created",
            ProjectStatus::Extracting => "extracting",
            ProjectStatus::Extracted => "extracted",
            ProjectStatus::Analyzing => "analyzing",
            ProjectStatus::Analyzed => "analyzed",
            ProjectStatus::Emulating => "emulating",
            ProjectStatus::Error => "error",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "created" => Some(ProjectStatus::Created),
            "extracting" => Some(ProjectStatus::Extracting),
            "extracted" => Some(ProjectStatus::Extracted),
            "analyzing" => Some(ProjectStatus::Analyzing),
            "analyzed" => Some(ProjectStatus::Analyzed),
            "emulating" => Some(ProjectStatus::Emulating),
            "error" => Some(ProjectStatus::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub name: String,
    pub firmware_name: String,
    pub status: ProjectStatus,
    pub fingerprint: Option<FirmwareFingerprint>,
}

impl Project {
    pub fn new(name: String, firmware_name: String) -> Self {
        Self {
            name,
            firmware_name,
            status: ProjectStatus::Created,
            fingerprint: None,
        }
    }
}
