use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSubject {
    Binary { binary_id: String },
    File { rel_path: String },
    Bootloader { family: String },
    Project,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub subject: FindingSubject,
    #[serde(default)]
    pub plugin_id: Option<String>,
    #[serde(default)]
    pub evidence_artifact_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: FindingSeverity,
        subject: FindingSubject,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            severity,
            subject,
            plugin_id: None,
            evidence_artifact_ids: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_plugin_id(mut self, plugin_id: impl Into<String>) -> Self {
        self.plugin_id = Some(plugin_id.into());
        self
    }

    pub fn with_evidence_artifact_ids(mut self, evidence_artifact_ids: Vec<String>) -> Self {
        self.evidence_artifact_ids = evidence_artifact_ids;
        self
    }

    pub fn with_metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }
}
