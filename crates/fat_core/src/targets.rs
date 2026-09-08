use serde::{Deserialize, Serialize};

use crate::artifacts::{ArtifactHashes, ArtifactKind, ArtifactRetentionPolicy};
use crate::ids::stable_prefixed_id;

pub fn derive_target_id(project_id: &str, firmware_name: &str) -> String {
    stable_prefixed_id("target", [project_id, firmware_name])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRecord {
    pub target_id: String,
    pub project_id: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl TargetRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        display_name: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let display_name = display_name.into();
        let created_at = created_at.into();

        Self {
            target_id,
            project_id,
            display_name,
            created_at: created_at.clone(),
            updated_at: created_at,
        }
    }

    pub fn touch(mut self, updated_at: impl Into<String>) -> Self {
        self.updated_at = updated_at.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetArtifactRecord {
    pub artifact_id: String,
    pub project_id: String,
    pub target_id: String,
    pub kind: ArtifactKind,
    pub subkind: String,
    pub producer_type: String,
    pub producer_id: String,
    pub created_at: String,
    pub path: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub hashes: Option<ArtifactHashes>,
    pub provenance: String,
    pub retention_policy: ArtifactRetentionPolicy,
    pub phase: Option<String>,
    pub tool_version: Option<String>,
    pub labels: Vec<String>,
    pub related_artifact_ids: Vec<String>,
}

impl TargetArtifactRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        kind: ArtifactKind,
        subkind: impl Into<String>,
        producer_type: impl Into<String>,
        producer_id: impl Into<String>,
        created_at: impl Into<String>,
        path: impl Into<String>,
        content_type: impl Into<String>,
        size_bytes: u64,
        hashes: Option<ArtifactHashes>,
        provenance: impl Into<String>,
        retention_policy: ArtifactRetentionPolicy,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let subkind = subkind.into();
        let producer_type = producer_type.into();
        let producer_id = producer_id.into();
        let created_at = created_at.into();
        let path = path.into();
        let content_type = content_type.into();
        let provenance = provenance.into();
        let artifact_id = stable_prefixed_id(
            "tart",
            [
                project_id.as_str(),
                target_id.as_str(),
                kind.as_str(),
                subkind.as_str(),
                path.as_str(),
            ],
        );

        Self {
            artifact_id,
            project_id,
            target_id,
            kind,
            subkind,
            producer_type,
            producer_id,
            created_at,
            path,
            content_type,
            size_bytes,
            hashes,
            provenance,
            retention_policy,
            phase: None,
            tool_version: None,
            labels: Vec::new(),
            related_artifact_ids: Vec::new(),
        }
    }

    pub fn with_phase(mut self, phase: impl Into<String>) -> Self {
        self.phase = Some(phase.into());
        self
    }

    pub fn with_tool_version(mut self, tool_version: impl Into<String>) -> Self {
        self.tool_version = Some(tool_version.into());
        self
    }

    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_related_artifact_ids(mut self, related_artifact_ids: Vec<String>) -> Self {
        self.related_artifact_ids = related_artifact_ids;
        self
    }
}
