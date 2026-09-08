use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;
use crate::runs::SubstrateKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    Source,
    Extraction,
    Strategy,
    RuntimeInput,
    RuntimeLog,
    RuntimeState,
    RuntimeDebug,
    RuntimeCapture,
    Analysis,
    DiagnosticSupport,
    Diff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRetentionPolicy {
    Ephemeral,
    Session,
    Project,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ArtifactHashes {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
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
    pub backend_driver: Option<String>,
    pub substrate_kind: Option<SubstrateKind>,
    pub tool_version: Option<String>,
    pub labels: Vec<String>,
    pub related_artifact_ids: Vec<String>,
}

impl ArtifactRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
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
        let session_id = session_id.into();
        let run_id = run_id.into();
        let subkind = subkind.into();
        let producer_type = producer_type.into();
        let producer_id = producer_id.into();
        let created_at = created_at.into();
        let path = path.into();
        let content_type = content_type.into();
        let provenance = provenance.into();
        let artifact_id = stable_prefixed_id(
            "art",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                kind.as_str(),
                subkind.as_str(),
                path.as_str(),
            ],
        );

        Self {
            artifact_id,
            project_id,
            target_id,
            session_id,
            run_id,
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
            backend_driver: None,
            substrate_kind: None,
            tool_version: None,
            labels: Vec::new(),
            related_artifact_ids: Vec::new(),
        }
    }

    pub fn with_created_at(mut self, created_at: impl Into<String>) -> Self {
        self.created_at = created_at.into();
        self
    }

    pub fn with_phase(mut self, phase: impl Into<String>) -> Self {
        self.phase = Some(phase.into());
        self
    }

    pub fn with_backend_driver(mut self, backend_driver: impl Into<String>) -> Self {
        self.backend_driver = Some(backend_driver.into());
        self
    }

    pub fn with_substrate_kind(mut self, substrate_kind: SubstrateKind) -> Self {
        self.substrate_kind = Some(substrate_kind);
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

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Source => "source",
            ArtifactKind::Extraction => "extraction",
            ArtifactKind::Strategy => "strategy",
            ArtifactKind::RuntimeInput => "runtime-input",
            ArtifactKind::RuntimeLog => "runtime-log",
            ArtifactKind::RuntimeState => "runtime-state",
            ArtifactKind::RuntimeDebug => "runtime-debug",
            ArtifactKind::RuntimeCapture => "runtime-capture",
            ArtifactKind::Analysis => "analysis",
            ArtifactKind::DiagnosticSupport => "diagnostic-support",
            ArtifactKind::Diff => "diff",
        }
    }
}
