use fat_core::artifacts::ArtifactKind;
use fat_core::diagnostics::DiagnosticRecord;
use fat_core::finding::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyzerClass {
    Static,
    Runtime,
    CrossRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginTrustTier {
    FirstParty,
    Curated,
    Community,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisTrigger {
    ExtractionCompleted,
    AnalysisRequested,
    RunCompleted,
    RunDegradedCompleted,
    RunFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInputRef {
    pub kind: ArtifactKind,
    pub required: bool,
}

impl ArtifactInputRef {
    pub fn required(kind: ArtifactKind) -> Self {
        Self {
            kind,
            required: true,
        }
    }

    pub fn optional(kind: ArtifactKind) -> Self {
        Self {
            kind,
            required: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDescriptor {
    pub plugin_id: String,
    pub display_name: String,
    pub class: AnalyzerClass,
    pub trust_tier: PluginTrustTier,
    pub supported_triggers: Vec<AnalysisTrigger>,
    pub supported_artifacts: Vec<ArtifactInputRef>,
}

impl PluginDescriptor {
    pub fn new(
        plugin_id: impl Into<String>,
        display_name: impl Into<String>,
        class: AnalyzerClass,
        trust_tier: PluginTrustTier,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            display_name: display_name.into(),
            class,
            trust_tier,
            supported_triggers: Vec::new(),
            supported_artifacts: Vec::new(),
        }
    }

    pub fn with_supported_triggers(mut self, supported_triggers: Vec<AnalysisTrigger>) -> Self {
        self.supported_triggers = supported_triggers;
        self
    }

    pub fn with_supported_artifacts(mut self, supported_artifacts: Vec<ArtifactInputRef>) -> Self {
        self.supported_artifacts = supported_artifacts;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactScope {
    Target,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub kind: ArtifactKind,
    pub scope: ArtifactScope,
}

impl ArtifactRef {
    pub fn new(artifact_id: impl Into<String>, kind: ArtifactKind, scope: ArtifactScope) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            kind,
            scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducedArtifact {
    pub scope: ArtifactScope,
    pub kind: ArtifactKind,
    pub subkind: String,
    pub content_type: String,
    pub text_content: String,
    pub provenance: String,
    pub labels: Vec<String>,
    pub related_artifact_ids: Vec<String>,
}

impl ProducedArtifact {
    pub fn text(
        scope: ArtifactScope,
        kind: ArtifactKind,
        subkind: impl Into<String>,
        content_type: impl Into<String>,
        text_content: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            kind,
            subkind: subkind.into(),
            content_type: content_type.into(),
            text_content: text_content.into(),
            provenance: provenance.into(),
            labels: Vec::new(),
            related_artifact_ids: Vec::new(),
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub trigger: AnalysisTrigger,
    pub project_id: String,
    pub target_id: String,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub artifacts: Vec<ArtifactRef>,
}

impl AnalysisRequest {
    pub fn new(
        trigger: AnalysisTrigger,
        project_id: impl Into<String>,
        target_id: impl Into<String>,
    ) -> Self {
        Self {
            trigger,
            project_id: project_id.into(),
            target_id: target_id.into(),
            session_id: None,
            run_id: None,
            artifacts: Vec::new(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactRef>) -> Self {
        self.artifacts = artifacts;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub produced_artifacts: Vec<ProducedArtifact>,
    pub produced_artifact_ids: Vec<String>,
}

pub trait AnalyzerPlugin: Send + Sync {
    fn descriptor(&self) -> PluginDescriptor;

    fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult;
}
