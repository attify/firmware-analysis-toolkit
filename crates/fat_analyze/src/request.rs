use fat_core::artifacts::ArtifactKind;
use fat_core::diagnostics::DiagnosticRecord;
use fat_core::inventory::AnalysisSnapshot;
use fat_plugin_api::{AnalysisRequest, ArtifactRef, ArtifactScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDocument {
    pub artifact_id: String,
    pub kind: ArtifactKind,
    pub scope: ArtifactScope,
    pub subkind: String,
    pub rel_path: Option<String>,
    pub content_type: String,
    pub text_content: Option<String>,
}

impl ArtifactDocument {
    pub fn new(
        artifact_id: impl Into<String>,
        kind: ArtifactKind,
        scope: ArtifactScope,
        subkind: impl Into<String>,
        rel_path: Option<String>,
        content_type: impl Into<String>,
        text_content: Option<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            kind,
            scope,
            subkind: subkind.into(),
            rel_path,
            content_type: content_type.into(),
            text_content,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAnalysisRequest {
    pub request: AnalysisRequest,
    pub snapshot: Option<AnalysisSnapshot>,
    pub artifact_documents: Vec<ArtifactDocument>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub historical_diagnostics: Vec<DiagnosticRecord>,
}

impl NormalizedAnalysisRequest {
    pub fn new(
        trigger: fat_plugin_api::AnalysisTrigger,
        project_id: impl Into<String>,
        target_id: impl Into<String>,
    ) -> Self {
        Self {
            request: AnalysisRequest::new(trigger, project_id, target_id),
            snapshot: None,
            artifact_documents: Vec::new(),
            diagnostics: Vec::new(),
            historical_diagnostics: Vec::new(),
        }
    }

    pub fn for_snapshot(snapshot: AnalysisSnapshot) -> Self {
        Self::new(
            fat_plugin_api::AnalysisTrigger::AnalysisRequested,
            "snapshot-project",
            "snapshot-target",
        )
        .with_snapshot(snapshot)
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.request = self.request.with_session_id(session_id);
        self
    }

    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.request = self.request.with_run_id(run_id);
        self
    }

    pub fn with_artifact_ids(mut self, artifact_ids: Vec<String>) -> Self {
        self.request = self.request.with_artifacts(
            artifact_ids
                .into_iter()
                .map(|artifact_id| {
                    ArtifactRef::new(
                        artifact_id,
                        fat_core::artifacts::ArtifactKind::Analysis,
                        ArtifactScope::Target,
                    )
                })
                .collect(),
        );
        self
    }

    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactRef>) -> Self {
        self.request = self.request.with_artifacts(artifacts);
        self
    }

    pub fn with_snapshot(mut self, snapshot: AnalysisSnapshot) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    pub fn with_artifact_documents(mut self, artifact_documents: Vec<ArtifactDocument>) -> Self {
        self.artifact_documents = artifact_documents;
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<DiagnosticRecord>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn with_historical_diagnostics(
        mut self,
        historical_diagnostics: Vec<DiagnosticRecord>,
    ) -> Self {
        self.historical_diagnostics = historical_diagnostics;
        self
    }
}
