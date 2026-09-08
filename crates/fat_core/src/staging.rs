use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StagingStrategy {
    MutableOverlay,
    CopyOnWriteImage,
    ReferenceWorkspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingMutation {
    pub mutation_kind: String,
    pub source: Option<String>,
    pub destination: String,
    pub detail: Option<String>,
}

impl StagingMutation {
    pub fn new(
        mutation_kind: impl Into<String>,
        source: Option<impl Into<String>>,
        destination: impl Into<String>,
    ) -> Self {
        Self {
            mutation_kind: mutation_kind.into(),
            source: source.map(|value| value.into()),
            destination: destination.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingManifest {
    pub staging_manifest_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub logical_substrate: String,
    pub strategy: StagingStrategy,
    pub source_root: String,
    pub staging_root: String,
    pub generated_artifacts: Vec<String>,
    pub mutations: Vec<StagingMutation>,
}

impl StagingManifest {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        logical_substrate: impl Into<String>,
        strategy: StagingStrategy,
        source_root: impl Into<String>,
        staging_root: impl Into<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let logical_substrate = logical_substrate.into();
        let source_root = source_root.into();
        let staging_root = staging_root.into();
        let staging_manifest_id = stable_prefixed_id(
            "staging",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                logical_substrate.as_str(),
                strategy.as_str(),
                source_root.as_str(),
                staging_root.as_str(),
            ],
        );

        Self {
            staging_manifest_id,
            project_id,
            target_id,
            session_id,
            run_id,
            logical_substrate,
            strategy,
            source_root,
            staging_root,
            generated_artifacts: Vec::new(),
            mutations: Vec::new(),
        }
    }

    pub fn with_generated_artifacts(mut self, generated_artifacts: Vec<String>) -> Self {
        self.generated_artifacts = generated_artifacts;
        self
    }

    pub fn with_mutations(mut self, mutations: Vec<StagingMutation>) -> Self {
        self.mutations = mutations;
        self
    }
}

impl StagingStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            StagingStrategy::MutableOverlay => "mutable-overlay",
            StagingStrategy::CopyOnWriteImage => "copy-on-write-image",
            StagingStrategy::ReferenceWorkspace => "reference-workspace",
        }
    }
}
