use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedFilesystemTree {
    pub role: String,
    pub path: PathBuf,
    pub tree_kind: String,
}

/// What an extraction engine did with the image. `Skipped` always carries the
/// reason it was not attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineStatus {
    Succeeded,
    Failed,
    Skipped,
}

impl EngineStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// One engine's contribution to an extraction, recorded so that "what extracted
/// this?" is answerable from the manifest instead of by reading `work/*.log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineReport {
    pub engine: String,
    pub status: EngineStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl EngineReport {
    pub fn new(engine: impl Into<String>, status: EngineStatus) -> Self {
        Self {
            engine: engine.into(),
            status,
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// `binwalk: succeeded (carved a rootfs)`
    pub fn summary_line(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{}: {} ({detail})", self.engine, self.status.label()),
            None => format!("{}: {}", self.engine, self.status.label()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExtractionManifest {
    #[serde(default)]
    pub artifacts: Vec<crate::pipeline::ArtifactRecord>,
    #[serde(default)]
    pub recovery_status: Option<String>,
    pub rootfs_path: Option<PathBuf>,
    pub kernel_paths: Vec<PathBuf>,
    pub file_count: usize,
    #[serde(default)]
    pub filesystem_trees: Vec<ExtractedFilesystemTree>,
    /// Engine whose output the manifest was built from. `None` on manifests
    /// written before provenance was recorded.
    #[serde(default)]
    pub engine: Option<String>,
    /// Version of the winning engine, as it reported itself at extraction time.
    /// Recorded so reproducing a run does not depend on reading logs or on the
    /// version installed today.
    #[serde(default)]
    pub engine_version: Option<String>,
    /// Exact arguments the winning engine was invoked with.
    #[serde(default)]
    pub engine_args: Vec<String>,
    /// Every engine considered for this extraction, in the order it was
    /// considered.
    #[serde(default)]
    pub engine_reports: Vec<EngineReport>,
}
