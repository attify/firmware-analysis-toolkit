use crate::target_detection::TargetKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterFamily {
    Source,
    BinaryStructural,
    BinaryFlow,
    BundleMetadata,
    RuntimePlane,
    RuntimeObservation,
    PatchDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryKind {
    Path,
    Slice,
    Invariant,
    PatchInvariant,
    Chain,
    RuntimeVerify,
    LauncherClassification,
    HandoffInspection,
    BundleReality,
    RuntimePlane,
    AuthorityMap,
    RoleDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRequest {
    pub kind: QueryKind,
}

impl QueryRequest {
    pub fn new(kind: QueryKind) -> Self {
        Self { kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    Triage,
    Deep,
}

impl ExecutionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionMode::Triage => "triage",
            ExecutionMode::Deep => "deep",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceLanguageFamily {
    CLike,
    ObjectiveC,
    ObjectiveCpp,
    Rust,
    Python,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterDescriptor {
    pub id: &'static str,
    pub family: AdapterFamily,
    pub target_kinds: Vec<TargetKind>,
    pub query_kinds: Vec<QueryKind>,
    pub confidence_rank: u8,
    pub supported_extensions: Vec<&'static str>,
    pub language_families: Vec<SourceLanguageFamily>,
    pub modes: Vec<ExecutionMode>,
    pub authoritative: bool,
}

impl AdapterDescriptor {
    pub fn supports(&self, target_kind: &TargetKind, query_kind: &QueryKind) -> bool {
        self.target_kinds.contains(target_kind) && self.query_kinds.contains(query_kind)
    }
}
