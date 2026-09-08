use std::fmt::Debug;

use crate::driver::BackendDriverContract;

#[derive(Debug, Clone, PartialEq)]
pub enum BackendKind {
    Native,
    LegacyAdapter,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendAdapterMetadata {
    pub wrapper_id: String,
    pub legacy_behavior: String,
    pub wrapped_backend: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FamilyMatch {
    pub family_id: String,
    pub score: f32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendCapability {
    pub supported_architectures: Vec<String>,
    pub family_matches: Vec<FamilyMatch>,
    pub backend_kind: BackendKind,
    pub adapter: Option<BackendAdapterMetadata>,
}

pub trait Backend: Debug + Send + Sync {
    fn backend_id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn capability(&self) -> &BackendCapability;
    fn driver_contract(&self) -> &BackendDriverContract;

    fn score_family(&self, family_id: &str) -> Option<f32> {
        self.capability()
            .family_matches
            .iter()
            .find(|candidate| candidate.family_id == family_id)
            .map(|candidate| candidate.score)
    }
}
