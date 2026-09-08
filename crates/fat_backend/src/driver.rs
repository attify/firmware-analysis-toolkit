use crate::substrate::{BackendSubstrateContract, BackendSubstrateKind};
use crate::traits::BackendCapability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendDriverPhase {
    Suitability,
    Provisioning,
    Preparation,
    Execution,
    Observation,
    Diagnostics,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendDriverContract {
    pub backend_id: String,
    pub display_name: String,
    pub capability: BackendCapability,
    pub phases: Vec<BackendDriverPhase>,
    pub supported_substrates: Vec<BackendSubstrateKind>,
    pub substrates: Vec<BackendSubstrateContract>,
}
