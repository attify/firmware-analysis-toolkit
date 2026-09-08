mod lifetime;
mod protocol;
mod size;
mod validation;

use crate::discovery::BugFamily;
use crate::result::{DerivedAnalysis, FusedSourceEvidence, RollResolution};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvestedCandidate {
    pub symbol: String,
    pub family: BugFamily,
    pub score: i32,
    pub fingerprint: String,
    #[serde(default)]
    pub role_overlap: Vec<String>,
    #[serde(default)]
    pub family_overlap: Vec<String>,
    #[serde(default)]
    pub locality_notes: Vec<String>,
    #[serde(default)]
    pub suppression_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HarvestReport {
    #[serde(default)]
    pub emitted: Vec<HarvestedCandidate>,
    #[serde(default)]
    pub suppressed: Vec<HarvestedCandidate>,
}

pub fn harvest_family_candidates(
    family: BugFamily,
    fused: &FusedSourceEvidence,
    derived: &DerivedAnalysis,
    locality: &RollResolution,
) -> HarvestReport {
    match family {
        BugFamily::LifetimeReentrancy => lifetime::harvest(fused, derived, locality),
        BugFamily::SizeStrideArithmetic => size::harvest(fused, derived, locality),
        BugFamily::GpuProtocolOrderLifecycle => protocol::harvest(fused, derived, locality),
        BugFamily::ValidationTrustBoundary => validation::harvest(fused, derived, locality),
    }
}
