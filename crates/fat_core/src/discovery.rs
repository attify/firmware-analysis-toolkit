use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryLifecycleStatus {
    Queued,
    Ready,
    Running,
    Completed,
    FailedInfra,
    NeedsReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryOutcomeClass {
    AsanUseAfterFree,
    AsanHeapBufferOverflow,
    UbsanIntegerOverflow,
    GuardTrip,
    BadMessage,
    BlockedByLocality,
    NoSignal,
    Flaky,
}

impl DiscoveryOutcomeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryOutcomeClass::AsanUseAfterFree => "asan-use-after-free",
            DiscoveryOutcomeClass::AsanHeapBufferOverflow => "asan-heap-buffer-overflow",
            DiscoveryOutcomeClass::UbsanIntegerOverflow => "ubsan-integer-overflow",
            DiscoveryOutcomeClass::GuardTrip => "guard-trip",
            DiscoveryOutcomeClass::BadMessage => "bad-message",
            DiscoveryOutcomeClass::BlockedByLocality => "blocked-by-locality",
            DiscoveryOutcomeClass::NoSignal => "no-signal",
            DiscoveryOutcomeClass::Flaky => "flaky",
        }
    }

    pub fn requires_review(&self) -> bool {
        matches!(
            self,
            DiscoveryOutcomeClass::AsanUseAfterFree
                | DiscoveryOutcomeClass::AsanHeapBufferOverflow
                | DiscoveryOutcomeClass::UbsanIntegerOverflow
                | DiscoveryOutcomeClass::GuardTrip
                | DiscoveryOutcomeClass::BadMessage
                | DiscoveryOutcomeClass::Flaky
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryTriggerRecipeStepRecord {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryProofSignalRecord {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForbiddenTransitionRecord {
    pub transition_id: String,
    pub expected_proof_class: String,
    #[serde(default)]
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryStateHypothesisRecord {
    pub hypothesis_id: String,
    pub machine_id: String,
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default)]
    pub active_regions: Vec<String>,
    #[serde(default)]
    pub key_states: Vec<String>,
    #[serde(default)]
    pub ghost_states: Vec<String>,
    #[serde(default)]
    pub invalidating_events: Vec<String>,
    #[serde(default)]
    pub required_guards: Vec<String>,
    #[serde(default)]
    pub forbidden_transitions: Vec<ForbiddenTransitionRecord>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryLeadRecord {
    pub discovery_lead_id: String,
    pub lifecycle: DiscoveryLifecycleStatus,
    pub family: String,
    pub symbol: String,
    #[serde(default)]
    pub family_confidence: f32,
    #[serde(default)]
    pub family_pack_version: String,
    #[serde(default)]
    pub analysis_scope: String,
    #[serde(default)]
    pub candidate_status: String,
    #[serde(default)]
    pub locality: String,
    #[serde(default)]
    pub trigger_recipe: Vec<DiscoveryTriggerRecipeStepRecord>,
    #[serde(default)]
    pub expected_proof_signals: Vec<DiscoveryProofSignalRecord>,
    #[serde(default)]
    pub state_hypotheses: Vec<DiscoveryStateHypothesisRecord>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvesterExpansionRecord {
    pub harvester_expansion_id: String,
    pub lead_id: String,
    pub lifecycle: DiscoveryLifecycleStatus,
    pub attempt_plan_hash: String,
    pub artifact_root: String,
    pub retry_count: u32,
    #[serde(default)]
    pub sibling_fingerprint: Option<String>,
    #[serde(default)]
    pub family_overlap: Vec<String>,
    #[serde(default)]
    pub role_overlap: Vec<String>,
    #[serde(default)]
    pub locality_notes: Vec<String>,
    #[serde(default)]
    pub suppression_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessAttemptRecord {
    pub harness_attempt_id: String,
    pub expansion_id: String,
    pub lifecycle: DiscoveryLifecycleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DiscoveryOutcomeClass>,
    pub attempt_plan_hash: String,
    pub artifact_root: String,
    pub retry_count: u32,
    pub launcher_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_binding_id: Option<String>,
    #[serde(default)]
    pub generated_input_bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub resolved_argv: Vec<String>,
    #[serde(default)]
    pub resolved_env: BTreeMap<String, String>,
    #[serde(default)]
    pub resolved_cwd: String,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_hypothesis_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_transition_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_transition_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageRecord {
    pub triage_id: String,
    pub harness_attempt_id: String,
    pub lifecycle: DiscoveryLifecycleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DiscoveryOutcomeClass>,
    pub attempt_plan_hash: String,
    pub artifact_root: String,
    pub retry_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_hypothesis_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_transition_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_transition_summary: Option<String>,
    pub summary: String,
}
