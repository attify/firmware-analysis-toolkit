mod lifetime;
mod protocol;
mod size;
mod target_adapters;
mod validation;

use std::collections::BTreeMap;

use crate::attempt_generation::{GenerationStrategy, ParamDomain};
use crate::discovery::{BugFamily, DiscoveryLead, TriggerRecipeStep};
use crate::state_machines::select_transition_for_lead;
use crate::target_lanes::{TargetLaneManifest, TargetLaneRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessKind {
    ReentrancyTeardown,
    ShapeStride,
    ProtocolOrder,
    TrustBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ArgTemplate {
    Literal { value: String },
    Binding { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnvTemplate {
    Literal { value: String },
    Binding { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputBinding {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessPlan {
    pub harness_id: String,
    pub kind: HarnessKind,
    pub family: BugFamily,
    pub lane_id: String,
    pub source_root: String,
    pub build_dir: String,
    pub launcher_command: Vec<String>,
    #[serde(default)]
    pub base_command: Vec<String>,
    #[serde(default)]
    pub argv_template: Vec<ArgTemplate>,
    #[serde(default)]
    pub env_template: BTreeMap<String, EnvTemplate>,
    #[serde(default)]
    pub input_bindings: Vec<InputBinding>,
    #[serde(default)]
    pub param_domains: Vec<ParamDomain>,
    #[serde(default)]
    pub generation_strategy: GenerationStrategy,
    pub required_env: std::collections::BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub artifact_dir: String,
    pub sanitizer_mode: String,
    #[serde(default)]
    pub trigger_recipe: Vec<TriggerRecipeStep>,
    #[serde(default)]
    pub expected_proof_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_hypothesis_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_transition_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_transition_summary: Option<String>,
    pub attempt_plan_hash: String,
}

pub fn generate_harness_plans(
    lead: &DiscoveryLead,
    manifest: &TargetLaneManifest,
) -> Vec<HarnessPlan> {
    if lead_is_blocked(lead) {
        return Vec::new();
    }

    match lead.family {
        BugFamily::LifetimeReentrancy => manifest
            .resolve_family(lead.family.as_str())
            .into_iter()
            .filter(|lane| lane_supports_lead(lane, lead))
            .take(1)
            .map(|lane| lifetime::build_plan(lead, lane))
            .collect(),
        BugFamily::SizeStrideArithmetic => manifest
            .resolve_family(lead.family.as_str())
            .into_iter()
            .filter(|lane| lane_supports_lead(lane, lead))
            .take(1)
            .map(|lane| size::build_plan(lead, lane))
            .collect(),
        BugFamily::GpuProtocolOrderLifecycle => manifest
            .resolve_family(lead.family.as_str())
            .into_iter()
            .filter(|lane| lane_supports_lead(lane, lead))
            .take(1)
            .map(|lane| protocol::build_plan(lead, lane))
            .collect(),
        BugFamily::ValidationTrustBoundary => manifest
            .resolve_family(lead.family.as_str())
            .into_iter()
            .filter(|lane| lane_supports_lead(lane, lead))
            .take(1)
            .map(|lane| validation::build_plan(lead, lane))
            .collect(),
    }
}

fn lead_is_blocked(lead: &DiscoveryLead) -> bool {
    matches!(
        lead.candidate_status,
        crate::discovery::CandidateStatus::BlockedByLocality
    )
}

fn lane_supports_lead(lane: &TargetLaneRecord, lead: &DiscoveryLead) -> bool {
    if lead.expected_proof_signal.is_empty() {
        return true;
    }

    lead.expected_proof_signal.iter().any(|signal| {
        lane.proof_class_allowlist
            .iter()
            .any(|allowed| allowed == &signal.kind)
    })
}

fn new_plan(
    lead: &DiscoveryLead,
    lane: &TargetLaneRecord,
    kind: HarnessKind,
    expected_proof_classes: Vec<String>,
) -> HarnessPlan {
    let selected_transition = select_transition_for_lead(lead, &expected_proof_classes);
    let attempt_plan_hash = fingerprint(lead, lane, &kind);
    let forbidden_transition_id = selected_transition
        .as_ref()
        .map(|value| value.transition_id.clone());
    let attempted_transition_summary = selected_transition.as_ref().map(|transition| {
        let mut summary = format!(
            "{}: {}",
            transition.transition_id,
            transition.attempted_transition_summary()
        );
        if let Some(rationale) = transition.rationale.first() {
            summary.push_str(" (");
            summary.push_str(rationale);
            summary.push(')');
        }
        summary
    });
    HarnessPlan {
        harness_id: format!("{}::{}", lane.lane_id, lead.lead_id),
        kind,
        family: lead.family.clone(),
        lane_id: lane.lane_id.clone(),
        source_root: lane.source_root.clone(),
        build_dir: lane.build_dir.clone(),
        launcher_command: lane.launcher_command.clone(),
        base_command: Vec::new(),
        argv_template: Vec::new(),
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: GenerationStrategy::SeedOnly,
        required_env: lane.required_env.clone(),
        timeout_ms: lane.timeout_ms,
        artifact_dir: lane.artifact_dir.clone(),
        sanitizer_mode: lane.sanitizer_mode.clone(),
        trigger_recipe: lead.suggested_trigger_recipe.clone(),
        expected_proof_classes,
        state_hypothesis_id: selected_transition
            .as_ref()
            .map(|value| value.hypothesis_id.clone()),
        forbidden_transition_id,
        attempted_transition_summary,
        attempt_plan_hash,
    }
}

fn fingerprint(lead: &DiscoveryLead, lane: &TargetLaneRecord, kind: &HarnessKind) -> String {
    let mut hasher = Sha256::new();
    hasher.update(lead.lead_id.as_bytes());
    hasher.update(lead.symbol.as_bytes());
    hasher.update(lane.lane_id.as_bytes());
    hasher.update(format!("{kind:?}").as_bytes());
    for step in &lead.suggested_trigger_recipe {
        hasher.update(step.kind.as_bytes());
        hasher.update(step.detail.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
