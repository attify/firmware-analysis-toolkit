use fat_core::ids::stable_prefixed_id;
use fat_core::recipes::RecipeRecord;
use fat_core::rehosting::TargetExecutionProfile;
use fat_core::rehosting_policy::{
    FallbackReason, SelectionTrace, SubstrateAttempt, SubstrateAttemptState, SubstratePreference,
};
use fat_core::rehosting_recipe::{RecipeLaunchPlan, RecipeValidator, RehostingRecipe};
use fat_core::runs::{
    GoalProgressDelta, RunOrigin, RunRecord, RunStatus, RuntimeEndpoint, RuntimeEndpointKind,
    SubstrateKind,
};
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};
use fat_core::target_model::TargetModel;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::run::EmulationRun;
use crate::session::EmulationSession;
use crate::strategy::{
    EmulationAutomationMode, PriorRunSummary, StrategyEngine, StrategyError, StrategyRequest,
    StrategySelection,
};
use crate::target_profile::{
    build_target_model, profile_context_entries, readiness_goal_debug_features,
    readiness_goal_signature, readiness_goals_for_profile, TargetProfileRequest,
    PROFILE_PROJECT_ID, PROFILE_TARGET_ID,
};

const EMULATION_PROJECT_ID: &str = "emulation-project";
const EMULATION_TARGET_ID: &str = "emulation-target";
const EMULATION_STRATEGY_FAMILY: &str = "fat-emulate";
const STRATEGY_VERSION: &str = "fat-emulate-slice-1";
const GOAL: &str = "emulate firmware";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationPlanError {
    UnsupportedBackend { backend_id: String },
}

impl std::fmt::Display for EmulationPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmulationPlanError::UnsupportedBackend { backend_id } => {
                write!(
                    f,
                    "unsupported backend for emulation planning: {backend_id}"
                )
            }
        }
    }
}

impl std::error::Error for EmulationPlanError {}

#[derive(Debug, Clone, PartialEq)]
pub struct EmulationPlan {
    pub requested_session_id: String,
    pub strategy: StrategySelection,
    pub target_model: TargetModel,
    pub profile: TargetExecutionProfile,
    pub readiness_goals: Vec<String>,
    pub rehosting_recipe: RehostingRecipe,
    pub selection_trace: SelectionTrace,
    pub recipe: RecipeRecord,
    pub session: SessionRecord,
    pub run: EmulationRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulationBundleRequest {
    pub session_id: String,
    pub mapped_ports: Vec<u16>,
    pub target_evidence: Vec<String>,
    pub host_capabilities: Vec<String>,
    pub prior_runs: Vec<PriorRunSummary>,
    pub substrate_preference: SubstratePreference,
    pub requested_backend: Option<String>,
    pub requested_substrate: Option<String>,
    pub automation_mode: EmulationAutomationMode,
}

impl EmulationBundleRequest {
    pub fn new(session_id: impl Into<String>, mapped_ports: Vec<u16>) -> Self {
        Self {
            session_id: session_id.into(),
            mapped_ports,
            target_evidence: Vec::new(),
            host_capabilities: Vec::new(),
            prior_runs: Vec::new(),
            substrate_preference: SubstratePreference::Auto,
            requested_backend: None,
            requested_substrate: None,
            automation_mode: EmulationAutomationMode::SuggestOnly,
        }
    }

    pub fn with_target_evidence(mut self, target_evidence: Vec<String>) -> Self {
        self.target_evidence = target_evidence;
        self
    }

    pub fn with_host_capabilities(mut self, host_capabilities: Vec<String>) -> Self {
        self.host_capabilities = host_capabilities;
        self
    }

    pub fn with_prior_runs(mut self, prior_runs: Vec<PriorRunSummary>) -> Self {
        self.prior_runs = prior_runs;
        self
    }

    pub fn with_substrate_preference(mut self, substrate_preference: SubstratePreference) -> Self {
        self.substrate_preference = substrate_preference;
        self
    }

    pub fn with_requested_backend(mut self, requested_backend: impl Into<String>) -> Self {
        self.requested_backend = Some(requested_backend.into());
        self
    }

    pub fn with_requested_substrate(mut self, requested_substrate: impl Into<String>) -> Self {
        self.requested_substrate = Some(requested_substrate.into());
        self
    }

    pub fn with_automation_mode(mut self, automation_mode: EmulationAutomationMode) -> Self {
        self.automation_mode = automation_mode;
        self
    }
}

pub fn create_emulation_bundle(
    session_id: impl Into<String>,
    backend_id: impl Into<String>,
    mapped_ports: Vec<u16>,
) -> Result<EmulationPlan, EmulationPlanError> {
    let session_id = session_id.into();
    let backend_id = backend_id.into();
    let substrate_kind = substrate_kind_for_backend(&backend_id)?;
    let request = EmulationBundleRequest::new(session_id, mapped_ports)
        .with_host_capabilities(vec![substrate_kind.as_str().to_string()])
        .with_requested_backend(backend_id)
        .with_requested_substrate(substrate_kind.as_str().to_string())
        .with_automation_mode(EmulationAutomationMode::AutoSafe);
    create_emulation_bundle_from_request(request)
}

pub fn create_emulation_bundle_from_request(
    request: EmulationBundleRequest,
) -> Result<EmulationPlan, EmulationPlanError> {
    let requested_session_id = request.session_id.clone();
    let ports_signature = ports_signature(&request.mapped_ports);
    let mut strategy_request = StrategyRequest::new(
        GOAL,
        request.target_evidence.clone(),
        request.host_capabilities.clone(),
        request.prior_runs.clone(),
    )
    .with_substrate_preference(request.substrate_preference)
    .with_automation_mode(request.automation_mode);
    if let Some(requested_backend) = request.requested_backend.clone() {
        strategy_request = strategy_request.with_requested_backend(requested_backend);
    }
    if let Some(requested_substrate) = request.requested_substrate.clone() {
        strategy_request = strategy_request.with_requested_substrate(requested_substrate);
    }
    let strategy = StrategyEngine::new(fat_backend::BackendRegistry::with_test_backends())
        .select(strategy_request)
        .map_err(|err| match err {
            StrategyError::RequestedBackendUnavailable { backend_id } => {
                EmulationPlanError::UnsupportedBackend { backend_id }
            }
            StrategyError::NoViableCandidates { goal, family_id } => {
                EmulationPlanError::UnsupportedBackend {
                    backend_id: format!("{goal}:{family_id}"),
                }
            }
        })?;
    let selected_backend = strategy.selected.backend_id.clone();
    let selected_substrate = strategy.selected.substrate.as_str().to_string();
    let target_model = build_target_model(&TargetProfileRequest {
        project_id: PROFILE_PROJECT_ID.to_string(),
        target_id: PROFILE_TARGET_ID.to_string(),
        evidence: request.target_evidence.clone(),
    });
    let profile = target_model.to_execution_profile();
    let readiness_goals = readiness_goals_for_profile(&profile);
    let readiness_signature = readiness_goal_signature(&readiness_goals);
    let launch_parameters = build_launch_parameters(&selected_backend, &request.mapped_ports);
    let created_at = current_created_at();

    let mut recipe = RecipeRecord::new(
        EMULATION_TARGET_ID,
        STRATEGY_VERSION,
        GOAL,
        selected_backend.clone(),
        selected_substrate,
    )
    .with_launch_parameters(launch_parameters);
    recipe = recipe
        .with_resolved_profile_chain(profile_context_entries(&profile))
        .with_debug_features(readiness_goal_debug_features(&readiness_goals));
    recipe.recipe_id = stable_prefixed_id(
        "recipe",
        [
            EMULATION_TARGET_ID,
            STRATEGY_VERSION,
            GOAL,
            selected_backend.as_str(),
            recipe.selected_substrate.as_str(),
            requested_session_id.as_str(),
            ports_signature.as_str(),
            profile.profile_id.as_str(),
            readiness_signature.as_str(),
        ],
    );

    let mut session = SessionRecord::new(
        EMULATION_PROJECT_ID,
        EMULATION_TARGET_ID,
        GOAL,
        EMULATION_STRATEGY_FAMILY,
        SessionOrigin::Automatic,
        created_at,
    )
    .with_requested_session_id(requested_session_id.clone())
    .with_status(SessionStatus::Planned)
    .with_progress(GoalProgress::NotStarted);
    session.session_id = stable_prefixed_id(
        "sess",
        [
            EMULATION_PROJECT_ID,
            EMULATION_TARGET_ID,
            GOAL,
            EMULATION_STRATEGY_FAMILY,
            requested_session_id.as_str(),
            selected_backend.as_str(),
            ports_signature.as_str(),
        ],
    );

    let active_endpoints = runtime_endpoints_from_ports(&request.mapped_ports);
    let run = EmulationRun::new(
        RunRecord::new(
            &session.session_id,
            &recipe.recipe_id,
            selected_backend.clone(),
            strategy.selected.substrate,
            1,
            RunOrigin::Automatic,
        )
        .with_status(RunStatus::Created)
        .with_goal_progress_delta(GoalProgressDelta::new(
            GoalProgress::NotStarted,
            GoalProgress::NotStarted,
        ))
        .with_active_endpoints(active_endpoints),
    );

    let session = session.with_run_ids(vec![run.record.run_id.clone()]);
    let selected_logical_substrate = strategy.selected.logical_substrate;
    let mut rehosting_recipe = RehostingRecipe::new(
        EMULATION_TARGET_ID,
        target_model.model_id.clone(),
        run.record.run_id.clone(),
        GOAL,
        SubstratePreference::Auto,
        selected_logical_substrate,
    )
    .with_retry_budget(default_retry_budget(selected_logical_substrate))
    .with_selected_backend(selected_backend.clone())
    .with_validators(
        readiness_goals
            .iter()
            .map(|goal| RecipeValidator::new(goal.clone(), "goal"))
            .collect(),
    );
    if let Some(launch_plan) = default_launch_plan(selected_logical_substrate, &target_model) {
        rehosting_recipe = rehosting_recipe.with_launch_plan(launch_plan);
    }
    let selection_attempts = strategy
        .request
        .substrate_preference
        .default_order()
        .into_iter()
        .map(|substrate| {
            if substrate == selected_logical_substrate {
                let mut attempt = SubstrateAttempt::new(substrate, SubstrateAttemptState::Selected);
                if strategy.request.requested_backend.is_some() {
                    attempt = attempt.with_reason(FallbackReason::ExplicitRequest);
                }
                attempt.with_detail(format!(
                    "selected backend={} substrate={}",
                    strategy.selected.backend_id,
                    strategy.selected.substrate.as_str()
                ))
            } else if strategy
                .candidates
                .iter()
                .any(|candidate| candidate.logical_substrate == substrate)
            {
                SubstrateAttempt::new(substrate, SubstrateAttemptState::Considered)
                    .with_detail("candidate available but not selected")
            } else {
                SubstrateAttempt::new(substrate, SubstrateAttemptState::Unavailable)
                    .with_reason(FallbackReason::Unavailable)
                    .with_detail("no viable candidate matched current constraints")
            }
        })
        .collect();

    let selection_trace = SelectionTrace::new(
        EMULATION_PROJECT_ID,
        EMULATION_TARGET_ID,
        session.session_id.clone(),
        run.record.run_id.clone(),
    )
    .with_preference(strategy.request.substrate_preference)
    .with_attempts(selection_attempts);

    Ok(EmulationPlan {
        requested_session_id,
        strategy,
        target_model,
        profile,
        readiness_goals,
        rehosting_recipe,
        selection_trace,
        recipe,
        session,
        run,
    })
}

impl EmulationPlan {
    pub fn new(
        session_id: impl Into<String>,
        backend_id: impl Into<String>,
        mapped_ports: Vec<u16>,
    ) -> Result<Self, EmulationPlanError> {
        create_emulation_bundle(session_id, backend_id, mapped_ports)
    }

    pub fn launch(self) -> EmulationSession {
        let session = self.session.with_status(SessionStatus::Active);
        let run = self.run.queued();
        EmulationSession::new(self.requested_session_id, session, run)
    }

    pub fn recipe_record(&self) -> &RecipeRecord {
        &self.recipe
    }

    pub fn session_record(&self) -> &SessionRecord {
        &self.session
    }

    pub fn run_record(&self) -> &RunRecord {
        &self.run.record
    }
}

fn build_launch_parameters(backend_id: &str, mapped_ports: &[u16]) -> Vec<String> {
    let mut launch_parameters = Vec::with_capacity(mapped_ports.len() + 1);
    launch_parameters.push(format!("backend={backend_id}"));
    launch_parameters.extend(mapped_ports.iter().map(|port| format!("port={port}")));
    launch_parameters
}

fn ports_signature(mapped_ports: &[u16]) -> String {
    if mapped_ports.is_empty() {
        return "no-ports".to_string();
    }

    mapped_ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn runtime_endpoints_from_ports(mapped_ports: &[u16]) -> Vec<RuntimeEndpoint> {
    mapped_ports
        .iter()
        .map(|port| {
            RuntimeEndpoint::new(
                RuntimeEndpointKind::PortForward,
                format!("port-{port}"),
                "127.0.0.1",
                *port,
            )
            .with_target_port(*port)
        })
        .collect()
}

fn current_created_at() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis();
    format!("unix-ms:{millis}")
}

fn substrate_kind_for_backend(backend_id: &str) -> Result<SubstrateKind, EmulationPlanError> {
    match backend_id {
        "qemu-direct" | "native-host" => Ok(SubstrateKind::NativeHost),
        "managed-linux-vm" => Ok(SubstrateKind::ManagedLinuxVm),
        "firmae" | "firmadyne" => Ok(SubstrateKind::ManagedLinuxVm),
        "emux" | "renode" | "docker" | "docker-native" => Ok(SubstrateKind::DockerEngine),
        other => Err(EmulationPlanError::UnsupportedBackend {
            backend_id: other.to_string(),
        }),
    }
}

fn default_retry_budget(
    selected_logical_substrate: fat_core::rehosting_policy::SubstrateKind,
) -> u32 {
    match selected_logical_substrate {
        fat_core::rehosting_policy::SubstrateKind::Service => 3,
        fat_core::rehosting_policy::SubstrateKind::System => 5,
        fat_core::rehosting_policy::SubstrateKind::Reference => 4,
    }
}

fn default_launch_plan(
    selected_logical_substrate: fat_core::rehosting_policy::SubstrateKind,
    target_model: &TargetModel,
) -> Option<RecipeLaunchPlan> {
    match selected_logical_substrate {
        fat_core::rehosting_policy::SubstrateKind::Service => target_model
            .service_candidates
            .first()
            .map(|candidate| RecipeLaunchPlan::new(candidate.path.clone(), Vec::new())),
        fat_core::rehosting_policy::SubstrateKind::System => target_model
            .init_candidates
            .first()
            .map(|candidate| RecipeLaunchPlan::new(candidate.path.clone(), Vec::new())),
        fat_core::rehosting_policy::SubstrateKind::Reference => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emux_planning_uses_the_docker_engine_substrate() {
        let plan = create_emulation_bundle("emux-session", "emux", vec![80, 443])
            .expect("emux should be selectable for planning");

        assert_eq!(plan.run.record.backend_driver, "emux");
        assert_eq!(plan.run.record.substrate_kind, SubstrateKind::DockerEngine);
        assert_eq!(plan.recipe.selected_backend, "emux");
    }
}
