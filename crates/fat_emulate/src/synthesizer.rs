use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::ids::stable_prefixed_id;
use fat_core::recipes::RecipeRecord;
use fat_core::rehosting::TargetExecutionProfile;
use fat_core::runs::SubstrateKind;
use fat_core::target_model::TargetModel;
use fat_family::runtime_hints::{runtime_hints_for_family, RuntimeHintActionKind, RuntimeHints};

use crate::strategy::StrategySelection;
use crate::target_profile::{
    build_target_model, profile_context_entries, readiness_goal_debug_features,
    readiness_goal_signature, readiness_goals_for_profile, TargetProfileRequest,
    PROFILE_PROJECT_ID, PROFILE_TARGET_ID,
};

const SYNTHESIS_STRATEGY_VERSION: &str = "fat-emulate-synthesis-slice-1";
const SYNTHESIS_PROJECT_ID: &str = "emulation-project";
static SYNTHESIS_CONTEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SynthesisCategory {
    Mount,
    Overlay,
    ConfigMaterialization,
    DeviceNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaterializationTarget {
    NativeHost,
    DockerEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaterializationAdapter {
    NativeHost,
    DockerEngine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationStepRecord {
    pub adapter: MaterializationAdapter,
    pub category: SynthesisCategory,
    pub path: String,
    pub detail: String,
    pub required: bool,
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationResult {
    pub adapter: MaterializationAdapter,
    pub supported_steps: Vec<MaterializationStepRecord>,
    pub deferred_steps: Vec<MaterializationStepRecord>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesisStep {
    pub category: SynthesisCategory,
    pub path: String,
    pub detail: String,
    pub required: bool,
}

impl SynthesisStep {
    pub fn new(
        category: SynthesisCategory,
        path: impl Into<String>,
        detail: impl Into<String>,
        required: bool,
    ) -> Self {
        Self {
            category,
            path: path.into(),
            detail: detail.into(),
            required,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesisPlan {
    pub steps: Vec<SynthesisStep>,
    pub materialization_targets: Vec<MaterializationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesisContext {
    pub request_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
}

impl SynthesisContext {
    pub fn new(
        request_id: impl Into<String>,
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            project_id: project_id.into(),
            target_id: target_id.into(),
            session_id: session_id.into(),
            run_id: run_id.into(),
        }
    }

    pub fn from_strategy(strategy: &StrategySelection) -> Self {
        let sequence = SYNTHESIS_CONTEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let request_id = stable_prefixed_id(
            "synthreq",
            [
                strategy.request.goal.as_str(),
                strategy.family_id.as_str(),
                strategy.selected.backend_id.as_str(),
                strategy.selected.substrate.as_str(),
                &sequence.to_string(),
                &current_timestamp_string(),
            ],
        );
        let target_id = stable_prefixed_id(
            "synth-target",
            [request_id.as_str(), strategy.selected.backend_id.as_str()],
        );
        let session_id = stable_prefixed_id(
            "synth-session",
            [request_id.as_str(), strategy.family_id.as_str()],
        );
        let run_id = stable_prefixed_id(
            "synth-run",
            [
                request_id.as_str(),
                strategy.selected.backend_id.as_str(),
                strategy.selected.substrate.as_str(),
            ],
        );

        Self::new(
            request_id,
            SYNTHESIS_PROJECT_ID,
            target_id,
            session_id,
            run_id,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SynthesisRequest {
    pub strategy: StrategySelection,
    pub runtime_hints: RuntimeHints,
    pub context: SynthesisContext,
    pub target_model: TargetModel,
    pub profile: TargetExecutionProfile,
    pub readiness_goals: Vec<String>,
}

impl SynthesisRequest {
    pub fn from_strategy(strategy: StrategySelection) -> Self {
        let runtime_hints = runtime_hints_for_family(&strategy.family_id);
        let context = SynthesisContext::from_strategy(&strategy);
        let target_model = build_target_model(&TargetProfileRequest {
            project_id: PROFILE_PROJECT_ID.to_string(),
            target_id: PROFILE_TARGET_ID.to_string(),
            evidence: strategy.request.target_evidence.clone(),
        });
        let profile = target_model.to_execution_profile();
        let readiness_goals = readiness_goals_for_profile(&profile);
        Self {
            strategy,
            runtime_hints,
            context,
            target_model,
            profile,
            readiness_goals,
        }
    }

    pub fn with_context(mut self, context: SynthesisContext) -> Self {
        self.target_model = build_target_model(&TargetProfileRequest {
            project_id: PROFILE_PROJECT_ID.to_string(),
            target_id: PROFILE_TARGET_ID.to_string(),
            evidence: self.strategy.request.target_evidence.clone(),
        });
        self.profile = self.target_model.to_execution_profile();
        self.readiness_goals = readiness_goals_for_profile(&self.profile);
        self.context = context;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SynthesisResult {
    pub request: SynthesisRequest,
    pub target_model: TargetModel,
    pub profile: TargetExecutionProfile,
    pub readiness_goals: Vec<String>,
    pub plan: SynthesisPlan,
    pub recipe: RecipeRecord,
    pub artifacts: Vec<ArtifactRecord>,
    pub materialization: MaterializationResult,
    pub materialization_target: MaterializationTarget,
}

#[derive(Debug)]
pub struct SynthesisEngine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynthesisError {
    SelectedMaterializationTargetUnavailable {
        family_id: String,
        selected: MaterializationTarget,
        available: Vec<MaterializationTarget>,
    },
}

impl Default for SynthesisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SynthesisEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn synthesize(&self, request: SynthesisRequest) -> Result<SynthesisResult, SynthesisError> {
        let materialization_targets = materialization_targets_for_request(&request);
        let plan_steps = steps_from_hints(&request.runtime_hints);
        let selected_target = selected_materialization_target(&request, &materialization_targets)?;
        let adapter = MaterializationAdapter::from_target(selected_target);
        let materialization = adapter.materialize(&plan_steps);

        let mut recipe = RecipeRecord::new(
            request.context.target_id.clone(),
            SYNTHESIS_STRATEGY_VERSION,
            request.strategy.request.goal.clone(),
            request.strategy.selected.backend_id.clone(),
            request.strategy.selected.substrate.as_str().to_string(),
        )
        .with_synthesis_steps(
            plan_steps
                .iter()
                .map(|step| {
                    let kind = match step.category {
                        SynthesisCategory::Mount => "mount",
                        SynthesisCategory::Overlay => "overlay",
                        SynthesisCategory::ConfigMaterialization => "config",
                        SynthesisCategory::DeviceNode => "device-node",
                    };
                    format!("{kind}:{}:{}", step.path, step.detail)
                })
                .collect(),
        )
        .with_resolved_profile_chain(profile_context_entries(&request.profile))
        .with_debug_features(readiness_goal_debug_features(&request.readiness_goals));
        let readiness_signature = readiness_goal_signature(&request.readiness_goals);
        let profile_id = request.profile.profile_id.clone();
        recipe.recipe_id = stable_prefixed_id(
            "recipe",
            [
                request.context.target_id.as_str(),
                SYNTHESIS_STRATEGY_VERSION,
                request.strategy.request.goal.as_str(),
                request.strategy.selected.backend_id.as_str(),
                request.strategy.selected.substrate.as_str(),
                request.context.request_id.as_str(),
                profile_id.as_str(),
                readiness_signature.as_str(),
            ],
        );

        let plan = SynthesisPlan {
            steps: plan_steps,
            materialization_targets: materialization_targets.clone(),
        };

        let mut strategy_artifact = build_artifact(
            &request,
            ArtifactKind::Strategy,
            "synthesis-plan",
            "analysis/strategy/synthesis-plan.json",
            "strategy synthesis plan",
        );
        let strategy_artifact_id = strategy_artifact.artifact_id.clone();

        let mut runtime_input_artifact = build_artifact(
            &request,
            ArtifactKind::RuntimeInput,
            "synthesis-runtime-input",
            "analysis/runtime-input/synthesis.json",
            "runtime input synthesis bundle",
        );
        let runtime_input_artifact_id = runtime_input_artifact.artifact_id.clone();

        strategy_artifact =
            strategy_artifact.with_related_artifact_ids(vec![runtime_input_artifact_id.clone()]);
        runtime_input_artifact =
            runtime_input_artifact.with_related_artifact_ids(vec![strategy_artifact_id]);

        let target_model = request.target_model.clone();
        let profile = request.profile.clone();
        let readiness_goals = request.readiness_goals.clone();

        Ok(SynthesisResult {
            request,
            target_model,
            profile,
            readiness_goals,
            plan,
            recipe,
            artifacts: vec![strategy_artifact, runtime_input_artifact],
            materialization,
            materialization_target: selected_target,
        })
    }
}

fn steps_from_hints(hints: &RuntimeHints) -> Vec<SynthesisStep> {
    let mut steps = Vec::new();

    steps.extend(hints.required_actions.iter().map(action_to_step));
    steps.extend(hints.recommended_actions.iter().map(action_to_step));

    steps
}

fn action_to_step(action: &fat_family::runtime_hints::RuntimeHintAction) -> SynthesisStep {
    let category = match action.kind {
        RuntimeHintActionKind::Mount => SynthesisCategory::Mount,
        RuntimeHintActionKind::Overlay => SynthesisCategory::Overlay,
        RuntimeHintActionKind::ConfigMaterialization => SynthesisCategory::ConfigMaterialization,
        RuntimeHintActionKind::DeviceNode => SynthesisCategory::DeviceNode,
    };

    SynthesisStep::new(category, &action.path, &action.detail, action.required)
}

fn materialization_targets_for_request(request: &SynthesisRequest) -> Vec<MaterializationTarget> {
    let mut targets = request
        .strategy
        .request
        .host_capabilities
        .iter()
        .filter_map(|capability| materialization_target_from_label(capability))
        .collect::<Vec<_>>();

    if targets.is_empty() {
        targets.push(selected_materialization_target_for_substrate(
            request.strategy.selected.substrate,
        ));
    }

    dedup_materialization_targets(targets)
}

fn selected_materialization_target(
    request: &SynthesisRequest,
    materialization_targets: &[MaterializationTarget],
) -> Result<MaterializationTarget, SynthesisError> {
    let selected_target =
        selected_materialization_target_for_substrate(request.strategy.selected.substrate);

    if materialization_targets.contains(&selected_target) {
        Ok(selected_target)
    } else {
        Err(SynthesisError::SelectedMaterializationTargetUnavailable {
            family_id: request.strategy.family_id.clone(),
            selected: selected_target,
            available: materialization_targets.to_vec(),
        })
    }
}

fn selected_materialization_target_for_substrate(
    substrate: SubstrateKind,
) -> MaterializationTarget {
    match substrate {
        SubstrateKind::NativeHost | SubstrateKind::ManagedLinuxVm => {
            MaterializationTarget::NativeHost
        }
        SubstrateKind::DockerEngine => MaterializationTarget::DockerEngine,
    }
}

fn materialization_target_from_label(label: &str) -> Option<MaterializationTarget> {
    match label {
        "native-host" => Some(MaterializationTarget::NativeHost),
        "docker-engine" => Some(MaterializationTarget::DockerEngine),
        _ => None,
    }
}

fn dedup_materialization_targets(
    mut targets: Vec<MaterializationTarget>,
) -> Vec<MaterializationTarget> {
    targets.sort_by_key(|target| match target {
        MaterializationTarget::NativeHost => 0,
        MaterializationTarget::DockerEngine => 1,
    });
    targets.dedup();
    targets
}

fn build_artifact(
    request: &SynthesisRequest,
    kind: ArtifactKind,
    subkind: impl Into<String>,
    path: impl Into<String>,
    provenance: impl Into<String>,
) -> ArtifactRecord {
    let now = current_timestamp_string();
    ArtifactRecord::new(
        request.context.project_id.clone(),
        request.context.target_id.clone(),
        request.context.session_id.clone(),
        request.context.run_id.clone(),
        kind,
        subkind,
        "fat-emulate",
        request.strategy.selected.backend_id.clone(),
        now,
        path,
        "application/json",
        0,
        None,
        provenance,
        ArtifactRetentionPolicy::Session,
    )
    .with_phase("runtime-synthesis")
    .with_backend_driver(request.strategy.selected.backend_id.clone())
    .with_substrate_kind(request.strategy.selected.substrate)
    .with_tool_version(SYNTHESIS_STRATEGY_VERSION)
    .with_labels(vec!["synthesis".to_string()])
}

impl MaterializationAdapter {
    pub fn from_target(target: MaterializationTarget) -> Self {
        match target {
            MaterializationTarget::NativeHost => MaterializationAdapter::NativeHost,
            MaterializationTarget::DockerEngine => MaterializationAdapter::DockerEngine,
        }
    }

    pub fn materialize(self, steps: &[SynthesisStep]) -> MaterializationResult {
        let supported_categories = [
            SynthesisCategory::Mount,
            SynthesisCategory::Overlay,
            SynthesisCategory::ConfigMaterialization,
        ];

        let mut supported_steps = Vec::new();
        let mut deferred_steps = Vec::new();

        for step in steps {
            let record = MaterializationStepRecord {
                adapter: self,
                category: step.category,
                path: step.path.clone(),
                detail: substrate_detail(self, step),
                required: step.required,
                supported: supported_categories.contains(&step.category),
            };

            if record.supported {
                supported_steps.push(record);
            } else {
                deferred_steps.push(record);
            }
        }

        let supported_count = supported_steps.len();
        let deferred_count = deferred_steps.len();

        MaterializationResult {
            adapter: self,
            supported_steps,
            deferred_steps,
            summary: format!(
                "{self:?} materialization: {supported_count} supported steps, {deferred_count} deferred steps"
            ),
        }
    }
}

fn substrate_detail(adapter: MaterializationAdapter, step: &SynthesisStep) -> String {
    let substrate_label = match adapter {
        MaterializationAdapter::NativeHost => "native-host",
        MaterializationAdapter::DockerEngine => "docker-engine",
    };

    let category_label = match step.category {
        SynthesisCategory::Mount => "mount",
        SynthesisCategory::Overlay => "overlay",
        SynthesisCategory::ConfigMaterialization => "config-materialization",
        SynthesisCategory::DeviceNode => "device-node",
    };

    format!("{substrate_label} {category_label}: {}", step.detail)
}

fn current_timestamp_string() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis();
    format!("unix-ms:{millis}")
}
