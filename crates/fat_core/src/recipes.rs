use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackPolicy {
    RetrySame,
    RetryWithFallback,
    ManualIntervention,
    DoNotRetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeRecord {
    pub recipe_id: String,
    pub target_id: String,
    pub strategy_version: String,
    pub goal: String,
    pub selected_backend: String,
    pub selected_substrate: String,
    pub resolved_profile_chain: Vec<String>,
    pub synthesis_steps: Vec<String>,
    pub debug_features: Vec<String>,
    pub launch_parameters: Vec<String>,
    pub fallback_policy: FallbackPolicy,
}

impl RecipeRecord {
    pub fn new(
        target_id: impl Into<String>,
        strategy_version: impl Into<String>,
        goal: impl Into<String>,
        selected_backend: impl Into<String>,
        selected_substrate: impl Into<String>,
    ) -> Self {
        let target_id = target_id.into();
        let strategy_version = strategy_version.into();
        let goal = goal.into();
        let selected_backend = selected_backend.into();
        let selected_substrate = selected_substrate.into();
        let recipe_id = stable_prefixed_id(
            "recipe",
            [
                target_id.as_str(),
                strategy_version.as_str(),
                goal.as_str(),
                selected_backend.as_str(),
                selected_substrate.as_str(),
            ],
        );

        Self {
            recipe_id,
            target_id,
            strategy_version,
            goal,
            selected_backend,
            selected_substrate,
            resolved_profile_chain: Vec::new(),
            synthesis_steps: Vec::new(),
            debug_features: Vec::new(),
            launch_parameters: Vec::new(),
            fallback_policy: FallbackPolicy::RetrySame,
        }
    }

    pub fn with_resolved_profile_chain(mut self, resolved_profile_chain: Vec<String>) -> Self {
        self.resolved_profile_chain = resolved_profile_chain;
        self
    }

    pub fn with_synthesis_steps(mut self, synthesis_steps: Vec<String>) -> Self {
        self.synthesis_steps = synthesis_steps;
        self
    }

    pub fn with_debug_features(mut self, debug_features: Vec<String>) -> Self {
        self.debug_features = debug_features;
        self
    }

    pub fn with_launch_parameters(mut self, launch_parameters: Vec<String>) -> Self {
        self.launch_parameters = launch_parameters;
        self
    }

    pub fn with_fallback_policy(mut self, fallback_policy: FallbackPolicy) -> Self {
        self.fallback_policy = fallback_policy;
        self
    }
}
