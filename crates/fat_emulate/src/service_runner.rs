use std::path::Path;

use fat_core::readiness::ConfidenceReport;
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::staging::StagingManifest;
use fat_core::target_model::{ServiceExecutionClass, TargetModel};

use crate::plan::EmulationPlan;
use crate::readiness_engine::build_initial_confidence;
use crate::staging_builder::{append_recipe_repair_materialization, service_staging_manifest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRunnerPlan {
    pub executable: Option<String>,
    pub validator_goals: Vec<String>,
    pub fidelity_caveats: Vec<String>,
    pub staging_manifest: StagingManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRunnerBlueprint {
    pub executable: Option<String>,
    pub validator_goals: Vec<String>,
    pub fidelity_caveats: Vec<String>,
    pub staging: StagingManifest,
    pub initial_confidence: ConfidenceReport,
}

pub fn launchable_service_executable(target_model: &TargetModel) -> Option<String> {
    target_model
        .service_candidates
        .iter()
        .find(|candidate| {
            matches!(
                candidate.execution_class,
                ServiceExecutionClass::Standalone | ServiceExecutionClass::RequiresPeerDaemon
            ) && service_candidate_is_launchable(candidate.path.as_str())
        })
        .map(|candidate| candidate.path.clone())
}

pub fn build_service_runner_plan(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    target_model: &TargetModel,
    recipe: &RehostingRecipe,
    source_root: &str,
    staging_root: &str,
) -> ServiceRunnerPlan {
    let executable = launchable_service_executable(target_model);
    let mut fidelity_caveats = recipe.fidelity_caveats.clone();
    if target_model
        .service_candidates
        .iter()
        .any(|candidate| candidate.execution_class == ServiceExecutionClass::RequiresPeerDaemon)
    {
        fidelity_caveats.push("service runner may require peer-daemon bootstrap".to_string());
    }

    let mut staging_manifest = service_staging_manifest(
        project_id,
        target_id,
        session_id,
        run_id,
        source_root,
        staging_root,
    );
    append_recipe_repair_materialization(&mut staging_manifest, staging_root, recipe);

    ServiceRunnerPlan {
        executable,
        validator_goals: recipe
            .validators
            .iter()
            .map(|validator| validator.goal.clone())
            .collect(),
        fidelity_caveats,
        staging_manifest,
    }
}

pub fn build_service_runner_blueprint(
    plan: &EmulationPlan,
    staging_root: &Path,
) -> ServiceRunnerBlueprint {
    let source_root = staging_root.join("source-rootfs");
    let run_staging_root = staging_root.join("overlay-root");
    let runner_plan = build_service_runner_plan(
        plan.target_model.project_id.as_str(),
        plan.target_model.target_id.as_str(),
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
        &plan.target_model,
        &plan.rehosting_recipe,
        source_root.to_string_lossy().as_ref(),
        run_staging_root.to_string_lossy().as_ref(),
    );
    let initial_confidence = build_initial_confidence(
        plan.target_model.project_id.as_str(),
        plan.target_model.target_id.as_str(),
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
        plan.rehosting_recipe.selected_substrate,
        runner_plan.fidelity_caveats.clone(),
        runner_plan.validator_goals.clone(),
    );

    ServiceRunnerBlueprint {
        executable: runner_plan.executable,
        validator_goals: runner_plan.validator_goals,
        fidelity_caveats: runner_plan.fidelity_caveats,
        staging: runner_plan.staging_manifest,
        initial_confidence,
    }
}

fn service_candidate_is_launchable(path: &str) -> bool {
    path.starts_with('/') && path != "/cgi-bin" && !path.ends_with("/cgi-bin")
}
