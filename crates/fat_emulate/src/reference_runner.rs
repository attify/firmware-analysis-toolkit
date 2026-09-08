use std::path::Path;

use fat_core::readiness::ConfidenceReport;
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::staging::StagingManifest;

use crate::plan::EmulationPlan;
use crate::readiness_engine::build_initial_confidence;
use crate::staging_builder::reference_staging_manifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRunnerPlan {
    pub reference_backend: String,
    pub fidelity_caveats: Vec<String>,
    pub staging_manifest: StagingManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRunnerBlueprint {
    pub reference_backend: String,
    pub fidelity_caveats: Vec<String>,
    pub staging: StagingManifest,
    pub initial_confidence: ConfidenceReport,
}

pub fn build_reference_runner_plan(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    recipe: &RehostingRecipe,
    source_root: &str,
    staging_root: &str,
) -> ReferenceRunnerPlan {
    let mut fidelity_caveats = recipe.fidelity_caveats.clone();
    if fidelity_caveats.is_empty() {
        fidelity_caveats.push(
            "reference runner provides a stable foothold, not target-faithful validation"
                .to_string(),
        );
    }

    ReferenceRunnerPlan {
        reference_backend: recipe
            .selected_backend
            .clone()
            .unwrap_or_else(|| "reference".to_string()),
        fidelity_caveats,
        staging_manifest: reference_staging_manifest(
            project_id,
            target_id,
            session_id,
            run_id,
            source_root,
            staging_root,
        ),
    }
}

pub fn build_reference_runner_blueprint(
    plan: &EmulationPlan,
    staging_root: &Path,
) -> ReferenceRunnerBlueprint {
    let source_root = staging_root.join("source-rootfs");
    let run_staging_root = staging_root.join("reference-root");
    let runner_plan = build_reference_runner_plan(
        plan.target_model.project_id.as_str(),
        plan.target_model.target_id.as_str(),
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
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
        plan.rehosting_recipe
            .validators
            .iter()
            .map(|validator| validator.goal.clone())
            .collect(),
    );

    ReferenceRunnerBlueprint {
        reference_backend: runner_plan.reference_backend,
        fidelity_caveats: runner_plan.fidelity_caveats,
        staging: runner_plan.staging_manifest,
        initial_confidence,
    }
}
