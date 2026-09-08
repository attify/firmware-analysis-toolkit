use fat_core::diagnostics::DiagnosticRecord;
use fat_core::readiness::{BlockerRecord, ConfidenceLevel};
use fat_core::rehosting::ReadinessReport;
use fat_core::rehosting_recipe::RehostingRecipe;

pub fn blocker_from_diagnostic(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    recipe: &RehostingRecipe,
    diagnostic: &DiagnosticRecord,
) -> BlockerRecord {
    BlockerRecord::new(
        project_id,
        target_id,
        session_id,
        run_id,
        recipe.selected_substrate,
        diagnostic
            .subclass
            .clone()
            .unwrap_or_else(|| diagnostic.class.as_str().to_string()),
        diagnostic.summary.clone(),
        ConfidenceLevel::High,
    )
}

pub fn blocker_from_readiness(
    project_id: &str,
    target_id: &str,
    readiness: &ReadinessReport,
    recipe: &RehostingRecipe,
) -> Option<BlockerRecord> {
    let missing_goal = recipe.validators.iter().find(|validator| {
        !readiness
            .validated_goals
            .iter()
            .any(|goal| goal == &validator.goal)
    })?;
    Some(
        BlockerRecord::new(
            project_id,
            target_id,
            &readiness.session_id,
            &readiness.run_id,
            recipe.selected_substrate,
            "validator-blocked",
            format!("goal {} is still blocked", missing_goal.goal),
            ConfidenceLevel::Medium,
        )
        .with_process_name(missing_goal.validator_kind.clone()),
    )
}
