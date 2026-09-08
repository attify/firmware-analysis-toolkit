use fat_core::readiness::{BlockerRecord, ConfidenceLevel, ConfidenceReport, GoalConfidence};
use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::rehosting_policy::SubstrateKind;
use fat_core::rehosting_recipe::RehostingRecipe;

use crate::blocker::{blocker_from_diagnostic, blocker_from_readiness};
use crate::validators::goal_confidence_from_readiness;

pub fn build_registered_readiness(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    requested_goals: &[String],
    surfaces: Vec<RuntimeSurfaceRecord>,
    summary: impl Into<String>,
) -> ReadinessReport {
    ReadinessReport::new(
        project_id.to_string(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        requested_goals.to_vec(),
        surfaces,
    )
    .with_summary(summary)
}

pub fn build_ready_readiness(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    requested_goals: &[String],
    mut surfaces: Vec<RuntimeSurfaceRecord>,
    summary: impl Into<String>,
) -> ReadinessReport {
    for surface in &mut surfaces {
        if surface.readiness == SurfaceReadiness::Registered {
            surface.readiness = SurfaceReadiness::Ready;
        }
    }
    ReadinessReport::new(
        project_id.to_string(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        requested_goals.to_vec(),
        surfaces,
    )
    .with_summary(summary)
}

pub fn build_initial_confidence(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    logical_substrate: SubstrateKind,
    fidelity_caveats: Vec<String>,
    goals: Vec<String>,
) -> ConfidenceReport {
    let (level, score, summary) = match logical_substrate {
        SubstrateKind::Service => (
            ConfidenceLevel::Medium,
            55,
            "service runner selected for fastest viable rehosting path",
        ),
        SubstrateKind::System => (
            ConfidenceLevel::Medium,
            60,
            "system runner selected for higher-fidelity boot coverage",
        ),
        SubstrateKind::Reference => (
            ConfidenceLevel::Low,
            35,
            "reference runner selected as a stable fallback substrate",
        ),
    };

    ConfidenceReport::new(
        project_id.to_string(),
        target_id.to_string(),
        session_id.to_string(),
        run_id.to_string(),
        Some(logical_substrate),
        level,
        score,
    )
    .with_summary(summary)
    .with_fidelity_caveats(fidelity_caveats)
    .with_goals(
        goals
            .into_iter()
            .map(|goal| GoalConfidence::new(goal, fat_core::readiness::GoalState::Registered))
            .collect(),
    )
}

pub fn build_runtime_confidence(
    project_id: &str,
    target_id: &str,
    readiness: &ReadinessReport,
    recipe: &RehostingRecipe,
) -> ConfidenceReport {
    let goals = goal_confidence_from_readiness(recipe, readiness);
    let blockers = blocker_from_readiness(project_id, target_id, readiness, recipe)
        .into_iter()
        .map(|blocker| blocker.blocker_id)
        .collect::<Vec<_>>();
    let any_validated = goals
        .iter()
        .any(|goal| goal.state == fat_core::readiness::GoalState::Validated);
    let any_ready = goals
        .iter()
        .any(|goal| goal.state == fat_core::readiness::GoalState::Ready);
    let (level, score, summary) = if any_validated {
        (ConfidenceLevel::High, 85, "requested goals validated")
    } else if any_ready {
        (
            ConfidenceLevel::Medium,
            60,
            "surfaces ready but goals still pending validation",
        )
    } else {
        (
            ConfidenceLevel::Low,
            30,
            "launch registered but no validators satisfied yet",
        )
    };

    ConfidenceReport::new(
        project_id.to_string(),
        target_id.to_string(),
        readiness.session_id.clone(),
        readiness.run_id.clone(),
        Some(recipe.selected_substrate),
        level,
        score,
    )
    .with_summary(summary)
    .with_blockers(blockers)
    .with_fidelity_caveats(recipe.fidelity_caveats.clone())
    .with_goals(goals)
}

pub fn build_diagnostic_blocker(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    recipe: &RehostingRecipe,
    diagnostic: &fat_core::diagnostics::DiagnosticRecord,
) -> Option<BlockerRecord> {
    Some(blocker_from_diagnostic(
        project_id, target_id, session_id, run_id, recipe, diagnostic,
    ))
}
