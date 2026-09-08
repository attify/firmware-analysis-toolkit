use fat_core::readiness::{GoalConfidence, GoalState};
use fat_core::rehosting::{ReadinessReport, SurfaceReadiness};
use fat_core::rehosting_recipe::RehostingRecipe;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeValidationSnapshot {
    pub shell_surface_ready: bool,
    pub monitor_surface_ready: bool,
    pub debugger_surface_ready: bool,
    pub service_surface_ready: bool,
    pub service_listener_bound: bool,
    pub process_snapshot_present: bool,
    pub service_snapshot_present: bool,
    pub network_snapshot_present: bool,
    pub process_chain_observed: bool,
    pub http_reply_received: bool,
    pub managed_probe_healthy: bool,
    pub managed_services_reachable: bool,
    pub init_stage_complete: bool,
    pub reference_runtime_ready: bool,
    pub serial_log: String,
    pub process_names: Vec<String>,
    pub existing_paths: Vec<String>,
    pub listener_ports: Vec<u16>,
    pub http_reply_ports: Vec<u16>,
}

pub fn goal_confidence_from_readiness(
    recipe: &RehostingRecipe,
    readiness: &ReadinessReport,
) -> Vec<GoalConfidence> {
    recipe
        .validators
        .iter()
        .map(|validator| {
            if readiness
                .validated_goals
                .iter()
                .any(|goal| goal == &validator.goal)
            {
                GoalConfidence::new(validator.goal.clone(), GoalState::Validated)
            } else if readiness
                .requested_goals
                .iter()
                .any(|goal| goal == &validator.goal)
                && readiness.surfaces.iter().any(|surface| {
                    surface.readiness == fat_core::rehosting::SurfaceReadiness::Ready
                        || surface.readiness == fat_core::rehosting::SurfaceReadiness::Validated
                })
            {
                GoalConfidence::new(validator.goal.clone(), GoalState::Ready)
            } else {
                GoalConfidence::new(validator.goal.clone(), GoalState::Blocked)
                    .with_note("requested goal has not been validated")
            }
        })
        .collect()
}

pub fn apply_runtime_validation(
    recipe: &RehostingRecipe,
    readiness: &ReadinessReport,
    snapshot: &RuntimeValidationSnapshot,
) -> ReadinessReport {
    let mut validated_goals = readiness.validated_goals.clone();

    for validator in &recipe.validators {
        if typed_validator_observed(validator, snapshot)
            && !validated_goals
                .iter()
                .any(|existing| existing == &validator.goal)
        {
            validated_goals.push(validator.goal.clone());
        }
    }

    for goal in &readiness.requested_goals {
        let allows_generic_evidence = recipe
            .validators
            .iter()
            .any(|validator| validator.goal == *goal && validator.validator_kind == "goal");
        if !allows_generic_evidence {
            continue;
        }
        let should_validate = match goal.as_str() {
            "shell-access" => {
                snapshot.process_snapshot_present
                    || (snapshot.reference_runtime_ready && snapshot.shell_surface_ready)
            }
            "listener-bind" => {
                snapshot.service_listener_bound
                    || snapshot.service_surface_ready
                    || snapshot.service_snapshot_present
                    || snapshot.network_snapshot_present
            }
            "http-validation" => snapshot.http_reply_received,
            "process-chain" => snapshot.process_chain_observed,
            "init-complete" => {
                snapshot.managed_probe_healthy
                    || snapshot.managed_services_reachable
                    || snapshot.init_stage_complete
            }
            "reference-bootstrap" => {
                snapshot.reference_runtime_ready
                    || (snapshot.shell_surface_ready
                        && (snapshot.monitor_surface_ready || snapshot.debugger_surface_ready))
            }
            _ => false,
        };
        if should_validate && !validated_goals.iter().any(|existing| existing == goal) {
            validated_goals.push(goal.clone());
        }
    }

    let surfaces = readiness
        .surfaces
        .iter()
        .cloned()
        .map(|mut surface| {
            if surface.readiness == SurfaceReadiness::Validated {
                return surface;
            }

            let mark_validated = match surface.kind.as_str() {
                "shell" => validated_goals.iter().any(|goal| goal == "shell-access"),
                "monitor" | "debugger" => validated_goals
                    .iter()
                    .any(|goal| goal == "reference-bootstrap"),
                "service" | "port-forward" => {
                    validated_goals.iter().any(|goal| goal == "listener-bind")
                        || (validated_goals.iter().any(|goal| goal == "http-validation")
                            && surface
                                .uri
                                .as_deref()
                                .map(|uri| {
                                    uri.starts_with("http://") || uri.starts_with("https://")
                                })
                                .unwrap_or_else(|| surface.port == Some(80)))
                }
                _ => false,
            };

            if mark_validated {
                surface.readiness = SurfaceReadiness::Validated;
                surface.validation_note = Some(validation_note_for_surface(
                    surface.kind.as_str(),
                    &validated_goals,
                ));
            }
            surface
        })
        .collect();

    let summary = if validated_goals.is_empty() {
        readiness.summary.clone()
    } else {
        Some(match readiness.summary.as_deref() {
            Some(existing) if !existing.is_empty() => {
                format!(
                    "{existing}; validated goals: {}",
                    validated_goals.join(", ")
                )
            }
            _ => format!("validated goals: {}", validated_goals.join(", ")),
        })
    };

    let mut updated = ReadinessReport::new(
        readiness.project_id.clone(),
        readiness.target_id.clone(),
        readiness.session_id.clone(),
        readiness.run_id.clone(),
        readiness.requested_goals.clone(),
        surfaces,
    )
    .with_validated_goals(validated_goals);
    if let Some(summary) = summary {
        updated = updated.with_summary(summary);
    }
    updated
}

fn typed_validator_observed(
    validator: &fat_core::rehosting_recipe::RecipeValidator,
    snapshot: &RuntimeValidationSnapshot,
) -> bool {
    match validator.validator_kind.as_str() {
        "serial-log-pattern" => validator
            .pattern
            .as_deref()
            .is_some_and(|pattern| snapshot.serial_log.contains(pattern)),
        "process" => validator
            .name
            .as_ref()
            .is_some_and(|name| snapshot.process_names.iter().any(|process| process == name)),
        "file-exists" => validator.path.as_ref().is_some_and(|path| {
            snapshot
                .existing_paths
                .iter()
                .any(|existing| existing == path)
        }),
        "listener" => validator
            .port
            .is_some_and(|port| snapshot.listener_ports.contains(&port)),
        "http" => validator
            .port
            .is_some_and(|port| snapshot.http_reply_ports.contains(&port)),
        "surface-ready" => snapshot.service_surface_ready,
        _ => false,
    }
}

fn validation_note_for_surface(surface_kind: &str, validated_goals: &[String]) -> String {
    match surface_kind {
        "shell" => "shell access validated".to_string(),
        "monitor" | "debugger" => "reference bootstrap validated".to_string(),
        "service" | "port-forward" => {
            if validated_goals.iter().any(|goal| goal == "http-validation") {
                "http validation observed".to_string()
            } else {
                "listener bind observed".to_string()
            }
        }
        _ => "runtime validation observed".to_string(),
    }
}
