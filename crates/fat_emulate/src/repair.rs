use fat_core::diagnostics::{DiagnosticClass, DiagnosticRecord};
use fat_core::rehosting::{FailureClass, RepairActionKind};
use fat_core::rehosting_recipe::{
    RecipeDeviceNodePlan, RecipeFilesystemTransform, RecipeLaunchPlan, RehostingRecipe,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairDecision {
    pub failure_class: FailureClass,
    pub action: RepairActionKind,
    pub retry_allowed: bool,
}

pub fn decide_repair(diagnostic: &DiagnosticRecord) -> Option<RepairDecision> {
    let summary = diagnostic.summary.to_ascii_lowercase();
    let next_actions = diagnostic
        .suggested_next_actions
        .iter()
        .map(|entry| entry.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let config_hint = contains_any(&summary, &["config", "materializ", "overlay"])
        || next_actions
            .iter()
            .any(|entry| contains_any(entry, &["config", "materializ", "overlay"]));
    let wrong_init_hint = contains_any(
        &summary,
        &[
            "wrong init path",
            "rotate init candidate",
            "retry with /etc/init.d",
            "preinit",
        ],
    ) || next_actions.iter().any(|entry| {
        contains_any(
            entry,
            &[
                "wrong init path",
                "rotate init candidate",
                "retry with /etc/init.d",
                "preinit",
            ],
        )
    });
    let missing_device_path_hint = extract_guest_paths(diagnostic)
        .into_iter()
        .any(|path| path.starts_with("/dev/"))
        && (contains_any(&summary, &["missing", "no such file"])
            || next_actions
                .iter()
                .any(|entry| contains_any(entry, &["missing", "no such file"])));

    if missing_device_path_hint {
        return Some(RepairDecision {
            failure_class: FailureClass::SystemResource,
            action: RepairActionKind::CreateNode,
            retry_allowed: true,
        });
    }

    let decision = match diagnostic.class {
        DiagnosticClass::DeviceOrPathMissing => RepairDecision {
            failure_class: FailureClass::SystemResource,
            action: RepairActionKind::CreateNode,
            retry_allowed: true,
        },
        DiagnosticClass::IpcOrServiceMissing => RepairDecision {
            failure_class: FailureClass::IpcDependency,
            action: RepairActionKind::StartPeerService,
            retry_allowed: true,
        },
        DiagnosticClass::PreparationFailed if config_hint || wrong_init_hint => RepairDecision {
            failure_class: FailureClass::InitDependency,
            action: RepairActionKind::PatchConfig,
            retry_allowed: true,
        },
        DiagnosticClass::LaunchFailed if config_hint || wrong_init_hint => RepairDecision {
            failure_class: FailureClass::InitDependency,
            action: RepairActionKind::PatchConfig,
            retry_allowed: true,
        },
        DiagnosticClass::NetworkExposureFailed | DiagnosticClass::GuestUnreachable => {
            RepairDecision {
                failure_class: FailureClass::Validation,
                action: RepairActionKind::RetryPlan,
                retry_allowed: false,
            }
        }
        DiagnosticClass::BackendUnavailable
        | DiagnosticClass::SubstrateUnavailable
        | DiagnosticClass::BackendProvisioningFailed
        | DiagnosticClass::LaunchFailed
        | DiagnosticClass::LoaderFailed
        | DiagnosticClass::CpuOrAbiMismatch
        | DiagnosticClass::MemoryMappingFailed
        | DiagnosticClass::RuntimeSynthesisMissingState
        | DiagnosticClass::RuntimeSynthesisInvalidState
        | DiagnosticClass::PreparationFailed => RepairDecision {
            failure_class: FailureClass::TargetLaunch,
            action: RepairActionKind::RetryPlan,
            retry_allowed: false,
        },
        _ => return None,
    };

    Some(decision)
}

pub fn apply_repair_for_retry(
    recipe: &RehostingRecipe,
    diagnostic: &DiagnosticRecord,
) -> Option<(RepairDecision, RehostingRecipe)> {
    let decision = decide_repair(diagnostic)?;
    if !decision.retry_allowed {
        return None;
    }

    let mut updated = recipe.clone();
    match decision.action {
        RepairActionKind::CreateNode => {
            let node_path = extract_guest_paths(diagnostic)
                .into_iter()
                .find(|path| path.starts_with("/dev/"))
                .unwrap_or_else(|| "/dev/console".to_string());
            if !updated
                .device_nodes
                .iter()
                .any(|node| node.path == node_path)
            {
                updated
                    .device_nodes
                    .push(RecipeDeviceNodePlan::new(node_path.clone(), "char"));
            }
            push_unique(
                &mut updated.instrumentation_flags,
                format!("repair:create-node:{node_path}"),
            );
        }
        RepairActionKind::PatchConfig => {
            if let Some(init_path) = extract_init_rotation_path(diagnostic) {
                updated.launch_plan = Some(RecipeLaunchPlan::new(init_path.clone(), Vec::new()));
                if !updated.filesystem_transforms.iter().any(|transform| {
                    transform.transform_kind == "patch-config"
                        && transform.destination == "/etc/fat/repair-init.sh"
                }) {
                    updated
                        .filesystem_transforms
                        .push(RecipeFilesystemTransform::new(
                            "patch-config",
                            "synth:repair-init",
                            "/etc/fat/repair-init.sh",
                        ));
                }
                push_unique(
                    &mut updated.instrumentation_flags,
                    format!("repair:rotate-init:{init_path}"),
                );
            } else {
                let destination = extract_guest_paths(diagnostic)
                    .into_iter()
                    .find(|path| path.starts_with("/etc/") || path.starts_with("/var/"))
                    .unwrap_or_else(|| "/etc/fat/generated-repair.conf".to_string());
                if !updated.filesystem_transforms.iter().any(|transform| {
                    transform.transform_kind == "patch-config"
                        && transform.destination == destination
                }) {
                    updated
                        .filesystem_transforms
                        .push(RecipeFilesystemTransform::new(
                            "patch-config",
                            "synth:repair-config",
                            destination.clone(),
                        ));
                }
                push_unique(
                    &mut updated.instrumentation_flags,
                    format!("repair:patch-config:{destination}"),
                );
            }
        }
        RepairActionKind::StartPeerService => {
            push_unique(
                &mut updated.env_injections,
                "FAT_REPAIR_START_PEER_SERVICE=1".to_string(),
            );
            push_unique(
                &mut updated.instrumentation_flags,
                "repair:start-peer-service".to_string(),
            );
        }
        RepairActionKind::InjectEnv => {
            push_unique(
                &mut updated.env_injections,
                "FAT_REPAIR_INJECTED_ENV=1".to_string(),
            );
        }
        RepairActionKind::RetryPlan => return None,
    }

    Some((decision, updated))
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn extract_guest_paths(diagnostic: &DiagnosticRecord) -> Vec<String> {
    let mut paths = Vec::new();
    for text in std::iter::once(diagnostic.summary.as_str())
        .chain(diagnostic.suggested_next_actions.iter().map(String::as_str))
    {
        for token in text.split_whitespace() {
            let cleaned = token
                .trim_matches(|character: char| {
                    character == ','
                        || character == ';'
                        || character == ':'
                        || character == ')'
                        || character == '('
                        || character == '.'
                })
                .trim();
            if cleaned.starts_with('/') && !paths.iter().any(|existing| existing == cleaned) {
                paths.push(cleaned.to_string());
            }
        }
    }
    paths
}

fn extract_init_rotation_path(diagnostic: &DiagnosticRecord) -> Option<String> {
    extract_guest_paths(diagnostic)
        .into_iter()
        .rfind(|path| path.contains("init") || path.contains("preinit"))
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}
