use fat_backend::BackendRegistry;
use fat_core::rehosting_policy::{SubstrateKind as LogicalSubstrateKind, SubstratePreference};
use fat_core::runs::SubstrateKind;

use crate::plan::EmulationPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerKind {
    Service,
    System,
    Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateSelection {
    pub kind: RunnerKind,
    pub backend_id: String,
    pub physical_substrate: SubstrateKind,
    pub logical_substrate: LogicalSubstrateKind,
    pub substrate_preference: SubstratePreference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    BackendUnavailable { backend_id: String },
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionError::BackendUnavailable { backend_id } => {
                write!(f, "backend {backend_id} is not registered")
            }
        }
    }
}

impl std::error::Error for SelectionError {}

pub fn select_substrate(plan: &EmulationPlan) -> SubstrateSelection {
    let logical_substrate = plan.rehosting_recipe.selected_substrate;
    let kind = match logical_substrate {
        LogicalSubstrateKind::Service => RunnerKind::Service,
        LogicalSubstrateKind::System => RunnerKind::System,
        LogicalSubstrateKind::Reference => RunnerKind::Reference,
    };

    SubstrateSelection {
        kind,
        backend_id: plan.strategy.selected.backend_id.clone(),
        physical_substrate: plan.strategy.selected.substrate,
        logical_substrate,
        substrate_preference: plan.selection_trace.preference,
    }
}

pub fn select_runner(
    plan: &EmulationPlan,
    registry: &BackendRegistry,
) -> Result<SubstrateSelection, SelectionError> {
    let selection = select_substrate(plan);
    let backend_known = registry
        .driver_contracts()
        .iter()
        .any(|contract| contract.backend_id == selection.backend_id);
    if backend_known {
        Ok(selection)
    } else {
        Err(SelectionError::BackendUnavailable {
            backend_id: selection.backend_id,
        })
    }
}
