use fat_core::rehosting_policy::SubstrateKind as LogicalSubstrateKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendSubstrateKind {
    NativeHost,
    DockerEngine,
    ManagedLinuxVm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSubstrateStatus {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSubstrateCapability {
    pub is_supported: bool,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSubstrateHealth {
    pub status: BackendSubstrateStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSubstrateContract {
    pub kind: BackendSubstrateKind,
    pub display_name: String,
    pub capability: BackendSubstrateCapability,
    pub health: BackendSubstrateHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSubstratePrecondition {
    pub requirement: String,
    pub satisfied: bool,
    pub detail: String,
}

impl BackendSubstratePrecondition {
    pub fn new(requirement: impl Into<String>, satisfied: bool, detail: impl Into<String>) -> Self {
        Self {
            requirement: requirement.into(),
            satisfied,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendLogicalSubstrateContract {
    pub logical_kind: LogicalSubstrateKind,
    pub backend_id: String,
    pub display_name: String,
    pub supported_physical_substrates: Vec<BackendSubstrateContract>,
    pub execution_preconditions: Vec<BackendSubstratePrecondition>,
    pub fidelity_caveats: Vec<String>,
}

pub trait BackendSubstrateAdapter {
    fn logical_kind(&self) -> LogicalSubstrateKind;
    fn backend_id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn contract(&self) -> &BackendLogicalSubstrateContract;
}

impl BackendSubstrateContract {
    pub fn healthy(
        kind: BackendSubstrateKind,
        display_name: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            display_name: display_name.into(),
            capability: BackendSubstrateCapability {
                is_supported: true,
                notes: notes.into(),
            },
            health: BackendSubstrateHealth {
                status: BackendSubstrateStatus::Healthy,
                detail: "ready".to_string(),
            },
        }
    }

    pub fn degraded(
        kind: BackendSubstrateKind,
        display_name: impl Into<String>,
        notes: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            display_name: display_name.into(),
            capability: BackendSubstrateCapability {
                is_supported: true,
                notes: notes.into(),
            },
            health: BackendSubstrateHealth {
                status: BackendSubstrateStatus::Degraded,
                detail: detail.into(),
            },
        }
    }

    pub fn unavailable(
        kind: BackendSubstrateKind,
        display_name: impl Into<String>,
        notes: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            display_name: display_name.into(),
            capability: BackendSubstrateCapability {
                is_supported: true,
                notes: notes.into(),
            },
            health: BackendSubstrateHealth {
                status: BackendSubstrateStatus::Unavailable,
                detail: detail.into(),
            },
        }
    }
}
