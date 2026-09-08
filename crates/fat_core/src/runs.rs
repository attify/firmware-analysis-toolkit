use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubstrateKind {
    NativeHost,
    DockerEngine,
    ManagedLinuxVm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Created,
    Queued,
    Provisioning,
    Preparing,
    Synthesizing,
    Launching,
    Booting,
    UserspaceStarting,
    Running,
    DegradedRunning,
    Paused,
    Stopping,
    Completed,
    DegradedCompleted,
    Failed,
    Cancelled,
    TimedOut,
    CleanupFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunOrigin {
    Manual,
    Automatic,
    Retry,
    Replay,
    Fallback,
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEndpointKind {
    Shell,
    Debugger,
    Monitor,
    PortForward,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisionMode {
    None,
    ProbeOnStatus,
    BackgroundSupervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthState {
    Unknown,
    Healthy,
    Stale,
    Unreachable,
    GuestUnreachable,
    BootedServicesUnreachable,
    BootedServicesReachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEndpoint {
    pub kind: RuntimeEndpointKind,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub target_port: Option<u16>,
    pub uri: Option<String>,
}

impl RuntimeEndpoint {
    pub fn new(
        kind: RuntimeEndpointKind,
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            host: host.into(),
            port,
            target_port: None,
            uri: None,
        }
    }

    pub fn with_target_port(mut self, target_port: u16) -> Self {
        self.target_port = Some(target_port);
        self
    }

    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GoalProgressDelta {
    pub from: crate::sessions::GoalProgress,
    pub to: crate::sessions::GoalProgress,
}

impl GoalProgressDelta {
    pub fn new(from: crate::sessions::GoalProgress, to: crate::sessions::GoalProgress) -> Self {
        Self { from, to }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub session_id: String,
    pub recipe_id: String,
    pub backend_driver: String,
    pub substrate_kind: SubstrateKind,
    pub status: RunStatus,
    pub sequence_in_session: u32,
    pub derived_from_run_id: Option<String>,
    pub origin: RunOrigin,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub active_endpoints: Vec<RuntimeEndpoint>,
    pub goal_progress_delta: GoalProgressDelta,
    pub supervision_mode: SupervisionMode,
    pub health_state: HealthState,
    pub last_health_check_at: Option<String>,
    pub supervisor_pid: Option<u32>,
    pub last_heartbeat_at: Option<String>,
    pub supervision_lease_expires_at: Option<String>,
}

impl RunRecord {
    pub fn new(
        session_id: impl Into<String>,
        recipe_id: impl Into<String>,
        backend_driver: impl Into<String>,
        substrate_kind: SubstrateKind,
        sequence_in_session: u32,
        origin: RunOrigin,
    ) -> Self {
        let session_id = session_id.into();
        let recipe_id = recipe_id.into();
        let backend_driver = backend_driver.into();
        let run_id = stable_prefixed_id(
            "run",
            [
                session_id.as_str(),
                recipe_id.as_str(),
                backend_driver.as_str(),
                substrate_kind.as_str(),
                &sequence_in_session.to_string(),
                origin.as_str(),
            ],
        );

        Self {
            run_id,
            session_id,
            recipe_id,
            backend_driver,
            substrate_kind,
            status: RunStatus::Created,
            sequence_in_session,
            derived_from_run_id: None,
            origin,
            started_at: None,
            finished_at: None,
            active_endpoints: Vec::new(),
            goal_progress_delta: GoalProgressDelta::new(
                crate::sessions::GoalProgress::NotStarted,
                crate::sessions::GoalProgress::NotStarted,
            ),
            supervision_mode: SupervisionMode::None,
            health_state: HealthState::Unknown,
            last_health_check_at: None,
            supervisor_pid: None,
            last_heartbeat_at: None,
            supervision_lease_expires_at: None,
        }
    }

    pub fn with_status(mut self, status: RunStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_derived_from_run_id(mut self, derived_from_run_id: impl Into<String>) -> Self {
        self.derived_from_run_id = Some(derived_from_run_id.into());
        self
    }

    pub fn with_started_at(mut self, started_at: Option<String>) -> Self {
        self.started_at = started_at;
        self
    }

    pub fn with_finished_at(mut self, finished_at: Option<String>) -> Self {
        self.finished_at = finished_at;
        self
    }

    pub fn with_active_endpoints(mut self, active_endpoints: Vec<RuntimeEndpoint>) -> Self {
        self.active_endpoints = active_endpoints;
        self
    }

    pub fn with_goal_progress_delta(mut self, goal_progress_delta: GoalProgressDelta) -> Self {
        self.goal_progress_delta = goal_progress_delta;
        self
    }

    pub fn with_supervision_mode(mut self, supervision_mode: SupervisionMode) -> Self {
        self.supervision_mode = supervision_mode;
        self
    }

    pub fn with_health_state(mut self, health_state: HealthState) -> Self {
        self.health_state = health_state;
        self
    }

    pub fn with_last_health_check_at(mut self, last_health_check_at: Option<String>) -> Self {
        self.last_health_check_at = last_health_check_at;
        self
    }

    pub fn with_supervisor_pid(mut self, supervisor_pid: Option<u32>) -> Self {
        self.supervisor_pid = supervisor_pid;
        self
    }

    pub fn with_last_heartbeat_at(mut self, last_heartbeat_at: Option<String>) -> Self {
        self.last_heartbeat_at = last_heartbeat_at;
        self
    }

    pub fn with_supervision_lease_expires_at(
        mut self,
        supervision_lease_expires_at: Option<String>,
    ) -> Self {
        self.supervision_lease_expires_at = supervision_lease_expires_at;
        self
    }
}

impl SubstrateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubstrateKind::NativeHost => "native-host",
            SubstrateKind::DockerEngine => "docker-engine",
            SubstrateKind::ManagedLinuxVm => "managed-linux-vm",
        }
    }
}

impl RunOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            RunOrigin::Manual => "manual",
            RunOrigin::Automatic => "automatic",
            RunOrigin::Retry => "retry",
            RunOrigin::Replay => "replay",
            RunOrigin::Fallback => "fallback",
            RunOrigin::Imported => "imported",
        }
    }
}

impl SupervisionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SupervisionMode::None => "none",
            SupervisionMode::ProbeOnStatus => "probe-on-status",
            SupervisionMode::BackgroundSupervisor => "background-supervisor",
        }
    }
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Unknown => "unknown",
            HealthState::Healthy => "healthy",
            HealthState::Stale => "stale",
            HealthState::Unreachable => "unreachable",
            HealthState::GuestUnreachable => "guest-unreachable",
            HealthState::BootedServicesUnreachable => "booted-services-unreachable",
            HealthState::BootedServicesReachable => "booted-services-reachable",
        }
    }

    pub fn from_runtime_outcome(runtime_outcome: Option<&str>) -> Self {
        match runtime_outcome {
            Some("healthy") => HealthState::Healthy,
            Some("stale") => HealthState::Stale,
            Some("unreachable") => HealthState::Unreachable,
            Some("guest-unreachable") => HealthState::GuestUnreachable,
            Some("booted-services-unreachable") => HealthState::BootedServicesUnreachable,
            Some("booted-services-reachable") => HealthState::BootedServicesReachable,
            _ => HealthState::Unknown,
        }
    }
}
