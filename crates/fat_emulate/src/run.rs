use fat_core::runs::{
    GoalProgressDelta, HealthState, RunRecord, RunStatus, RuntimeEndpoint, SupervisionMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulationRun {
    pub record: RunRecord,
}

impl EmulationRun {
    pub fn new(record: RunRecord) -> Self {
        Self { record }
    }

    pub fn record(&self) -> &RunRecord {
        &self.record
    }

    pub fn queued(self) -> Self {
        Self {
            record: self.record.with_status(RunStatus::Queued),
        }
    }

    pub fn preparing(self) -> Self {
        Self {
            record: self.record.with_status(RunStatus::Preparing),
        }
    }

    pub fn completed(self) -> Self {
        Self {
            record: self.record.with_status(RunStatus::Completed),
        }
    }

    pub fn failed(self) -> Self {
        Self {
            record: self.record.with_status(RunStatus::Failed),
        }
    }

    pub fn with_lifecycle(
        self,
        status: RunStatus,
        goal_progress_delta: GoalProgressDelta,
        started_at: Option<String>,
        finished_at: Option<String>,
    ) -> Self {
        Self {
            record: self
                .record
                .with_status(status)
                .with_goal_progress_delta(goal_progress_delta)
                .with_started_at(started_at)
                .with_finished_at(finished_at),
        }
    }

    pub fn with_active_endpoints(self, active_endpoints: Vec<RuntimeEndpoint>) -> Self {
        Self {
            record: self.record.with_active_endpoints(active_endpoints),
        }
    }

    pub fn with_supervision(
        self,
        supervision_mode: SupervisionMode,
        health_state: HealthState,
        last_health_check_at: Option<String>,
    ) -> Self {
        Self {
            record: self
                .record
                .with_supervision_mode(supervision_mode)
                .with_health_state(health_state)
                .with_last_health_check_at(last_health_check_at),
        }
    }

    pub fn with_supervisor_runtime(
        self,
        supervisor_pid: Option<u32>,
        last_heartbeat_at: Option<String>,
        supervision_lease_expires_at: Option<String>,
    ) -> Self {
        Self {
            record: self
                .record
                .with_supervisor_pid(supervisor_pid)
                .with_last_heartbeat_at(last_heartbeat_at)
                .with_supervision_lease_expires_at(supervision_lease_expires_at),
        }
    }
}

impl Default for EmulationRun {
    fn default() -> Self {
        Self::new(RunRecord::new(
            "",
            "",
            "",
            fat_core::runs::SubstrateKind::NativeHost,
            0,
            fat_core::runs::RunOrigin::Manual,
        ))
    }
}
