use fat_core::diagnostics::DiagnosticRecord;
use fat_core::runs::{
    GoalProgressDelta, HealthState, RunRecord, RunStatus, RuntimeEndpoint, SupervisionMode,
};
use fat_core::sessions::{GoalProgress, SessionRecord, SessionStatus};

use crate::session::EmulationSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRun {
    session: EmulationSession,
    diagnostics: Vec<DiagnosticRecord>,
}

impl ActiveRun {
    pub fn from_session(session: EmulationSession) -> Self {
        Self {
            session,
            diagnostics: Vec::new(),
        }
    }

    pub fn session(&self) -> &EmulationSession {
        &self.session
    }

    pub fn session_record(&self) -> &SessionRecord {
        &self.session.session
    }

    pub fn run_record(&self) -> &RunRecord {
        &self.session.run.record
    }

    pub fn diagnostics(&self) -> &[DiagnosticRecord] {
        &self.diagnostics
    }

    pub fn active_endpoints(&self) -> &[RuntimeEndpoint] {
        &self.session.run.record.active_endpoints
    }

    pub fn reattach_endpoint(mut self, endpoint: RuntimeEndpoint) -> Self {
        self.session.run.record.active_endpoints.push(endpoint);
        self
    }

    pub fn with_supervision(
        mut self,
        supervision_mode: SupervisionMode,
        health_state: HealthState,
        last_health_check_at: Option<String>,
    ) -> Self {
        self.session.run =
            self.session
                .run
                .with_supervision(supervision_mode, health_state, last_health_check_at);
        self
    }

    pub fn with_supervisor_runtime(
        mut self,
        supervisor_pid: Option<u32>,
        last_heartbeat_at: Option<String>,
        supervision_lease_expires_at: Option<String>,
    ) -> Self {
        self.session.run = self.session.run.with_supervisor_runtime(
            supervisor_pid,
            last_heartbeat_at,
            supervision_lease_expires_at,
        );
        self
    }

    pub fn preparing_at(self, updated_at: impl Into<String>) -> Self {
        self.transition(
            SessionStatus::Active,
            GoalProgress::Partial,
            RunStatus::Preparing,
            updated_at.into(),
            None,
            None,
            None,
        )
    }

    pub fn launching_at(self, updated_at: impl Into<String>) -> Self {
        self.transition(
            SessionStatus::Active,
            GoalProgress::Substantial,
            RunStatus::Launching,
            updated_at.into(),
            None,
            None,
            None,
        )
    }

    pub fn running_at(self, updated_at: impl Into<String>) -> Self {
        let updated_at = updated_at.into();
        self.transition(
            SessionStatus::Active,
            GoalProgress::Substantial,
            RunStatus::Running,
            updated_at.clone(),
            Some(updated_at),
            None,
            None,
        )
    }

    pub fn degraded_running_at(
        self,
        updated_at: impl Into<String>,
        diagnostic: DiagnosticRecord,
    ) -> Self {
        let updated_at = updated_at.into();
        let started_at = self
            .run_record()
            .started_at
            .clone()
            .unwrap_or_else(|| updated_at.clone());
        self.transition(
            SessionStatus::Degraded,
            GoalProgress::Substantial,
            RunStatus::DegradedRunning,
            updated_at,
            Some(started_at),
            None,
            Some(diagnostic),
        )
    }

    pub fn completed_at(self, updated_at: impl Into<String>) -> Self {
        let updated_at = updated_at.into();
        let started_at = self
            .run_record()
            .started_at
            .clone()
            .unwrap_or_else(|| updated_at.clone());
        self.transition(
            SessionStatus::Completed,
            GoalProgress::Achieved,
            RunStatus::Completed,
            updated_at.clone(),
            Some(started_at),
            Some(updated_at),
            None,
        )
    }

    pub fn degraded_completed_at(
        self,
        updated_at: impl Into<String>,
        diagnostic: DiagnosticRecord,
    ) -> Self {
        let updated_at = updated_at.into();
        let started_at = self
            .run_record()
            .started_at
            .clone()
            .unwrap_or_else(|| updated_at.clone());
        self.transition(
            SessionStatus::Completed,
            GoalProgress::Achieved,
            RunStatus::DegradedCompleted,
            updated_at.clone(),
            Some(started_at),
            Some(updated_at),
            Some(diagnostic),
        )
    }

    pub fn failed_at(self, updated_at: impl Into<String>, diagnostic: DiagnosticRecord) -> Self {
        let updated_at = updated_at.into();
        let started_at = self.run_record().started_at.clone();
        self.transition(
            SessionStatus::Degraded,
            GoalProgress::Blocked,
            RunStatus::Failed,
            updated_at.clone(),
            started_at,
            Some(updated_at),
            Some(diagnostic),
        )
    }

    fn transition(
        self,
        session_status: SessionStatus,
        session_progress: GoalProgress,
        run_status: RunStatus,
        updated_at: String,
        started_at: Option<String>,
        finished_at: Option<String>,
        diagnostic: Option<DiagnosticRecord>,
    ) -> Self {
        let previous_progress = self.session.run.record.goal_progress_delta.to;
        let EmulationSession {
            requested_session_id,
            session,
            run,
        } = self
            .session
            .with_lifecycle(session_status, session_progress, updated_at);
        let run = run.with_lifecycle(
            run_status,
            GoalProgressDelta::new(previous_progress, session_progress),
            started_at,
            finished_at,
        );

        let mut diagnostics = self.diagnostics;
        if let Some(diagnostic) = diagnostic {
            diagnostics.push(diagnostic);
        }

        Self {
            session: EmulationSession {
                requested_session_id,
                session,
                run,
            },
            diagnostics,
        }
    }
}
