use fat_core::runs::RunRecord;
use fat_core::sessions::SessionRecord;

use crate::active_run::ActiveRun;
use crate::run::EmulationRun;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulationSession {
    pub requested_session_id: String,
    pub session: SessionRecord,
    pub run: EmulationRun,
}

impl EmulationSession {
    pub fn new(
        requested_session_id: impl Into<String>,
        session: SessionRecord,
        run: EmulationRun,
    ) -> Self {
        Self {
            requested_session_id: requested_session_id.into(),
            session,
            run,
        }
    }

    pub fn requested_session_id(&self) -> &str {
        &self.requested_session_id
    }

    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }

    pub fn backend_id(&self) -> &str {
        &self.run.record.backend_driver
    }

    pub fn mapped_ports(&self) -> Vec<u16> {
        self.run
            .record
            .active_endpoints
            .iter()
            .map(|endpoint| endpoint.port)
            .collect()
    }

    pub fn session_record(&self) -> &SessionRecord {
        &self.session
    }

    pub fn run_record(&self) -> &RunRecord {
        &self.run.record
    }

    pub fn with_lifecycle(
        self,
        status: fat_core::sessions::SessionStatus,
        progress: fat_core::sessions::GoalProgress,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            requested_session_id: self.requested_session_id,
            session: self
                .session
                .with_status(status)
                .with_progress(progress)
                .with_updated_at(updated_at),
            run: self.run,
        }
    }

    pub fn into_active_run(self) -> ActiveRun {
        ActiveRun::from_session(self)
    }
}
