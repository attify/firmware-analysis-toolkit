use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStatus {
    Draft,
    Planned,
    Active,
    Paused,
    Degraded,
    Completed,
    Archived,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GoalProgress {
    NotStarted,
    Partial,
    Substantial,
    Achieved,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionOrigin {
    Manual,
    Automatic,
    Imported,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    #[serde(default)]
    pub requested_session_id: Option<String>,
    pub project_id: String,
    pub target_id: String,
    pub goal: String,
    pub strategy_family: String,
    pub status: SessionStatus,
    pub progress: GoalProgress,
    pub run_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub origin: SessionOrigin,
}

impl SessionRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        goal: impl Into<String>,
        strategy_family: impl Into<String>,
        origin: SessionOrigin,
        created_at: impl Into<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let goal = goal.into();
        let strategy_family = strategy_family.into();
        let created_at = created_at.into();
        let session_id = stable_prefixed_id(
            "sess",
            [
                project_id.as_str(),
                target_id.as_str(),
                goal.as_str(),
                strategy_family.as_str(),
                origin.as_str(),
            ],
        );

        Self {
            session_id,
            requested_session_id: None,
            project_id,
            target_id,
            goal,
            strategy_family,
            status: SessionStatus::Draft,
            progress: GoalProgress::NotStarted,
            run_ids: Vec::new(),
            created_at: created_at.clone(),
            updated_at: created_at,
            origin,
        }
    }

    pub fn with_status(mut self, status: SessionStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_requested_session_id(mut self, requested_session_id: impl Into<String>) -> Self {
        self.requested_session_id = Some(requested_session_id.into());
        self
    }

    pub fn with_progress(mut self, progress: GoalProgress) -> Self {
        self.progress = progress;
        self
    }

    pub fn with_run_ids(mut self, run_ids: Vec<String>) -> Self {
        self.run_ids = run_ids;
        self
    }

    pub fn with_updated_at(mut self, updated_at: impl Into<String>) -> Self {
        self.updated_at = updated_at.into();
        self
    }
}

impl SessionOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionOrigin::Manual => "manual",
            SessionOrigin::Automatic => "automatic",
            SessionOrigin::Imported => "imported",
            SessionOrigin::Derived => "derived",
        }
    }
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Draft => "draft",
            SessionStatus::Planned => "planned",
            SessionStatus::Active => "active",
            SessionStatus::Paused => "paused",
            SessionStatus::Degraded => "degraded",
            SessionStatus::Completed => "completed",
            SessionStatus::Archived => "archived",
            SessionStatus::Abandoned => "abandoned",
        }
    }
}
