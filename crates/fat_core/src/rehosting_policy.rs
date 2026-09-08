use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubstrateKind {
    Service,
    System,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubstratePreference {
    ServiceFirst,
    SystemFirst,
    ReferenceOnly,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubstrateAttemptState {
    Considered,
    Skipped,
    Unavailable,
    Failed,
    Selected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackReason {
    ExplicitRequest,
    Unavailable,
    ExecutionFailed,
    EscalatedForFidelity,
    EscalatedForRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateAttempt {
    pub substrate: SubstrateKind,
    pub state: SubstrateAttemptState,
    pub reason: Option<FallbackReason>,
    pub detail: Option<String>,
}

impl SubstrateAttempt {
    pub fn new(substrate: SubstrateKind, state: SubstrateAttemptState) -> Self {
        Self {
            substrate,
            state,
            reason: None,
            detail: None,
        }
    }

    pub fn with_reason(mut self, reason: FallbackReason) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionTrace {
    pub selection_trace_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub preference: SubstratePreference,
    pub attempts: Vec<SubstrateAttempt>,
}

impl SelectionTrace {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let selection_trace_id = stable_prefixed_id(
            "select",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
            ],
        );

        Self {
            selection_trace_id,
            project_id,
            target_id,
            session_id,
            run_id,
            preference: SubstratePreference::Auto,
            attempts: Vec::new(),
        }
    }

    pub fn with_preference(mut self, preference: SubstratePreference) -> Self {
        self.preference = preference;
        self
    }

    pub fn with_attempts(mut self, attempts: Vec<SubstrateAttempt>) -> Self {
        self.attempts = attempts;
        self
    }
}

impl SubstratePreference {
    pub fn default_order(self) -> Vec<SubstrateKind> {
        match self {
            SubstratePreference::ServiceFirst | SubstratePreference::Auto => vec![
                SubstrateKind::Service,
                SubstrateKind::System,
                SubstrateKind::Reference,
            ],
            SubstratePreference::SystemFirst => vec![
                SubstrateKind::System,
                SubstrateKind::Service,
                SubstrateKind::Reference,
            ],
            SubstratePreference::ReferenceOnly => vec![SubstrateKind::Reference],
        }
    }
}

impl SubstrateAttemptState {
    pub fn as_str(self) -> &'static str {
        match self {
            SubstrateAttemptState::Considered => "considered",
            SubstrateAttemptState::Skipped => "skipped",
            SubstrateAttemptState::Unavailable => "unavailable",
            SubstrateAttemptState::Failed => "failed",
            SubstrateAttemptState::Selected => "selected",
        }
    }
}

impl FallbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FallbackReason::ExplicitRequest => "explicit-request",
            FallbackReason::Unavailable => "unavailable",
            FallbackReason::ExecutionFailed => "execution-failed",
            FallbackReason::EscalatedForFidelity => "escalated-for-fidelity",
            FallbackReason::EscalatedForRecovery => "escalated-for-recovery",
        }
    }
}
