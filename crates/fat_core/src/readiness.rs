use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;
use crate::rehosting_policy::SubstrateKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GoalState {
    Registered,
    Ready,
    Validated,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

pub type ReadinessGoalState = GoalState;
pub type ReadinessGoalRecord = GoalConfidence;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalConfidence {
    pub goal: String,
    pub state: GoalState,
    pub note: Option<String>,
}

impl GoalConfidence {
    pub fn new(goal: impl Into<String>, state: GoalState) -> Self {
        Self {
            goal: goal.into(),
            state,
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerRecord {
    pub blocker_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub logical_substrate: SubstrateKind,
    pub blocker_kind: String,
    pub process_name: Option<String>,
    pub detail: String,
    pub confidence: ConfidenceLevel,
}

impl BlockerRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        logical_substrate: SubstrateKind,
        blocker_kind: impl Into<String>,
        detail: impl Into<String>,
        confidence: ConfidenceLevel,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let blocker_kind = blocker_kind.into();
        let blocker_id = stable_prefixed_id(
            "blocker",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                logical_substrate.as_str(),
                blocker_kind.as_str(),
            ],
        );

        Self {
            blocker_id,
            project_id,
            target_id,
            session_id,
            run_id,
            logical_substrate,
            blocker_kind,
            process_name: None,
            detail: detail.into(),
            confidence,
        }
    }

    pub fn with_process_name(mut self, process_name: impl Into<String>) -> Self {
        self.process_name = Some(process_name.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceReport {
    pub confidence_report_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub logical_substrate: Option<SubstrateKind>,
    pub level: ConfidenceLevel,
    pub score: u8,
    pub summary: Option<String>,
    pub blockers: Vec<String>,
    pub fidelity_caveats: Vec<String>,
    pub goals: Vec<GoalConfidence>,
}

impl ConfidenceReport {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        logical_substrate: Option<SubstrateKind>,
        level: ConfidenceLevel,
        score: u8,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let logical_substrate_label = logical_substrate
            .map(|kind| kind.as_str())
            .unwrap_or("unknown");
        let score_label = score.to_string();
        let confidence_report_id = stable_prefixed_id(
            "confidence",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                logical_substrate_label,
                level.as_str(),
                score_label.as_str(),
            ],
        );

        Self {
            confidence_report_id,
            project_id,
            target_id,
            session_id,
            run_id,
            logical_substrate,
            level,
            score,
            summary: None,
            blockers: Vec::new(),
            fidelity_caveats: Vec::new(),
            goals: Vec::new(),
        }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    pub fn with_blockers(mut self, blockers: Vec<String>) -> Self {
        self.blockers = blockers;
        self
    }

    pub fn with_fidelity_caveats(mut self, fidelity_caveats: Vec<String>) -> Self {
        self.fidelity_caveats = fidelity_caveats;
        self
    }

    pub fn with_goals(mut self, goals: Vec<GoalConfidence>) -> Self {
        self.goals = goals;
        self
    }
}

impl ConfidenceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfidenceLevel::Low => "low",
            ConfidenceLevel::Medium => "medium",
            ConfidenceLevel::High => "high",
        }
    }
}
