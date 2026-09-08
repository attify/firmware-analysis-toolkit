use std::fmt;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

use crate::diagnostics::DiagnosticRecord;
use crate::finding::Finding;
use crate::ids::stable_prefixed_id;
use crate::readiness::{ConfidenceReport, GoalState};
use crate::rehosting::{ReadinessReport, SurfaceReadiness};
use crate::runs::{RunRecord, RunStatus, RuntimeEndpointKind};
use crate::services::ManagedRuntimeSummary;
use crate::targets::TargetRecord;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkTarget {
    pub target_id: String,
    pub display_name: String,
    pub architecture: String,
    pub packaging: String,
}

impl BenchmarkTarget {
    pub fn new(
        target_id: impl Into<String>,
        display_name: impl Into<String>,
        architecture: impl Into<String>,
        packaging: impl Into<String>,
    ) -> Self {
        Self {
            target_id: target_id.into(),
            display_name: display_name.into(),
            architecture: architecture.into(),
            packaging: packaging.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkRunMode {
    RawUpstream,
    ComparatorTuned,
    FatNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkOutcomeClass {
    Failed,
    Partial,
    Useful,
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkEvidenceGrade {
    Minimal,
    Moderate,
    Rich,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparatorKind {
    External,
    Internal,
    Synthetic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkComparator {
    pub comparator_id: String,
    pub kind: ComparatorKind,
    pub run_mode: BenchmarkRunMode,
}

impl BenchmarkComparator {
    pub fn new(
        comparator_id: impl Into<String>,
        kind: ComparatorKind,
        run_mode: BenchmarkRunMode,
    ) -> Self {
        Self {
            comparator_id: comparator_id.into(),
            kind,
            run_mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BenchmarkRunRecord {
    pub benchmark_run_id: String,
    pub target_id: String,
    pub comparator: BenchmarkComparator,
    pub host_profile: String,
    pub execution_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchmarkRunRecordError {
    EmptyExecutionId,
    NullExecutionId,
    BenchmarkRunIdMismatch,
}

impl BenchmarkRunRecord {
    pub fn try_new(
        target_id: impl Into<String>,
        comparator: BenchmarkComparator,
        host_profile: impl Into<String>,
        execution_id: impl Into<String>,
    ) -> Result<Self, BenchmarkRunRecordError> {
        let target_id = target_id.into();
        let host_profile = host_profile.into();
        let execution_id = normalize_required_execution_id(execution_id.into())?;
        let benchmark_run_id =
            canonical_benchmark_run_id(&target_id, &comparator, &host_profile, &execution_id);

        Ok(Self {
            benchmark_run_id,
            target_id,
            comparator,
            host_profile,
            execution_id,
        })
    }
}

impl<'de> Deserialize<'de> for BenchmarkRunRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BenchmarkRunRecordWire {
            benchmark_run_id: String,
            target_id: String,
            comparator: BenchmarkComparator,
            host_profile: String,
            #[serde(default, deserialize_with = "deserialize_execution_id_field")]
            execution_id: ExecutionIdField,
        }

        let wire = BenchmarkRunRecordWire::deserialize(deserializer)?;

        let (benchmark_run_id, execution_id) = match wire.execution_id {
            ExecutionIdField::Missing => {
                let execution_id = wire.benchmark_run_id.clone();
                let benchmark_run_id = canonical_benchmark_run_id(
                    &wire.target_id,
                    &wire.comparator,
                    &wire.host_profile,
                    &execution_id,
                );
                (benchmark_run_id, execution_id)
            }
            ExecutionIdField::Null => {
                return Err(D::Error::custom(BenchmarkRunRecordError::NullExecutionId))
            }
            ExecutionIdField::Present(execution_id) => {
                let execution_id =
                    normalize_required_execution_id(execution_id).map_err(D::Error::custom)?;
                let expected_benchmark_run_id = canonical_benchmark_run_id(
                    &wire.target_id,
                    &wire.comparator,
                    &wire.host_profile,
                    &execution_id,
                );
                if wire.benchmark_run_id != expected_benchmark_run_id {
                    return Err(D::Error::custom(
                        BenchmarkRunRecordError::BenchmarkRunIdMismatch,
                    ));
                }
                (wire.benchmark_run_id.clone(), execution_id)
            }
        };

        Ok(Self {
            execution_id,
            benchmark_run_id,
            target_id: wire.target_id,
            comparator: wire.comparator,
            host_profile: wire.host_profile,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkStageStatus {
    NotReached,
    Partial,
    Reached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkStageScore {
    pub status: BenchmarkStageStatus,
}

impl BenchmarkStageScore {
    pub fn not_reached() -> Self {
        Self {
            status: BenchmarkStageStatus::NotReached,
        }
    }

    pub fn partial() -> Self {
        Self {
            status: BenchmarkStageStatus::Partial,
        }
    }

    pub fn reached() -> Self {
        Self {
            status: BenchmarkStageStatus::Reached,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkStageVector {
    pub intake: BenchmarkStageScore,
    pub boot: BenchmarkStageScore,
    pub reachability: BenchmarkStageScore,
    pub operator_access: BenchmarkStageScore,
    pub research_utility: BenchmarkStageScore,
    pub exploit_readiness: BenchmarkStageScore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkOutcomeRecord {
    pub benchmark_run_id: String,
    pub outcome_class: BenchmarkOutcomeClass,
    pub evidence_grade: BenchmarkEvidenceGrade,
    pub stage_vector: BenchmarkStageVector,
}

impl BenchmarkOutcomeRecord {
    pub fn new(
        benchmark_run_id: impl Into<String>,
        outcome_class: BenchmarkOutcomeClass,
        evidence_grade: BenchmarkEvidenceGrade,
        stage_vector: BenchmarkStageVector,
    ) -> Self {
        Self {
            benchmark_run_id: benchmark_run_id.into(),
            outcome_class,
            evidence_grade,
            stage_vector,
        }
    }
}

pub fn score_fat_native_run(
    target: &TargetRecord,
    run: &RunRecord,
    runtime_summary: Option<&ManagedRuntimeSummary>,
    readiness_report: Option<&ReadinessReport>,
    confidence_report: Option<&ConfidenceReport>,
    findings: &[Finding],
    diagnostics: &[DiagnosticRecord],
) -> BenchmarkOutcomeRecord {
    let summary_boot_evidence =
        runtime_summary.is_some_and(ManagedRuntimeSummary::has_boot_established_phase);
    let summary_partial_reachability =
        runtime_summary.is_some_and(ManagedRuntimeSummary::has_booted_services_unreachable_outcome);
    let service_interaction = run_has_service_interaction(run);
    let operator_access_signal = run_has_operator_access(run)
        || goal_is_ready_or_validated("shell-access", readiness_report, confidence_report)
        || goal_is_ready_or_validated("reference-bootstrap", readiness_report, confidence_report)
        || readiness_report.is_some_and(readiness_has_operator_surface);
    let listener_bind_signal =
        goal_is_ready_or_validated("listener-bind", readiness_report, confidence_report)
            || readiness_report.is_some_and(readiness_has_listener_bind_surface);
    let http_validation_signal =
        goal_is_validated("http-validation", readiness_report, confidence_report)
            || readiness_report.is_some_and(readiness_has_http_validated_surface);
    let process_chain_signal =
        goal_is_ready_or_validated("process-chain", readiness_report, confidence_report);
    let init_complete_signal =
        goal_is_ready_or_validated("init-complete", readiness_report, confidence_report);
    let readiness_boot_evidence = readiness_has_boot_evidence(readiness_report, confidence_report);
    let operator_access = if operator_access_signal {
        BenchmarkStageScore::reached()
    } else {
        BenchmarkStageScore::not_reached()
    };
    let stage_vector = BenchmarkStageVector {
        intake: if target_has_intake_evidence(target) {
            BenchmarkStageScore::reached()
        } else {
            BenchmarkStageScore::not_reached()
        },
        boot: if run_has_boot_evidence(run)
            || summary_boot_evidence
            || readiness_boot_evidence
            || init_complete_signal
            || listener_bind_signal
            || operator_access_signal
        {
            BenchmarkStageScore::reached()
        } else {
            BenchmarkStageScore::not_reached()
        },
        reachability: if service_interaction || http_validation_signal {
            BenchmarkStageScore::reached()
        } else if listener_bind_signal
            || process_chain_signal
            || summary_partial_reachability
            || summary_boot_evidence
            || readiness_boot_evidence
        {
            BenchmarkStageScore::partial()
        } else {
            BenchmarkStageScore::not_reached()
        },
        operator_access,
        research_utility: if summary_partial_reachability
            || summary_boot_evidence
            || readiness_report.is_some_and(|report| {
                !report.surfaces.is_empty() || !report.validated_goals.is_empty()
            })
            || confidence_report.is_some_and(|report| {
                report.level != crate::readiness::ConfidenceLevel::Low || !report.goals.is_empty()
            })
            || !run.active_endpoints.is_empty()
            || !findings.is_empty()
            || !diagnostics.is_empty()
        {
            BenchmarkStageScore::reached()
        } else {
            BenchmarkStageScore::not_reached()
        },
        exploit_readiness: if service_interaction
            || http_validation_signal
            || goal_is_validated("process-chain", readiness_report, confidence_report)
            || operator_access.status == BenchmarkStageStatus::Reached
        {
            BenchmarkStageScore::reached()
        } else {
            BenchmarkStageScore::not_reached()
        },
    };
    let outcome_class = classify_stage_vector(&stage_vector);
    let evidence_grade = evidence_grade_for_stage_vector(&stage_vector);

    BenchmarkOutcomeRecord::new(
        run.run_id.clone(),
        outcome_class,
        evidence_grade,
        stage_vector,
    )
}

impl ComparatorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::Internal => "internal",
            Self::Synthetic => "synthetic",
        }
    }
}

impl BenchmarkRunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RawUpstream => "raw-upstream",
            Self::ComparatorTuned => "comparator-tuned",
            Self::FatNative => "fat-native",
        }
    }
}

impl fmt::Display for BenchmarkRunRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExecutionId => write!(f, "benchmark execution_id must not be empty"),
            Self::NullExecutionId => write!(f, "benchmark execution_id must not be null"),
            Self::BenchmarkRunIdMismatch => write!(
                f,
                "benchmark_run_id does not match canonical benchmark run identity"
            ),
        }
    }
}

impl std::error::Error for BenchmarkRunRecordError {}

fn normalize_required_execution_id(
    execution_id: String,
) -> Result<String, BenchmarkRunRecordError> {
    let normalized = execution_id.trim();
    if normalized.is_empty() {
        Err(BenchmarkRunRecordError::EmptyExecutionId)
    } else {
        Ok(normalized.to_string())
    }
}

#[derive(Default)]
enum ExecutionIdField {
    #[default]
    Missing,
    Null,
    Present(String),
}

fn deserialize_execution_id_field<'de, D>(deserializer: D) -> Result<ExecutionIdField, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(execution_id) => Ok(ExecutionIdField::Present(execution_id)),
        None => Ok(ExecutionIdField::Null),
    }
}

fn canonical_benchmark_run_id(
    target_id: &str,
    comparator: &BenchmarkComparator,
    host_profile: &str,
    execution_id: &str,
) -> String {
    stable_prefixed_id(
        "brun",
        [
            target_id,
            comparator.comparator_id.as_str(),
            comparator.kind.as_str(),
            comparator.run_mode.as_str(),
            host_profile,
            execution_id,
        ],
    )
}

fn target_has_intake_evidence(target: &TargetRecord) -> bool {
    !target.target_id.trim().is_empty()
        && !target.project_id.trim().is_empty()
        && !target.display_name.trim().is_empty()
}

fn run_has_boot_evidence(run: &RunRecord) -> bool {
    matches!(
        run.status,
        RunStatus::Running
            | RunStatus::DegradedRunning
            | RunStatus::Completed
            | RunStatus::DegradedCompleted
    )
}

fn run_has_service_interaction(run: &RunRecord) -> bool {
    run.active_endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Service)
}

fn run_has_operator_access(run: &RunRecord) -> bool {
    run.active_endpoints.iter().any(|endpoint| {
        matches!(
            endpoint.kind,
            RuntimeEndpointKind::Shell | RuntimeEndpointKind::Debugger
        )
    })
}

fn readiness_has_operator_surface(report: &ReadinessReport) -> bool {
    report.surfaces.iter().any(|surface| {
        matches!(surface.kind.as_str(), "shell" | "debugger" | "monitor")
            && matches!(
                surface.readiness,
                SurfaceReadiness::Ready | SurfaceReadiness::Validated
            )
    })
}

fn readiness_has_listener_bind_surface(report: &ReadinessReport) -> bool {
    report.surfaces.iter().any(|surface| {
        matches!(surface.kind.as_str(), "service" | "port-forward")
            && matches!(
                surface.readiness,
                SurfaceReadiness::Ready | SurfaceReadiness::Validated
            )
    })
}

fn readiness_has_http_validated_surface(report: &ReadinessReport) -> bool {
    report.surfaces.iter().any(|surface| {
        matches!(surface.kind.as_str(), "service" | "port-forward")
            && surface.readiness == SurfaceReadiness::Validated
            && surface
                .uri
                .as_deref()
                .map(|uri| uri.starts_with("http://") || uri.starts_with("https://"))
                .unwrap_or_else(|| surface.port == Some(80))
    })
}

fn readiness_has_boot_evidence(
    readiness_report: Option<&ReadinessReport>,
    confidence_report: Option<&ConfidenceReport>,
) -> bool {
    readiness_report
        .is_some_and(|report| !report.surfaces.is_empty() || !report.validated_goals.is_empty())
        || confidence_report.is_some_and(|report| {
            report
                .goals
                .iter()
                .any(|goal| matches!(goal.state, GoalState::Ready | GoalState::Validated))
        })
}

fn goal_is_ready_or_validated(
    goal: &str,
    readiness_report: Option<&ReadinessReport>,
    confidence_report: Option<&ConfidenceReport>,
) -> bool {
    goal_is_validated(goal, readiness_report, confidence_report)
        || confidence_report.is_some_and(|report| {
            report.goals.iter().any(|entry| {
                entry.goal == goal && matches!(entry.state, GoalState::Ready | GoalState::Validated)
            })
        })
}

fn goal_is_validated(
    goal: &str,
    readiness_report: Option<&ReadinessReport>,
    confidence_report: Option<&ConfidenceReport>,
) -> bool {
    readiness_report.is_some_and(|report| report.validated_goals.iter().any(|entry| entry == goal))
        || confidence_report.is_some_and(|report| {
            report
                .goals
                .iter()
                .any(|entry| entry.goal == goal && entry.state == GoalState::Validated)
        })
}

fn classify_stage_vector(stage_vector: &BenchmarkStageVector) -> BenchmarkOutcomeClass {
    if stage_vector.boot.status != BenchmarkStageStatus::Reached {
        BenchmarkOutcomeClass::Failed
    } else if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        && stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        && stage_vector.reachability.status == BenchmarkStageStatus::Reached
        && stage_vector.operator_access.status == BenchmarkStageStatus::Reached
    {
        BenchmarkOutcomeClass::Strong
    } else if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        || stage_vector.reachability.status == BenchmarkStageStatus::Reached
        || stage_vector.operator_access.status == BenchmarkStageStatus::Reached
    {
        BenchmarkOutcomeClass::Useful
    } else if stage_vector.intake.status == BenchmarkStageStatus::Reached
        || stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        || stage_vector.reachability.status == BenchmarkStageStatus::Partial
    {
        BenchmarkOutcomeClass::Partial
    } else {
        BenchmarkOutcomeClass::Failed
    }
}

fn evidence_grade_for_stage_vector(stage_vector: &BenchmarkStageVector) -> BenchmarkEvidenceGrade {
    if stage_vector.exploit_readiness.status == BenchmarkStageStatus::Reached
        && stage_vector.research_utility.status == BenchmarkStageStatus::Reached
        && (stage_vector.reachability.status == BenchmarkStageStatus::Reached
            || stage_vector.operator_access.status == BenchmarkStageStatus::Reached)
    {
        BenchmarkEvidenceGrade::Rich
    } else if stage_vector.boot.status == BenchmarkStageStatus::Reached
        && (stage_vector.research_utility.status == BenchmarkStageStatus::Reached
            || stage_vector.reachability.status != BenchmarkStageStatus::NotReached)
    {
        BenchmarkEvidenceGrade::Moderate
    } else {
        BenchmarkEvidenceGrade::Minimal
    }
}
