use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticPhase {
    Intake,
    Extraction,
    Classification,
    ProfileResolution,
    StrategySelection,
    SubstrateProvisioning,
    BackendProvisioning,
    Preparation,
    RuntimeSynthesis,
    Launch,
    Boot,
    UserspaceStartup,
    SteadyState,
    Observation,
    Analysis,
    Export,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticOwner {
    Input,
    Extractor,
    Profile,
    StrategyEngine,
    Substrate,
    BackendDriver,
    BackendTool,
    RuntimeSynthesizer,
    Observer,
    Analyzer,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticClass {
    InputInvalid,
    InputUnsupported,
    ExtractionFailed,
    ClassificationAmbiguous,
    ProfileConflict,
    StrategyUnsatisfied,
    SubstrateUnavailable,
    SubstrateUnhealthy,
    BackendUnavailable,
    BackendProvisioningFailed,
    PreparationFailed,
    RuntimeSynthesisMissingState,
    RuntimeSynthesisInvalidState,
    LaunchFailed,
    LoaderFailed,
    CpuOrAbiMismatch,
    MemoryMappingFailed,
    DeviceOrPathMissing,
    IpcOrServiceMissing,
    NetworkExposureFailed,
    GuestUnreachable,
    DebugAttachFailed,
    AnalysisFailed,
    ExportFailed,
    CleanupFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticActionability {
    Retryable,
    FallbackRecommended,
    RequiresUserInput,
    RequiresProfileFix,
    RequiresBackendFix,
    RequiresSubstrateFix,
    RequiresTargetChange,
    TerminalForThisStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticRecord {
    pub diagnostic_id: String,
    pub run_id: String,
    pub phase: DiagnosticPhase,
    pub owner: DiagnosticOwner,
    pub class: DiagnosticClass,
    pub subclass: Option<String>,
    pub severity: DiagnosticSeverity,
    pub confidence: DiagnosticConfidence,
    pub actionability: DiagnosticActionability,
    pub summary: String,
    pub evidence_artifact_ids: Vec<String>,
    pub contradicted_artifact_ids: Vec<String>,
    pub suggested_next_actions: Vec<String>,
}

impl DiagnosticRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        phase: DiagnosticPhase,
        owner: DiagnosticOwner,
        class: DiagnosticClass,
        subclass: Option<String>,
        severity: DiagnosticSeverity,
        confidence: DiagnosticConfidence,
        actionability: DiagnosticActionability,
        summary: impl Into<String>,
        evidence_artifact_ids: Vec<String>,
        contradicted_artifact_ids: Vec<String>,
        suggested_next_actions: Vec<String>,
    ) -> Self {
        let run_id = run_id.into();
        let summary = summary.into();
        let diagnostic_id = stable_prefixed_id(
            "diag",
            [
                run_id.as_str(),
                phase.as_str(),
                owner.as_str(),
                class.as_str(),
                subclass.as_deref().unwrap_or(""),
            ],
        );

        Self {
            diagnostic_id,
            run_id,
            phase,
            owner,
            class,
            subclass,
            severity,
            confidence,
            actionability,
            summary,
            evidence_artifact_ids,
            contradicted_artifact_ids,
            suggested_next_actions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDiagnosticRecord {
    pub diagnostic_id: String,
    pub project_id: String,
    pub target_id: String,
    pub phase: DiagnosticPhase,
    pub owner: DiagnosticOwner,
    pub class: DiagnosticClass,
    pub subclass: Option<String>,
    pub severity: DiagnosticSeverity,
    pub confidence: DiagnosticConfidence,
    pub actionability: DiagnosticActionability,
    pub summary: String,
    pub evidence_artifact_ids: Vec<String>,
    pub contradicted_artifact_ids: Vec<String>,
    pub suggested_next_actions: Vec<String>,
}

impl TargetDiagnosticRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        phase: DiagnosticPhase,
        owner: DiagnosticOwner,
        class: DiagnosticClass,
        subclass: Option<String>,
        severity: DiagnosticSeverity,
        confidence: DiagnosticConfidence,
        actionability: DiagnosticActionability,
        summary: impl Into<String>,
        evidence_artifact_ids: Vec<String>,
        contradicted_artifact_ids: Vec<String>,
        suggested_next_actions: Vec<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let summary = summary.into();
        let diagnostic_id = stable_prefixed_id(
            "tdiag",
            [
                project_id.as_str(),
                target_id.as_str(),
                phase.as_str(),
                owner.as_str(),
                class.as_str(),
                subclass.as_deref().unwrap_or(""),
            ],
        );

        Self {
            diagnostic_id,
            project_id,
            target_id,
            phase,
            owner,
            class,
            subclass,
            severity,
            confidence,
            actionability,
            summary,
            evidence_artifact_ids,
            contradicted_artifact_ids,
            suggested_next_actions,
        }
    }

    pub fn from_runless_diagnostic(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        diagnostic: &DiagnosticRecord,
    ) -> Self {
        Self::new(
            project_id,
            target_id,
            diagnostic.phase,
            diagnostic.owner,
            diagnostic.class,
            diagnostic.subclass.clone(),
            diagnostic.severity,
            diagnostic.confidence,
            diagnostic.actionability,
            diagnostic.summary.clone(),
            diagnostic.evidence_artifact_ids.clone(),
            diagnostic.contradicted_artifact_ids.clone(),
            diagnostic.suggested_next_actions.clone(),
        )
    }
}

impl DiagnosticPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticPhase::Intake => "intake",
            DiagnosticPhase::Extraction => "extraction",
            DiagnosticPhase::Classification => "classification",
            DiagnosticPhase::ProfileResolution => "profile-resolution",
            DiagnosticPhase::StrategySelection => "strategy-selection",
            DiagnosticPhase::SubstrateProvisioning => "substrate-provisioning",
            DiagnosticPhase::BackendProvisioning => "backend-provisioning",
            DiagnosticPhase::Preparation => "preparation",
            DiagnosticPhase::RuntimeSynthesis => "runtime-synthesis",
            DiagnosticPhase::Launch => "launch",
            DiagnosticPhase::Boot => "boot",
            DiagnosticPhase::UserspaceStartup => "userspace-startup",
            DiagnosticPhase::SteadyState => "steady-state",
            DiagnosticPhase::Observation => "observation",
            DiagnosticPhase::Analysis => "analysis",
            DiagnosticPhase::Export => "export",
            DiagnosticPhase::Cleanup => "cleanup",
        }
    }
}

impl DiagnosticOwner {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticOwner::Input => "input",
            DiagnosticOwner::Extractor => "extractor",
            DiagnosticOwner::Profile => "profile",
            DiagnosticOwner::StrategyEngine => "strategy-engine",
            DiagnosticOwner::Substrate => "substrate",
            DiagnosticOwner::BackendDriver => "backend-driver",
            DiagnosticOwner::BackendTool => "backend-tool",
            DiagnosticOwner::RuntimeSynthesizer => "runtime-synthesizer",
            DiagnosticOwner::Observer => "observer",
            DiagnosticOwner::Analyzer => "analyzer",
            DiagnosticOwner::Policy => "policy",
        }
    }
}

impl DiagnosticClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticClass::InputInvalid => "input-invalid",
            DiagnosticClass::InputUnsupported => "input-unsupported",
            DiagnosticClass::ExtractionFailed => "extraction-failed",
            DiagnosticClass::ClassificationAmbiguous => "classification-ambiguous",
            DiagnosticClass::ProfileConflict => "profile-conflict",
            DiagnosticClass::StrategyUnsatisfied => "strategy-unsatisfied",
            DiagnosticClass::SubstrateUnavailable => "substrate-unavailable",
            DiagnosticClass::SubstrateUnhealthy => "substrate-unhealthy",
            DiagnosticClass::BackendUnavailable => "backend-unavailable",
            DiagnosticClass::BackendProvisioningFailed => "backend-provisioning-failed",
            DiagnosticClass::PreparationFailed => "preparation-failed",
            DiagnosticClass::RuntimeSynthesisMissingState => "runtime-synthesis-missing-state",
            DiagnosticClass::RuntimeSynthesisInvalidState => "runtime-synthesis-invalid-state",
            DiagnosticClass::LaunchFailed => "launch-failed",
            DiagnosticClass::LoaderFailed => "loader-failed",
            DiagnosticClass::CpuOrAbiMismatch => "cpu-or-abi-mismatch",
            DiagnosticClass::MemoryMappingFailed => "memory-mapping-failed",
            DiagnosticClass::DeviceOrPathMissing => "device-or-path-missing",
            DiagnosticClass::IpcOrServiceMissing => "ipc-or-service-missing",
            DiagnosticClass::NetworkExposureFailed => "network-exposure-failed",
            DiagnosticClass::GuestUnreachable => "guest-unreachable",
            DiagnosticClass::DebugAttachFailed => "debug-attach-failed",
            DiagnosticClass::AnalysisFailed => "analysis-failed",
            DiagnosticClass::ExportFailed => "export-failed",
            DiagnosticClass::CleanupFailed => "cleanup-failed",
        }
    }
}
