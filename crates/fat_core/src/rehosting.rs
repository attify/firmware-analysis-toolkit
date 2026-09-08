use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;
use crate::rehosting_recipe::{RecipeDeviceNodePlan, RecipeFilesystemTransform, RecipeLaunchPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RehostingMode {
    Service,
    System,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceReadiness {
    Registered,
    Ready,
    Validated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    SystemResource,
    InitDependency,
    IpcDependency,
    TargetLaunch,
    Validation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairActionKind {
    CreateNode,
    PatchConfig,
    InjectEnv,
    StartPeerService,
    RetryPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetExecutionProfile {
    pub profile_id: String,
    pub project_id: String,
    pub target_id: String,
    pub architecture: Option<String>,
    pub family_id: Option<String>,
    pub evidence: Vec<String>,
    pub nvram_hints: Vec<String>,
    pub network_hints: Vec<String>,
    pub init_hints: Vec<String>,
    pub candidate_modes: Vec<RehostingMode>,
}

impl TargetExecutionProfile {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        architecture: Option<&str>,
        family_id: Option<&str>,
        evidence: Vec<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let architecture_value = architecture.map(str::to_string);
        let family_value = family_id.map(str::to_string);
        let mut evidence_signature = evidence.clone();
        evidence_signature.sort();
        let evidence_signature = if evidence_signature.is_empty() {
            "no-evidence".to_string()
        } else {
            evidence_signature.join("|")
        };
        let profile_id = stable_prefixed_id(
            "rprof",
            [
                project_id.as_str(),
                target_id.as_str(),
                architecture.unwrap_or("unknown"),
                family_id.unwrap_or("unknown"),
                evidence_signature.as_str(),
            ],
        );

        Self {
            profile_id,
            project_id,
            target_id,
            architecture: architecture_value,
            family_id: family_value,
            evidence,
            nvram_hints: Vec::new(),
            network_hints: Vec::new(),
            init_hints: Vec::new(),
            candidate_modes: Vec::new(),
        }
    }

    pub fn with_nvram_hints(mut self, nvram_hints: Vec<String>) -> Self {
        self.nvram_hints = nvram_hints;
        self
    }

    pub fn with_network_hints(mut self, network_hints: Vec<String>) -> Self {
        self.network_hints = network_hints;
        self
    }

    pub fn with_init_hints(mut self, init_hints: Vec<String>) -> Self {
        self.init_hints = init_hints;
        self
    }

    pub fn with_candidate_modes(mut self, candidate_modes: Vec<RehostingMode>) -> Self {
        self.candidate_modes = candidate_modes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSurfaceRecord {
    pub surface_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub name: String,
    pub kind: String,
    pub readiness: SurfaceReadiness,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub uri: Option<String>,
    pub validation_note: Option<String>,
}

impl RuntimeSurfaceRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        name: impl Into<String>,
        kind: impl Into<String>,
        identity_hint: impl Into<String>,
        readiness: SurfaceReadiness,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let name = name.into();
        let kind = kind.into();
        let identity_hint = identity_hint.into();
        let surface_id = stable_prefixed_id(
            "surface",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                name.as_str(),
                kind.as_str(),
                identity_hint.as_str(),
            ],
        );

        Self {
            surface_id,
            project_id,
            target_id,
            session_id,
            run_id,
            name,
            kind,
            readiness,
            host: None,
            port: None,
            uri: None,
            validation_note: None,
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    pub fn with_validation_note(mut self, validation_note: impl Into<String>) -> Self {
        self.validation_note = Some(validation_note.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub readiness_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub requested_goals: Vec<String>,
    pub validated_goals: Vec<String>,
    pub summary: Option<String>,
    pub surfaces: Vec<RuntimeSurfaceRecord>,
}

impl ReadinessReport {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        requested_goals: Vec<String>,
        surfaces: Vec<RuntimeSurfaceRecord>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let readiness_id = stable_prefixed_id(
            "ready",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
            ],
        );

        Self {
            readiness_id,
            project_id,
            target_id,
            session_id,
            run_id,
            requested_goals,
            validated_goals: Vec::new(),
            summary: None,
            surfaces,
        }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    pub fn with_validated_goals(mut self, validated_goals: Vec<String>) -> Self {
        self.validated_goals = validated_goals;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub sequence: u32,
    pub mode: RehostingMode,
    pub summary: Option<String>,
}

impl AttemptRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        sequence: u32,
        mode: RehostingMode,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let attempt_id = stable_prefixed_id(
            "attempt",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                &sequence.to_string(),
                mode.as_str(),
            ],
        );

        Self {
            attempt_id,
            project_id,
            target_id,
            session_id,
            run_id,
            sequence,
            mode,
            summary: None,
        }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRecord {
    pub repair_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub failure_class: FailureClass,
    pub action: RepairActionKind,
    pub detail: Option<String>,
}

impl RepairRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        attempt_id: impl Into<String>,
        failure_class: FailureClass,
        action: RepairActionKind,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let attempt_id = attempt_id.into();
        let repair_id = stable_prefixed_id(
            "repair",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                attempt_id.as_str(),
                failure_class.as_str(),
                action.as_str(),
            ],
        );

        Self {
            repair_id,
            project_id,
            target_id,
            session_id,
            run_id,
            attempt_id,
            failure_class,
            action,
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairMaterializationRecord {
    pub repair_materialization_id: String,
    pub project_id: String,
    pub target_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub repair_id: String,
    pub action: RepairActionKind,
    pub device_nodes: Vec<RecipeDeviceNodePlan>,
    pub filesystem_transforms: Vec<RecipeFilesystemTransform>,
    pub launch_plan: Option<RecipeLaunchPlan>,
    pub detail: Option<String>,
}

impl RepairMaterializationRecord {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
        attempt_id: impl Into<String>,
        repair_id: impl Into<String>,
        action: RepairActionKind,
        device_nodes: Vec<RecipeDeviceNodePlan>,
        filesystem_transforms: Vec<RecipeFilesystemTransform>,
        launch_plan: Option<RecipeLaunchPlan>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let session_id = session_id.into();
        let run_id = run_id.into();
        let attempt_id = attempt_id.into();
        let repair_id = repair_id.into();
        let repair_materialization_id = stable_prefixed_id(
            "repair-materialization",
            [
                project_id.as_str(),
                target_id.as_str(),
                session_id.as_str(),
                run_id.as_str(),
                repair_id.as_str(),
                action.as_str(),
            ],
        );

        Self {
            repair_materialization_id,
            project_id,
            target_id,
            session_id,
            run_id,
            attempt_id,
            repair_id,
            action,
            device_nodes,
            filesystem_transforms,
            launch_plan,
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl RehostingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RehostingMode::Service => "service",
            RehostingMode::System => "system",
            RehostingMode::Reference => "reference",
        }
    }
}

impl SurfaceReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            SurfaceReadiness::Registered => "registered",
            SurfaceReadiness::Ready => "ready",
            SurfaceReadiness::Validated => "validated",
        }
    }
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureClass::SystemResource => "system-resource",
            FailureClass::InitDependency => "init-dependency",
            FailureClass::IpcDependency => "ipc-dependency",
            FailureClass::TargetLaunch => "target-launch",
            FailureClass::Validation => "validation",
        }
    }
}

impl RepairActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RepairActionKind::CreateNode => "create-node",
            RepairActionKind::PatchConfig => "patch-config",
            RepairActionKind::InjectEnv => "inject-env",
            RepairActionKind::StartPeerService => "start-peer-service",
            RepairActionKind::RetryPlan => "retry-plan",
        }
    }
}
