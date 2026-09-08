use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::substrate::{BackendSubstrateContract, BackendSubstrateKind};
use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticRecord, DiagnosticSeverity,
};
use fat_core::runs::{RuntimeEndpoint, RuntimeEndpointKind};
use serde::{Deserialize, Serialize};

const BASE_IMAGE_NAME: &str = "base-image.qcow2";
const GUEST_AGENT_NAME: &str = "guest-agent";
pub const MANAGED_LINUX_VM_BUNDLE_DIR_ENV: &str = "FAT_MANAGED_LINUX_VM_BUNDLE_DIR";
pub const MANAGED_LINUX_VM_BUNDLE_VERSION_ENV: &str = "FAT_MANAGED_LINUX_VM_BUNDLE_VERSION";
pub const FIRMAE_UPSTREAM_DIR_ENV: &str = "FAT_FIRMAE_UPSTREAM_DIR";
pub const FIRMAE_HOST_PYTHON_ENV: &str = "FAT_FIRMAE_HOST_PYTHON";
pub const FIRMAE_DOCKER_PSQL_IP_ENV: &str = "FAT_FIRMAE_DOCKER_PSQL_IP";
pub const FIRMAE_UPSTREAM_BRAND_ENV: &str = "FAT_FIRMAE_UPSTREAM_BRAND";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmRequest {
    pub backend_id: String,
    pub run_id: Option<String>,
    pub bundle_version: String,
    pub bundle_dir: PathBuf,
    pub workspace_root: PathBuf,
    pub mapped_ports: Vec<u16>,
}

impl ManagedLinuxVmRequest {
    pub fn new(
        backend_id: impl Into<String>,
        bundle_version: impl Into<String>,
        bundle_dir: PathBuf,
        workspace_root: PathBuf,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            run_id: None,
            bundle_version: bundle_version.into(),
            bundle_dir,
            workspace_root,
            mapped_ports: Vec::new(),
        }
    }

    pub fn with_mapped_ports(mut self, mapped_ports: Vec<u16>) -> Self {
        self.mapped_ports = mapped_ports;
        self
    }

    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmBundle {
    pub bundle_version: String,
    pub base_image: PathBuf,
    pub guest_agent: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedLinuxVmPrepared {
    pub request: ManagedLinuxVmRequest,
    pub bundle: ManagedLinuxVmBundle,
    pub workspace_dir: PathBuf,
    pub contract: BackendSubstrateContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmLaunchResult {
    pub substrate: BackendSubstrateKind,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub endpoints: Vec<RuntimeEndpoint>,
    pub launch_manifest: Option<ManagedLinuxVmLaunchManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmStopResult {
    pub substrate: BackendSubstrateKind,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedLinuxVmStopError {
    pub diagnostic: DiagnosticRecord,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmProbeResult {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedLinuxVmProbeError {
    pub diagnostic: DiagnosticRecord,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedLinuxVmPreparationError {
    pub contract: BackendSubstrateContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamLaunchRequest {
    pub upstream_dir: PathBuf,
    pub host_python: PathBuf,
    pub firmware_path: PathBuf,
    pub brand: String,
}

impl ManagedLinuxVmUpstreamLaunchRequest {
    pub fn new(
        upstream_dir: PathBuf,
        host_python: PathBuf,
        firmware_path: PathBuf,
        brand: impl Into<String>,
    ) -> Self {
        Self {
            upstream_dir,
            host_python,
            firmware_path,
            brand: brand.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamLaunchResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub container_name: Option<String>,
    pub declared_artifact_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagedLinuxVmUpstreamLaunchError {
    pub diagnostic: DiagnosticRecord,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamObservationRequest {
    pub upstream_dir: PathBuf,
    pub guest_ip: Option<String>,
}

impl ManagedLinuxVmUpstreamObservationRequest {
    pub fn new(upstream_dir: PathBuf, guest_ip: Option<String>) -> Self {
        Self {
            upstream_dir,
            guest_ip,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamObservationResult {
    pub container_name: Option<String>,
    pub container_running: bool,
    pub scratch_artifacts_present: bool,
    pub observed_artifact_paths: Vec<PathBuf>,
    pub guest_ip: Option<String>,
    pub guest_reachable: bool,
    pub port_80_reachable: bool,
    pub port_31337_reachable: bool,
    pub port_31338_reachable: bool,
    pub runtime_status: ManagedLinuxVmRuntimeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamStopRequest {
    pub container_name: String,
}

impl ManagedLinuxVmUpstreamStopRequest {
    pub fn new(container_name: impl Into<String>) -> Self {
        Self {
            container_name: container_name.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedLinuxVmUpstreamStopResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub container_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmLaunchManifest {
    pub endpoints: Vec<ManagedLinuxVmLaunchEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmLaunchEndpoint {
    pub kind: RuntimeEndpointKind,
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub target_port: Option<u16>,
    #[serde(default)]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmLaunchState {
    pub backend_id: String,
    pub driver_profile: String,
    pub control_contract: ManagedLinuxVmControlContract,
    pub lifecycle_adapter: ManagedLinuxVmLifecycleAdapter,
    pub launch_mode: ManagedLinuxVmLaunchMode,
    pub stop_mode: ManagedLinuxVmStopMode,
    pub bundle_version: String,
    pub workspace_dir: String,
    pub base_image: String,
    pub guest_agent: String,
    pub mapped_ports: Vec<u16>,
    pub endpoints: Vec<RuntimeEndpoint>,
    pub launch_manifest_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmProbeSource {
    ProbeOnStatus,
    BackgroundSupervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmProbeOutcome {
    Healthy,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmProbeResultContract {
    ExitCodeOnlyV1,
    FirmaeLegacyWrapperProbeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmProbeState {
    pub backend_id: String,
    pub driver_profile: String,
    pub control_contract: ManagedLinuxVmControlContract,
    pub lifecycle_adapter: ManagedLinuxVmLifecycleAdapter,
    pub result_contract: ManagedLinuxVmProbeResultContract,
    pub result_contract_verified: bool,
    pub workspace_dir: String,
    pub probe_source: ManagedLinuxVmProbeSource,
    pub outcome: ManagedLinuxVmProbeOutcome,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmStopState {
    pub backend_id: String,
    pub driver_profile: String,
    pub control_contract: ManagedLinuxVmControlContract,
    pub lifecycle_adapter: ManagedLinuxVmLifecycleAdapter,
    pub stop_mode: ManagedLinuxVmStopMode,
    pub result_contract: ManagedLinuxVmStopResultContract,
    pub result_contract_verified: bool,
    pub workspace_dir: String,
    pub exit_code: Option<i32>,
    pub workspace_removed: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmRuntimePhase {
    LaunchComplete,
    ProbeHealthy,
    ProbeUnreachable,
    StopComplete,
    StopFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmRuntimeOutcome {
    GuestUnreachable,
    BootedServicesUnreachable,
    BootedServicesReachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLinuxVmRuntimeStatus {
    pub backend_id: String,
    pub driver_profile: String,
    pub control_contract: ManagedLinuxVmControlContract,
    pub lifecycle_adapter: ManagedLinuxVmLifecycleAdapter,
    pub phase: ManagedLinuxVmRuntimePhase,
    pub runtime_outcome: Option<ManagedLinuxVmRuntimeOutcome>,
    pub bundle_version: String,
    pub workspace_dir: String,
    pub base_image: String,
    pub guest_agent: String,
    pub mapped_ports: Vec<u16>,
    pub endpoints: Vec<RuntimeEndpoint>,
    pub launch_mode: ManagedLinuxVmLaunchMode,
    pub stop_mode: ManagedLinuxVmStopMode,
    pub launch_manifest_present: bool,
    pub probe_source: Option<ManagedLinuxVmProbeSource>,
    pub probe_outcome: Option<ManagedLinuxVmProbeOutcome>,
    pub probe_result_contract: Option<ManagedLinuxVmProbeResultContract>,
    pub probe_result_contract_verified: Option<bool>,
    pub stop_result_contract: Option<ManagedLinuxVmStopResultContract>,
    pub stop_result_contract_verified: Option<bool>,
    pub stop_exit_code: Option<i32>,
    pub workspace_removed: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmLifecycleAdapter {
    Generic,
    LegacyWrapper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmLaunchMode {
    GuestAgentLaunch,
    LegacyWrapperLaunch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmStopMode {
    GuestAgentStop,
    LegacyWrapperStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmStopResultContract {
    ExitCodeOnlyV1,
    FirmaeLegacyWrapperStopV1,
    FirmaeUpstreamContainerStopV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedLinuxVmControlContract {
    GenericGuestAgentV1,
    FirmaeLegacyWrapperV1,
}

#[derive(Debug, Default)]
pub struct ManagedLinuxVmManager;

impl ManagedLinuxVmPrepared {
    pub fn control_contract(&self) -> ManagedLinuxVmControlContract {
        match self.request.backend_id.as_str() {
            "firmae" => ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1,
            _ => ManagedLinuxVmControlContract::GenericGuestAgentV1,
        }
    }

    pub fn lifecycle_adapter(&self) -> ManagedLinuxVmLifecycleAdapter {
        match self.request.backend_id.as_str() {
            "firmae" | "firmadyne" => ManagedLinuxVmLifecycleAdapter::LegacyWrapper,
            _ => ManagedLinuxVmLifecycleAdapter::Generic,
        }
    }

    pub fn launch_mode(&self) -> ManagedLinuxVmLaunchMode {
        match self.request.backend_id.as_str() {
            "firmae" | "firmadyne" => ManagedLinuxVmLaunchMode::LegacyWrapperLaunch,
            _ => ManagedLinuxVmLaunchMode::GuestAgentLaunch,
        }
    }

    pub fn stop_mode(&self) -> ManagedLinuxVmStopMode {
        match self.request.backend_id.as_str() {
            "firmae" | "firmadyne" => ManagedLinuxVmStopMode::LegacyWrapperStop,
            _ => ManagedLinuxVmStopMode::GuestAgentStop,
        }
    }

    pub fn driver_profile(&self) -> &'static str {
        match self.request.backend_id.as_str() {
            "firmae" => "firmae-managed-legacy-wrapper",
            "firmadyne" => "firmadyne-managed-legacy-wrapper",
            _ => "managed-linux-vm-generic",
        }
    }

    pub fn launch_state(&self, result: &ManagedLinuxVmLaunchResult) -> ManagedLinuxVmLaunchState {
        ManagedLinuxVmLaunchState {
            backend_id: self.request.backend_id.clone(),
            driver_profile: self.driver_profile().to_string(),
            control_contract: self.control_contract(),
            lifecycle_adapter: self.lifecycle_adapter(),
            launch_mode: self.launch_mode(),
            stop_mode: self.stop_mode(),
            bundle_version: self.bundle.bundle_version.clone(),
            workspace_dir: self.workspace_dir.to_string_lossy().into_owned(),
            base_image: self.bundle.base_image.to_string_lossy().into_owned(),
            guest_agent: self.bundle.guest_agent.to_string_lossy().into_owned(),
            mapped_ports: self.request.mapped_ports.clone(),
            endpoints: result.endpoints.clone(),
            launch_manifest_present: result.launch_manifest.is_some(),
        }
    }

    pub fn runtime_status_from_launch_state(
        &self,
        launch_state: &ManagedLinuxVmLaunchState,
    ) -> ManagedLinuxVmRuntimeStatus {
        ManagedLinuxVmRuntimeStatus::from_launch_state(launch_state)
    }

    pub fn runtime_status(
        &self,
        endpoints: Vec<RuntimeEndpoint>,
        launch_manifest_present: bool,
    ) -> ManagedLinuxVmRuntimeStatus {
        ManagedLinuxVmRuntimeStatus {
            backend_id: self.request.backend_id.clone(),
            driver_profile: self.driver_profile().to_string(),
            control_contract: self.control_contract(),
            lifecycle_adapter: self.lifecycle_adapter(),
            phase: ManagedLinuxVmRuntimePhase::LaunchComplete,
            runtime_outcome: None,
            bundle_version: self.bundle.bundle_version.clone(),
            workspace_dir: self.workspace_dir.to_string_lossy().into_owned(),
            base_image: self.bundle.base_image.to_string_lossy().into_owned(),
            guest_agent: self.bundle.guest_agent.to_string_lossy().into_owned(),
            mapped_ports: self.request.mapped_ports.clone(),
            endpoints,
            launch_mode: self.launch_mode(),
            stop_mode: self.stop_mode(),
            launch_manifest_present,
            probe_source: None,
            probe_outcome: None,
            probe_result_contract: None,
            probe_result_contract_verified: None,
            stop_result_contract: None,
            stop_result_contract_verified: None,
            stop_exit_code: None,
            workspace_removed: None,
        }
    }

    pub fn probe_state(
        &self,
        source: ManagedLinuxVmProbeSource,
        outcome: ManagedLinuxVmProbeOutcome,
        result_contract_verified: bool,
        stdout: &str,
        stderr: &str,
    ) -> ManagedLinuxVmProbeState {
        ManagedLinuxVmProbeState {
            backend_id: self.request.backend_id.clone(),
            driver_profile: self.driver_profile().to_string(),
            control_contract: self.control_contract(),
            lifecycle_adapter: self.lifecycle_adapter(),
            result_contract: self.probe_result_contract(),
            result_contract_verified,
            workspace_dir: self.workspace_dir.to_string_lossy().into_owned(),
            probe_source: source,
            outcome,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    pub fn stop_state(
        &self,
        exit_code: Option<i32>,
        workspace_removed: bool,
        result_contract_verified: bool,
        stdout: &str,
        stderr: &str,
    ) -> ManagedLinuxVmStopState {
        ManagedLinuxVmStopState {
            backend_id: self.request.backend_id.clone(),
            driver_profile: self.driver_profile().to_string(),
            control_contract: self.control_contract(),
            lifecycle_adapter: self.lifecycle_adapter(),
            stop_mode: self.stop_mode(),
            result_contract: self.stop_result_contract(),
            result_contract_verified,
            workspace_dir: self.workspace_dir.to_string_lossy().into_owned(),
            exit_code,
            workspace_removed,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    pub fn upstream_stop_state(
        &self,
        exit_code: Option<i32>,
        workspace_removed: bool,
        result_contract_verified: bool,
        stdout: &str,
        stderr: &str,
    ) -> ManagedLinuxVmStopState {
        ManagedLinuxVmStopState {
            backend_id: self.request.backend_id.clone(),
            driver_profile: self.driver_profile().to_string(),
            control_contract: self.control_contract(),
            lifecycle_adapter: self.lifecycle_adapter(),
            stop_mode: self.stop_mode(),
            result_contract: ManagedLinuxVmStopResultContract::FirmaeUpstreamContainerStopV1,
            result_contract_verified,
            workspace_dir: self.workspace_dir.to_string_lossy().into_owned(),
            exit_code,
            workspace_removed,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    pub fn probe_result_contract(&self) -> ManagedLinuxVmProbeResultContract {
        match self.control_contract() {
            ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 => {
                ManagedLinuxVmProbeResultContract::FirmaeLegacyWrapperProbeV1
            }
            ManagedLinuxVmControlContract::GenericGuestAgentV1 => {
                ManagedLinuxVmProbeResultContract::ExitCodeOnlyV1
            }
        }
    }

    pub fn stop_result_contract(&self) -> ManagedLinuxVmStopResultContract {
        match self.control_contract() {
            ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 => {
                ManagedLinuxVmStopResultContract::FirmaeLegacyWrapperStopV1
            }
            ManagedLinuxVmControlContract::GenericGuestAgentV1 => {
                ManagedLinuxVmStopResultContract::ExitCodeOnlyV1
            }
        }
    }
}

impl ManagedLinuxVmRuntimeStatus {
    pub fn from_launch_state(launch_state: &ManagedLinuxVmLaunchState) -> Self {
        Self {
            backend_id: launch_state.backend_id.clone(),
            driver_profile: launch_state.driver_profile.clone(),
            control_contract: launch_state.control_contract,
            lifecycle_adapter: launch_state.lifecycle_adapter,
            phase: ManagedLinuxVmRuntimePhase::LaunchComplete,
            runtime_outcome: None,
            bundle_version: launch_state.bundle_version.clone(),
            workspace_dir: launch_state.workspace_dir.clone(),
            base_image: launch_state.base_image.clone(),
            guest_agent: launch_state.guest_agent.clone(),
            mapped_ports: launch_state.mapped_ports.clone(),
            endpoints: launch_state.endpoints.clone(),
            launch_mode: launch_state.launch_mode,
            stop_mode: launch_state.stop_mode,
            launch_manifest_present: launch_state.launch_manifest_present,
            probe_source: None,
            probe_outcome: None,
            probe_result_contract: None,
            probe_result_contract_verified: None,
            stop_result_contract: None,
            stop_result_contract_verified: None,
            stop_exit_code: None,
            workspace_removed: None,
        }
    }

    pub fn with_probe_state(
        mut self,
        probe_state: &ManagedLinuxVmProbeState,
        phase: ManagedLinuxVmRuntimePhase,
    ) -> Self {
        self.phase = phase;
        self.probe_source = Some(probe_state.probe_source);
        self.probe_outcome = Some(probe_state.outcome);
        self.probe_result_contract = Some(probe_state.result_contract);
        self.probe_result_contract_verified = Some(probe_state.result_contract_verified);
        self.runtime_outcome = self.infer_runtime_outcome_for_phase(phase);
        self
    }

    pub fn with_stop_state(
        mut self,
        stop_state: &ManagedLinuxVmStopState,
        phase: ManagedLinuxVmRuntimePhase,
    ) -> Self {
        self.phase = phase;
        self.stop_result_contract = Some(stop_state.result_contract);
        self.stop_result_contract_verified = Some(stop_state.result_contract_verified);
        self.stop_exit_code = stop_state.exit_code;
        self.workspace_removed = Some(stop_state.workspace_removed);
        self
    }

    fn infer_runtime_outcome_for_phase(
        &self,
        phase: ManagedLinuxVmRuntimePhase,
    ) -> Option<ManagedLinuxVmRuntimeOutcome> {
        if phase == ManagedLinuxVmRuntimePhase::ProbeUnreachable
            && !self.endpoints.is_empty()
            && !self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Service)
        {
            return Some(ManagedLinuxVmRuntimeOutcome::BootedServicesUnreachable);
        }

        None
    }
}

impl ManagedLinuxVmManager {
    pub fn new() -> Self {
        Self
    }

    pub fn prepare(
        &self,
        request: ManagedLinuxVmRequest,
    ) -> Result<ManagedLinuxVmPrepared, ManagedLinuxVmPreparationError> {
        let bundle = bundle_for_request(&request)?;
        let workspace_dir = request
            .workspace_root
            .join("managed-linux-vm")
            .join(&request.backend_id)
            .join(&request.bundle_version);
        fs::create_dir_all(&workspace_dir).map_err(|err| ManagedLinuxVmPreparationError {
            contract: BackendSubstrateContract::unavailable(
                BackendSubstrateKind::ManagedLinuxVm,
                "managed-linux-vm",
                "managed Linux VM workspace could not be initialized",
                format!("failed to create workspace: {err}"),
            ),
        })?;
        let contract = prepare_contract_for(&request);

        Ok(ManagedLinuxVmPrepared {
            request,
            bundle,
            workspace_dir,
            contract,
        })
    }

    pub fn resume(
        &self,
        request: ManagedLinuxVmRequest,
    ) -> Result<ManagedLinuxVmPrepared, ManagedLinuxVmPreparationError> {
        let bundle = bundle_for_request(&request)?;
        let workspace_dir = request
            .workspace_root
            .join("managed-linux-vm")
            .join(&request.backend_id)
            .join(&request.bundle_version);
        if !workspace_dir.is_dir() {
            return Err(ManagedLinuxVmPreparationError {
                contract: BackendSubstrateContract::unavailable(
                    BackendSubstrateKind::ManagedLinuxVm,
                    "managed-linux-vm",
                    "managed Linux VM workspace is missing",
                    format!("missing workspace: {}", workspace_dir.display()),
                ),
            });
        }
        let contract = prepare_contract_for(&request);

        Ok(ManagedLinuxVmPrepared {
            request,
            bundle,
            workspace_dir,
            contract,
        })
    }

    pub fn launch(
        &self,
        prepared: &ManagedLinuxVmPrepared,
    ) -> Result<ManagedLinuxVmLaunchResult, DiagnosticRecord> {
        let output = Command::new(&prepared.bundle.guest_agent)
            .args(launch_args_for(prepared))
            .current_dir(&prepared.workspace_dir)
            .output()
            .map_err(|err| {
                launch_error_for(
                    prepared,
                    format!("failed to spawn managed guest launcher: {err}"),
                    None,
                    "",
                    "",
                )
            })?;

        if !output.status.success() {
            return Err(launch_error_for(
                prepared,
                "managed guest launcher exited unsuccessfully".to_string(),
                output.status.code(),
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let launch_manifest = parse_launch_manifest(prepared, &stdout)?;
        let endpoints = launch_manifest
            .as_ref()
            .map(runtime_endpoints_from_manifest)
            .unwrap_or_else(|| build_endpoints(&prepared.request.mapped_ports));

        Ok(ManagedLinuxVmLaunchResult {
            substrate: BackendSubstrateKind::ManagedLinuxVm,
            exit_code: output.status.code(),
            stdout,
            stderr,
            endpoints,
            launch_manifest,
        })
    }

    pub fn launch_firmae_upstream(
        &self,
        prepared: &ManagedLinuxVmPrepared,
        request: &ManagedLinuxVmUpstreamLaunchRequest,
    ) -> Result<ManagedLinuxVmUpstreamLaunchResult, ManagedLinuxVmUpstreamLaunchError> {
        if prepared.control_contract() != ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 {
            return Err(upstream_launch_error_for(
                prepared,
                "upstream FirmAE launch is only available for firmae".to_string(),
                None,
                "",
                "",
            ));
        }

        validate_firmae_upstream_checkout(prepared, request)?;

        let output = Command::new(&request.host_python)
            .arg("docker-helper.py")
            .arg("-ec")
            .arg(request.brand.as_str())
            .arg(&request.firmware_path)
            .current_dir(&request.upstream_dir)
            .env(
                FIRMAE_DOCKER_PSQL_IP_ENV,
                firmae_docker_psql_ip_from_env()
                    .unwrap_or_else(|| "host.docker.internal".to_string()),
            )
            .output()
            .map_err(|err| {
                upstream_launch_error_for(
                    prepared,
                    format!("failed to spawn upstream FirmAE launch helper: {err}"),
                    None,
                    "",
                    "",
                )
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(upstream_launch_error_for(
                prepared,
                "upstream FirmAE launch helper exited unsuccessfully".to_string(),
                output.status.code(),
                &stdout,
                &stderr,
            ));
        }

        Ok(ManagedLinuxVmUpstreamLaunchResult {
            exit_code: output.status.code(),
            stdout: stdout.clone(),
            stderr,
            container_name: declared_container_name_from_stdout(&stdout),
            declared_artifact_paths: declared_artifact_paths_from_stdout(
                &stdout,
                &request.upstream_dir,
            ),
        })
    }

    pub fn observe_firmae_upstream(
        &self,
        prepared: &ManagedLinuxVmPrepared,
        launch_result: &ManagedLinuxVmUpstreamLaunchResult,
        request: &ManagedLinuxVmUpstreamObservationRequest,
        command_probe: &impl crate::model::CommandProbe,
    ) -> Result<ManagedLinuxVmUpstreamObservationResult, DiagnosticRecord> {
        if prepared.control_contract() != ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 {
            return Err(upstream_observation_error_for(
                prepared,
                "upstream FirmAE observation is only available for firmae".to_string(),
            ));
        }

        let observed_artifact_paths = launch_result.declared_artifact_paths.clone();
        let scratch_artifacts_present = !observed_artifact_paths.is_empty()
            && observed_artifact_paths.iter().all(|path| path.is_file());
        let guest_ip = request
            .guest_ip
            .clone()
            .or_else(|| infer_guest_ip_from_artifacts(&observed_artifact_paths));
        let container_name = launch_result.container_name.clone();
        let container_running = container_name
            .as_deref()
            .is_some_and(|name| docker_container_running(command_probe, name));
        let guest_reachable = guest_ip
            .as_deref()
            .is_some_and(|ip| ping_guest(command_probe, ip));
        let port_80_reachable = guest_ip
            .as_deref()
            .is_some_and(|ip| probe_guest_port(command_probe, ip, 80));
        let port_31337_reachable = guest_ip
            .as_deref()
            .is_some_and(|ip| probe_guest_port(command_probe, ip, 31337));
        let port_31338_reachable = guest_ip
            .as_deref()
            .is_some_and(|ip| probe_guest_port(command_probe, ip, 31338));
        let any_known_service_reachable =
            port_80_reachable || port_31337_reachable || port_31338_reachable;

        let phase = if guest_reachable {
            if any_known_service_reachable {
                ManagedLinuxVmRuntimePhase::ProbeHealthy
            } else {
                ManagedLinuxVmRuntimePhase::ProbeUnreachable
            }
        } else {
            ManagedLinuxVmRuntimePhase::ProbeUnreachable
        };
        let probe_state = prepared.probe_state(
            ManagedLinuxVmProbeSource::ProbeOnStatus,
            if any_known_service_reachable {
                ManagedLinuxVmProbeOutcome::Healthy
            } else {
                ManagedLinuxVmProbeOutcome::Unreachable
            },
            true,
            "",
            "",
        );
        let runtime_endpoints = upstream_runtime_endpoints(
            guest_ip.as_deref(),
            port_80_reachable,
            port_31337_reachable,
            port_31338_reachable,
        );
        let mut runtime_status = prepared
            .runtime_status(runtime_endpoints, false)
            .with_probe_state(&probe_state, phase);
        runtime_status.runtime_outcome = Some(if !guest_reachable {
            ManagedLinuxVmRuntimeOutcome::GuestUnreachable
        } else if any_known_service_reachable {
            ManagedLinuxVmRuntimeOutcome::BootedServicesReachable
        } else {
            ManagedLinuxVmRuntimeOutcome::BootedServicesUnreachable
        });

        Ok(ManagedLinuxVmUpstreamObservationResult {
            container_name,
            container_running,
            scratch_artifacts_present,
            observed_artifact_paths,
            guest_ip,
            guest_reachable,
            port_80_reachable,
            port_31337_reachable,
            port_31338_reachable,
            runtime_status,
        })
    }

    pub fn stop_firmae_upstream(
        &self,
        prepared: &ManagedLinuxVmPrepared,
        request: &ManagedLinuxVmUpstreamStopRequest,
        command_probe: &impl crate::model::CommandProbe,
    ) -> Result<ManagedLinuxVmUpstreamStopResult, ManagedLinuxVmStopError> {
        if prepared.control_contract() != ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 {
            return Err(ManagedLinuxVmStopError {
                diagnostic: upstream_stop_error_for(
                    prepared,
                    "upstream FirmAE stop is only available for firmae".to_string(),
                    None,
                    "",
                    "",
                ),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let Some(docker) = command_probe.command_path("docker") else {
            return Err(ManagedLinuxVmStopError {
                diagnostic: upstream_stop_error_for(
                    prepared,
                    "docker command is missing for upstream FirmAE stop".to_string(),
                    None,
                    "",
                    "",
                ),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
            });
        };

        let output = Command::new(docker)
            .arg("stop")
            .arg(request.container_name.as_str())
            .output()
            .map_err(|err| ManagedLinuxVmStopError {
                diagnostic: upstream_stop_error_for(
                    prepared,
                    format!("failed to spawn upstream FirmAE stop command: {err}"),
                    None,
                    "",
                    "",
                ),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(ManagedLinuxVmStopError {
                diagnostic: upstream_stop_error_for(
                    prepared,
                    "upstream FirmAE stop command exited unsuccessfully".to_string(),
                    output.status.code(),
                    &stdout,
                    &stderr,
                ),
                exit_code: output.status.code(),
                stdout,
                stderr,
            });
        }

        validate_upstream_stop_success_for(prepared, request, &stdout, &stderr)?;
        fs::remove_dir_all(&prepared.workspace_dir).map_err(|err| ManagedLinuxVmStopError {
            diagnostic: upstream_stop_error_for(
                prepared,
                format!("failed to clean upstream FirmAE workspace: {err}"),
                output.status.code(),
                &stdout,
                &stderr,
            ),
            exit_code: output.status.code(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        })?;

        Ok(ManagedLinuxVmUpstreamStopResult {
            exit_code: output.status.code(),
            stdout,
            stderr,
            container_name: request.container_name.clone(),
        })
    }

    pub fn stop(
        &self,
        prepared: &ManagedLinuxVmPrepared,
    ) -> Result<ManagedLinuxVmStopResult, ManagedLinuxVmStopError> {
        let output = Command::new(&prepared.bundle.guest_agent)
            .args(stop_args_for(prepared))
            .current_dir(&prepared.workspace_dir)
            .output()
            .map_err(|err| ManagedLinuxVmStopError {
                diagnostic: cleanup_error_for(
                    prepared,
                    format!("failed to spawn managed guest stop command: {err}"),
                    None,
                    "",
                    "",
                ),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
            })?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(ManagedLinuxVmStopError {
                diagnostic: cleanup_error_for(
                    prepared,
                    "managed guest stop command exited unsuccessfully".to_string(),
                    output.status.code(),
                    &stdout,
                    &stderr,
                ),
                exit_code: output.status.code(),
                stdout,
                stderr,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        validate_stop_success_for(prepared, &stdout, &stderr)?;

        fs::remove_dir_all(&prepared.workspace_dir).map_err(|err| ManagedLinuxVmStopError {
            diagnostic: cleanup_error_for(
                prepared,
                format!("failed to clean managed workspace: {err}"),
                None,
                &stdout,
                &stderr,
            ),
            exit_code: output.status.code(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        })?;

        Ok(ManagedLinuxVmStopResult {
            substrate: BackendSubstrateKind::ManagedLinuxVm,
            exit_code: output.status.code(),
            stdout,
            stderr,
        })
    }

    pub fn probe(
        &self,
        prepared: &ManagedLinuxVmPrepared,
    ) -> Result<ManagedLinuxVmProbeResult, ManagedLinuxVmProbeError> {
        let output = Command::new(&prepared.bundle.guest_agent)
            .args(probe_args_for(prepared))
            .current_dir(&prepared.workspace_dir)
            .output()
            .map_err(|err| ManagedLinuxVmProbeError {
                diagnostic: probe_error_for(
                    prepared,
                    format!("failed to spawn managed guest probe: {err}"),
                    None,
                    "",
                    "",
                ),
                stdout: String::new(),
                stderr: String::new(),
            })?;

        if !output.status.success() {
            return Err(ManagedLinuxVmProbeError {
                diagnostic: probe_error_for(
                    prepared,
                    "managed guest probe exited unsuccessfully".to_string(),
                    output.status.code(),
                    &String::from_utf8_lossy(&output.stdout),
                    &String::from_utf8_lossy(&output.stderr),
                ),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        validate_probe_success_for(prepared, &stdout, &stderr)?;

        Ok(ManagedLinuxVmProbeResult { stdout, stderr })
    }
}

pub fn managed_linux_vm_bundle_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(MANAGED_LINUX_VM_BUNDLE_DIR_ENV).map(PathBuf::from)
}

pub fn managed_linux_vm_bundle_version_from_env() -> String {
    std::env::var(MANAGED_LINUX_VM_BUNDLE_VERSION_ENV).unwrap_or_else(|_| "dev".to_string())
}

pub fn firmae_upstream_dir_from_env() -> Option<PathBuf> {
    std::env::var_os(FIRMAE_UPSTREAM_DIR_ENV).map(PathBuf::from)
}

pub fn firmae_host_python_from_env() -> Option<PathBuf> {
    std::env::var_os(FIRMAE_HOST_PYTHON_ENV).map(PathBuf::from)
}

pub fn firmae_docker_psql_ip_from_env() -> Option<String> {
    std::env::var(FIRMAE_DOCKER_PSQL_IP_ENV).ok()
}

/// The brand argument upstream FirmAE requires for `docker-helper.py -ec`.
///
/// FAT does not infer this from firmware evidence. Upstream treats the value
/// as a selector into its own tables, so a wrong guess is an unsupported claim
/// about the target rather than a harmless default. The operator supplies it
/// explicitly or the backend reports itself unavailable.
pub fn firmae_upstream_brand_from_env() -> Option<Result<String, String>> {
    let raw = std::env::var(FIRMAE_UPSTREAM_BRAND_ENV).ok()?;
    Some(validate_firmae_upstream_brand(&raw))
}

/// Accepts the shape upstream's brand tables use. The value reaches
/// `docker-helper.py` as a distinct argv entry, so this guards against an
/// empty selector and against a value that would be read as an option flag,
/// not against shell metacharacters.
pub fn validate_firmae_upstream_brand(raw: &str) -> Result<String, String> {
    let brand = raw.trim();
    if brand.is_empty() {
        return Err(format!("{FIRMAE_UPSTREAM_BRAND_ENV} is empty"));
    }
    if brand.starts_with('-') {
        return Err(format!(
            "{FIRMAE_UPSTREAM_BRAND_ENV} must not start with '-': {brand:?}"
        ));
    }
    if !brand
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "{FIRMAE_UPSTREAM_BRAND_ENV} must be alphanumeric with '-', '_' or '.': {brand:?}"
        ));
    }
    Ok(brand.to_string())
}

pub fn inspect_managed_linux_vm_bundle(
    bundle_dir: PathBuf,
    bundle_version: impl Into<String>,
) -> Result<ManagedLinuxVmBundle, BackendSubstrateContract> {
    let request = ManagedLinuxVmRequest::new(
        "managed-linux-vm",
        bundle_version,
        bundle_dir,
        std::env::temp_dir().join("fat-managed-linux-vm-inspect"),
    );
    validate_bundle(&request).map_err(|err| err.contract)
}

pub fn inspect_managed_linux_vm_bundle_from_env(
) -> Option<Result<ManagedLinuxVmBundle, BackendSubstrateContract>> {
    managed_linux_vm_bundle_dir_from_env().map(|bundle_dir| {
        inspect_managed_linux_vm_bundle(bundle_dir, managed_linux_vm_bundle_version_from_env())
    })
}

fn validate_firmae_upstream_checkout(
    prepared: &ManagedLinuxVmPrepared,
    request: &ManagedLinuxVmUpstreamLaunchRequest,
) -> Result<(), ManagedLinuxVmUpstreamLaunchError> {
    if !is_executable_path(&request.host_python) {
        return Err(upstream_launch_error_for(
            prepared,
            format!(
                "host helper python is missing or not executable: {}",
                request.host_python.display()
            ),
            None,
            "",
            "",
        ));
    }
    if !request.firmware_path.is_file() {
        return Err(upstream_launch_error_for(
            prepared,
            format!(
                "firmware input is missing: {}",
                request.firmware_path.display()
            ),
            None,
            "",
            "",
        ));
    }
    let required_paths = [
        request.upstream_dir.join("docker-helper.py"),
        request.upstream_dir.join("download.sh"),
        request.upstream_dir.join("database").join("schema"),
        request.upstream_dir.join("core").join("Dockerfile"),
    ];
    let missing: Vec<String> = required_paths
        .iter()
        .filter(|path| !path.exists())
        .map(|path| path.display().to_string())
        .collect();
    if !missing.is_empty() {
        return Err(upstream_launch_error_for(
            prepared,
            format!(
                "missing upstream FirmAE checkout inputs: {}",
                missing.join(", ")
            ),
            None,
            "",
            "",
        ));
    }

    Ok(())
}

fn declared_artifact_paths_from_stdout(stdout: &str, upstream_dir: &Path) -> Vec<PathBuf> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("artifact:"))
        .map(|raw| {
            let path = PathBuf::from(raw.trim());
            if path.is_absolute() {
                path
            } else {
                upstream_dir.join(path)
            }
        })
        .collect()
}

fn declared_container_name_from_stdout(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("container:"))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn infer_guest_ip_from_artifacts(artifact_paths: &[PathBuf]) -> Option<String> {
    artifact_paths.iter().find_map(|path| {
        let content = fs::read_to_string(path).ok()?;
        content.lines().find_map(parse_guest_ip_from_line)
    })
}

fn parse_guest_ip_from_line(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix("guest-ip:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn docker_container_running(
    command_probe: &impl crate::model::CommandProbe,
    container_name: &str,
) -> bool {
    let Some(docker) = command_probe.command_path("docker") else {
        return false;
    };
    Command::new(docker)
        .arg("inspect")
        .arg("-f")
        .arg("{{.State.Running}}")
        .arg(container_name)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "true")
        .unwrap_or(false)
}

fn ping_guest(command_probe: &impl crate::model::CommandProbe, guest_ip: &str) -> bool {
    let Some(ping) = command_probe.command_path("ping") else {
        return false;
    };
    Command::new(ping)
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(guest_ip)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn probe_guest_port(
    command_probe: &impl crate::model::CommandProbe,
    guest_ip: &str,
    port: u16,
) -> bool {
    let Some(nc) = command_probe.command_path("nc") else {
        return false;
    };
    Command::new(nc)
        .arg("-z")
        .arg("-w")
        .arg("1")
        .arg(guest_ip)
        .arg(port.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn upstream_launch_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> ManagedLinuxVmUpstreamLaunchError {
    let mut suggested_next_actions = vec![
        "inspect the upstream FirmAE checkout".to_string(),
        "inspect the native arm64 recipe inputs".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect upstream launch stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect upstream launch stderr".to_string());
    }

    let diagnostic = DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Launch,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::LaunchFailed,
        Some("firmae-upstream-launch-failed".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("FirmAE upstream launch: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    );

    ManagedLinuxVmUpstreamLaunchError {
        diagnostic,
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

fn upstream_observation_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
) -> DiagnosticRecord {
    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Observation,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::GuestUnreachable,
        Some("firmae-upstream-observation-failed".to_string()),
        DiagnosticSeverity::Medium,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        format!("FirmAE upstream observation: {summary}"),
        Vec::new(),
        Vec::new(),
        vec![
            "inspect the persisted upstream launch artifacts".to_string(),
            "inspect the bounded live observation tools and inputs".to_string(),
        ],
    )
}

fn upstream_stop_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the upstream FirmAE launch artifacts to recover the container identity"
            .to_string(),
        "inspect the upstream container stop path".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect upstream stop stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect upstream stop stderr".to_string());
    }

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Cleanup,
        DiagnosticOwner::BackendDriver,
        DiagnosticClass::CleanupFailed,
        Some("firmae-upstream-stop-failed".to_string()),
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("FirmAE upstream stop: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn validate_bundle(
    request: &ManagedLinuxVmRequest,
) -> Result<ManagedLinuxVmBundle, ManagedLinuxVmPreparationError> {
    let base_image = request.bundle_dir.join(BASE_IMAGE_NAME);
    let guest_agent = request.bundle_dir.join(GUEST_AGENT_NAME);
    let mut missing = Vec::new();
    if !base_image.is_file() {
        missing.push(BASE_IMAGE_NAME);
    }
    if !guest_agent.is_file() {
        missing.push(GUEST_AGENT_NAME);
    }

    if !missing.is_empty() {
        return Err(ManagedLinuxVmPreparationError {
            contract: BackendSubstrateContract::unavailable(
                BackendSubstrateKind::ManagedLinuxVm,
                "managed-linux-vm",
                "managed Linux VM bundle is incomplete",
                format!("missing bundle inputs: {}", missing.join(", ")),
            ),
        });
    }

    Ok(ManagedLinuxVmBundle {
        bundle_version: request.bundle_version.clone(),
        base_image,
        guest_agent,
    })
}

fn bundle_for_request(
    request: &ManagedLinuxVmRequest,
) -> Result<ManagedLinuxVmBundle, ManagedLinuxVmPreparationError> {
    if request.backend_id == "firmae" {
        return Ok(ManagedLinuxVmBundle {
            bundle_version: request.bundle_version.clone(),
            base_image: request.bundle_dir.join(BASE_IMAGE_NAME),
            guest_agent: request.bundle_dir.join(GUEST_AGENT_NAME),
        });
    }

    validate_bundle(request)
}

fn prepare_contract_for(request: &ManagedLinuxVmRequest) -> BackendSubstrateContract {
    let detail = if request.backend_id == "firmae" {
        "upstream FirmAE checkout and workspace are ready"
    } else {
        "managed Linux VM bundle is present and workspace is ready"
    };

    BackendSubstrateContract::healthy(
        BackendSubstrateKind::ManagedLinuxVm,
        "managed-linux-vm",
        detail,
    )
}

fn is_executable_path(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn build_endpoints(_mapped_ports: &[u16]) -> Vec<RuntimeEndpoint> {
    vec![
        RuntimeEndpoint::new(RuntimeEndpointKind::Shell, "shell", "127.0.0.1", 12022)
            .with_target_port(22)
            .with_uri("ssh://127.0.0.1:12022"),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Debugger,
            "debugger",
            "127.0.0.1",
            12023,
        )
        .with_target_port(1234)
        .with_uri("tcp://127.0.0.1:12023"),
        RuntimeEndpoint::new(RuntimeEndpointKind::Monitor, "monitor", "127.0.0.1", 12024)
            .with_target_port(4444)
            .with_uri("tcp://127.0.0.1:12024"),
    ]
}

fn upstream_runtime_endpoints(
    guest_ip: Option<&str>,
    port_80_reachable: bool,
    port_31337_reachable: bool,
    port_31338_reachable: bool,
) -> Vec<RuntimeEndpoint> {
    let Some(guest_ip) = guest_ip else {
        return Vec::new();
    };

    let mut endpoints = Vec::new();
    if port_80_reachable {
        endpoints.push(
            RuntimeEndpoint::new(RuntimeEndpointKind::Service, "port-80", guest_ip, 80)
                .with_target_port(80)
                .with_uri(format!("http://{guest_ip}:80")),
        );
    }
    if port_31337_reachable {
        endpoints.push(
            RuntimeEndpoint::new(RuntimeEndpointKind::Debugger, "gdb", guest_ip, 31337)
                .with_target_port(31337)
                .with_uri(format!("tcp://{guest_ip}:31337")),
        );
    }
    if port_31338_reachable {
        endpoints.push(
            RuntimeEndpoint::new(RuntimeEndpointKind::Monitor, "monitor", guest_ip, 31338)
                .with_target_port(31338)
                .with_uri(format!("tcp://{guest_ip}:31338")),
        );
    }
    endpoints
}

fn runtime_endpoints_from_manifest(
    manifest: &ManagedLinuxVmLaunchManifest,
) -> Vec<RuntimeEndpoint> {
    manifest
        .endpoints
        .iter()
        .map(|endpoint| {
            let mut runtime_endpoint = RuntimeEndpoint::new(
                endpoint.kind,
                endpoint.name.clone(),
                endpoint.host.clone(),
                endpoint.port,
            );
            if let Some(target_port) = endpoint.target_port {
                runtime_endpoint = runtime_endpoint.with_target_port(target_port);
            }
            if let Some(uri) = &endpoint.uri {
                runtime_endpoint = runtime_endpoint.with_uri(uri.clone());
            }
            runtime_endpoint
        })
        .collect()
}

fn parse_launch_manifest(
    prepared: &ManagedLinuxVmPrepared,
    stdout: &str,
) -> Result<Option<ManagedLinuxVmLaunchManifest>, DiagnosticRecord> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') {
        return Ok(None);
    }

    let manifest: ManagedLinuxVmLaunchManifest = serde_json::from_str(trimmed).map_err(|err| {
        invalid_launch_manifest_error(prepared, format!("failed to parse launch manifest: {err}"))
    })?;
    if manifest.endpoints.is_empty() {
        return Err(invalid_launch_manifest_error(
            prepared,
            "launch manifest did not declare any endpoints".to_string(),
        ));
    }
    if prepared.control_contract() == ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1
        && !manifest
            .endpoints
            .iter()
            .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Shell)
    {
        return Err(invalid_launch_manifest_error(
            prepared,
            "FirmAE launch manifest did not declare a shell endpoint".to_string(),
        ));
    }
    Ok(Some(manifest))
}

fn validate_probe_success_for(
    prepared: &ManagedLinuxVmPrepared,
    stdout: &str,
    stderr: &str,
) -> Result<(), ManagedLinuxVmProbeError> {
    if prepared.control_contract() == ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1
        && !stdout.lines().any(|line| line.trim() == "firmae-probe-ok")
    {
        return Err(ManagedLinuxVmProbeError {
            diagnostic: invalid_probe_contract_error_for(
                prepared,
                "FirmAE probe result did not declare the firmae-probe-ok success marker"
                    .to_string(),
                stdout,
                stderr,
            ),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        });
    }

    Ok(())
}

fn validate_stop_success_for(
    prepared: &ManagedLinuxVmPrepared,
    stdout: &str,
    stderr: &str,
) -> Result<(), ManagedLinuxVmStopError> {
    if prepared.control_contract() == ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1
        && !stdout.lines().any(|line| line.trim() == "firmae-stop-ok")
    {
        return Err(ManagedLinuxVmStopError {
            diagnostic: invalid_stop_contract_error_for(
                prepared,
                "FirmAE stop result did not declare the firmae-stop-ok success marker".to_string(),
                stdout,
                stderr,
            ),
            exit_code: Some(0),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        });
    }

    Ok(())
}

fn validate_upstream_stop_success_for(
    prepared: &ManagedLinuxVmPrepared,
    request: &ManagedLinuxVmUpstreamStopRequest,
    stdout: &str,
    stderr: &str,
) -> Result<(), ManagedLinuxVmStopError> {
    if prepared.control_contract() == ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1
        && !stdout
            .lines()
            .any(|line| line.trim() == request.container_name.as_str())
    {
        return Err(ManagedLinuxVmStopError {
            diagnostic: DiagnosticRecord::new(
                request_run_id(&prepared.request).to_string(),
                DiagnosticPhase::Cleanup,
                DiagnosticOwner::BackendDriver,
                DiagnosticClass::CleanupFailed,
                Some("firmae-upstream-stop-contract-invalid".to_string()),
                DiagnosticSeverity::High,
                DiagnosticConfidence::High,
                DiagnosticActionability::RequiresBackendFix,
                "FirmAE upstream stop: invalid upstream stop success contract".to_string(),
                Vec::new(),
                if stdout.trim().is_empty() {
                    Vec::new()
                } else {
                    vec![stdout.trim().to_string()]
                },
                vec![
                    "verify the upstream container stop output includes the stopped container name"
                        .to_string(),
                    "inspect upstream stop stderr".to_string(),
                ],
            ),
            exit_code: Some(0),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        });
    }

    Ok(())
}

fn request_run_id(request: &ManagedLinuxVmRequest) -> &str {
    request
        .run_id
        .as_deref()
        .unwrap_or(request.backend_id.as_str())
}

fn base_args(
    request: &ManagedLinuxVmRequest,
    bundle: &ManagedLinuxVmBundle,
    workspace_dir: &std::path::Path,
) -> Vec<PathBuf> {
    let mut args = vec![
        PathBuf::from("--backend"),
        PathBuf::from(request.backend_id.clone()),
        PathBuf::from("--bundle-version"),
        PathBuf::from(bundle.bundle_version.clone()),
        PathBuf::from("--workspace"),
        workspace_dir.to_path_buf(),
        PathBuf::from("--base-image"),
        bundle.base_image.clone(),
    ];
    for port in &request.mapped_ports {
        args.push(PathBuf::from("--port"));
        args.push(PathBuf::from(port.to_string()));
    }
    args
}

fn launch_args_for(prepared: &ManagedLinuxVmPrepared) -> Vec<PathBuf> {
    match prepared.request.backend_id.as_str() {
        "firmae" => {
            firmae_launch_args(&prepared.request, &prepared.bundle, &prepared.workspace_dir)
        }
        _ => base_args(&prepared.request, &prepared.bundle, &prepared.workspace_dir),
    }
}

fn stop_args_for(prepared: &ManagedLinuxVmPrepared) -> Vec<PathBuf> {
    match prepared.request.backend_id.as_str() {
        "firmae" => firmae_stop_args(&prepared.request, &prepared.bundle, &prepared.workspace_dir),
        _ => {
            let mut args = vec![PathBuf::from("--stop")];
            args.extend(base_args(
                &prepared.request,
                &prepared.bundle,
                &prepared.workspace_dir,
            ));
            args
        }
    }
}

fn probe_args_for(prepared: &ManagedLinuxVmPrepared) -> Vec<PathBuf> {
    match prepared.request.backend_id.as_str() {
        "firmae" => firmae_probe_args(&prepared.request, &prepared.bundle, &prepared.workspace_dir),
        _ => {
            let mut args = vec![PathBuf::from("--probe")];
            args.extend(base_args(
                &prepared.request,
                &prepared.bundle,
                &prepared.workspace_dir,
            ));
            args
        }
    }
}

fn firmae_launch_args(
    request: &ManagedLinuxVmRequest,
    bundle: &ManagedLinuxVmBundle,
    workspace_dir: &std::path::Path,
) -> Vec<PathBuf> {
    let mut args = base_args(request, bundle, workspace_dir);
    args.push(PathBuf::from("--control-contract"));
    args.push(PathBuf::from("firmae-legacy-wrapper-v1"));
    args.push(PathBuf::from("--firmae-action"));
    args.push(PathBuf::from("launch"));
    args
}

fn firmae_stop_args(
    request: &ManagedLinuxVmRequest,
    bundle: &ManagedLinuxVmBundle,
    workspace_dir: &std::path::Path,
) -> Vec<PathBuf> {
    let mut args = vec![PathBuf::from("--stop")];
    args.extend(base_args(request, bundle, workspace_dir));
    args.push(PathBuf::from("--control-contract"));
    args.push(PathBuf::from("firmae-legacy-wrapper-v1"));
    args.push(PathBuf::from("--firmae-action"));
    args.push(PathBuf::from("stop"));
    args
}

fn firmae_probe_args(
    request: &ManagedLinuxVmRequest,
    bundle: &ManagedLinuxVmBundle,
    workspace_dir: &std::path::Path,
) -> Vec<PathBuf> {
    let mut args = vec![PathBuf::from("--probe")];
    args.extend(base_args(request, bundle, workspace_dir));
    args.push(PathBuf::from("--control-contract"));
    args.push(PathBuf::from("firmae-legacy-wrapper-v1"));
    args.push(PathBuf::from("--firmae-action"));
    args.push(PathBuf::from("probe"));
    args
}

fn launch_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the managed-linux-vm workspace".to_string(),
        "inspect the guest-agent launcher and bundle contents".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect launch stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect launch stderr".to_string());
    }

    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-launch-failed",
        vec![
            "inspect the FirmAE legacy-wrapper control contract".to_string(),
            "verify the guest-agent shim honors --control-contract firmae-legacy-wrapper-v1"
                .to_string(),
        ],
    );
    suggested_next_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Launch,
        owner,
        DiagnosticClass::LaunchFailed,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("managed-linux-vm: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn cleanup_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the managed-linux-vm workspace".to_string(),
        "inspect the guest-agent stop path".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect stop stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect stop stderr".to_string());
    }

    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-stop-failed",
        vec![
            "inspect the FirmAE legacy-wrapper stop control contract".to_string(),
            "verify the guest-agent shim honors --firmae-action stop".to_string(),
        ],
    );
    suggested_next_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Cleanup,
        owner,
        DiagnosticClass::CleanupFailed,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresSubstrateFix,
        format!("managed-linux-vm: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn probe_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the managed guest probe path".to_string(),
        "inspect the managed-linux-vm workspace".to_string(),
    ];
    if let Some(code) = exit_code {
        suggested_next_actions.push(format!("review the exit code {code}"));
    }
    if !stdout.trim().is_empty() {
        suggested_next_actions.push("inspect probe stdout".to_string());
    }
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect probe stderr".to_string());
    }

    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-probe-failed",
        vec![
            "inspect the FirmAE legacy-wrapper probe control contract".to_string(),
            "verify the guest-agent shim honors --firmae-action probe".to_string(),
        ],
    );
    suggested_next_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Observation,
        owner,
        DiagnosticClass::GuestUnreachable,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::Retryable,
        format!("managed-linux-vm: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_next_actions,
    )
}

fn invalid_probe_contract_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the managed guest probe stdout".to_string(),
        "verify the probe success contract emitted by the guest-agent shim".to_string(),
    ];
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect probe stderr".to_string());
    }

    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-probe-contract-invalid",
        vec![
            "repair the FirmAE probe success contract for the legacy-wrapper adapter".to_string(),
            "verify the guest-agent shim emits firmae-probe-ok on successful --firmae-action probe"
                .to_string(),
        ],
    );
    suggested_next_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Observation,
        owner,
        DiagnosticClass::GuestUnreachable,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresBackendFix,
        format!("managed-linux-vm: invalid probe success contract: {summary}"),
        Vec::new(),
        if stdout.trim().is_empty() {
            Vec::new()
        } else {
            vec![stdout.trim().to_string()]
        },
        suggested_next_actions,
    )
}

fn invalid_stop_contract_error_for(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
    stdout: &str,
    stderr: &str,
) -> DiagnosticRecord {
    let mut suggested_next_actions = vec![
        "inspect the managed guest stop stdout".to_string(),
        "verify the stop success contract emitted by the guest-agent shim".to_string(),
    ];
    if !stderr.trim().is_empty() {
        suggested_next_actions.push("inspect stop stderr".to_string());
    }

    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-stop-contract-invalid",
        vec![
            "repair the FirmAE stop success contract for the legacy-wrapper adapter".to_string(),
            "verify the guest-agent shim emits firmae-stop-ok on successful --firmae-action stop"
                .to_string(),
        ],
    );
    suggested_next_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Cleanup,
        owner,
        DiagnosticClass::CleanupFailed,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresBackendFix,
        format!("managed-linux-vm: invalid stop success contract: {summary}"),
        Vec::new(),
        if stdout.trim().is_empty() {
            Vec::new()
        } else {
            vec![stdout.trim().to_string()]
        },
        suggested_next_actions,
    )
}

fn invalid_launch_manifest_error(
    prepared: &ManagedLinuxVmPrepared,
    summary: String,
) -> DiagnosticRecord {
    let (owner, subclass, extra_actions) = firmae_diagnostic_overrides(
        prepared,
        "firmae-managed-launch-manifest-invalid",
        vec![
            "repair the FirmAE launch manifest for the legacy-wrapper control contract".to_string(),
            "verify the guest-agent shim emits a JSON endpoint manifest for --firmae-action launch"
                .to_string(),
        ],
    );
    let mut suggested_actions = vec![
        "inspect the managed guest launch stdout".to_string(),
        "repair the guest-agent launch manifest schema".to_string(),
    ];
    suggested_actions.extend(extra_actions);

    DiagnosticRecord::new(
        request_run_id(&prepared.request).to_string(),
        DiagnosticPhase::Launch,
        owner,
        DiagnosticClass::LaunchFailed,
        subclass,
        DiagnosticSeverity::High,
        DiagnosticConfidence::High,
        DiagnosticActionability::RequiresBackendFix,
        format!("managed-linux-vm: invalid launch manifest: {summary}"),
        Vec::new(),
        Vec::new(),
        suggested_actions,
    )
}

fn firmae_diagnostic_overrides(
    prepared: &ManagedLinuxVmPrepared,
    firmae_subclass: &str,
    firmae_actions: Vec<String>,
) -> (DiagnosticOwner, Option<String>, Vec<String>) {
    match prepared.control_contract() {
        ManagedLinuxVmControlContract::FirmaeLegacyWrapperV1 => (
            DiagnosticOwner::BackendDriver,
            Some(firmae_subclass.to_string()),
            firmae_actions,
        ),
        ManagedLinuxVmControlContract::GenericGuestAgentV1 => (
            DiagnosticOwner::Substrate,
            Some("managed-linux-vm".to_string()),
            Vec::new(),
        ),
    }
}
