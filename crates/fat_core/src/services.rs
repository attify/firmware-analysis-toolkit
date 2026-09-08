use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::runs::HealthState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedService {
    pub name: String,
    pub endpoint: Option<String>,
}

impl ObservedService {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            endpoint: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn display_label(&self) -> String {
        match self.endpoint.as_deref() {
            Some(endpoint) if !endpoint.trim().is_empty() => {
                format!("{} {}", self.name.trim(), endpoint.trim()).to_ascii_lowercase()
            }
            _ => self.name.trim().to_ascii_lowercase(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSummaryArtifact {
    pub producer_id: String,
    pub services: Vec<ObservedService>,
}

impl ServiceSummaryArtifact {
    pub fn new(producer_id: impl Into<String>, services: Vec<ObservedService>) -> Self {
        Self {
            producer_id: producer_id.into(),
            services: dedup_services(services),
        }
    }

    pub fn service_labels(&self) -> Vec<String> {
        self.services
            .iter()
            .map(ObservedService::display_label)
            .collect()
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("service summary artifact should serialize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedStopSummaryArtifact {
    pub phase: Option<String>,
    pub backend_id: String,
    pub driver_profile: String,
    pub control_contract: String,
    pub lifecycle_adapter: String,
    pub result_contract: String,
    pub result_contract_verified: bool,
    pub stop_mode: Option<String>,
    pub workspace_dir: String,
    pub workspace_removed: bool,
    pub exit_code: Option<i64>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

impl ManagedStopSummaryArtifact {
    pub fn is_fully_verified(&self) -> bool {
        self.result_contract_verified && self.workspace_removed
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("managed stop summary should serialize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRuntimeSummary {
    pub backend_id: String,
    pub control_contract: String,
    pub driver_profile: String,
    pub lifecycle_adapter: String,
    pub runtime_phase: String,
    #[serde(default)]
    pub runtime_outcome: Option<String>,
    pub workspace_dir: String,
    #[serde(default)]
    pub services: Vec<ObservedService>,
    pub launch_mode: Option<String>,
    pub stop_mode: Option<String>,
    pub launch_manifest_present: Option<bool>,
    pub probe_result_contract: Option<String>,
    pub probe_result_contract_verified: Option<bool>,
    pub probe_source: Option<String>,
    pub probe_outcome: Option<String>,
    pub stop_result_contract: Option<String>,
    pub stop_result_contract_verified: Option<bool>,
    pub stop_exit_code: Option<i64>,
    pub workspace_removed: Option<bool>,
}

impl ManagedRuntimeSummary {
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("managed runtime summary should serialize")
    }

    pub fn health_state(&self) -> HealthState {
        match HealthState::from_runtime_outcome(self.runtime_outcome.as_deref()) {
            HealthState::Unknown => match self.runtime_phase.as_str() {
                "launch-complete" | "probe-healthy" => HealthState::Healthy,
                "probe-unreachable" => HealthState::Unreachable,
                _ => HealthState::Unknown,
            },
            other => other,
        }
    }

    pub fn has_boot_established_phase(&self) -> bool {
        matches!(
            self.runtime_phase.as_str(),
            "launch-complete"
                | "probe-healthy"
                | "probe-unreachable"
                | "stop-complete"
                | "stop-failed"
        )
    }

    pub fn has_exposed_services(&self) -> bool {
        !self.services.is_empty()
    }

    pub fn has_booted_services_unreachable_outcome(&self) -> bool {
        self.runtime_outcome.as_deref() == Some("booted-services-unreachable")
    }

    pub fn service_labels(&self) -> Vec<String> {
        self.services
            .iter()
            .map(ObservedService::display_label)
            .collect()
    }

    pub fn phase_signature(&self) -> String {
        format!("{}:{}", self.backend_id, self.runtime_phase).to_ascii_lowercase()
    }

    pub fn stop_summary(&self) -> Option<ManagedStopSummaryArtifact> {
        Some(ManagedStopSummaryArtifact {
            phase: Some(self.runtime_phase.clone()),
            backend_id: self.backend_id.clone(),
            driver_profile: self.driver_profile.clone(),
            control_contract: self.control_contract.clone(),
            lifecycle_adapter: self.lifecycle_adapter.clone(),
            result_contract: self.stop_result_contract.clone()?,
            result_contract_verified: self.stop_result_contract_verified.unwrap_or(false),
            stop_mode: self.stop_mode.clone(),
            workspace_dir: self.workspace_dir.clone(),
            workspace_removed: self.workspace_removed.unwrap_or(false),
            exit_code: self.stop_exit_code,
            stdout: None,
            stderr: None,
        })
    }
}

fn dedup_services(services: Vec<ObservedService>) -> Vec<ObservedService> {
    let mut deduped: BTreeMap<String, ObservedService> = BTreeMap::new();
    for service in services {
        deduped.insert(service.display_label(), service);
    }
    deduped.into_values().collect()
}

pub fn services_from_runtime_state_json(text: &str) -> Vec<ObservedService> {
    let Some(state) = runtime_status_state_from_json(text) else {
        return Vec::new();
    };
    if let Some(endpoints) = state.get("endpoints").and_then(|value| value.as_array()) {
        return dedup_services(
            endpoints
                .iter()
                .filter_map(|endpoint| {
                    if endpoint.get("kind").and_then(|value| value.as_str()) != Some("service") {
                        return None;
                    }

                    let name = endpoint.get("name").and_then(|value| value.as_str())?;
                    let service =
                        if let Some(uri) = endpoint.get("uri").and_then(|value| value.as_str()) {
                            ObservedService::new(name).with_endpoint(uri)
                        } else if let (Some(host), Some(port)) = (
                            endpoint.get("host").and_then(|value| value.as_str()),
                            endpoint.get("port").and_then(|value| value.as_u64()),
                        ) {
                            ObservedService::new(name).with_endpoint(format!("{host}:{port}"))
                        } else {
                            ObservedService::new(name)
                        };
                    Some(service)
                })
                .collect(),
        );
    }

    let Some(services) = state.get("services").and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    dedup_services(
        services
            .iter()
            .filter_map(|service| {
                let name = service.get("name").and_then(|value| value.as_str())?;
                let observed = if let Some(endpoint) =
                    service.get("endpoint").and_then(|value| value.as_str())
                {
                    ObservedService::new(name).with_endpoint(endpoint)
                } else {
                    ObservedService::new(name)
                };
                Some(observed)
            })
            .collect(),
    )
}

pub fn managed_runtime_phase_signature_from_json(text: &str) -> Option<String> {
    let state = runtime_status_state_from_json(text)?;
    let backend_id = state.get("backend_id").and_then(|value| value.as_str())?;
    let phase = state.get("phase").and_then(|value| value.as_str())?;
    Some(format!("{backend_id}:{phase}").to_ascii_lowercase())
}

pub fn services_from_runtime_summary_json(text: &str) -> Vec<ObservedService> {
    managed_runtime_summary_from_summary_json(text)
        .map(|summary| dedup_services(summary.services))
        .unwrap_or_default()
}

pub fn managed_runtime_phase_signature_from_summary_json(text: &str) -> Option<String> {
    managed_runtime_summary_from_summary_json(text).map(|summary| summary.phase_signature())
}

pub fn managed_stop_summary_from_runtime_state_json(
    subkind: &str,
    text: &str,
) -> Option<ManagedStopSummaryArtifact> {
    if subkind == "managed-runtime-summary" {
        return managed_runtime_summary_from_summary_json(text)
            .and_then(|summary| summary.stop_summary());
    }
    let Ok(state) = serde_json::from_str::<serde_json::Value>(text) else {
        return None;
    };
    if subkind == "managed-runtime-status" && state.get("stop_result_contract").is_none() {
        return None;
    }

    Some(ManagedStopSummaryArtifact {
        phase: state
            .get("phase")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        backend_id: state
            .get("backend_id")
            .and_then(|value| value.as_str())?
            .to_string(),
        driver_profile: state
            .get("driver_profile")
            .and_then(|value| value.as_str())?
            .to_string(),
        control_contract: state
            .get("control_contract")
            .and_then(|value| value.as_str())?
            .to_string(),
        lifecycle_adapter: state
            .get("lifecycle_adapter")
            .and_then(|value| value.as_str())?
            .to_string(),
        result_contract: state
            .get("result_contract")
            .or_else(|| state.get("stop_result_contract"))
            .and_then(|value| value.as_str())?
            .to_string(),
        result_contract_verified: state
            .get("result_contract_verified")
            .or_else(|| state.get("stop_result_contract_verified"))
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        stop_mode: state
            .get("stop_mode")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        workspace_dir: state
            .get("workspace_dir")
            .and_then(|value| value.as_str())?
            .to_string(),
        workspace_removed: state
            .get("workspace_removed")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        exit_code: state
            .get("exit_code")
            .or_else(|| state.get("stop_exit_code"))
            .and_then(|value| value.as_i64()),
        stdout: state
            .get("stdout")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        stderr: state
            .get("stderr")
            .and_then(|value| value.as_str())
            .map(str::to_string),
    })
}

pub fn managed_runtime_summary_from_runtime_status_json(
    text: &str,
) -> Option<ManagedRuntimeSummary> {
    let state = runtime_status_state_from_json(text)?;

    Some(ManagedRuntimeSummary {
        backend_id: state
            .get("backend_id")
            .and_then(|value| value.as_str())?
            .to_string(),
        control_contract: state
            .get("control_contract")
            .and_then(|value| value.as_str())?
            .to_string(),
        driver_profile: state
            .get("driver_profile")
            .and_then(|value| value.as_str())?
            .to_string(),
        lifecycle_adapter: state
            .get("lifecycle_adapter")
            .and_then(|value| value.as_str())?
            .to_string(),
        runtime_phase: state
            .get("phase")
            .and_then(|value| value.as_str())?
            .to_string(),
        runtime_outcome: state
            .get("runtime_outcome")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        workspace_dir: state
            .get("workspace_dir")
            .and_then(|value| value.as_str())?
            .to_string(),
        services: services_from_runtime_state_json(text),
        launch_mode: state
            .get("launch_mode")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        stop_mode: state
            .get("stop_mode")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        launch_manifest_present: state
            .get("launch_manifest_present")
            .and_then(|value| value.as_bool()),
        probe_result_contract: state
            .get("probe_result_contract")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        probe_result_contract_verified: state
            .get("probe_result_contract_verified")
            .and_then(|value| value.as_bool()),
        probe_source: state
            .get("probe_source")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        probe_outcome: state
            .get("probe_outcome")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        stop_result_contract: state
            .get("stop_result_contract")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        stop_result_contract_verified: state
            .get("stop_result_contract_verified")
            .and_then(|value| value.as_bool()),
        stop_exit_code: state.get("stop_exit_code").and_then(|value| value.as_i64()),
        workspace_removed: state
            .get("workspace_removed")
            .and_then(|value| value.as_bool()),
    })
}

pub fn managed_runtime_summary_from_runtime_state_json(
    subkind: &str,
    text: &str,
) -> Option<ManagedRuntimeSummary> {
    match subkind {
        "managed-runtime-summary" => managed_runtime_summary_from_summary_json(text),
        "managed-runtime-status"
        | "managed-linux-vm-launch-state"
        | "firmae-upstream-observation" => managed_runtime_summary_from_runtime_status_json(text),
        _ => None,
    }
}

fn runtime_status_state_from_json(text: &str) -> Option<serde_json::Value> {
    let Ok(state) = serde_json::from_str::<serde_json::Value>(text) else {
        return None;
    };
    if let Some(runtime_status) = state.get("runtime_status") {
        return runtime_status
            .as_object()
            .map(|object| serde_json::Value::Object(object.clone()));
    }
    Some(state)
}

pub fn managed_runtime_summary_from_summary_json(text: &str) -> Option<ManagedRuntimeSummary> {
    let mut summary = serde_json::from_str::<ManagedRuntimeSummary>(text).ok()?;
    summary.services = dedup_services(summary.services);
    Some(summary)
}

#[cfg(test)]
mod tests {
    use super::{
        managed_runtime_phase_signature_from_json,
        managed_runtime_phase_signature_from_summary_json,
        managed_runtime_summary_from_runtime_state_json,
        managed_runtime_summary_from_runtime_status_json,
        managed_runtime_summary_from_summary_json, managed_stop_summary_from_runtime_state_json,
        services_from_runtime_state_json,
    };
    use crate::runs::HealthState;

    #[test]
    fn runtime_state_service_parser_extracts_service_endpoints() {
        let services = services_from_runtime_state_json(
            &serde_json::json!({
                "endpoints": [
                    {
                        "kind": "shell",
                        "name": "shell",
                        "host": "127.0.0.1",
                        "port": 2202,
                        "uri": "ssh://127.0.0.1:2202"
                    },
                    {
                        "kind": "service",
                        "name": "web-admin",
                        "host": "127.0.0.1",
                        "port": 18080,
                        "uri": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        );

        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].display_label(),
            "web-admin http://127.0.0.1:18080"
        );
    }

    #[test]
    fn managed_runtime_phase_signature_parser_extracts_backend_phase() {
        let signature = managed_runtime_phase_signature_from_json(
            &serde_json::json!({
                "backend_id": "firmae",
                "phase": "probe-healthy"
            })
            .to_string(),
        );

        assert_eq!(signature.as_deref(), Some("firmae:probe-healthy"));
    }

    #[test]
    fn managed_stop_summary_parser_handles_unified_runtime_status() {
        let summary = managed_stop_summary_from_runtime_state_json(
            "managed-runtime-status",
            &serde_json::json!({
                "phase": "stop-failed",
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "stop_result_contract": "firmae-legacy-wrapper-stop-v1",
                "stop_result_contract_verified": false,
                "stop_mode": "legacy-wrapper-stop",
                "workspace_dir": "/tmp/firmae",
                "workspace_removed": false,
                "stop_exit_code": 0,
                "stdout": "firmware stopped"
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.phase.as_deref(), Some("stop-failed"));
        assert_eq!(summary.result_contract, "firmae-legacy-wrapper-stop-v1");
        assert!(!summary.is_fully_verified());
    }

    #[test]
    fn managed_stop_summary_parser_handles_upstream_stop_contract() {
        let summary = managed_stop_summary_from_runtime_state_json(
            "managed-runtime-status",
            &serde_json::json!({
                "phase": "stop-complete",
                "backend_id": "firmae",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "control_contract": "firmae-legacy-wrapper-v1",
                "lifecycle_adapter": "legacy-wrapper",
                "stop_result_contract": "firmae-upstream-container-stop-v1",
                "stop_result_contract_verified": true,
                "stop_mode": "legacy-wrapper-stop",
                "workspace_dir": "/tmp/firmae",
                "workspace_removed": true,
                "stop_exit_code": 0,
                "stdout": "firmae-upstream-stop-1"
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.phase.as_deref(), Some("stop-complete"));
        assert_eq!(summary.result_contract, "firmae-upstream-container-stop-v1");
        assert!(summary.is_fully_verified());
    }

    #[test]
    fn managed_runtime_summary_parser_extracts_unified_runtime_fields() {
        let summary = managed_runtime_summary_from_runtime_status_json(
            &serde_json::json!({
                "backend_id": "firmae",
                "control_contract": "firmae-legacy-wrapper-v1",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "lifecycle_adapter": "legacy-wrapper",
                "phase": "probe-healthy",
                "runtime_outcome": "booted-services-unreachable",
                "workspace_dir": "/tmp/firmae",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "launch_manifest_present": false,
                "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                "probe_result_contract_verified": true,
                "probe_source": "background-supervisor",
                "probe_outcome": "healthy",
                "endpoints": [
                    {
                        "kind": "service",
                        "name": "web-admin",
                        "host": "127.0.0.1",
                        "port": 18080,
                        "uri": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.backend_id, "firmae");
        assert_eq!(summary.runtime_phase, "probe-healthy");
        assert_eq!(
            summary.runtime_outcome.as_deref(),
            Some("booted-services-unreachable")
        );
        assert_eq!(
            summary.probe_result_contract.as_deref(),
            Some("firmae-legacy-wrapper-probe-v1")
        );
        assert_eq!(summary.probe_result_contract_verified, Some(true));
        assert_eq!(
            summary.services[0].display_label(),
            "web-admin http://127.0.0.1:18080"
        );
    }

    #[test]
    fn managed_runtime_summary_health_state_maps_guest_unreachable_outcome() {
        let summary = managed_runtime_summary_from_runtime_status_json(
            &serde_json::json!({
                "backend_id": "firmae",
                "control_contract": "firmae-legacy-wrapper-v1",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "lifecycle_adapter": "legacy-wrapper",
                "phase": "probe-unreachable",
                "runtime_outcome": "guest-unreachable",
                "workspace_dir": "/tmp/firmae",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "probe_source": "probe-on-status",
                "probe_outcome": "unreachable"
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(
            summary.runtime_outcome.as_deref(),
            Some("guest-unreachable")
        );
        assert_eq!(summary.health_state(), HealthState::GuestUnreachable);
    }

    #[test]
    fn managed_runtime_summary_health_state_maps_booted_services_reachable_outcome() {
        let summary = managed_runtime_summary_from_runtime_status_json(
            &serde_json::json!({
                "backend_id": "firmae",
                "control_contract": "firmae-legacy-wrapper-v1",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "lifecycle_adapter": "legacy-wrapper",
                "phase": "probe-healthy",
                "runtime_outcome": "booted-services-reachable",
                "workspace_dir": "/tmp/firmae",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "probe_source": "probe-on-status",
                "probe_outcome": "healthy"
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(
            summary.runtime_outcome.as_deref(),
            Some("booted-services-reachable")
        );
        assert_eq!(summary.health_state(), HealthState::BootedServicesReachable);
    }

    #[test]
    fn managed_runtime_summary_artifact_parser_extracts_normalized_fields() {
        let summary = managed_runtime_summary_from_summary_json(
            &serde_json::json!({
                "backend_id": "firmae",
                "control_contract": "firmae-legacy-wrapper-v1",
                "driver_profile": "firmae-managed-legacy-wrapper",
                "lifecycle_adapter": "legacy-wrapper",
                "runtime_phase": "probe-healthy",
                "runtime_outcome": "booted-services-unreachable",
                "workspace_dir": "/tmp/firmae",
                "launch_mode": "legacy-wrapper-launch",
                "stop_mode": "legacy-wrapper-stop",
                "launch_manifest_present": false,
                "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                "probe_result_contract_verified": true,
                "probe_source": "background-supervisor",
                "probe_outcome": "healthy",
                "services": [
                    {
                        "name": "web-admin",
                        "endpoint": "http://127.0.0.1:18080"
                    }
                ]
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.backend_id, "firmae");
        assert_eq!(summary.runtime_phase, "probe-healthy");
        assert_eq!(
            summary.runtime_outcome.as_deref(),
            Some("booted-services-unreachable")
        );
        assert_eq!(
            summary.services[0].display_label(),
            "web-admin http://127.0.0.1:18080"
        );
        assert_eq!(
            managed_runtime_phase_signature_from_summary_json(&summary.to_json_string()).as_deref(),
            Some("firmae:probe-healthy")
        );
    }

    #[test]
    fn managed_runtime_summary_parser_normalizes_upstream_observation_runtime_status() {
        let summary = managed_runtime_summary_from_runtime_status_json(
            &serde_json::json!({
                "observation_source": "bounded-live-inspection",
                "observation_timestamp": "unix-ms:1710000000000",
                "container_name": "firmae-upstream-1",
                "container_running": true,
                "scratch_artifacts_present": true,
                "observed_artifact_paths": [
                    "/tmp/firmae/scratch/1/qemu.initial.serial.log",
                    "/tmp/firmae/scratch/1/qemu.final.serial.log",
                    "/tmp/firmae/scratch/1/makeNetwork.log"
                ],
                "guest_ip": "192.168.0.1",
                "guest_reachable": true,
                "port_80_reachable": false,
                "port_31337_reachable": false,
                "port_31338_reachable": false,
                "runtime_status": {
                    "backend_id": "firmae",
                    "control_contract": "firmae-legacy-wrapper-v1",
                    "driver_profile": "firmae-managed-legacy-wrapper",
                    "lifecycle_adapter": "legacy-wrapper",
                    "phase": "probe-unreachable",
                    "runtime_outcome": "booted-services-unreachable",
                    "workspace_dir": "/tmp/firmae",
                    "services": [
                        {
                            "name": "web-admin",
                            "endpoint": "http://127.0.0.1:18080"
                        }
                    ],
                    "launch_mode": "legacy-wrapper-launch",
                    "stop_mode": "legacy-wrapper-stop",
                    "launch_manifest_present": false,
                    "probe_result_contract": "firmae-legacy-wrapper-probe-v1",
                    "probe_result_contract_verified": true,
                    "probe_source": "probe-on-status",
                    "probe_outcome": "unreachable"
                }
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.backend_id, "firmae");
        assert_eq!(summary.runtime_phase, "probe-unreachable");
        assert_eq!(
            summary.runtime_outcome.as_deref(),
            Some("booted-services-unreachable")
        );
        assert_eq!(summary.services.len(), 1);
        assert_eq!(
            summary.services[0].display_label(),
            "web-admin http://127.0.0.1:18080"
        );
    }

    #[test]
    fn managed_runtime_summary_from_runtime_state_handles_observation_subkind() {
        let summary = managed_runtime_summary_from_runtime_state_json(
            "firmae-upstream-observation",
            &serde_json::json!({
                "runtime_status": {
                    "backend_id": "firmae",
                    "control_contract": "firmae-legacy-wrapper-v1",
                    "driver_profile": "firmae-managed-legacy-wrapper",
                    "lifecycle_adapter": "legacy-wrapper",
                    "phase": "probe-unreachable",
                    "runtime_outcome": "booted-services-unreachable",
                    "workspace_dir": "/tmp/firmae",
                    "launch_mode": "upstream-launch",
                    "stop_mode": "legacy-wrapper-stop",
                    "probe_source": "probe-on-status",
                    "probe_outcome": "unreachable"
                }
            })
            .to_string(),
        )
        .expect("summary");

        assert_eq!(summary.backend_id, "firmae");
        assert_eq!(summary.runtime_phase, "probe-unreachable");
    }
}
