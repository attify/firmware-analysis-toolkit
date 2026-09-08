use serde::{Deserialize, Serialize};

use crate::runs::{HealthState, RunStatus, SubstrateKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugSurfaceKind {
    Shell,
    Debugger,
    Monitor,
    ForwardedPort,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugSurfaceState {
    Registered,
    Ready,
    Validated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugCapability {
    ObserveSupported,
    DiagnosticsSupported,
    ShellAttachable,
    DebuggerAttachable,
    MonitorAttachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSurface {
    pub surface_kind: DebugSurfaceKind,
    pub state: DebugSurfaceState,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub target_port: Option<u16>,
    pub uri: Option<String>,
}

impl DebugSurface {
    pub fn new(
        surface_kind: DebugSurfaceKind,
        state: DebugSurfaceState,
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            surface_kind,
            state,
            name: name.into(),
            host: host.into(),
            port,
            target_port: None,
            uri: None,
        }
    }

    pub fn with_target_port(mut self, target_port: u16) -> Self {
        self.target_port = Some(target_port);
        self
    }

    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSurfaceReport {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub substrate_kind: SubstrateKind,
    pub run_status: RunStatus,
    pub health_state: HealthState,
    pub surfaces: Vec<DebugSurface>,
    pub capabilities: Vec<DebugCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSuggestion {
    pub summary: String,
    pub rationale: String,
    pub command: Option<String>,
}

impl DebugSuggestion {
    pub fn new(summary: impl Into<String>, rationale: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            rationale: rationale.into(),
            command: None,
        }
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSuggestionReport {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub suggestions: Vec<DebugSuggestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedServiceEntry {
    pub name: String,
    pub endpoint: Option<String>,
    pub source_kind: String,
}

impl ObservedServiceEntry {
    pub fn new(
        name: impl Into<String>,
        endpoint: Option<&str>,
        source_kind: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.map(str::to_string),
            source_kind: source_kind.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedServiceSnapshot {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub services: Vec<ObservedServiceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedNetworkEntry {
    pub surface_kind: DebugSurfaceKind,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub target_port: Option<u16>,
    pub uri: Option<String>,
}

impl ObservedNetworkEntry {
    pub fn new(
        surface_kind: DebugSurfaceKind,
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            surface_kind,
            name: name.into(),
            host: host.into(),
            port,
            target_port: None,
            uri: None,
        }
    }

    pub fn with_target_port(mut self, target_port: u16) -> Self {
        self.target_port = Some(target_port);
        self
    }

    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedNetworkSnapshot {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub substrate_kind: SubstrateKind,
    pub endpoints: Vec<ObservedNetworkEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProcessEntry {
    pub pid: u32,
    pub command: String,
    pub source_kind: String,
}

impl ObservedProcessEntry {
    pub fn new(pid: u32, command: impl Into<String>, source_kind: impl Into<String>) -> Self {
        Self {
            pid,
            command: command.into(),
            source_kind: source_kind.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProcessSnapshot {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub processes: Vec<ObservedProcessEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugShellTranscript {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub shell_uri: String,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugMonitorTranscript {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub monitor_uri: String,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugGdbTranscript {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub debugger_uri: String,
    pub target: Option<String>,
    pub command: Option<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugMapsTranscript {
    pub session_id: String,
    pub run_id: String,
    pub backend_id: String,
    pub target: String,
    pub maps_uri: String,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl DebugSurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DebugSurfaceKind::Shell => "shell",
            DebugSurfaceKind::Debugger => "debugger",
            DebugSurfaceKind::Monitor => "monitor",
            DebugSurfaceKind::ForwardedPort => "forwarded-port",
            DebugSurfaceKind::Service => "service",
        }
    }
}

impl DebugSurfaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            DebugSurfaceState::Registered => "registered",
            DebugSurfaceState::Ready => "ready",
            DebugSurfaceState::Validated => "validated",
        }
    }
}

impl DebugCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            DebugCapability::ObserveSupported => "observe-supported",
            DebugCapability::DiagnosticsSupported => "diagnostics-supported",
            DebugCapability::ShellAttachable => "shell-attachable",
            DebugCapability::DebuggerAttachable => "debugger-attachable",
            DebugCapability::MonitorAttachable => "monitor-attachable",
        }
    }
}
