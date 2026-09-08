use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

pub const TARGET_LANE_SCHEMA_VERSION: &str = "fat-discovery-target-lanes-v1";
const VALID_SANITIZER_MODES: &[&str] = &["asan", "ubsan", "asan+ubsan", "none"];
const VALID_PATH_TARGETS: &[&str] = &["source_root", "build_dir", "artifact_dir"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLaneManifest {
    pub schema_version: String,
    #[serde(default)]
    pub local_manifest_path_hint: Option<String>,
    pub lanes: Vec<TargetLaneRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePreflightCheckResult {
    pub check_id: String,
    pub kind: String,
    pub target: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePreflightResult {
    pub lane_id: String,
    pub ok: bool,
    #[serde(default)]
    pub checks: Vec<LanePreflightCheckResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetLanePreflightReport {
    pub ok: bool,
    #[serde(default)]
    pub local_manifest_path_hint: Option<String>,
    #[serde(default)]
    pub lanes: Vec<LanePreflightResult>,
}

impl TargetLaneManifest {
    pub fn resolve_lane(&self, lane_id: &str) -> Option<&TargetLaneRecord> {
        self.lanes.iter().find(|lane| lane.lane_id == lane_id)
    }

    pub fn resolve_family(&self, family_id: &str) -> Vec<&TargetLaneRecord> {
        self.lanes
            .iter()
            .filter(|lane| {
                lane.family_allowlist
                    .iter()
                    .any(|family| family == family_id)
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLaneRecord {
    pub lane_id: String,
    pub family_allowlist: Vec<String>,
    pub source_root: String,
    pub build_dir: String,
    pub binary_or_driver: String,
    pub launcher_command: Vec<String>,
    pub required_env: BTreeMap<String, String>,
    #[serde(default)]
    pub adapter: Option<LaneAdapter>,
    pub timeout_ms: u64,
    pub artifact_dir: String,
    pub sanitizer_mode: String,
    pub proof_class_allowlist: Vec<String>,
    #[serde(default)]
    pub runtime_capabilities: RuntimeCapabilities,
    pub preflight_checks: Vec<PreflightCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaneAdapterKind {
    BrowserLifetimeWebtest,
    DirectCliSize,
    StderrProofProtocol,
    StderrProofValidation,
    AndroidAdbIcc,
    AndroidInstrumentationWebview,
    AndroidAdbProvider,
    AndroidInstrumentationNative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BrowserLifetimeWebtestAdapterConfig {
    #[serde(default)]
    pub target_binary_env: Option<String>,
    #[serde(default)]
    pub timeout_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyAdapterConfig {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LaneAdapter {
    BrowserLifetimeWebtest {
        #[serde(default)]
        config: BrowserLifetimeWebtestAdapterConfig,
    },
    DirectCliSize {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    StderrProofProtocol {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    StderrProofValidation {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    AndroidAdbIcc {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    AndroidInstrumentationWebview {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    AndroidAdbProvider {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
    AndroidInstrumentationNative {
        #[serde(default)]
        config: EmptyAdapterConfig,
    },
}

impl LaneAdapter {
    pub fn kind(&self) -> LaneAdapterKind {
        match self {
            LaneAdapter::BrowserLifetimeWebtest { .. } => LaneAdapterKind::BrowserLifetimeWebtest,
            LaneAdapter::DirectCliSize { .. } => LaneAdapterKind::DirectCliSize,
            LaneAdapter::StderrProofProtocol { .. } => LaneAdapterKind::StderrProofProtocol,
            LaneAdapter::StderrProofValidation { .. } => LaneAdapterKind::StderrProofValidation,
            LaneAdapter::AndroidAdbIcc { .. } => LaneAdapterKind::AndroidAdbIcc,
            LaneAdapter::AndroidInstrumentationWebview { .. } => {
                LaneAdapterKind::AndroidInstrumentationWebview
            }
            LaneAdapter::AndroidAdbProvider { .. } => LaneAdapterKind::AndroidAdbProvider,
            LaneAdapter::AndroidInstrumentationNative { .. } => {
                LaneAdapterKind::AndroidInstrumentationNative
            }
        }
    }

    pub fn browser_lifetime_webtest_config(&self) -> Option<&BrowserLifetimeWebtestAdapterConfig> {
        match self {
            LaneAdapter::BrowserLifetimeWebtest { config } => Some(config),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeCapabilities {
    pub accepts_arg_size: bool,
    pub accepts_width: bool,
    pub accepts_height: bool,
    pub accepts_row_pitch: bool,
    pub accepts_depth_pitch: bool,
    pub accepts_payload_bytes: bool,
    pub honors_arg_size: bool,
    pub honors_width: bool,
    pub honors_height: bool,
    pub honors_row_pitch: bool,
    pub honors_depth_pitch: bool,
    pub honors_payload_bytes: bool,
    pub accepts_callback_count: bool,
    pub accepts_teardown_mode: bool,
    pub accepts_cancellation_mode: bool,
    pub accepts_observer_mutation_mode: bool,
    pub accepts_navigation_mode: bool,
    pub honors_callback_count: bool,
    pub honors_teardown_mode: bool,
    pub honors_cancellation_mode: bool,
    pub honors_observer_mutation_mode: bool,
    pub honors_navigation_mode: bool,
    pub requires_vk_icd: bool,
    pub requires_gpu_backend: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightCheck {
    pub check_id: String,
    pub kind: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightCheckKind {
    PathExists,
    EnvNonempty,
    CommandAvailable,
    AdbDevice,
    AdbPackageInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredEnvValue {
    Literal(String),
    HostPlaceholder(String),
}

impl PreflightCheck {
    pub fn parsed_kind(&self) -> Option<PreflightCheckKind> {
        match self.kind.as_str() {
            "path-exists" => Some(PreflightCheckKind::PathExists),
            "env-nonempty" => Some(PreflightCheckKind::EnvNonempty),
            "command-available" => Some(PreflightCheckKind::CommandAvailable),
            "adb-device" => Some(PreflightCheckKind::AdbDevice),
            "adb-package-installed" => Some(PreflightCheckKind::AdbPackageInstalled),
            _ => None,
        }
    }
}

impl TargetLaneRecord {
    pub fn parsed_adapter_kind(&self) -> Option<LaneAdapterKind> {
        self.adapter.as_ref().map(|adapter| adapter.kind())
    }

    pub fn resolve_required_env_value(&self, key: &str) -> Option<RequiredEnvValue> {
        self.required_env
            .get(key)
            .and_then(|value| parse_required_env_value(value))
    }
}

pub fn load_target_lane_manifest(path: &Path) -> Result<TargetLaneManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let manifest: TargetLaneManifest =
        serde_json::from_str(&text).map_err(|e| format!("invalid target lane manifest: {e}"))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn load_target_lanes(path: &Path) -> Result<Vec<TargetLaneRecord>, String> {
    let manifest = load_target_lane_manifest(path)?;
    Ok(manifest.lanes)
}

pub fn preflight_target_lane_manifest(manifest: &TargetLaneManifest) -> TargetLanePreflightReport {
    let lanes = manifest
        .lanes
        .iter()
        .map(preflight_lane)
        .collect::<Vec<_>>();
    let ok = lanes.iter().all(|lane| lane.ok);
    TargetLanePreflightReport {
        ok,
        local_manifest_path_hint: manifest.local_manifest_path_hint.clone(),
        lanes,
    }
}

fn validate_manifest(manifest: &TargetLaneManifest) -> Result<(), String> {
    if manifest.schema_version != TARGET_LANE_SCHEMA_VERSION {
        return Err(format!(
            "target lane manifest schema_version must be {TARGET_LANE_SCHEMA_VERSION}"
        ));
    }
    if manifest
        .local_manifest_path_hint
        .as_ref()
        .is_some_and(|hint| hint.trim().is_empty())
    {
        return Err("local_manifest_path_hint must not be empty when present".into());
    }
    if manifest.lanes.is_empty() {
        return Err("target lane manifest must contain at least one lane".into());
    }

    let mut lane_ids = BTreeSet::new();
    for lane in &manifest.lanes {
        validate_lane(lane)?;
        if !lane_ids.insert(lane.lane_id.as_str()) {
            return Err(format!("duplicate lane_id {}", lane.lane_id));
        }
    }

    Ok(())
}

fn validate_lane(lane: &TargetLaneRecord) -> Result<(), String> {
    if lane.lane_id.trim().is_empty() {
        return Err("lane_id must not be empty".into());
    }
    if lane.family_allowlist.is_empty() {
        return Err(format!("lane {} missing family_allowlist", lane.lane_id));
    }
    if lane
        .family_allowlist
        .iter()
        .any(|family| family.trim().is_empty())
    {
        return Err(format!(
            "lane {} has an empty family_allowlist entry",
            lane.lane_id
        ));
    }
    if lane.source_root.trim().is_empty() {
        return Err(format!("lane {} missing source_root", lane.lane_id));
    }
    if lane.build_dir.trim().is_empty() {
        return Err(format!("lane {} missing build_dir", lane.lane_id));
    }
    if lane.binary_or_driver.trim().is_empty() {
        return Err(format!("lane {} missing binary_or_driver", lane.lane_id));
    }
    if lane.launcher_command.is_empty() {
        return Err(format!("lane {} missing launcher_command", lane.lane_id));
    }
    if lane
        .launcher_command
        .iter()
        .any(|arg| arg.trim().is_empty())
    {
        return Err(format!(
            "lane {} has an empty launcher_command entry",
            lane.lane_id
        ));
    }
    if lane.launcher_command[0] != lane.binary_or_driver {
        return Err(format!(
            "lane {} binary_or_driver must match launcher_command[0]",
            lane.lane_id
        ));
    }
    if lane.required_env.is_empty() {
        return Err(format!("lane {} missing required_env", lane.lane_id));
    }
    validate_adapter(lane)?;
    validate_runtime_capabilities(lane)?;
    if lane
        .required_env
        .iter()
        .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
    {
        return Err(format!(
            "lane {} has an empty required_env binding",
            lane.lane_id
        ));
    }
    for (key, value) in &lane.required_env {
        if parse_required_env_value(value).is_none() {
            return Err(format!(
                "lane {} has an invalid required_env binding for {}",
                lane.lane_id, key
            ));
        }
    }
    if lane.timeout_ms == 0 {
        return Err(format!("lane {} must have timeout_ms > 0", lane.lane_id));
    }
    if lane.artifact_dir.trim().is_empty() {
        return Err(format!("lane {} missing artifact_dir", lane.lane_id));
    }
    if lane.sanitizer_mode.trim().is_empty() {
        return Err(format!("lane {} missing sanitizer_mode", lane.lane_id));
    }
    if !VALID_SANITIZER_MODES.contains(&lane.sanitizer_mode.as_str()) {
        return Err(format!(
            "lane {} has unsupported sanitizer_mode {}",
            lane.lane_id, lane.sanitizer_mode
        ));
    }
    if lane.proof_class_allowlist.is_empty() {
        return Err(format!(
            "lane {} missing proof_class_allowlist",
            lane.lane_id
        ));
    }
    if lane
        .proof_class_allowlist
        .iter()
        .any(|proof_class| proof_class.trim().is_empty())
    {
        return Err(format!(
            "lane {} has an empty proof_class_allowlist entry",
            lane.lane_id
        ));
    }
    if lane.preflight_checks.is_empty() {
        return Err(format!("lane {} missing preflight_checks", lane.lane_id));
    }
    for check in &lane.preflight_checks {
        validate_preflight_check(lane, check)?;
    }

    Ok(())
}

fn validate_adapter(lane: &TargetLaneRecord) -> Result<(), String> {
    let Some(adapter) = &lane.adapter else {
        return Ok(());
    };

    match adapter {
        LaneAdapter::BrowserLifetimeWebtest { config } => {
            if config
                .target_binary_env
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(format!(
                    "lane {} browser-lifetime-webtest target_binary_env must not be empty",
                    lane.lane_id
                ));
            }
            if config
                .timeout_env
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(format!(
                    "lane {} browser-lifetime-webtest timeout_env must not be empty",
                    lane.lane_id
                ));
            }
        }
        LaneAdapter::DirectCliSize { .. }
        | LaneAdapter::StderrProofProtocol { .. }
        | LaneAdapter::StderrProofValidation { .. }
        | LaneAdapter::AndroidAdbIcc { .. }
        | LaneAdapter::AndroidInstrumentationWebview { .. }
        | LaneAdapter::AndroidAdbProvider { .. }
        | LaneAdapter::AndroidInstrumentationNative { .. } => {}
    }

    Ok(())
}

fn validate_runtime_capabilities(lane: &TargetLaneRecord) -> Result<(), String> {
    let caps = &lane.runtime_capabilities;
    for (honors, accepts, name) in [
        (caps.honors_arg_size, caps.accepts_arg_size, "arg_size"),
        (caps.honors_width, caps.accepts_width, "width"),
        (caps.honors_height, caps.accepts_height, "height"),
        (caps.honors_row_pitch, caps.accepts_row_pitch, "row_pitch"),
        (
            caps.honors_depth_pitch,
            caps.accepts_depth_pitch,
            "depth_pitch",
        ),
        (
            caps.honors_payload_bytes,
            caps.accepts_payload_bytes,
            "payload_bytes",
        ),
        (
            caps.honors_callback_count,
            caps.accepts_callback_count,
            "callback_count",
        ),
        (
            caps.honors_teardown_mode,
            caps.accepts_teardown_mode,
            "teardown_mode",
        ),
        (
            caps.honors_cancellation_mode,
            caps.accepts_cancellation_mode,
            "cancellation_mode",
        ),
        (
            caps.honors_observer_mutation_mode,
            caps.accepts_observer_mutation_mode,
            "observer_mutation_mode",
        ),
        (
            caps.honors_navigation_mode,
            caps.accepts_navigation_mode,
            "navigation_mode",
        ),
    ] {
        if honors && !accepts {
            return Err(format!(
                "lane {} honors {} but does not accept it",
                lane.lane_id, name
            ));
        }
    }
    Ok(())
}

fn preflight_lane(lane: &TargetLaneRecord) -> LanePreflightResult {
    let checks = lane
        .preflight_checks
        .iter()
        .map(|check| {
            let passed = match check.parsed_kind() {
                Some(PreflightCheckKind::PathExists) => resolve_path_target(lane, &check.target)
                    .map(|path| Path::new(path).exists())
                    .unwrap_or(false),
                Some(PreflightCheckKind::EnvNonempty) => lane
                    .resolve_required_env_value(&check.target)
                    .map(|value| match value {
                        RequiredEnvValue::Literal(inner) => !inner.trim().is_empty(),
                        RequiredEnvValue::HostPlaceholder(env_key) => std::env::var(env_key)
                            .ok()
                            .is_some_and(|value| !value.trim().is_empty()),
                    })
                    .unwrap_or(false),
                Some(PreflightCheckKind::CommandAvailable) => {
                    resolve_preflight_target_value(lane, &check.target)
                        .map(|command| command_available(&command))
                        .unwrap_or(false)
                }
                Some(PreflightCheckKind::AdbDevice) => {
                    resolve_preflight_target_value(lane, &check.target)
                        .map(|serial| adb_device_ready(&serial))
                        .unwrap_or(false)
                }
                Some(PreflightCheckKind::AdbPackageInstalled) => {
                    adb_package_installed(lane, &check.target)
                }
                None => false,
            };
            LanePreflightCheckResult {
                check_id: check.check_id.clone(),
                kind: check.kind.clone(),
                target: check.target.clone(),
                passed,
                detail: check.detail.clone(),
            }
        })
        .collect::<Vec<_>>();

    LanePreflightResult {
        lane_id: lane.lane_id.clone(),
        ok: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn resolve_path_target<'a>(lane: &'a TargetLaneRecord, target: &str) -> Option<&'a str> {
    match target {
        "source_root" => Some(lane.source_root.as_str()),
        "build_dir" => Some(lane.build_dir.as_str()),
        "artifact_dir" => Some(lane.artifact_dir.as_str()),
        _ => None,
    }
}

fn resolve_preflight_target_value(lane: &TargetLaneRecord, target: &str) -> Option<String> {
    if lane.required_env.contains_key(target) {
        return lane
            .resolve_required_env_value(target)
            .and_then(|value| match value {
                RequiredEnvValue::Literal(inner) => Some(inner),
                RequiredEnvValue::HostPlaceholder(env_key) => std::env::var(env_key).ok(),
            });
    }
    Some(target.to_string())
}

fn validate_preflight_check(lane: &TargetLaneRecord, check: &PreflightCheck) -> Result<(), String> {
    if check.check_id.trim().is_empty() {
        return Err(format!(
            "lane {} has a preflight check without check_id",
            lane.lane_id
        ));
    }
    if check.kind.trim().is_empty() {
        return Err(format!(
            "lane {} has preflight check {} without kind",
            lane.lane_id, check.check_id
        ));
    }
    if check.target.trim().is_empty() {
        return Err(format!(
            "lane {} has preflight check {} without target",
            lane.lane_id, check.check_id
        ));
    }
    if check.detail.trim().is_empty() {
        return Err(format!(
            "lane {} has preflight check {} without detail",
            lane.lane_id, check.check_id
        ));
    }

    match check.parsed_kind() {
        Some(PreflightCheckKind::PathExists) => {
            if !VALID_PATH_TARGETS.contains(&check.target.as_str()) {
                return Err(format!(
                    "lane {} has path-exists preflight check {} with unsupported target {}",
                    lane.lane_id, check.check_id, check.target
                ));
            }
        }
        Some(PreflightCheckKind::EnvNonempty) => {
            if !lane.required_env.contains_key(&check.target) {
                return Err(format!(
                    "lane {} has env-nonempty preflight check {} for missing required_env key {}",
                    lane.lane_id, check.check_id, check.target
                ));
            }
        }
        Some(PreflightCheckKind::CommandAvailable)
        | Some(PreflightCheckKind::AdbDevice)
        | Some(PreflightCheckKind::AdbPackageInstalled) => {}
        None => {
            return Err(format!(
                "lane {} has preflight check {} with unsupported kind {}",
                lane.lane_id, check.check_id, check.kind
            ));
        }
    }

    Ok(())
}

fn parse_required_env_value(value: &str) -> Option<RequiredEnvValue> {
    if value.trim().is_empty() {
        return None;
    }
    if let Some(stripped) = value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|inner| !inner.trim().is_empty())
    {
        return Some(RequiredEnvValue::HostPlaceholder(stripped.to_string()));
    }
    Some(RequiredEnvValue::Literal(value.to_string()))
}

fn command_available(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(command).exists())
}

fn adb_device_ready(serial: &str) -> bool {
    Command::new("adb")
        .args(["-s", serial, "get-state"])
        .output()
        .ok()
        .is_some_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .to_ascii_lowercase()
                    .contains("device")
        })
}

fn adb_package_installed(lane: &TargetLaneRecord, package_name: &str) -> bool {
    let serial = lane
        .resolve_required_env_value("ANDROID_SERIAL")
        .and_then(|value| match value {
            RequiredEnvValue::Literal(inner) => Some(inner),
            RequiredEnvValue::HostPlaceholder(env_key) => std::env::var(env_key).ok(),
        });
    let mut command = Command::new("adb");
    if let Some(serial) = serial.as_deref() {
        command.args(["-s", serial]);
    }
    command
        .args(["shell", "pm", "path", package_name])
        .output()
        .ok()
        .is_some_and(|output| output.status.success())
}
