use crate::android::discovery::{AndroidDiscoverLead, AndroidDiscoverReport, AndroidEntrySurface};
use crate::target_lanes::{
    EmptyAdapterConfig, LaneAdapter, PreflightCheck, TargetLaneManifest, TargetLaneRecord,
    TARGET_LANE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fat_core::data_dir::DataResolver;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidRuntimeHandoff {
    pub lead_id: String,
    pub lane_id: String,
    pub family: String,
    pub adapter_kind: String,
    pub package_name: String,
}

pub fn build_runtime_manifest(
    report: &AndroidDiscoverReport,
    package_name: &str,
    output_path: &Path,
) -> Result<(TargetLaneManifest, Vec<AndroidRuntimeHandoff>), String> {
    if report.leads.is_empty() {
        return Err("android discover report has no leads to hand off".into());
    }
    let data_root = android_runtime_data_root()?;
    let artifact_root = output_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("android-runtime-artifacts");

    let mut handoffs = Vec::new();
    let mut lanes = Vec::new();
    for lead in &report.leads {
        let handoff = build_handoff(lead, package_name);
        let lane = build_lane_record(
            lead,
            &handoff,
            &data_root,
            &artifact_root,
            &report.base_apk,
            &report.split_apks,
        );
        handoffs.push(handoff);
        lanes.push(lane);
    }

    Ok((
        TargetLaneManifest {
            schema_version: TARGET_LANE_SCHEMA_VERSION.into(),
            local_manifest_path_hint: Some(output_path.display().to_string()),
            lanes,
        },
        handoffs,
    ))
}

pub fn write_runtime_manifest(manifest: &TargetLaneManifest, path: &Path) -> Result<(), String> {
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("serialize runtime manifest failed: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create manifest parent {} failed: {e}", parent.display()))?;
    }
    fs::write(path, body)
        .map_err(|e| format!("write runtime manifest {} failed: {e}", path.display()))
}

fn build_handoff(lead: &AndroidDiscoverLead, package_name: &str) -> AndroidRuntimeHandoff {
    AndroidRuntimeHandoff {
        lead_id: lead.lead_id.clone(),
        lane_id: format!("android-{}", sanitize(&lead.lead_id)),
        family: lead.family.clone(),
        adapter_kind: adapter_kind_for_family(&lead.family).into(),
        package_name: package_name.into(),
    }
}

fn build_lane_record(
    lead: &AndroidDiscoverLead,
    handoff: &AndroidRuntimeHandoff,
    repo_root: &Path,
    artifact_root: &Path,
    base_apk: &str,
    split_apks: &[String],
) -> TargetLaneRecord {
    let artifact_dir = artifact_root.join(&handoff.lane_id);
    let binary_or_driver = "python3".to_string();
    let launcher_command = launcher_command_for_lead(
        lead,
        handoff,
        repo_root,
        &artifact_dir,
        base_apk,
        split_apks,
    );
    TargetLaneRecord {
        lane_id: handoff.lane_id.clone(),
        family_allowlist: vec![lead.family.clone()],
        source_root: repo_root.display().to_string(),
        build_dir: repo_root.display().to_string(),
        binary_or_driver: binary_or_driver.clone(),
        launcher_command,
        required_env: BTreeMap::from([("ANDROID_SERIAL".into(), "${ANDROID_SERIAL}".into())]),
        adapter: Some(adapter_for_kind(&handoff.adapter_kind)),
        timeout_ms: 30_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "none".into(),
        proof_class_allowlist: if lead.expected_proof_signal.is_empty() {
            vec!["observation".into()]
        } else {
            lead.expected_proof_signal
                .iter()
                .map(|signal| signal.kind.clone())
                .collect()
        },
        runtime_capabilities: Default::default(),
        preflight_checks: vec![
            PreflightCheck {
                check_id: "python3-available".into(),
                kind: "command-available".into(),
                target: "python3".into(),
                detail: "python3 must be available to execute Android runner scripts".into(),
            },
            PreflightCheck {
                check_id: "adb-available".into(),
                kind: "command-available".into(),
                target: "adb".into(),
                detail: "adb must be available to reach the Android runtime target".into(),
            },
            PreflightCheck {
                check_id: "adb-device-ready".into(),
                kind: "adb-device".into(),
                target: "ANDROID_SERIAL".into(),
                detail: "ANDROID_SERIAL must identify a ready adb device".into(),
            },
            PreflightCheck {
                check_id: "package-installed".into(),
                kind: "adb-package-installed".into(),
                target: handoff.package_name.clone(),
                detail: "target package should already be installable or present on the device"
                    .into(),
            },
        ],
    }
}

fn launcher_command_for_lead(
    lead: &AndroidDiscoverLead,
    handoff: &AndroidRuntimeHandoff,
    repo_root: &Path,
    artifact_dir: &Path,
    base_apk: &str,
    split_apks: &[String],
) -> Vec<String> {
    let script = match handoff.adapter_kind.as_str() {
        "android-adb-icc" => repo_root.join("scripts/discovery/android/adb_icc_runner.py"),
        "android-instrumentation-webview" => {
            repo_root.join("scripts/discovery/android/webview_runner.py")
        }
        "android-instrumentation-native" => {
            repo_root.join("scripts/discovery/android/native_runner.py")
        }
        _ => repo_root.join("scripts/discovery/android/adb_icc_runner.py"),
    };
    let mut command = vec![
        "python3".into(),
        script.display().to_string(),
        "--package".into(),
        handoff.package_name.clone(),
        "--apk".into(),
        base_apk.to_string(),
        "--artifact-dir".into(),
        artifact_dir.display().to_string(),
    ];
    for split in split_apks {
        command.push("--split-apk".into());
        command.push(split.clone());
    }

    match handoff.adapter_kind.as_str() {
        "android-adb-icc" => {
            if matches!(
                lead.metadata.entry_surface,
                Some(AndroidEntrySurface::DeepLink)
            ) {
                command.push("--action".into());
                command.push("android.intent.action.VIEW".into());
                command.push("--data-uri".into());
                command.push(runtime_uri_for_lead(lead));
            } else {
                command.push("--action".into());
                command.push("android.intent.action.VIEW".into());
                command.push("--extra".into());
                command.push(format!(
                    "fat_trigger={}",
                    lead.suggested_trigger_recipe
                        .first()
                        .map(|step| step.detail.as_str())
                        .unwrap_or("android-trigger")
                ));
            }
        }
        "android-instrumentation-webview" => {
            command.push("--entry-url".into());
            command.push(
                lead.suggested_trigger_recipe
                    .first()
                    .map(|step| step.detail.clone())
                    .unwrap_or_else(|| "https://attacker.example/bridge.html".into()),
            );
            command.push("--runner".into());
            command.push(format!(
                "{}.test/androidx.test.runner.AndroidJUnitRunner",
                handoff.package_name
            ));
        }
        "android-instrumentation-native" => {
            command.push("--binder-transaction".into());
            command.push(
                lead.suggested_trigger_recipe
                    .first()
                    .map(|step| step.detail.clone())
                    .unwrap_or_else(|| "TRANSACTION_probe".into()),
            );
            command.push("--symbol".into());
            command.push(lead.symbol.clone());
            command.push("--runner".into());
            command.push(format!(
                "{}.test/androidx.test.runner.AndroidJUnitRunner",
                handoff.package_name
            ));
        }
        _ => {}
    }

    command
}

fn runtime_uri_for_lead(lead: &AndroidDiscoverLead) -> String {
    let detail = lead
        .suggested_trigger_recipe
        .first()
        .map(|step| step.detail.as_str())
        .unwrap_or("route://deeplink");
    if detail.contains("://") {
        return detail.to_string();
    }
    if lead.symbol.starts_with('/') {
        return format!(
            "https://runtime.example{}",
            lead.symbol.replace("{sn}", "demo")
        );
    }
    "route://deeplink".into()
}

fn adapter_kind_for_family(family: &str) -> &'static str {
    match family {
        "remote-router-gadget" | "capability-chain-confused-deputy" => "android-adb-icc",
        "webview-bridge-uri" => "android-instrumentation-webview",
        "binder-native-boundary" => "android-instrumentation-native",
        _ => "android-adb-icc",
    }
}

fn adapter_for_kind(kind: &str) -> LaneAdapter {
    match kind {
        "android-adb-icc" => LaneAdapter::AndroidAdbIcc {
            config: EmptyAdapterConfig::default(),
        },
        "android-instrumentation-webview" => LaneAdapter::AndroidInstrumentationWebview {
            config: EmptyAdapterConfig::default(),
        },
        "android-adb-provider" => LaneAdapter::AndroidAdbProvider {
            config: EmptyAdapterConfig::default(),
        },
        "android-instrumentation-native" => LaneAdapter::AndroidInstrumentationNative {
            config: EmptyAdapterConfig::default(),
        },
        _ => LaneAdapter::AndroidAdbIcc {
            config: EmptyAdapterConfig::default(),
        },
    }
}

fn android_runtime_data_root() -> Result<PathBuf, String> {
    let resolved = DataResolver::for_current_process(None)
        .resolve_required("scripts/discovery/android")
        .map_err(|error| error.to_string())?;
    Ok(resolved.root)
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '-',
        })
        .collect()
}
