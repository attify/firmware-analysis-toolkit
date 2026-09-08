use crate::android::empty_bundle;
use crate::android::extractor::AndroidSemanticMode;
use crate::android::semantic::{
    AndroidControlSurface, AndroidNativeSemantic, AndroidProvenance, AndroidResourceSemantic,
    AndroidSemanticBundle, AndroidSemanticFact, AndroidSupportLevel, AndroidSymbolIdentity,
    AndroidTrustBoundary,
};
use fat_core::zip_preflight::{preflight_zip_file, ZipPreflightLimits};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const MAX_APK_ENTRIES: usize = 65_536;
const MAX_FLUTTER_ENV_BYTES: u64 = 1024 * 1024;
const MAX_FLUTTER_ASSET_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FLUTTER_LUA_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FLUTTER_LIBAPP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FLUTTER_SELECTED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_APK_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_APK_CENTRAL_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_APK_ENTRY_NAME_BYTES: usize = 8 * 1024 * 1024;

pub fn derive_flutter_runtime_semantics(
    base_apk: &Path,
    split_apks: &[PathBuf],
    mode: AndroidSemanticMode,
) -> Result<AndroidSemanticBundle, String> {
    let mut bundle = empty_bundle();
    let mut observed_flutter = None::<AndroidProvenance>;
    let mut env_keys = BTreeMap::<String, AndroidProvenance>::new();
    let mut dart_packages = BTreeMap::<String, AndroidProvenance>::new();
    let mut plugins = BTreeMap::<String, AndroidProvenance>::new();
    let mut platform_channels = BTreeMap::<String, AndroidProvenance>::new();
    let mut scripts = BTreeMap::<String, AndroidProvenance>::new();
    let mut firmware_assets = BTreeMap::<String, AndroidProvenance>::new();
    let mut api_endpoints = BTreeMap::<String, AndroidProvenance>::new();
    let mut local_device_control = None::<(String, AndroidProvenance)>;
    let mut runtime_role_members = BTreeMap::<String, Vec<String>>::new();
    let mut selected_bytes = 0_u64;
    let mut retained_entry_name_bytes = 0usize;

    for apk in std::iter::once(base_apk).chain(split_apks.iter().map(PathBuf::as_path)) {
        let mut file =
            File::open(apk).map_err(|e| format!("failed to open {}: {}", apk.display(), e))?;
        preflight_zip_file(
            &mut file,
            ZipPreflightLimits {
                max_file_bytes: MAX_APK_FILE_BYTES,
                max_entries: MAX_APK_ENTRIES as u64,
                max_central_directory_bytes: MAX_APK_CENTRAL_DIRECTORY_BYTES,
            },
        )
        .map_err(|error| format!("APK {} {error}", apk.display()))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| format!("failed to read apk zip {}: {}", apk.display(), e))?;
        if archive.len() > MAX_APK_ENTRIES {
            return Err(format!(
                "APK {} has too many entries: {} exceeds {}",
                apk.display(),
                archive.len(),
                MAX_APK_ENTRIES
            ));
        }

        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|e| {
                format!(
                    "failed to read zip entry {} from {}: {}",
                    index,
                    apk.display(),
                    e
                )
            })?;
            let entry_name = entry.name().to_string();
            retained_entry_name_bytes = retained_entry_name_bytes
                .checked_add(entry_name.len())
                .ok_or_else(|| "APK retained entry-name byte count overflowed".to_string())?;
            if retained_entry_name_bytes > MAX_APK_ENTRY_NAME_BYTES {
                return Err(format!(
                    "APK retained entry names exceed byte limit of {MAX_APK_ENTRY_NAME_BYTES}"
                ));
            }
            let provenance = runtime_provenance(apk, &entry_name);

            if entry_name.starts_with("assets/flutter_assets/") {
                observed_flutter.get_or_insert_with(|| provenance.clone());
            }
            if entry_name.ends_with("libflutter.so") || entry_name.ends_with("libapp.so") {
                observed_flutter.get_or_insert_with(|| provenance.clone());
            }

            match entry_name.as_str() {
                "assets/flutter_assets/.env" => {
                    let text = read_text_entry(
                        &mut entry,
                        ".env",
                        MAX_FLUTTER_ENV_BYTES,
                        &mut selected_bytes,
                    )?;
                    for key in parse_env_keys(&text) {
                        env_keys.entry(key).or_insert_with(|| provenance.clone());
                    }
                }
                "assets/flutter_assets/AssetManifest.json" => {
                    let text = read_text_entry(
                        &mut entry,
                        "AssetManifest.json",
                        MAX_FLUTTER_ASSET_MANIFEST_BYTES,
                        &mut selected_bytes,
                    )?;
                    for asset_path in parse_asset_manifest_paths(&text) {
                        classify_runtime_asset(
                            &asset_path,
                            &provenance,
                            &mut scripts,
                            &mut firmware_assets,
                            &mut local_device_control,
                        );
                    }
                }
                _ => {
                    if let Some(asset_path) = entry_name.strip_prefix("assets/flutter_assets/") {
                        classify_runtime_asset(
                            asset_path,
                            &provenance,
                            &mut scripts,
                            &mut firmware_assets,
                            &mut local_device_control,
                        );
                        if asset_path.ends_with(".lua") {
                            let text = read_text_entry(
                                &mut entry,
                                "Lua asset",
                                MAX_FLUTTER_LUA_BYTES,
                                &mut selected_bytes,
                            )?;
                            if looks_like_local_device_script(&text) {
                                local_device_control.get_or_insert_with(|| {
                                    (asset_path.to_string(), provenance.clone())
                                });
                            }
                        } else if entry_name.ends_with("libapp.so") {
                            // Unreachable in this branch; handled below.
                        }
                    }

                    if entry_name.ends_with("libapp.so") {
                        let bytes = read_bytes_entry(
                            &mut entry,
                            "libapp.so",
                            MAX_FLUTTER_LIBAPP_BYTES,
                            &mut selected_bytes,
                        )?;
                        for line in extract_ascii_strings(&bytes) {
                            if let Some(package) = normalize_dart_package(&line) {
                                dart_packages
                                    .entry(package)
                                    .or_insert_with(|| provenance.clone());
                            }
                            if let Some(plugin) = classify_flutter_plugin(&line) {
                                plugins
                                    .entry(plugin.into())
                                    .or_insert_with(|| provenance.clone());
                            }
                            if let Some(channel) = classify_platform_channel(&line) {
                                platform_channels
                                    .entry(channel)
                                    .or_insert_with(|| provenance.clone());
                            }
                            if let Some(endpoint) = normalize_http_endpoint(&line) {
                                api_endpoints
                                    .entry(endpoint)
                                    .or_insert_with(|| provenance.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(provenance) = observed_flutter {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-runtime-app-framework-flutter".into(),
            kind: "runtime.app-framework".into(),
            subject: "flutter".into(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        bundle.native_semantics.push(AndroidNativeSemantic {
            native_id: "native-runtime-flutter".into(),
            kind: "runtime-framework".into(),
            library_name: Some("flutter".into()),
            symbol_name: "Flutter runtime".into(),
            linked_symbol_id: None,
            synthetic: false,
            notes: vec!["flutter assets or runtime libraries observed in APK containers".into()],
        });
    }

    for (key, provenance) in env_keys {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-runtime-env-{}", sanitize_id(&key)),
            kind: "runtime.env-key".into(),
            subject: key,
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance],
            attributes: mode_attributes(mode),
        });
    }

    for (package, provenance) in dart_packages {
        let symbol_id = format!("sym-dart-package-{}", sanitize_id(&package));
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: symbol_id.clone(),
            language: Some("dart".into()),
            kind: "dart-library".into(),
            qualified_name: package.clone(),
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-dart-package-{}", sanitize_id(&package)),
            kind: "source.dart-package".into(),
            subject: package.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = classify_dart_package_role(&package) {
            let fact_id = format!("fact-runtime-package-role-{}", sanitize_id(&package));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: fact_id.clone(),
                kind: "role.runtime-package".into(),
                subject: package,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(fact_id);
        }
    }

    for (plugin, provenance) in plugins {
        let fact_id = format!("fact-runtime-plugin-{}", sanitize_id(&plugin));
        bundle.facts.push(AndroidSemanticFact {
            fact_id: fact_id.clone(),
            kind: "runtime.plugin".into(),
            subject: plugin.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = classify_plugin_role(&plugin) {
            let role_fact_id = format!("fact-runtime-plugin-role-{}", sanitize_id(&plugin));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: role_fact_id.clone(),
                kind: "role.runtime-plugin".into(),
                subject: plugin,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(role_fact_id);
        }
    }

    for (channel, provenance) in platform_channels {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-runtime-channel-{}", sanitize_id(&channel)),
            kind: "runtime.platform-channel".into(),
            subject: channel.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = classify_platform_channel_role(&channel) {
            let role_fact_id = format!("fact-runtime-channel-role-{}", sanitize_id(&channel));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: role_fact_id.clone(),
                kind: "role.runtime-channel".into(),
                subject: channel,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(role_fact_id);
        }
    }

    for (script_path, provenance) in scripts {
        let script_symbol_id = format!("sym-runtime-script-{}", sanitize_id(&script_path));
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: script_symbol_id.clone(),
            language: Some("lua".into()),
            kind: "runtime-script".into(),
            qualified_name: script_path.clone(),
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.resources.push(AndroidResourceSemantic {
            resource_id: format!("resource-runtime-script-{}", sanitize_id(&script_path)),
            kind: "bundled-script".into(),
            path: script_path.clone(),
            qualifiers: Vec::new(),
            notes: vec!["flutter bundled runtime asset".into()],
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-bundled-script-{}", sanitize_id(&script_path)),
            kind: "artifact.bundled-script".into(),
            subject: script_path.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = classify_asset_role(&script_path) {
            let role_fact_id = format!("fact-runtime-asset-role-{}", sanitize_id(&script_path));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: role_fact_id.clone(),
                kind: "role.runtime-asset".into(),
                subject: script_path,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(role_fact_id);
        }
    }

    for (asset_path, provenance) in firmware_assets {
        bundle.resources.push(AndroidResourceSemantic {
            resource_id: format!("resource-bundled-firmware-{}", sanitize_id(&asset_path)),
            kind: "bundled-firmware".into(),
            path: asset_path.clone(),
            qualifiers: Vec::new(),
            notes: vec!["flutter bundled firmware asset".into()],
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-bundled-firmware-{}", sanitize_id(&asset_path)),
            kind: "artifact.bundled-firmware".into(),
            subject: asset_path.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = classify_asset_role(&asset_path) {
            let role_fact_id = format!("fact-runtime-asset-role-{}", sanitize_id(&asset_path));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: role_fact_id.clone(),
                kind: "role.runtime-asset".into(),
                subject: asset_path,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(role_fact_id);
        }
    }

    for (endpoint, provenance) in api_endpoints {
        let endpoint_class = classify_endpoint(&endpoint);
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: format!("control-runtime-http-{}", sanitize_id(&endpoint)),
            kind: endpoint_class.surface_kind().into(),
            entry_symbol: None,
            exported_component: None,
            trigger: Some(endpoint.clone()),
            notes: vec!["endpoint recovered from flutter runtime strings".into()],
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: format!("fact-runtime-http-{}", sanitize_id(&endpoint)),
            kind: endpoint_class.fact_kind().into(),
            subject: endpoint.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        if let Some(role) = endpoint_class.role() {
            let role_fact_id = format!("fact-runtime-endpoint-role-{}", sanitize_id(&endpoint));
            bundle.facts.push(AndroidSemanticFact {
                fact_id: role_fact_id.clone(),
                kind: "role.runtime-endpoint".into(),
                subject: endpoint,
                support_level: AndroidSupportLevel::Observed,
                provenance: vec![provenance],
                attributes: role_attributes(mode, role),
            });
            runtime_role_members
                .entry(role.into())
                .or_default()
                .push(role_fact_id);
        }
    }

    if let Some((trigger, provenance)) = local_device_control {
        let script_symbol_id = format!("sym-runtime-script-{}", sanitize_id(&trigger));
        let fact_id = "fact-runtime-local-device-control".to_string();
        bundle.facts.push(AndroidSemanticFact {
            fact_id: fact_id.clone(),
            kind: "role.local-device-control".into(),
            subject: trigger.clone(),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![provenance.clone()],
            attributes: mode_attributes(mode),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-runtime-local-device-control".into(),
            kind: "local-device-control-surface".into(),
            entry_symbol: Some(script_symbol_id),
            exported_component: None,
            trigger: Some(trigger),
            notes: vec!["bundled runtime script reaches a local device channel".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-runtime-app-to-local-device-control".into(),
            kind: "app-to-local-device-control".into(),
            from_zone: "mobile-app".into(),
            to_zone: "local-device".into(),
            guard: None,
            notes: vec!["flutter runtime assets drive a local device control channel".into()],
        });
        runtime_role_members
            .entry("local-device-control".into())
            .or_default()
            .push(fact_id);
    }

    for (role, members) in runtime_role_members {
        if members.len() < 2 {
            continue;
        }
        bundle
            .correlations
            .push(crate::android::semantic::AndroidCorrelation {
                correlation_id: format!("corr-runtime-role-cluster-{}", sanitize_id(&role)),
                kind: "runtime-role-cluster".into(),
                members,
                support_level: AndroidSupportLevel::Inferred,
                rationale: Some(format!("runtime role cluster: {role}")),
            });
    }

    Ok(bundle)
}

fn runtime_provenance(apk: &Path, entry_name: &str) -> AndroidProvenance {
    AndroidProvenance {
        origin: "apk-runtime".into(),
        artifact: format!("{}:{}", apk.display(), entry_name),
        location: None,
        detail: Some("flutter runtime extraction".into()),
    }
}

fn read_text_entry<R: Read>(
    entry: &mut R,
    label: &str,
    entry_limit: u64,
    selected_bytes: &mut u64,
) -> Result<String, String> {
    let bytes = read_bytes_entry(entry, label, entry_limit, selected_bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_bytes_entry<R: Read>(
    entry: &mut R,
    label: &str,
    entry_limit: u64,
    selected_bytes: &mut u64,
) -> Result<Vec<u8>, String> {
    let cumulative_remaining = MAX_FLUTTER_SELECTED_BYTES.saturating_sub(*selected_bytes);
    let allowed = entry_limit.min(cumulative_remaining);
    let mut bytes = Vec::new();
    entry
        .take(allowed.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read {label} bytes: {e}"))?;
    if bytes.len() as u64 > entry_limit {
        return Err(format!(
            "APK {label} exceeds byte limit of {entry_limit} bytes"
        ));
    }
    if bytes.len() as u64 > cumulative_remaining {
        return Err(format!(
            "APK selected entries exceed cumulative byte limit of {MAX_FLUTTER_SELECTED_BYTES} bytes"
        ));
    }
    *selected_bytes = selected_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| "APK selected byte count overflowed".to_string())?;
    Ok(bytes)
}

fn parse_env_keys(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .filter(|key| !key.is_empty() && !key.starts_with('#'))
        .map(|key| key.trim_matches('"').to_string())
        .collect()
}

fn parse_asset_manifest_paths(text: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    object.keys().cloned().collect()
}

fn classify_runtime_asset(
    asset_path: &str,
    provenance: &AndroidProvenance,
    scripts: &mut BTreeMap<String, AndroidProvenance>,
    firmware_assets: &mut BTreeMap<String, AndroidProvenance>,
    local_device_control: &mut Option<(String, AndroidProvenance)>,
) {
    let normalized = asset_path.trim_start_matches('/').to_string();
    let lower = normalized.to_ascii_lowercase();
    if lower.ends_with(".lua") {
        scripts
            .entry(normalized.clone())
            .or_insert_with(|| provenance.clone());
        if lower.contains("bluetooth") {
            local_device_control.get_or_insert_with(|| (normalized.clone(), provenance.clone()));
        }
    } else if lower.ends_with(".zip") && (lower.contains("firmware") || lower.contains("update")) {
        firmware_assets
            .entry(normalized)
            .or_insert_with(|| provenance.clone());
    }
}

fn looks_like_local_device_script(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("device.bluetooth")
        || lower.contains("bluetooth.send")
        || lower.contains("receive_callback")
        || lower.contains("is_connected")
}

fn extract_ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut current = Vec::new();
    let mut strings = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
            continue;
        }
        if current.len() >= 4 {
            strings.push(String::from_utf8_lossy(&current).into_owned());
        }
        current.clear();
    }
    if current.len() >= 4 {
        strings.push(String::from_utf8_lossy(&current).into_owned());
    }
    strings
}

fn normalize_dart_package(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("package:") {
        return None;
    }
    let normalized = trimmed
        .strip_suffix(".dart2")
        .map(|prefix| format!("{prefix}.dart"))
        .unwrap_or_else(|| trimmed.to_string());
    let package_name = normalized
        .strip_prefix("package:")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    if package_name.is_empty() || is_common_third_party_dart_package(package_name) {
        return None;
    }
    Some(normalized)
}

fn classify_flutter_plugin(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("webview_flutter_android") || lower.contains("plugins.flutter.io/webview") {
        Some("webview_flutter_android")
    } else if lower.contains("flutter_blue_plus") {
        Some("flutter_blue_plus")
    } else if lower.contains("google_sign_in_android") || lower.contains("google_sign_in") {
        Some("google_sign_in_android")
    } else if lower.contains("flutter_foreground_task") {
        Some("flutter_foreground_task")
    } else {
        None
    }
}

fn classify_dart_package_role(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("/bluetooth") || lower.contains("/ble") {
        Some("local-device-control")
    } else if lower.contains("/login") || lower.contains("/auth") {
        Some("account-auth")
    } else if lower.contains("/pairing") || lower.contains("/onboarding") {
        Some("device-pairing")
    } else if lower.contains("app_logic") || lower.contains("/model") {
        Some("application-state")
    } else {
        None
    }
}

fn classify_plugin_role(plugin: &str) -> Option<&'static str> {
    match plugin {
        "flutter_blue_plus" => Some("local-device-control"),
        "webview_flutter_android" => Some("embedded-web-content"),
        "google_sign_in_android" => Some("account-auth"),
        "flutter_foreground_task" => Some("background-execution"),
        _ => None,
    }
}

fn classify_platform_channel(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("plugins.flutter.io/") || trimmed.starts_with("dev.flutter.pigeon.") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn classify_platform_channel_role(channel: &str) -> Option<&'static str> {
    if channel.contains("webview") {
        Some("embedded-web-content")
    } else {
        None
    }
}

fn normalize_http_endpoint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    let normalized = trimmed.trim_end_matches('2').to_string();
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("api.flutter.dev")
        || lower.contains("flutter.dev/")
        || lower.contains("pub.dev/")
        || lower.contains("youtube.com/")
    {
        return None;
    }
    Some(normalized)
}

fn classify_endpoint_role(endpoint: &str) -> Option<&'static str> {
    let lower = endpoint.to_ascii_lowercase();
    if lower.contains("login")
        || lower.contains("oauth")
        || lower.contains("token")
        || lower.contains("signout")
        || lower.contains("/user")
    {
        Some("account-auth")
    } else if lower.contains("bind") || lower.contains("pair") {
        Some("device-pairing")
    } else if lower.contains("firmware") || lower.contains("update") {
        Some("firmware-update")
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeEndpointClass {
    Chainable(&'static str),
    Informational,
}

impl RuntimeEndpointClass {
    fn surface_kind(self) -> &'static str {
        match self {
            Self::Chainable(_) => "http-api-endpoint",
            Self::Informational => "http-info-endpoint",
        }
    }

    fn fact_kind(self) -> &'static str {
        match self {
            Self::Chainable(_) => "http.api-endpoint",
            Self::Informational => "http.info-endpoint",
        }
    }

    fn role(self) -> Option<&'static str> {
        match self {
            Self::Chainable(role) => Some(role),
            Self::Informational => None,
        }
    }
}

fn classify_endpoint(endpoint: &str) -> RuntimeEndpointClass {
    if is_informational_endpoint(endpoint) {
        RuntimeEndpointClass::Informational
    } else if let Some(role) = classify_endpoint_role(endpoint) {
        RuntimeEndpointClass::Chainable(role)
    } else {
        RuntimeEndpointClass::Chainable("runtime-api")
    }
}

fn is_informational_endpoint(endpoint: &str) -> bool {
    let lower = endpoint.to_ascii_lowercase();
    lower.contains("privacy")
        || lower.contains("terms")
        || lower.contains("legal")
        || lower.contains("policy")
        || lower.contains("help")
        || lower.contains("support")
        || lower.contains("docs")
}

fn classify_asset_role(asset_path: &str) -> Option<&'static str> {
    let lower = asset_path.to_ascii_lowercase();
    if lower.ends_with(".lua") {
        Some("local-device-control")
    } else if lower.contains("firmware") || lower.contains("update") {
        Some("firmware-update")
    } else {
        None
    }
}

fn mode_attributes(mode: AndroidSemanticMode) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    attributes.insert("semantic_mode".into(), mode.as_str().into());
    attributes
}

fn role_attributes(mode: AndroidSemanticMode, role: &str) -> BTreeMap<String, String> {
    let mut attributes = mode_attributes(mode);
    attributes.insert("role".into(), role.into());
    attributes
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch,
            _ => '-',
        })
        .collect()
}

fn is_common_third_party_dart_package(package_name: &str) -> bool {
    matches!(
        package_name,
        "archive"
            | "audio_session"
            | "characters"
            | "collection"
            | "flutter"
            | "flutter_blue_plus"
            | "flutter_dotenv"
            | "flutter_foreground_task"
            | "flutter_riverpod"
            | "geocoding_platform_interface"
            | "geolocator_platform_interface"
            | "google_sign_in_android"
            | "google_sign_in_platform_interface"
            | "http"
            | "http_parser"
            | "image"
            | "just_audio_platform_interface"
            | "material_color_utilities"
            | "mime"
            | "path"
            | "path_provider"
            | "path_provider_android"
            | "path_provider_platform_interface"
            | "riverpod"
            | "rxdart"
            | "saver_gallery"
            | "source_span"
            | "stack_trace"
            | "string_scanner"
            | "term_glyph"
            | "url_launcher"
            | "url_launcher_android"
            | "url_launcher_platform_interface"
            | "uuid"
            | "vector_math"
            | "webview_flutter"
            | "webview_flutter_android"
            | "webview_flutter_platform_interface"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_oversized_flutter_env_entry() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("oversized-env.apk");
        let file = File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("assets/flutter_assets/.env", options)
            .unwrap();
        zip.write_all(&vec![b'A'; 1024 * 1024 + 1]).unwrap();
        zip.finish().unwrap();

        let error = derive_flutter_runtime_semantics(&apk, &[], AndroidSemanticMode::Dense)
            .expect_err("oversized env must fail");
        assert!(error.contains(".env"), "{error}");
        assert!(error.contains("byte limit"), "{error}");
    }

    #[test]
    fn rejects_apk_entry_flood_before_scanning() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("entry-flood.apk");
        let file = File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for index in 0..65_537 {
            zip.start_file(format!("empty-{index}"), options).unwrap();
        }
        zip.finish().unwrap();

        let error = derive_flutter_runtime_semantics(&apk, &[], AndroidSemanticMode::Dense)
            .expect_err("entry flood must fail");
        assert!(error.contains("too many entries"), "{error}");
        assert!(error.contains("ZIP preflight"), "{error}");
    }

    #[test]
    fn rejects_excessive_cumulative_apk_entry_name_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let apk = temp.path().join("name-flood.apk");
        let file = File::create(&apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for index in 0..130 {
            let name = format!("{index:03}-{}", "a".repeat(65_000));
            zip.start_file(name, options).unwrap();
        }
        zip.finish().unwrap();

        let error = derive_flutter_runtime_semantics(&apk, &[], AndroidSemanticMode::Dense)
            .expect_err("entry-name flood must fail");
        assert!(
            error.contains("retained entry names exceed byte limit"),
            "{error}"
        );
    }
}
