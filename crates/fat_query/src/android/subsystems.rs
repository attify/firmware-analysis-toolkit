use crate::android::semantic::{
    AndroidControlSurface, AndroidNativeSemantic, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSubsystem, AndroidSupportLevel, AndroidSymbolIdentity,
};
use std::collections::BTreeSet;

pub(crate) fn derive_subsystems(bundle: &AndroidSemanticBundle) -> Vec<AndroidSubsystem> {
    let candidates = [
        SubsystemSpec {
            subsystem_id: "subsystem-weave-device-security",
            kind: "weave-device-security",
            package_prefix_hints: &["nl.Weave", "com.nestlabs.weave"],
            rationale: "Weave device management and security evidence cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-matter-commissioning",
            kind: "matter-commissioning",
            package_prefix_hints: &["com.example.matter.commissioning"],
            rationale: "Matter commissioning and setup evidence cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-ble-scanning",
            kind: "ble-scanning",
            package_prefix_hints: &["com.example.ble"],
            rationale: "BLE discovery and scanning signals cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-webrtc-media",
            kind: "webrtc-media",
            package_prefix_hints: &["com.google.media.webrtc"],
            rationale: "WebRTC media and gRPC-adjacent session handling cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-web-command-bridge",
            kind: "web-command-bridge",
            package_prefix_hints: &[],
            rationale: "JavascriptInterface and command bridge evidence cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-session-command-control",
            kind: "session-command-control",
            package_prefix_hints: &[],
            rationale: "Session signaling and command payloads cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-local-device-control",
            kind: "local-device-control",
            package_prefix_hints: &[],
            rationale: "Local device control and encrypted nearby-device messaging cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-account-device-binding",
            kind: "account-device-binding",
            package_prefix_hints: &[],
            rationale: "Login, token, and device-binding evidence cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-local-device-runtime-control",
            kind: "local-device-runtime-control",
            package_prefix_hints: &["package:", "assets/"],
            rationale: "Bundled runtime scripts, firmware assets, and nearby-device control evidence cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-runtime-account-auth",
            kind: "runtime-account-auth",
            package_prefix_hints: &["package:", "https://"],
            rationale: "Flutter runtime login packages, auth plugins, and account endpoints cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-runtime-embedded-web-content",
            kind: "runtime-embedded-web-content",
            package_prefix_hints: &["package:", "plugins.flutter.io/", "dev.flutter.pigeon."],
            rationale: "Flutter runtime webview plugins and generated web channels cluster together.",
        },
        SubsystemSpec {
            subsystem_id: "subsystem-runtime-firmware-update",
            kind: "runtime-firmware-update",
            package_prefix_hints: &["assets/", "https://"],
            rationale: "Bundled firmware artifacts and runtime firmware endpoints cluster together.",
        },
    ];

    candidates
        .iter()
        .filter_map(|spec| build_subsystem(bundle, spec))
        .collect()
}

struct SubsystemSpec<'a> {
    subsystem_id: &'a str,
    kind: &'a str,
    package_prefix_hints: &'a [&'a str],
    rationale: &'a str,
}

fn build_subsystem(
    bundle: &AndroidSemanticBundle,
    spec: &SubsystemSpec<'_>,
) -> Option<AndroidSubsystem> {
    let symbol_ids: Vec<String> = bundle
        .symbol_identities
        .iter()
        .filter(|symbol| symbol_matches(symbol, spec))
        .map(|symbol| symbol.symbol_id.clone())
        .collect();
    let control_surface_ids: Vec<String> = bundle
        .control_surfaces
        .iter()
        .filter(|surface| control_surface_matches(surface, &symbol_ids, spec))
        .map(|surface| surface.surface_id.clone())
        .collect();
    let transport_surface_ids: Vec<String> = bundle
        .transport_surfaces
        .iter()
        .filter(|surface| {
            control_surface_ids.iter().any(|id| id == &surface.sink)
                || package_hint_match(&surface.source, spec)
                || package_hint_match(&surface.sink, spec)
        })
        .map(|surface| surface.surface_id.clone())
        .collect();
    let trust_boundary_ids: Vec<String> = bundle
        .trust_boundaries
        .iter()
        .filter(|boundary| boundary_matches(boundary.kind.as_str(), spec))
        .map(|boundary| boundary.boundary_id.clone())
        .collect();
    let native_ids: Vec<String> = bundle
        .native_semantics
        .iter()
        .filter(|native| native_matches(native, &symbol_ids, spec))
        .map(|native| native.native_id.clone())
        .collect();
    let fact_ids: Vec<String> = bundle
        .facts
        .iter()
        .filter(|fact| fact_matches(fact, spec))
        .map(|fact| fact.fact_id.clone())
        .collect();
    let package_prefixes = collect_package_prefixes(bundle, spec);

    if symbol_ids.is_empty()
        && control_surface_ids.is_empty()
        && transport_surface_ids.is_empty()
        && trust_boundary_ids.is_empty()
        && native_ids.is_empty()
        && fact_ids.is_empty()
    {
        return None;
    }

    Some(AndroidSubsystem {
        subsystem_id: spec.subsystem_id.into(),
        kind: spec.kind.into(),
        support_level: AndroidSupportLevel::Observed,
        package_prefixes,
        symbol_ids,
        control_surface_ids,
        transport_surface_ids,
        trust_boundary_ids,
        native_ids,
        fact_ids,
        rationale: Some(spec.rationale.into()),
        notes: Vec::new(),
    })
}

fn symbol_matches(symbol: &AndroidSymbolIdentity, spec: &SubsystemSpec<'_>) -> bool {
    package_hint_match(&symbol.qualified_name, spec)
}

fn control_surface_matches(
    surface: &AndroidControlSurface,
    symbol_ids: &[String],
    spec: &SubsystemSpec<'_>,
) -> bool {
    surface
        .entry_symbol
        .as_ref()
        .is_some_and(|id| symbol_ids.iter().any(|symbol_id| symbol_id == id))
        || match spec.kind {
            "weave-device-security" => {
                matches!(
                    surface.kind.as_str(),
                    "weave-security-plane" | "device-management-callback"
                )
            }
            "matter-commissioning" => {
                matches!(
                    surface.kind.as_str(),
                    "matter-commissioning-session" | "device-commissioning-flow"
                )
            }
            "ble-scanning" => surface.kind.contains("ble") || surface.kind.contains("bluetooth"),
            "webrtc-media" => {
                surface.kind.contains("webrtc")
                    || surface.kind.contains("media")
                    || surface.kind.contains("audio")
                    || surface.kind.contains("video")
            }
            "web-command-bridge" => {
                matches!(
                    surface.kind.as_str(),
                    "web-command-bridge" | "javascript-bridge-method"
                )
            }
            "session-command-control" => {
                matches!(surface.kind.as_str(), "remote-command-dispatch")
                    || surface.kind.contains("webrtc")
            }
            "local-device-control" => {
                matches!(surface.kind.as_str(), "local-device-control-surface")
                    || surface.kind.contains("ble")
                    || surface.kind.contains("bluetooth")
            }
            "account-device-binding" => {
                matches!(surface.kind.as_str(), "account-device-bind-flow")
                    || surface.kind.contains("bind")
            }
            "local-device-runtime-control" => {
                matches!(surface.kind.as_str(), "local-device-control-surface")
            }
            "runtime-account-auth" => {
                surface.kind == "http-api-endpoint"
                    && surface
                        .trigger
                        .as_deref()
                        .is_some_and(looks_like_runtime_account_auth_surface)
            }
            "runtime-embedded-web-content" => surface
                .trigger
                .as_deref()
                .is_some_and(looks_like_embedded_web_content_surface),
            "runtime-firmware-update" => {
                surface.kind == "http-api-endpoint"
                    && surface
                        .trigger
                        .as_deref()
                        .is_some_and(looks_like_runtime_firmware_surface)
            }
            _ => false,
        }
}

fn native_matches(
    native: &AndroidNativeSemantic,
    symbol_ids: &[String],
    spec: &SubsystemSpec<'_>,
) -> bool {
    native
        .linked_symbol_id
        .as_ref()
        .is_some_and(|id| symbol_ids.iter().any(|symbol_id| symbol_id == id))
        || native
            .library_name
            .as_deref()
            .is_some_and(|name| package_hint_match(name, spec))
        || package_hint_match(&native.symbol_name, spec)
        || (spec.kind == "weave-device-security" && native.kind == "weave-key-export-native")
}

fn fact_matches(fact: &AndroidSemanticFact, spec: &SubsystemSpec<'_>) -> bool {
    package_hint_match(&fact.subject, spec)
        || fact
            .provenance
            .iter()
            .any(|provenance| package_hint_match(&provenance.artifact, spec))
        || match spec.kind {
            "weave-device-security" => {
                matches!(
                    fact.kind.as_str(),
                    "protocol.weave-key-export"
                        | "source.protocol-family"
                        | "source.security-family"
                ) && matches!(
                    fact.subject.as_str(),
                    "weave"
                        | "pairing-code"
                        | "fabric-membership"
                        | "certificate"
                        | "access-token"
                        | "key-export"
                        | "device-descriptor"
                )
            }
            "matter-commissioning" => {
                fact.kind == "protocol.matter-commissioning"
                    || (fact.kind == "source.security-family" && fact.subject == "commissioning")
            }
            "ble-scanning" => {
                (fact.kind == "source.protocol-family" && fact.subject == "ble")
                    || fact.provenance.iter().any(|provenance| {
                        let artifact = provenance.artifact.to_ascii_lowercase();
                        artifact.contains("blescanner") || artifact.contains("bluetooth")
                    })
            }
            "webrtc-media" => {
                (fact.kind == "source.protocol-family" && fact.subject == "webrtc")
                    || fact.provenance.iter().any(|provenance| {
                        let artifact = provenance.artifact.to_ascii_lowercase();
                        artifact.contains("webrtc")
                            || artifact.contains("webrtcaudio")
                            || artifact.contains("tacl")
                    })
            }
            "web-command-bridge" => {
                fact.kind == "role.command-envelope"
                    || fact.provenance.iter().any(|provenance| {
                        provenance
                            .artifact
                            .to_ascii_lowercase()
                            .contains("androidinterface")
                    })
            }
            "session-command-control" => {
                matches!(
                    fact.kind.as_str(),
                    "role.command-envelope" | "role.session-offer"
                ) || fact
                    .provenance
                    .iter()
                    .any(|provenance| provenance.artifact.to_ascii_lowercase().contains("webrtc"))
            }
            "local-device-control" => {
                fact.kind == "role.local-device-control"
                    || fact.provenance.iter().any(|provenance| {
                        let artifact = provenance.artifact.to_ascii_lowercase();
                        artifact.contains("bluetoothservice") || artifact.contains("lib_ble")
                    })
            }
            "account-device-binding" => {
                fact.kind == "role.account-device-binding"
                    || fact.provenance.iter().any(|provenance| {
                        let artifact = provenance.artifact.to_ascii_lowercase();
                        artifact.contains("loginapi") || artifact.contains("login/data")
                    })
            }
            "local-device-runtime-control" => {
                fact.kind == "role.local-device-control"
                    || fact.kind == "artifact.bundled-script"
                    || (fact.kind == "role.runtime-asset"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "local-device-control"))
                    || (fact.kind == "source.dart-package"
                        && looks_like_runtime_device_control_symbol(&fact.subject))
                    || (fact.kind == "role.runtime-package"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "local-device-control"))
                    || (fact.kind == "runtime.plugin" && fact.subject == "flutter_blue_plus")
                    || (fact.kind == "role.runtime-plugin"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "local-device-control"))
            }
            "runtime-account-auth" => {
                (fact.kind == "role.runtime-endpoint"
                    && fact
                        .attributes
                        .get("role")
                        .is_some_and(|role| role == "account-auth"))
                    || (fact.kind == "role.runtime-package"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "account-auth"))
                    || (fact.kind == "role.runtime-plugin"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "account-auth"))
                    || (fact.kind == "http.api-endpoint"
                        && looks_like_runtime_account_auth_surface(&fact.subject))
            }
            "runtime-embedded-web-content" => {
                (fact.kind == "role.runtime-plugin"
                    && fact
                        .attributes
                        .get("role")
                        .is_some_and(|role| role == "embedded-web-content"))
                    || (fact.kind == "role.runtime-channel"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "embedded-web-content"))
                    || (fact.kind == "source.dart-package"
                        && fact.subject.to_ascii_lowercase().contains("webview"))
            }
            "runtime-firmware-update" => {
                fact.kind == "artifact.bundled-firmware"
                    || (fact.kind == "role.runtime-asset"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "firmware-update"))
                    || (fact.kind == "role.runtime-endpoint"
                        && fact
                            .attributes
                            .get("role")
                            .is_some_and(|role| role == "firmware-update"))
                    || (fact.kind == "http.api-endpoint"
                        && looks_like_runtime_firmware_surface(&fact.subject))
            }
            _ => false,
        }
}

fn boundary_matches(kind: &str, spec: &SubsystemSpec<'_>) -> bool {
    match spec.kind {
        "weave-device-security" => kind.contains("native") || kind.contains("device"),
        "matter-commissioning" => kind.contains("commission"),
        "ble-scanning" => kind.contains("bluetooth") || kind.contains("ble"),
        "webrtc-media" => kind.contains("media") || kind.contains("webrtc"),
        "web-command-bridge" => kind.contains("webview-js") || kind.contains("command"),
        "session-command-control" => kind.contains("command") || kind.contains("webrtc"),
        "local-device-control" => kind.contains("local-device") || kind.contains("ble"),
        "account-device-binding" => kind.contains("device-binding") || kind.contains("account"),
        "local-device-runtime-control" => kind.contains("local-device") || kind.contains("runtime"),
        "runtime-account-auth" => kind.contains("account") || kind.contains("auth"),
        "runtime-embedded-web-content" => kind.contains("webview") || kind.contains("web"),
        "runtime-firmware-update" => kind.contains("firmware") || kind.contains("update"),
        _ => false,
    }
}

fn collect_package_prefixes(
    bundle: &AndroidSemanticBundle,
    spec: &SubsystemSpec<'_>,
) -> Vec<String> {
    let mut prefixes = BTreeSet::new();
    for symbol in &bundle.symbol_identities {
        for hint in spec.package_prefix_hints {
            if symbol.qualified_name.starts_with(hint) {
                prefixes.insert((*hint).to_string());
            }
        }
    }
    for fact in &bundle.facts {
        for provenance in &fact.provenance {
            for prefix in package_prefixes_from_artifact(&provenance.artifact) {
                if spec
                    .package_prefix_hints
                    .iter()
                    .any(|hint| prefix.starts_with(hint))
                {
                    prefixes.insert(prefix);
                }
            }
        }
    }
    prefixes.into_iter().collect()
}

fn package_prefixes_from_artifact(artifact: &str) -> Vec<String> {
    let Some(sources_index) = artifact.find("sources/") else {
        return Vec::new();
    };
    let rel = &artifact[sources_index + "sources/".len()..];
    let trimmed = rel
        .strip_suffix(".java")
        .or_else(|| rel.strip_suffix(".kt"))
        .unwrap_or(rel);
    let mut parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();
    let joined = parts.join(".");
    vec![joined]
}

fn package_hint_match(value: &str, spec: &SubsystemSpec<'_>) -> bool {
    let lower = value.to_ascii_lowercase();
    let allow_generic_hint_match = !matches!(
        spec.kind,
        "local-device-runtime-control"
            | "runtime-account-auth"
            | "runtime-embedded-web-content"
            | "runtime-firmware-update"
    );
    let package_prefix_hit = allow_generic_hint_match
        && spec
            .package_prefix_hints
            .iter()
            .any(|hint| lower.contains(&hint.to_ascii_lowercase()));

    package_prefix_hit || interface_evidence_match(&lower, spec.kind)
}

/// Vendor-neutral interface evidence: exact observed symbol, endpoint, and
/// transport names whose semantics stand on their own.
///
/// This is evaluated independently of `package_prefix_hints` so a spec that
/// carries no package hints still derives from observed evidence. Package
/// namespaces establish nothing on their own; these names do.
fn interface_evidence_match(lower: &str, kind: &str) -> bool {
    match kind {
        "matter-commissioning" => lower.contains("matter"),
        "webrtc-media" => {
            lower.contains("webrtc")
                || lower.contains("org.webrtc")
                || lower.contains("media.webrtc")
                || lower.contains("tacl")
        }
        "weave-device-security" => lower.contains("weave") || lower.contains("pairingcode"),
        "ble-scanning" => {
            lower.contains("blescanner")
                || lower.contains("bluetoothadapter")
                || lower.contains("bluetoothgatt")
                || lower.contains("bluetooth")
        }
        "web-command-bridge" => {
            lower.contains("androidinterface") || lower.contains("javascriptinterface")
        }
        "session-command-control" => {
            lower.contains("sendgo2req")
                || lower.contains("dogofferbean")
                || lower.contains("rt/api/")
        }
        "local-device-control" => {
            lower.contains("bluetoothservice")
                || lower.contains("uuid_server")
                || lower.contains("aesutil")
        }
        "account-device-binding" => {
            lower.contains("oauth/bind")
                || lower.contains("accesstoken")
                || lower.contains("refreshtoken")
                || lower.contains("device_address")
        }
        "local-device-runtime-control" => {
            lower.contains("package:")
                || lower.contains("assets/lua_scripts/")
                || lower.contains("bluetooth")
                || lower.contains("flutter_blue_plus")
        }
        "runtime-account-auth" => {
            lower.contains("/login")
                || lower.contains("/auth")
                || lower.contains("google_sign_in")
                || lower.contains("oauth")
                || lower.contains("token")
                || lower.contains("/user")
                || lower.contains("signout")
        }
        "runtime-embedded-web-content" => {
            lower.contains("webview")
                || lower.contains("plugins.flutter.io/webview")
                || lower.contains("dev.flutter.pigeon.webview")
        }
        "runtime-firmware-update" => {
            lower.contains("firmware")
                || lower.contains("update")
                || lower.contains("device-firmware")
        }
        _ => false,
    }
}

fn looks_like_runtime_device_control_symbol(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bluetooth")
        || lower.contains("pair")
        || lower.contains("device")
        || lower.contains("firmware")
        || lower.contains("app_logic")
        || lower.ends_with(".lua")
}

fn looks_like_runtime_account_auth_surface(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("login")
        || lower.contains("oauth")
        || lower.contains("token")
        || lower.contains("/user")
        || lower.contains("signout")
}

fn looks_like_runtime_firmware_surface(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("firmware") || lower.contains("update")
}

fn looks_like_embedded_web_content_surface(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("webview") || lower.contains("flutter.pigeon.webview")
}

#[cfg(test)]
mod tests {
    use super::derive_subsystems;
    use crate::android::semantic::{AndroidSemanticBundle, AndroidSymbolIdentity};

    /// Subsystems that previously keyed off target package prefixes and must now
    /// derive from observed interface evidence alone.
    const EVIDENCE_ONLY_KINDS: [&str; 4] = [
        "web-command-bridge",
        "session-command-control",
        "local-device-control",
        "account-device-binding",
    ];

    fn bundle_with_symbols(qualified_names: &[&str]) -> AndroidSemanticBundle {
        let mut bundle = crate::android::empty_bundle();
        bundle.symbol_identities = qualified_names
            .iter()
            .enumerate()
            .map(|(index, qualified_name)| AndroidSymbolIdentity {
                symbol_id: format!("symbol-{index}"),
                language: Some("java".into()),
                kind: "method".into(),
                qualified_name: (*qualified_name).into(),
                descriptor: None,
                synthetic: false,
                aliases: Vec::new(),
            })
            .collect();
        bundle
    }

    #[test]
    fn target_package_prefixes_alone_do_not_create_semantic_subsystems() {
        let bundle = bundle_with_symbols(&[
            "com.unitree.doggo2.ui.fragment.web.ArbitraryType.run",
            "com.unitree.webrtc.ArbitraryType.run",
            "com.unitree.lib_ble.ArbitraryType.run",
            "com.unitree.login.ArbitraryType.run",
        ]);

        let subsystems = derive_subsystems(&bundle);

        for prohibited_kind in EVIDENCE_ONLY_KINDS {
            assert!(
                subsystems
                    .iter()
                    .all(|subsystem| subsystem.kind != prohibited_kind),
                "package prefix alone created {prohibited_kind}: {subsystems:?}"
            );
        }
    }

    /// Positive counterpart to the test above. Without this, the negative test
    /// passes trivially whenever the matcher stops matching anything at all —
    /// it cannot distinguish "ignores package prefixes" from "matches nothing".
    #[test]
    fn vendor_neutral_interface_evidence_still_derives_semantic_subsystems() {
        for (qualified_name, expected_kind) in [
            (
                "com.neutral.app.AndroidInterface.postMessage",
                "web-command-bridge",
            ),
            (
                "com.neutral.app.SessionClient.sendGo2Req",
                "session-command-control",
            ),
            (
                "com.neutral.app.BluetoothService.writeUuidServer",
                "local-device-control",
            ),
            (
                "com.neutral.app.AccountApi.refreshToken",
                "account-device-binding",
            ),
        ] {
            let bundle = bundle_with_symbols(&[qualified_name]);
            let subsystems = derive_subsystems(&bundle);

            let subsystem = subsystems
                .iter()
                .find(|subsystem| subsystem.kind == expected_kind)
                .unwrap_or_else(|| {
                    panic!("{qualified_name} derived no {expected_kind}: {subsystems:?}")
                });

            assert_eq!(
                subsystem.symbol_ids,
                ["symbol-0"],
                "{expected_kind} did not link the observed symbol"
            );
            assert!(
                subsystem.package_prefixes.is_empty(),
                "{expected_kind} attributed a package prefix it was not given: {subsystem:?}"
            );
        }
    }
}
