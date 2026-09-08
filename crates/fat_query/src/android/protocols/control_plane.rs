use crate::android::protocols::{ProtocolFileView, ProtocolIndex, ProtocolSignalKind};
use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidSemanticBundle, AndroidSemanticFact,
    AndroidSupportLevel, AndroidSymbolIdentity, AndroidTransportSurface, AndroidTrustBoundary,
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
struct JavascriptBridgeSignalDetail {
    method_name: String,
    parameter_types: Vec<String>,
    sink_notes: Vec<String>,
}

pub(crate) fn derive_control_plane_semantics(
    index: &ProtocolIndex,
    mode: crate::android::extractor::AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    let js_bridge_entries = signals_of_kind(index, ProtocolSignalKind::WebBridgeEntry);
    let js_bridge = js_bridge_entries.first().copied();
    let command_topic = first_signal(index, ProtocolSignalKind::CommandEnvelope);
    let session_token = first_signal(index, ProtocolSignalKind::SessionOffer);
    let ble_control = first_signal(index, ProtocolSignalKind::LocalDeviceControl);
    let oauth_token = first_signal(index, ProtocolSignalKind::AccountAuth);
    let device_binding =
        preferred_signal(index, ProtocolSignalKind::AccountDeviceBinding, |detail| {
            detail
                .map(|value| value.eq_ignore_ascii_case("oauth/bind"))
                .unwrap_or(false)
        });

    let primary_bridge_detail = js_bridge
        .and_then(|(_file, detail)| detail.map(|value| decode_javascript_interface_signal(value)));
    let js_class = js_bridge
        .map(|(file, _)| symbol_from_path(&file.path))
        .unwrap_or_else(|| "com.example.web.ControlBridge".into());
    let js_method = js_bridge
        .map(|(file, _detail)| {
            let method_name = primary_bridge_detail
                .as_ref()
                .map(|detail| detail.method_name.as_str())
                .filter(|value| !value.is_empty())
                .unwrap_or("dispatch");
            format!("{}.{}", symbol_from_path(&file.path), method_name)
        })
        .unwrap_or_else(|| format!("{js_class}.dispatch"));
    let ble_class = ble_control
        .map(|(file, _)| symbol_from_path(&file.path))
        .unwrap_or_else(|| "com.example.device.LocalControlService".into());
    let login_class = device_binding
        .or(oauth_token)
        .map(|(file, _)| symbol_from_path(&file.path))
        .unwrap_or_else(|| "com.example.auth.BindingApi".into());

    if let Some((_file, detail)) = js_bridge {
        let symbol_id = "sym-web-control-bridge".to_string();
        let method_symbol_id = "sym-web-bridge-entry-method".to_string();
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: symbol_id.clone(),
            language: Some("java".into()),
            kind: "class".into(),
            qualified_name: js_class.clone(),
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: method_symbol_id.clone(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: js_method.clone(),
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-web-command-bridge".into(),
            kind: "web-command-bridge".into(),
            entry_symbol: Some(method_symbol_id.clone()),
            exported_component: None,
            trigger: primary_bridge_detail
                .as_ref()
                .map(format_javascript_interface_signature)
                .or_else(|| detail.cloned()),
            notes: vec!["JavascriptInterface exposes command-bearing bridge methods".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-webview-js-to-command".into(),
            kind: "webview-js-to-command".into(),
            from_zone: "web-content".into(),
            to_zone: "command-plane".into(),
            guard: None,
            notes: vec!["JavascriptInterface can bridge web input into command handling".into()],
        });
    }

    for (file, detail) in js_bridge_entries {
        let decoded = detail
            .and_then(|value| {
                let parsed = decode_javascript_interface_signal(value);
                (!parsed.method_name.is_empty()).then_some(parsed)
            })
            .unwrap_or_default();
        let method_name = if decoded.method_name.is_empty() {
            "dispatch".to_string()
        } else {
            decoded.method_name.clone()
        };
        let class_name = symbol_from_path(&file.path);
        let symbol_id = format!(
            "sym-js-interface-{}",
            stable_id_fragment(&format!("{class_name}.{method_name}"))
        );
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: symbol_id.clone(),
            language: Some("java".into()),
            kind: "method".into(),
            qualified_name: format!("{class_name}.{method_name}"),
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        let mut notes = decoded.sink_notes.clone();
        notes.push("JavascriptInterface method".into());
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: format!(
                "control-js-interface-{}",
                stable_id_fragment(&format!("{class_name}.{method_name}"))
            ),
            kind: "javascript-interface-method".into(),
            entry_symbol: Some(symbol_id),
            exported_component: None,
            trigger: Some(format_javascript_interface_signature(&decoded)),
            notes,
        });
    }

    if let Some((file, detail)) = command_topic {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-command-envelope".into(),
            kind: "role.command-envelope".into(),
            subject: detail.cloned().unwrap_or_else(|| "command-envelope".into()),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![file.provenance.clone()],
            attributes: mode_attribute(mode),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-remote-command-dispatch".into(),
            kind: "remote-command-dispatch".into(),
            entry_symbol: Some("sym-web-bridge-entry-method".into()),
            exported_component: None,
            trigger: detail.cloned(),
            notes: vec!["Topic/api_id style request reaches a remote command path".into()],
        });
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-command-envelope".into(),
            kind: "command-envelope".into(),
            source: "web-bridge-entry".into(),
            sink: "control-remote-command-dispatch".into(),
            carrier: detail.cloned(),
            notes: vec![format!("source={}", file.path.display())],
        });
    }

    if let Some((file, detail)) = session_token {
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-session-offer".into(),
            kind: "role.session-offer".into(),
            subject: detail.cloned().unwrap_or_else(|| "token".into()),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![file.provenance.clone()],
            attributes: mode_attribute(mode),
        });
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-session-offer".into(),
            kind: "session-offer".into(),
            source: "session-signaling".into(),
            sink: "control-remote-command-dispatch".into(),
            carrier: detail.cloned(),
            notes: vec!["session token and SDP fields co-occur in a signaling path".into()],
        });
    }

    if let Some((file, detail)) = ble_control {
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-local-device-control-service".into(),
            language: Some("java".into()),
            kind: "class".into(),
            qualified_name: ble_class,
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-local-device-control".into(),
            kind: "role.local-device-control".into(),
            subject: detail
                .cloned()
                .unwrap_or_else(|| "local-device-control".into()),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![file.provenance.clone()],
            attributes: mode_attribute(mode),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-local-device-control-surface".into(),
            kind: "local-device-control-surface".into(),
            entry_symbol: Some("sym-local-device-control-service".into()),
            exported_component: None,
            trigger: detail.cloned(),
            notes: vec!["Local control service performs encrypted command/data handling".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-app-to-local-device-control".into(),
            kind: "app-to-local-device-control".into(),
            from_zone: "mobile-app".into(),
            to_zone: "local-device".into(),
            guard: None,
            notes: vec!["Local control service reaches a nearby device channel".into()],
        });
    }

    if let Some((file, detail)) = device_binding {
        bundle.symbol_identities.push(AndroidSymbolIdentity {
            symbol_id: "sym-account-binding-api".into(),
            language: Some("java".into()),
            kind: "class".into(),
            qualified_name: login_class,
            descriptor: None,
            synthetic: false,
            aliases: Vec::new(),
        });
        bundle.facts.push(AndroidSemanticFact {
            fact_id: "fact-account-device-binding".into(),
            kind: "role.account-device-binding".into(),
            subject: detail.cloned().unwrap_or_else(|| "oauth/bind".into()),
            support_level: AndroidSupportLevel::Observed,
            provenance: vec![file.provenance.clone()],
            attributes: mode_attribute(mode),
        });
        bundle.control_surfaces.push(AndroidControlSurface {
            surface_id: "control-account-device-bind-flow".into(),
            kind: "account-device-bind-flow".into(),
            entry_symbol: Some("sym-account-binding-api".into()),
            exported_component: None,
            trigger: detail.cloned(),
            notes: vec!["Account auth and device bind endpoints coexist in one flow".into()],
        });
        bundle.trust_boundaries.push(AndroidTrustBoundary {
            boundary_id: "boundary-account-to-device-binding".into(),
            kind: "account-to-device-binding".into(),
            from_zone: "account-identity".into(),
            to_zone: "device-binding".into(),
            guard: None,
            notes: vec!["Account identity can transition into bound device ownership".into()],
        });
    }

    if let Some((file, detail)) = oauth_token {
        bundle.transport_surfaces.push(AndroidTransportSurface {
            surface_id: "transport-account-auth-token".into(),
            kind: "account-auth-token".into(),
            source: "account-auth".into(),
            sink: "control-account-device-bind-flow".into(),
            carrier: detail.cloned(),
            notes: vec![format!("source={}", file.path.display())],
        });
    }

    if has_members(
        &bundle,
        &[
            "fact-command-envelope",
            "fact-session-offer",
            "fact-local-device-control",
            "control-web-command-bridge",
            "control-remote-command-dispatch",
        ],
    ) {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-web-command-local-control".into(),
            kind: "web-command-local-control".into(),
            members: vec![
                "fact-command-envelope".into(),
                "fact-session-offer".into(),
                "fact-local-device-control".into(),
                "control-web-command-bridge".into(),
                "control-remote-command-dispatch".into(),
            ],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some(
                "Javascript bridge, command envelope, session offer, and local device control evidence co-occur"
                    .into(),
            ),
        });
    }

    if has_members(
        &bundle,
        &[
            "fact-account-device-binding",
            "control-account-device-bind-flow",
            "transport-account-auth-token",
            "boundary-account-to-device-binding",
        ],
    ) {
        bundle.correlations.push(AndroidCorrelation {
            correlation_id: "corr-account-device-binding".into(),
            kind: "account-device-binding".into(),
            members: vec![
                "fact-account-device-binding".into(),
                "control-account-device-bind-flow".into(),
                "transport-account-auth-token".into(),
                "boundary-account-to-device-binding".into(),
            ],
            support_level: AndroidSupportLevel::Inferred,
            rationale: Some(
                "Account auth token acquisition and device bind paths co-occur in one subsystem"
                    .into(),
            ),
        });
    }

    bundle
}

fn first_signal(
    index: &ProtocolIndex,
    kind: ProtocolSignalKind,
) -> Option<(&ProtocolFileView, Option<&String>)> {
    index.files.iter().find_map(|file| {
        file.signals
            .iter()
            .find(|signal| signal.kind == kind)
            .map(|signal| (file, signal.detail.as_ref()))
    })
}

fn signals_of_kind(
    index: &ProtocolIndex,
    kind: ProtocolSignalKind,
) -> Vec<(&ProtocolFileView, Option<&String>)> {
    let mut matches = Vec::new();
    for file in &index.files {
        for signal in &file.signals {
            if signal.kind == kind {
                matches.push((file, signal.detail.as_ref()));
            }
        }
    }
    matches
}

fn preferred_signal<F>(
    index: &ProtocolIndex,
    kind: ProtocolSignalKind,
    preferred: F,
) -> Option<(&ProtocolFileView, Option<&String>)>
where
    F: Fn(Option<&String>) -> bool,
{
    first_signal_by(index, kind, preferred).or_else(|| first_signal(index, kind))
}

fn first_signal_by<F>(
    index: &ProtocolIndex,
    kind: ProtocolSignalKind,
    predicate: F,
) -> Option<(&ProtocolFileView, Option<&String>)>
where
    F: Fn(Option<&String>) -> bool,
{
    index.files.iter().find_map(|file| {
        file.signals.iter().find_map(|signal| {
            (signal.kind == kind && predicate(signal.detail.as_ref()))
                .then_some((file, signal.detail.as_ref()))
        })
    })
}

fn symbol_from_path(path: &Path) -> String {
    let display = path.to_string_lossy();
    let rel = display
        .split("sources/")
        .nth(1)
        .unwrap_or(display.as_ref())
        .trim_end_matches(".java")
        .trim_end_matches(".kt");
    rel.replace('/', ".")
}

fn decode_javascript_interface_signal(detail: &str) -> JavascriptBridgeSignalDetail {
    let mut parsed = JavascriptBridgeSignalDetail::default();
    for part in detail.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "name" => parsed.method_name = value.to_string(),
            "params" => {
                parsed.parameter_types = value
                    .split(',')
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            "sinks" => {
                parsed.sink_notes = value
                    .split(',')
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            _ => {}
        }
    }
    if parsed.method_name.is_empty() && !detail.contains('=') {
        parsed.method_name = detail.to_string();
    }
    parsed
}

fn format_javascript_interface_signature(detail: &JavascriptBridgeSignalDetail) -> String {
    let params = if detail.parameter_types.is_empty() {
        String::new()
    } else {
        detail.parameter_types.join(", ")
    };
    format!("{}({params})", detail.method_name)
}

fn stable_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn mode_attribute(
    mode: crate::android::extractor::AndroidSemanticMode,
) -> BTreeMap<String, String> {
    BTreeMap::from([(
        "mode".into(),
        if mode == crate::android::extractor::AndroidSemanticMode::Dense {
            "dense"
        } else {
            "default"
        }
        .into(),
    )])
}

fn has_members(bundle: &AndroidSemanticBundle, required: &[&str]) -> bool {
    required.iter().all(|id| {
        bundle.facts.iter().any(|fact| fact.fact_id == *id)
            || bundle
                .control_surfaces
                .iter()
                .any(|surface| surface.surface_id == *id)
            || bundle
                .transport_surfaces
                .iter()
                .any(|surface| surface.surface_id == *id)
            || bundle
                .trust_boundaries
                .iter()
                .any(|boundary| boundary.boundary_id == *id)
    })
}

fn empty_bundle() -> AndroidSemanticBundle {
    crate::android::semantic::AndroidSemanticBundle {
        bundle_version: String::new(),
        target: crate::android::semantic::AndroidSemanticTarget {
            application_id: None,
            package_name: String::new(),
            version_code: None,
            version_name: None,
            split_names: Vec::new(),
        },
        extractor: crate::android::semantic::AndroidExtractorMetadata {
            extractor_id: String::new(),
            extractor_version: String::new(),
            input_kind: String::new(),
            generated_at_utc: None,
            degraded: false,
            notes: Vec::new(),
        },
        facts: Vec::new(),
        symbol_identities: Vec::new(),
        control_surfaces: Vec::new(),
        transport_surfaces: Vec::new(),
        trust_boundaries: Vec::new(),
        resources: Vec::new(),
        native_semantics: Vec::new(),
        subsystems: Vec::new(),
        revelations: Vec::new(),
        correlations: Vec::new(),
        warnings: Vec::new(),
    }
}
