use crate::android::discovery::{
    AndroidComponentFact, AndroidComponentKind, AndroidIntentFilterFact, AndroidManifestFact,
};
use crate::result::ParseStatus;
use regex::Regex;
use std::path::Path;
use std::process::Command;

pub fn parse_manifest(bytes: &[u8]) -> AndroidManifestFact {
    let first_non_whitespace = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    let binary_xml = !matches!(first_non_whitespace, Some(b'<'));
    if binary_xml {
        return AndroidManifestFact {
            parse_status: ParseStatus::Degraded,
            binary_xml: true,
            package_name: None,
            requested_permissions: Vec::new(),
            debuggable: None,
            uses_cleartext_traffic: None,
            components: Vec::new(),
            notes: vec![
                "built-in binary AXML parsing is unavailable; install apkanalyzer for the supported fallback"
                    .into(),
            ],
        };
    }

    let text = String::from_utf8_lossy(bytes);
    let package_name = capture_package_name(&text);
    let components = capture_components(&text);
    let mut notes = Vec::new();
    if package_name.is_none() {
        notes.push("package attribute not found in manifest text".into());
    }

    AndroidManifestFact {
        parse_status: ParseStatus::Parsed,
        binary_xml: false,
        package_name,
        requested_permissions: capture_requested_permissions(&text),
        debuggable: capture_application_flag(&text, "android:debuggable", "debuggable"),
        uses_cleartext_traffic: capture_application_flag(
            &text,
            "android:usesCleartextTraffic",
            "usesCleartextTraffic",
        ),
        components,
        notes,
    }
}

pub fn parse_manifest_via_apkanalyzer(apk_path: &Path) -> Option<AndroidManifestFact> {
    let output = Command::new("apkanalyzer")
        .args(["manifest", "print"])
        .arg(apk_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut parsed = parse_manifest(&output.stdout);
    parsed.binary_xml = true;
    parsed
        .notes
        .push("manifest parsed via apkanalyzer fallback".into());
    Some(parsed)
}

fn capture_package_name(text: &str) -> Option<String> {
    let re = Regex::new(r#"package\s*=\s*"([^"]+)""#).expect("package regex");
    re.captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn capture_components(text: &str) -> Vec<AndroidComponentFact> {
    let mut components = Vec::new();
    for tag in ["activity", "service", "receiver", "provider"] {
        let block_re = Regex::new(&format!(
            r#"(?s)<{tag}\b([^>/]*)>(.*?)</{tag}>"#,
            tag = regex::escape(tag)
        ))
        .expect("component block regex");
        let self_re = Regex::new(&format!(r#"<{tag}\b([^>]*)/>"#, tag = regex::escape(tag)))
            .expect("component regex");
        for captures in block_re.captures_iter(text) {
            if let Some(component) = build_component(
                Some(tag),
                captures.get(1).map(|value| value.as_str()),
                captures.get(2).map(|value| value.as_str()),
            ) {
                components.push(component);
            }
        }
        for captures in self_re.captures_iter(text) {
            if let Some(component) =
                build_component(Some(tag), captures.get(1).map(|value| value.as_str()), None)
            {
                components.push(component);
            }
        }
    }
    components
}

fn capture_requested_permissions(text: &str) -> Vec<String> {
    let re = Regex::new(r#"<uses-permission\b([^>]*)/?>"#).expect("uses-permission regex");
    re.captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
        .filter_map(|attrs| {
            extract_attr(attrs, "android:name").or_else(|| extract_attr(attrs, "name"))
        })
        .collect()
}

fn capture_application_flag(text: &str, android_key: &str, plain_key: &str) -> Option<bool> {
    let re = Regex::new(r#"(?s)<application\b([^>]*)>"#).expect("application regex");
    let attrs = re
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())?;
    extract_attr(attrs, android_key)
        .or_else(|| extract_attr(attrs, plain_key))
        .map(|value| value == "true")
}

fn build_component(
    kind: Option<&str>,
    attrs: Option<&str>,
    body: Option<&str>,
) -> Option<AndroidComponentFact> {
    let kind = match kind? {
        "activity" => AndroidComponentKind::Activity,
        "service" => AndroidComponentKind::Service,
        "receiver" => AndroidComponentKind::Receiver,
        "provider" => AndroidComponentKind::Provider,
        _ => return None,
    };
    let attrs = attrs?;
    let name = extract_attr(attrs, "android:name").or_else(|| extract_attr(attrs, "name"))?;
    let exported = extract_attr(attrs, "android:exported")
        .or_else(|| extract_attr(attrs, "exported"))
        .map(|value| value == "true");
    let permission =
        extract_attr(attrs, "android:permission").or_else(|| extract_attr(attrs, "permission"));
    let authorities =
        extract_attr(attrs, "android:authorities").or_else(|| extract_attr(attrs, "authorities"));
    let grant_uri_permissions = extract_attr(attrs, "android:grantUriPermissions")
        .or_else(|| extract_attr(attrs, "grantUriPermissions"))
        .map(|value| value == "true");
    Some(AndroidComponentFact {
        name,
        kind,
        exported,
        permission,
        intent_filters: capture_intent_filters(body.unwrap_or_default()),
        authorities,
        grant_uri_permissions,
    })
}

fn capture_intent_filters(body: &str) -> Vec<AndroidIntentFilterFact> {
    let re =
        Regex::new(r#"(?s)<intent-filter\b[^>]*>(.*?)</intent-filter>"#).expect("intent filter");
    re.captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
        .map(|body| AndroidIntentFilterFact {
            actions: capture_named_tags(body, "action"),
            categories: capture_named_tags(body, "category"),
            data_schemes: capture_data_attrs(body, "android:scheme", "scheme"),
            data_hosts: capture_data_attrs(body, "android:host", "host"),
            data_path_prefixes: capture_data_attrs(body, "android:pathPrefix", "pathPrefix"),
        })
        .collect()
}

fn capture_named_tags(body: &str, tag: &str) -> Vec<String> {
    let re = Regex::new(&format!(r#"<{tag}\b([^>]*)/?>"#, tag = regex::escape(tag)))
        .expect("named tag regex");
    re.captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
        .filter_map(|attrs| {
            extract_attr(attrs, "android:name").or_else(|| extract_attr(attrs, "name"))
        })
        .collect()
}

fn capture_data_attrs(body: &str, android_key: &str, plain_key: &str) -> Vec<String> {
    let re = Regex::new(r#"<data\b([^>]*)/?>"#).expect("data regex");
    re.captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
        .filter_map(|attrs| {
            extract_attr(attrs, android_key).or_else(|| extract_attr(attrs, plain_key))
        })
        .collect()
}

fn extract_attr(attrs: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"{key}\s*=\s*"([^"]+)""#);
    let re = Regex::new(&pattern).ok()?;
    re.captures(attrs)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_extracts_exported_components_intent_filters_and_provider_authorities() {
        let manifest = br#"
        <manifest package="com.example.surface">
          <uses-permission android:name="android.permission.INTERNET" />
          <application android:debuggable="true" android:usesCleartextTraffic="false">
            <activity android:name=".DeepLinkActivity" android:exported="true">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.app" android:pathPrefix="/devices/" />
              </intent-filter>
            </activity>
            <service android:name=".SyncService" android:exported="true" android:permission="com.example.SYNC" />
            <provider
              android:name=".FilesProvider"
              android:authorities="com.example.surface.files"
              android:exported="true"
              android:grantUriPermissions="true" />
          </application>
        </manifest>
        "#;

        let parsed = parse_manifest(manifest);

        assert_eq!(parsed.package_name.as_deref(), Some("com.example.surface"));
        assert_eq!(
            parsed.requested_permissions,
            vec!["android.permission.INTERNET"]
        );
        assert_eq!(parsed.debuggable, Some(true));
        assert_eq!(parsed.uses_cleartext_traffic, Some(false));
        assert_eq!(parsed.components.len(), 3);
        let activity = parsed
            .components
            .iter()
            .find(|component| component.name == ".DeepLinkActivity")
            .expect("activity");
        assert_eq!(activity.exported, Some(true));
        assert_eq!(activity.intent_filters.len(), 1);
        assert_eq!(
            activity.intent_filters[0].actions,
            vec!["android.intent.action.VIEW"]
        );
        assert_eq!(
            activity.intent_filters[0].categories,
            vec![
                "android.intent.category.DEFAULT",
                "android.intent.category.BROWSABLE"
            ]
        );
        assert_eq!(activity.intent_filters[0].data_hosts, vec!["example.app"]);
        assert_eq!(
            activity.intent_filters[0].data_path_prefixes,
            vec!["/devices/"]
        );
        let provider = parsed
            .components
            .iter()
            .find(|component| component.name == ".FilesProvider")
            .expect("provider");
        assert_eq!(
            provider.authorities.as_deref(),
            Some("com.example.surface.files")
        );
        assert_eq!(provider.grant_uri_permissions, Some(true));
    }
}
