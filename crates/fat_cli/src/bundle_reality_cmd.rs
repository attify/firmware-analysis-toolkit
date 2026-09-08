use crate::handoff_evidence::{
    filter_non_runtime_libraries, framework_bundle_root, infer_runtime_root,
    inspect_framework_bundle_reality, resolve_linked_target,
};
use fat_query::adapters::traits::QueryKind;
use regex::Regex;
use serde::Serialize;
use std::error::Error;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub(crate) struct BundleRealityReport {
    binary: String,
    runtime_root: Option<String>,
    evidence_notes: Vec<String>,
    items: Vec<BundleRealityItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleRealityItem {
    linked_library: String,
    resolved_target: String,
    bundle_root: Option<String>,
    exists_as_file: bool,
    framework_metadata: Option<BundleMetadataReport>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct BundleMetadataReport {
    pub(crate) info_plist: String,
    pub(crate) cf_bundle_executable: Option<String>,
    pub(crate) cf_bundle_identifier: Option<String>,
    pub(crate) cf_bundle_package_type: Option<String>,
    pub(crate) expected_executable: Option<String>,
    pub(crate) expected_executable_exists_as_file: Option<bool>,
    pub(crate) notes: Vec<String>,
}

pub fn run(file: &Path, json: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let mut evidence_notes = vec![crate::adapter_routing::adapter_plan_note(
        file,
        QueryKind::BundleReality,
    )];
    let linked_libraries = match fat_taint::recon::r2::linked_libraries(file) {
        Ok(libraries) => libraries,
        Err(err) => {
            evidence_notes.push(format!(
                "linked-library evidence could not be collected cleanly: {err}"
            ));
            Vec::new()
        }
    };

    let report = build_report(file, linked_libraries, evidence_notes);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text_report(&report);
    }
    Ok(())
}

pub(crate) fn build_report(
    file: &Path,
    linked_libraries: Vec<String>,
    evidence_notes: Vec<String>,
) -> BundleRealityReport {
    let runtime_root = infer_runtime_root(file).map(|path| path.display().to_string());
    let mut items = Vec::new();

    for linked in filter_non_runtime_libraries(&linked_libraries) {
        let resolved =
            resolve_linked_target(file, &linked).unwrap_or_else(|| PathBuf::from(&linked));
        let bundle_root = framework_bundle_root(&resolved);
        let framework_metadata = bundle_root
            .as_ref()
            .and_then(|bundle_root| inspect_framework_metadata(bundle_root));
        let exists_as_file = resolved.is_file();
        let mut notes = Vec::new();

        let reality = inspect_framework_bundle_reality(
            bundle_root.as_deref().unwrap_or(&resolved),
            framework_metadata
                .as_ref()
                .and_then(|meta| meta.cf_bundle_executable.as_deref())
                .unwrap_or_else(|| {
                    resolved
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("")
                }),
        );
        notes.extend(reality.notes);

        if let Some(metadata) = &framework_metadata {
            notes.extend(metadata.notes.clone());
        }

        items.push(BundleRealityItem {
            linked_library: linked,
            resolved_target: resolved.display().to_string(),
            bundle_root: bundle_root.map(|path| path.display().to_string()),
            exists_as_file,
            framework_metadata,
            notes: dedupe_strings(notes),
        });
    }

    BundleRealityReport {
        binary: file.display().to_string(),
        runtime_root,
        evidence_notes,
        items,
    }
}

fn render_text_report(report: &BundleRealityReport) {
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        render_text_report_plain(report, &palette);
        return;
    }

    let mut lines = Vec::new();
    lines.push(palette.kv("binary", &report.binary));
    if let Some(runtime_root) = &report.runtime_root {
        lines.push(palette.kv("runtime root", runtime_root));
    }
    if !report.evidence_notes.is_empty() {
        for note in &report.evidence_notes {
            lines.push(format!("{} {}", palette.dot_warn(), palette.warn(note)));
        }
    }

    if report.items.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.warn("No bundle-backed linked-library candidates were resolved.")
        ));
    }
    for item in &report.items {
        let resolved = item.exists_as_file;
        let mut line = format!(
            "{} {}  {}",
            if resolved {
                palette.dot_ok()
            } else {
                palette.dot_bad()
            },
            palette.key(&item.linked_library),
            palette.muted(format!("target {}", item.resolved_target))
        );
        if let Some(bundle_root) = &item.bundle_root {
            line.push_str(&format!(
                "  {}",
                palette.muted(format!("bundle root {bundle_root}"))
            ));
        }
        lines.push(line);
        if let Some(metadata) = &item.framework_metadata {
            if let Some(identifier) = &metadata.cf_bundle_identifier {
                lines.push(format!(
                    "· {}",
                    palette.muted(format!("bundle id: {identifier}"))
                ));
            }
            if let Some(executable) = &metadata.cf_bundle_executable {
                lines.push(format!(
                    "· {}",
                    palette.muted(format!("bundle executable: {executable}"))
                ));
            }
            if let Some(expected) = &metadata.expected_executable {
                lines.push(format!(
                    "· {}",
                    palette.muted(format!("expected executable path: {expected}"))
                ));
            }
        }
        for note in &item.notes {
            lines.push(format!("· {}", palette.muted(note)));
        }
    }

    // Fold evidence notes that repeat across libraries into a single tally so
    // the panel does not print the same pattern once per candidate.
    let mut folded: Vec<(String, usize)> = Vec::new();
    for item in &report.items {
        for note in &item.notes {
            let pattern = note.replace(&item.resolved_target, "{target}");
            match folded.iter_mut().find(|(existing, _)| *existing == pattern) {
                Some((_, count)) => *count += 1,
                None => folded.push((pattern, 1)),
            }
        }
    }
    let repeated: Vec<_> = folded.iter().filter(|(_, count)| *count > 1).collect();
    if !repeated.is_empty() {
        lines.push(palette.heading("Repeated Evidence Notes"));
        for (pattern, count) in repeated {
            lines.push(format!(
                "{} {}",
                palette.dot_warn(),
                palette.muted(format!("{pattern} ×{count}"))
            ));
        }
    }

    println!("{}", palette.panel("Bundle Reality", &lines));
}

/// Plain `key:`/`-` rendering; byte-identical to the historical output so
/// scripts and piped output keep parsing the same shape.
fn render_text_report_plain(report: &BundleRealityReport, palette: &crate::style::Palette) {
    println!("{}", palette.heading("Bundle Reality"));
    println!("{}", palette.kv("binary", &report.binary));
    if let Some(runtime_root) = &report.runtime_root {
        println!("{}", palette.kv("runtime root", runtime_root));
    }
    if !report.evidence_notes.is_empty() {
        println!("{}", palette.heading("Evidence Notes"));
        for note in &report.evidence_notes {
            println!("  {} {}", palette.bullet("-"), palette.warn(note));
        }
    }
    if report.items.is_empty() {
        println!(
            "{}",
            palette.warn("No bundle-backed linked-library candidates were resolved.")
        );
    }
    for item in &report.items {
        println!("{}", palette.heading(&item.linked_library));
        println!("  {}", palette.kv("resolved target", &item.resolved_target));
        println!(
            "  {}",
            palette.kv(
                "plain file",
                palette.status_word(if item.exists_as_file { "pass" } else { "fail" })
            )
        );
        if let Some(bundle_root) = &item.bundle_root {
            println!("  {}", palette.kv("bundle root", bundle_root));
        }
        if let Some(metadata) = &item.framework_metadata {
            if let Some(identifier) = &metadata.cf_bundle_identifier {
                println!("  {}", palette.kv("bundle id", identifier));
            }
            if let Some(executable) = &metadata.cf_bundle_executable {
                println!("  {}", palette.kv("bundle executable", executable));
            }
            if let Some(expected) = &metadata.expected_executable {
                println!("  {}", palette.kv("expected executable path", expected));
            }
        }
        for note in &item.notes {
            println!("  {} {}", palette.bullet("-"), palette.muted(note));
        }
    }
}

pub(crate) fn inspect_framework_metadata(bundle_root: &Path) -> Option<BundleMetadataReport> {
    let info_plist = locate_framework_metadata(bundle_root)?;
    let plist_path = info_plist.display().to_string();
    let mut notes = vec![format!("framework Info.plist found at {}.", plist_path)];

    let plist_text = match load_plist_text(&info_plist) {
        Ok(result) => {
            if let Some(note) = result.note {
                notes.push(note);
            }
            result.text
        }
        Err(err) => {
            notes.push(err);
            return Some(BundleMetadataReport {
                info_plist: plist_path,
                cf_bundle_executable: None,
                cf_bundle_identifier: None,
                cf_bundle_package_type: None,
                expected_executable: None,
                expected_executable_exists_as_file: None,
                notes,
            });
        }
    };

    let cf_bundle_executable = extract_plist_string(&plist_text, "CFBundleExecutable");
    let cf_bundle_identifier = extract_plist_string(&plist_text, "CFBundleIdentifier");
    let cf_bundle_package_type = extract_plist_string(&plist_text, "CFBundlePackageType");
    let expected_executable = cf_bundle_executable
        .as_ref()
        .map(|name| resolve_framework_executable_path(bundle_root, name));
    let expected_executable_exists_as_file =
        expected_executable.as_ref().map(|path| path.is_file());

    Some(BundleMetadataReport {
        info_plist: plist_path,
        cf_bundle_executable,
        cf_bundle_identifier,
        cf_bundle_package_type,
        expected_executable: expected_executable.map(|path| path.display().to_string()),
        expected_executable_exists_as_file,
        notes,
    })
}

struct PlistTextLoad {
    text: String,
    note: Option<String>,
}

fn load_plist_text(info_plist: &Path) -> Result<PlistTextLoad, String> {
    let bytes = std::fs::read(info_plist)
        .map_err(|err| format!("framework Info.plist could not be read from disk: {err}."))?;

    if !looks_like_binary_plist(&bytes) {
        if let Some(text) = decode_xml_plist_text(&bytes) {
            return Ok(PlistTextLoad { text, note: None });
        }
        if !cfg!(target_os = "macos") {
            return Err(
                "framework Info.plist could not be decoded as direct XML text and no plist conversion fallback is available on this platform."
                    .to_string(),
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        load_plist_text_via_plutil(info_plist)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(
            "framework Info.plist did not decode as direct UTF-8 XML and no plist conversion fallback is available on this platform."
                .to_string(),
        )
    }
}

fn extract_plist_string(plist_text: &str, key: &str) -> Option<String> {
    let pattern = format!(
        r"(?s)<key>\s*{}\s*</key>\s*<string>\s*(.*?)\s*</string>",
        regex::escape(key)
    );
    let regex = Regex::new(&pattern).ok()?;
    let captures = regex.captures(plist_text)?;
    let raw = captures.get(1)?.as_str().trim();
    let value = xml_unescape(raw);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn looks_like_binary_plist(bytes: &[u8]) -> bool {
    bytes.starts_with(b"bplist")
}

fn decode_xml_plist_text(bytes: &[u8]) -> Option<String> {
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        return Some(text);
    }
    None
}

#[cfg(target_os = "macos")]
fn load_plist_text_via_plutil(info_plist: &Path) -> Result<PlistTextLoad, String> {
    let output = Command::new("plutil")
        .arg("-convert")
        .arg("xml1")
        .arg("-o")
        .arg("-")
        .arg(info_plist)
        .output()
        .map_err(|err| {
            format!(
                "framework Info.plist did not decode as direct UTF-8 XML and plutil was unavailable: {err}."
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "framework Info.plist did not decode as direct UTF-8 XML and plist conversion failed: {}.",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8(output.stdout).map_err(|err| {
        format!(
            "framework Info.plist was converted through plutil, but the XML output was not valid UTF-8: {err}."
        )
    })?;

    Ok(PlistTextLoad {
        text,
        note: Some(format!(
            "framework Info.plist was decoded via plutil fallback from {}.",
            info_plist.display()
        )),
    })
}

fn locate_framework_metadata(bundle_root: &Path) -> Option<PathBuf> {
    let direct = bundle_root.join("Info.plist");
    if direct.is_file() {
        return Some(direct);
    }
    for version_dir in version_directories(bundle_root) {
        let candidate = version_dir.join("Resources/Info.plist");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_framework_executable_path(bundle_root: &Path, bundle_executable: &str) -> PathBuf {
    let direct = bundle_root.join(bundle_executable);
    if direct.exists() {
        return direct;
    }
    for version_dir in version_directories(bundle_root) {
        let candidate = version_dir.join(bundle_executable);
        if candidate.exists() {
            return candidate;
        }
    }
    direct
}

fn version_directories(bundle_root: &Path) -> Vec<PathBuf> {
    let versions_dir = bundle_root.join("Versions");
    let Ok(entries) = std::fs::read_dir(versions_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_report_surfaces_missing_bundle_executable() {
        let root = tempfile::tempdir().expect("tempdir");
        let binary = root.path().join("usr/libexec/service-launcher");
        std::fs::create_dir_all(binary.parent().expect("parent")).expect("binary parent");
        std::fs::write(&binary, b"fake").expect("binary");

        let bundle_root = root
            .path()
            .join("System/Library/PrivateFrameworks/ExampleRuntimeKit.framework");
        std::fs::create_dir_all(&bundle_root).expect("bundle root");
        std::fs::write(
            bundle_root.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ExampleRuntimeKit</string>
<key>CFBundleIdentifier</key><string>com.example.ExampleRuntimeKit</string>
</dict></plist>"#,
        )
        .expect("plist");

        let report = build_report(
            &binary,
            vec![
                "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .into(),
            ],
            Vec::new(),
        );

        assert_eq!(report.items.len(), 1);
        let item = &report.items[0];
        assert_eq!(
            item.framework_metadata
                .as_ref()
                .and_then(|meta| meta.cf_bundle_identifier.as_deref()),
            Some("com.example.ExampleRuntimeKit")
        );
        assert_eq!(
            item.framework_metadata
                .as_ref()
                .and_then(|meta| meta.expected_executable_exists_as_file),
            Some(false)
        );
    }
}
