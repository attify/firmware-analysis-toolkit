use crate::handoff_evidence::{
    extract_entrypoint_clues, framework_bundle_root, infer_runtime_root,
    inspect_framework_bundle_reality, inspect_linked_target_reality,
    rank_downstream_candidates_with_context,
};
use crate::style::Palette;
use fat_query::adapters::traits::QueryKind;
use fat_taint::recon::r2;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub(crate) struct HandoffInspectionReport {
    binary: String,
    runtime_root: Option<String>,
    evidence_notes: Vec<String>,
    linked_libraries: Vec<String>,
    entrypoint_clues: Vec<String>,
    semantic_profile: Option<String>,
    semantic_profile_terms: Vec<String>,
    primary_family: Option<String>,
    downstream_targets: Vec<DownstreamTargetReport>,
    artifact_reality: Vec<ArtifactRealityItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DownstreamTargetReport {
    path: String,
    linked_library: String,
    score: i32,
    semantic_family: String,
    exists_as_file: bool,
    bundle_root: Option<String>,
    framework_metadata: Option<FrameworkMetadataReport>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ArtifactRealityItem {
    subject: String,
    target: Option<String>,
    exists_as_file: bool,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FrameworkMetadataReport {
    info_plist: String,
    cf_bundle_executable: Option<String>,
    cf_bundle_identifier: Option<String>,
    cf_bundle_package_type: Option<String>,
    expected_executable: Option<String>,
    expected_executable_exists_as_file: Option<bool>,
    notes: Vec<String>,
}

pub fn run(file: &Path, json: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let mut evidence_notes = Vec::new();
    evidence_notes.push(crate::adapter_routing::adapter_plan_note(
        file,
        QueryKind::HandoffInspection,
    ));

    let linked_libraries = match r2::linked_libraries(file) {
        Ok(libraries) => libraries,
        Err(err) => {
            evidence_notes.push(format!(
                "linked-library evidence could not be collected cleanly: {err}"
            ));
            Vec::new()
        }
    };

    let entrypoint = match r2::entrypoint_disassembly(file, 40) {
        Ok(entrypoint) => entrypoint,
        Err(err) => {
            evidence_notes.push(format!(
                "entrypoint disassembly could not be collected cleanly: {err}"
            ));
            String::new()
        }
    };

    let report = build_report(file, linked_libraries, entrypoint, evidence_notes);
    emit_report(&report, json)
}

fn emit_report(report: &HandoffInspectionReport, json: bool) -> DynResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        let palette = Palette::stdout();
        if palette.enabled() {
            println!(
                "{}",
                palette.panel(&handoff_panel_title(report), &panel_lines(report, &palette))
            );
        } else {
            render_text_report(report);
        }
    }
    Ok(())
}

fn handoff_panel_title(report: &HandoffInspectionReport) -> String {
    let binary_name = Path::new(&report.binary)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| report.binary.clone());
    format!("fat inspect-handoff · {binary_name}")
}

/// Fold a note wall into at most `max` dimmed continuation lines, skipping
/// entries whose kind (text before the first ':') is already in `kinds`;
/// the remainder becomes a dimmed `… N more notes` count. Plain output is
/// never folded.
fn push_notes_folded(
    lines: &mut Vec<String>,
    palette: &Palette,
    notes: &[String],
    kinds: &mut Vec<String>,
    max: usize,
) {
    let mut shown = 0;
    let mut folded = 0;
    for note in notes {
        let kind = note_kind(note);
        if kinds.contains(&kind) {
            folded += 1;
            continue;
        }
        if shown >= max {
            folded += 1;
            continue;
        }
        kinds.push(kind);
        lines.push(palette.muted(format!("· {note}")));
        shown += 1;
    }
    if folded > 0 {
        lines.push(palette.muted(format!("· … {folded} more notes")));
    }
}

/// Dedup key for a note: the prefix before the first ':' when present,
/// else its first few words.
fn note_kind(note: &str) -> String {
    let trimmed = note.trim_end_matches('.').to_ascii_lowercase();
    match trimmed.find(':') {
        Some(pos) => trimmed[..pos].trim().to_string(),
        None => trimmed
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Panel-mode report body (colored TTY only; plain output stays verbatim).
fn panel_lines(report: &HandoffInspectionReport, palette: &Palette) -> Vec<String> {
    let mut lines = Vec::new();

    // Binary
    lines.push(format!(
        "{} {}",
        palette.dot_ok(),
        palette.code(&report.binary)
    ));
    if let Some(root) = &report.runtime_root {
        lines.push(palette.kv("runtime root", root));
    }
    for note in &report.evidence_notes {
        lines.push(palette.muted(format!("evidence note: {note}")));
    }
    if !report.linked_libraries.is_empty() {
        lines.push(palette.kv(
            "linked libraries",
            report.linked_libraries.len().to_string(),
        ));
    }
    if !report.entrypoint_clues.is_empty() {
        lines.push(palette.kv("entrypoint clues", report.entrypoint_clues.join(", ")));
    }
    if let Some(profile) = &report.semantic_profile {
        lines.push(palette.kv("semantic profile", profile));
    }
    if let Some(primary_family) = &report.primary_family {
        lines.push(palette.kv("primary family", primary_family));
    }
    if !report.semantic_profile_terms.is_empty() {
        lines.push(palette.kv("profile terms", report.semantic_profile_terms.join(", ")));
    }
    lines.push(String::new());

    // Downstream targets
    lines.push(palette.heading(format!(
        "Downstream targets ({})",
        report.downstream_targets.len()
    )));
    if report.downstream_targets.is_empty() {
        lines
            .push(palette.muted(
                "No strong downstream targets surfaced from linked-library evidence alone.",
            ));
    } else {
        for target in &report.downstream_targets {
            let dot = if target.exists_as_file {
                palette.dot_ok()
            } else {
                palette.dot_warn()
            };
            let first_note = target
                .notes
                .first()
                .map(|note| format!("  {}", palette.muted(note)))
                .unwrap_or_default();
            lines.push(format!(
                "{dot} {} {}{first_note}",
                palette.info(&target.path),
                palette.muted(format!("(score {})", target.score)),
            ));
            lines.push(palette.muted(format!("· family: {}", target.semantic_family)));
            let mut kinds = vec!["family".to_string()];
            push_notes_folded(
                &mut lines,
                palette,
                &target.notes[1.min(target.notes.len())..],
                &mut kinds,
                2,
            );
            lines.push(String::new());
        }
        lines.push(String::new());
    }

    // Artifact reality
    lines.push(palette.heading("Artifact reality"));
    for item in &report.artifact_reality {
        let dot = if item.exists_as_file {
            palette.dot_ok()
        } else {
            palette.dot_bad()
        };
        lines.push(format!(
            "{dot} {} {} {}",
            item.subject,
            palette.muted("→"),
            palette.info(item.target.as_deref().unwrap_or("<unresolved>")),
        ));
        let mut kinds = Vec::new();
        push_notes_folded(&mut lines, palette, &item.notes, &mut kinds, 1);
    }

    lines
}

fn build_report(
    file: &Path,
    linked_libraries: Vec<String>,
    entrypoint: String,
    evidence_notes: Vec<String>,
) -> HandoffInspectionReport {
    let runtime_root = infer_runtime_root(file).map(|path| path.display().to_string());
    let entrypoint_clues = if entrypoint.is_empty() {
        Vec::new()
    } else {
        extract_entrypoint_clues(&entrypoint)
    };
    let semantic_context = crate::semantic_profile::detect_semantic_context(
        file,
        &linked_libraries,
        &entrypoint_clues,
    );

    let mut downstream_candidates =
        rank_downstream_candidates_with_context(file, &linked_libraries, &semantic_context);
    downstream_candidates.sort_by(|left, right| {
        adjusted_score(right, &entrypoint_clues)
            .cmp(&adjusted_score(left, &entrypoint_clues))
            .then_with(|| left.path.cmp(&right.path))
    });

    let downstream_targets = downstream_candidates
        .into_iter()
        .map(|candidate| {
            render_downstream_target(file, candidate, &entrypoint_clues, &semantic_context)
        })
        .collect::<Vec<_>>();

    let mut artifact_reality = Vec::new();
    artifact_reality.push(ArtifactRealityItem {
        subject: "starting binary".to_string(),
        target: Some(file.display().to_string()),
        exists_as_file: file.is_file(),
        notes: vec![if file.is_file() {
            format!(
                "starting binary exists as a regular file: {}.",
                file.display()
            )
        } else {
            format!("starting binary is not a regular file: {}.", file.display())
        }],
    });

    for target in &downstream_targets {
        artifact_reality.push(ArtifactRealityItem {
            subject: target.linked_library.clone(),
            target: Some(target.path.clone()),
            exists_as_file: target.exists_as_file,
            notes: target.notes.clone(),
        });
    }

    HandoffInspectionReport {
        binary: file.display().to_string(),
        runtime_root,
        evidence_notes,
        linked_libraries,
        entrypoint_clues,
        semantic_profile: semantic_context
            .profile
            .as_ref()
            .map(|profile| profile.id.to_string()),
        semantic_profile_terms: semantic_context
            .profile
            .as_ref()
            .map(|profile| profile.matched_terms.clone())
            .unwrap_or_default(),
        primary_family: semantic_context
            .profile
            .as_ref()
            .map(|profile| profile.primary_family.to_string()),
        downstream_targets,
        artifact_reality: dedupe_artifact_reality(artifact_reality),
    }
}

fn adjusted_score(
    candidate: &crate::handoff_evidence::DownstreamCandidate,
    entrypoint_clues: &[String],
) -> i32 {
    candidate.score + clue_boost(&candidate.path, entrypoint_clues)
}

fn clue_boost(path: &Path, entrypoint_clues: &[String]) -> i32 {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    entrypoint_clues
        .iter()
        .filter(|clue| lower.contains(&clue.to_ascii_lowercase()))
        .count() as i32
        * 15
}

fn render_downstream_target(
    binary: &Path,
    candidate: crate::handoff_evidence::DownstreamCandidate,
    entrypoint_clues: &[String],
    semantic_context: &crate::semantic_profile::SemanticContext,
) -> DownstreamTargetReport {
    let score = adjusted_score(&candidate, entrypoint_clues);
    let candidate_semantics = crate::semantic_profile::classify_candidate(
        &candidate.linked,
        &candidate.path,
        semantic_context,
    );
    let mut notes = Vec::new();
    let mut exists_as_file = candidate.path.is_file();
    let mut bundle_root =
        framework_bundle_root(&candidate.path).map(|path| path.display().to_string());
    let mut resolved_target = candidate.path.clone();
    let mut framework_metadata = None;

    if let Some(linked_path) =
        crate::handoff_evidence::resolve_linked_target(binary, &candidate.linked)
    {
        notes.push(format!(
            "matched linked-library reference: {}.",
            candidate.linked
        ));
        let report = inspect_linked_target_reality(binary, &candidate.linked);
        resolved_target = report.target.unwrap_or(linked_path);
        exists_as_file = resolved_target.is_file();
        notes.extend(report.notes);
    }

    if let Some(bundle_root_path) = framework_bundle_root(&candidate.path) {
        let declared_executable = candidate
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let bundle_report =
            inspect_framework_bundle_reality(&bundle_root_path, &declared_executable);
        if let Some(target) = bundle_report.target {
            resolved_target = target;
            exists_as_file = resolved_target.is_file();
        }
        notes.extend(bundle_report.notes);
        bundle_root = Some(bundle_root_path.display().to_string());

        if let Some(metadata_report) = inspect_framework_metadata(&bundle_root_path) {
            notes.extend(metadata_report.notes.clone());
            framework_metadata = Some(metadata_report);
        }
    }

    if exists_as_file {
        notes.push(format!(
            "candidate resolves to a normal file on disk: {}.",
            resolved_target.display()
        ));
    } else {
        notes.push(format!(
            "candidate does not exist as a normal file on disk: {}.",
            resolved_target.display()
        ));
    }

    if !entrypoint_clues.is_empty() {
        let lower = candidate.path.to_string_lossy().to_ascii_lowercase();
        let clue_hits: Vec<String> = entrypoint_clues
            .iter()
            .filter(|clue| lower.contains(&clue.to_ascii_lowercase()))
            .cloned()
            .collect();
        if !clue_hits.is_empty() {
            notes.push(format!(
                "entrypoint clue overlap: {}.",
                clue_hits.join(", ")
            ));
        }
    }
    notes.extend(candidate_semantics.reasons.clone());

    DownstreamTargetReport {
        path: resolved_target.display().to_string(),
        linked_library: candidate.linked,
        score,
        semantic_family: candidate_semantics.family.to_string(),
        exists_as_file,
        bundle_root,
        framework_metadata,
        notes: dedupe_strings(notes),
    }
}

fn inspect_framework_metadata(bundle_root: &Path) -> Option<FrameworkMetadataReport> {
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
            return Some(FrameworkMetadataReport {
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

    match &cf_bundle_identifier {
        Some(value) => notes.push(format!("CFBundleIdentifier = {value}.")),
        None => {
            notes.push("CFBundleIdentifier was not present in the framework plist.".to_string())
        }
    }
    match &cf_bundle_package_type {
        Some(value) => notes.push(format!("CFBundlePackageType = {value}.")),
        None => {
            notes.push("CFBundlePackageType was not present in the framework plist.".to_string())
        }
    }

    let expected_executable = cf_bundle_executable
        .as_ref()
        .map(|name| resolve_framework_executable_path(bundle_root, name));
    let expected_executable_exists_as_file =
        expected_executable.as_ref().map(|path| path.is_file());

    if let Some(executable) = &cf_bundle_executable {
        if let Some(expected_path) = &expected_executable {
            let versioned_layout = is_versioned_framework_path(bundle_root, expected_path);
            notes.push(format!(
                "CFBundleExecutable = {}; expected executable path: {} ({}).",
                executable,
                expected_path.display(),
                if expected_path.is_file() {
                    if versioned_layout {
                        "regular file present in a versioned layout"
                    } else {
                        "regular file present"
                    }
                } else if versioned_layout {
                    "not a regular file in a versioned layout"
                } else {
                    "not a regular file"
                }
            ));
            if !expected_path.is_file() {
                notes.push(
                    "Declared executable is not present as a plain file; this is likely a packaged or runtime-backed implementation."
                        .to_string(),
                );
            }
        }
    } else {
        notes.push("CFBundleExecutable was not present in the framework plist.".to_string());
    }

    Some(FrameworkMetadataReport {
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

    decode_utf16_xml_text(bytes)
}

fn decode_utf16_xml_text(bytes: &[u8]) -> Option<String> {
    let endian = detect_utf16_endianness(bytes)?;
    let body = if matches!(bytes.get(0..2), Some([0xFF, 0xFE] | [0xFE, 0xFF])) {
        &bytes[2..]
    } else {
        bytes
    };
    if body.len() % 2 != 0 {
        return None;
    }

    let units = body
        .chunks_exact(2)
        .map(|chunk| match endian {
            Utf16Endian::Little => u16::from_le_bytes([chunk[0], chunk[1]]),
            Utf16Endian::Big => u16::from_be_bytes([chunk[0], chunk[1]]),
        })
        .collect::<Vec<_>>();

    String::from_utf16(&units)
        .ok()
        .map(|text| text.trim_start_matches('\u{feff}').to_string())
}

fn detect_utf16_endianness(bytes: &[u8]) -> Option<Utf16Endian> {
    match bytes.get(0..2) {
        Some([0xFF, 0xFE]) => return Some(Utf16Endian::Little),
        Some([0xFE, 0xFF]) => return Some(Utf16Endian::Big),
        _ => {}
    }

    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }

    let sample_pairs = bytes.chunks_exact(2).take(8).collect::<Vec<_>>();
    if sample_pairs.is_empty() {
        return None;
    }

    let likely_little = sample_pairs
        .iter()
        .all(|pair| pair[1] == 0 && pair[0].is_ascii());
    if likely_little {
        return Some(Utf16Endian::Little);
    }

    let likely_big = sample_pairs
        .iter()
        .all(|pair| pair[0] == 0 && pair[1].is_ascii());
    if likely_big {
        return Some(Utf16Endian::Big);
    }

    None
}

#[derive(Clone, Copy)]
enum Utf16Endian {
    Little,
    Big,
}

fn resolve_framework_executable_path(bundle_root: &Path, bundle_executable: &str) -> PathBuf {
    let direct = bundle_root.join(bundle_executable);
    if direct.exists() {
        return direct;
    }

    find_versioned_framework_executable(bundle_root, bundle_executable).unwrap_or(direct)
}

fn find_versioned_framework_executable(
    bundle_root: &Path,
    bundle_executable: &str,
) -> Option<PathBuf> {
    for path in version_directories(bundle_root) {
        let candidate = path.join(bundle_executable);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn is_versioned_framework_path(bundle_root: &Path, candidate: &Path) -> bool {
    let versions_dir = bundle_root.join("Versions");
    candidate.starts_with(&versions_dir)
}

#[cfg(target_os = "macos")]
fn load_plist_text_via_plutil(info_plist: &Path) -> Result<PlistTextLoad, String> {
    let output = Command::new("plutil")
        .args(["-convert", "xml1", "-o", "-"])
        .arg(info_plist)
        .output()
        .map_err(|err| {
            format!(
                "framework Info.plist did not decode as direct UTF-8 XML and plutil was unavailable: {err}."
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            "plutil returned a non-zero status".to_string()
        } else {
            format!("plutil returned a non-zero status: {stderr}")
        };
        return Err(format!(
            "framework Info.plist did not decode as direct UTF-8 XML and plist conversion failed: {detail}."
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

fn locate_framework_metadata(bundle_root: &Path) -> Option<std::path::PathBuf> {
    let direct = bundle_root.join("Info.plist");
    if direct.is_file() {
        return Some(direct);
    }

    for path in version_directories(bundle_root) {
        let candidate = path.join("Resources/Info.plist");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn version_directories(bundle_root: &Path) -> Vec<PathBuf> {
    let versions_dir = bundle_root.join("Versions");
    let entries = match std::fs::read_dir(&versions_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut paths = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    paths.sort_by_key(|left| version_sort_key(left));
    paths
}

fn version_sort_key(path: &Path) -> (u8, String) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let priority = if name == "Current" { 0 } else { 1 };
    (priority, name)
}

fn dedupe_strings(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }
    result
}

fn dedupe_artifact_reality(items: Vec<ArtifactRealityItem>) -> Vec<ArtifactRealityItem> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let key = format!("{}|{:?}|{}", item.subject, item.target, item.exists_as_file);
        if seen.insert(key) {
            result.push(item);
        }
    }
    result
}

fn render_text_report(report: &HandoffInspectionReport) {
    println!("=== Handoff Inspection ===");
    println!();
    println!("Binary");
    println!("  {}", report.binary);
    if let Some(root) = &report.runtime_root {
        println!("  inferred runtime root: {root}");
    }
    for note in &report.evidence_notes {
        println!("  evidence note: {note}");
    }
    if !report.linked_libraries.is_empty() {
        println!("  linked libraries: {}", report.linked_libraries.len());
    }
    if !report.entrypoint_clues.is_empty() {
        println!("  entrypoint clues: {}", report.entrypoint_clues.join(", "));
    }
    if let Some(profile) = &report.semantic_profile {
        println!("  semantic profile: {profile}");
    }
    if let Some(primary_family) = &report.primary_family {
        println!("  primary family: {primary_family}");
    }
    if !report.semantic_profile_terms.is_empty() {
        println!(
            "  profile terms: {}",
            report.semantic_profile_terms.join(", ")
        );
    }
    println!();

    println!("Downstream targets");
    if report.downstream_targets.is_empty() {
        println!("  No strong downstream targets surfaced from linked-library evidence alone.");
    } else {
        for target in &report.downstream_targets {
            println!("  - {} (score {})", target.path, target.score);
            println!("    source: {}", target.linked_library);
            println!("    semantic family: {}", target.semantic_family);
            if let Some(bundle_root) = &target.bundle_root {
                println!("    bundle root: {bundle_root}");
            }
            for note in &target.notes {
                println!("    note: {note}");
            }
        }
    }
    println!();

    println!("Artifact reality");
    for item in &report.artifact_reality {
        println!(
            "  - {} -> {} ({})",
            item.subject,
            item.target.as_deref().unwrap_or("<unresolved>"),
            if item.exists_as_file {
                "file present"
            } else {
                "not a plain file"
            }
        );
        for note in &item.notes {
            println!("    note: {note}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn temp_root(_name: &str) -> TempDir {
        tempfile::tempdir().expect("temporary test directory should be creatable")
    }

    #[test]
    fn generic_runtime_libraries_are_filtered_or_deprioritized() {
        let binary = Path::new("/tmp/example-rootfs/usr/libexec/service-launcher");
        let linked_libraries = vec![
            "/usr/lib/libSystem.B.dylib".to_string(),
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
        ];

        let ranked = crate::handoff_evidence::rank_downstream_candidates(binary, &linked_libraries);

        assert_eq!(
            ranked
                .first()
                .map(|candidate| candidate.path.display().to_string()),
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .to_string()
            )
        );
        assert!(
            ranked.iter().all(|candidate| {
                let path = candidate.path.display().to_string().to_ascii_lowercase();
                !path.contains("libsystem") && !path.contains("foundation.framework")
            }),
            "generic runtime libraries should not dominate the downstream candidate list"
        );
    }

    #[test]
    fn vendor_private_framework_or_app_specific_library_wins_as_likely_downstream_target() {
        let binary = Path::new("/tmp/example-rootfs/usr/libexec/service-launcher");
        let linked_libraries = vec![
            "/usr/lib/libobjc.A.dylib".to_string(),
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
        ];

        let ranked = crate::handoff_evidence::rank_downstream_candidates(binary, &linked_libraries);

        assert_eq!(
            ranked
                .first()
                .map(|candidate| candidate.path.display().to_string()),
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .to_string()
            )
        );
    }

    #[test]
    fn inferred_runtime_root_resolves_absolute_linked_paths_correctly() {
        let binary = Path::new("/tmp/example-rootfs/usr/libexec/service-launcher");
        let linked =
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit";

        assert_eq!(
            infer_runtime_root(binary),
            Some(PathBuf::from("/tmp/example-rootfs"))
        );
        assert_eq!(
            crate::handoff_evidence::resolve_linked_target(binary, linked),
            Some(PathBuf::from(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
            ))
        );
    }

    #[test]
    fn enriches_framework_bundle_targets_with_plist_metadata() {
        let root = temp_root("framework-plist-enrichment");
        let bundle_root = root.path().join("System/Library/Frameworks/Foo.framework");
        let executable = bundle_root.join("Foo");
        fs::create_dir_all(&bundle_root).expect("bundle root should be creatable");
        fs::write(
            bundle_root.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Foo</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.Foo</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#,
        )
        .expect("bundle metadata plist should be writable");
        fs::write(&executable, b"stub").expect("bundle executable should be writable");

        let candidate = crate::handoff_evidence::DownstreamCandidate {
            path: executable.clone(),
            score: 10,
            linked: executable.display().to_string(),
        };
        let report = render_downstream_target(
            Path::new("/tmp/example-rootfs/usr/libexec/service-launcher"),
            candidate,
            &[],
            &crate::semantic_profile::SemanticContext { profile: None },
        );

        let metadata = report
            .framework_metadata
            .expect("expected plist-backed framework metadata");
        assert_eq!(metadata.cf_bundle_executable.as_deref(), Some("Foo"));
        assert_eq!(
            metadata.cf_bundle_identifier.as_deref(),
            Some("com.example.Foo")
        );
        assert_eq!(metadata.cf_bundle_package_type.as_deref(), Some("FMWK"));
        assert_eq!(
            metadata.expected_executable.as_deref(),
            Some(executable.to_str().expect("bundle path should be utf-8"))
        );
        assert_eq!(metadata.expected_executable_exists_as_file, Some(true));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("CFBundleIdentifier = com.example.Foo")),
            "expected plist metadata notes to be surfaced in the downstream target report"
        );
    }

    #[test]
    fn notes_when_declared_framework_executable_is_missing_as_plain_file() {
        let root = temp_root("framework-plist-missing-executable");
        let bundle_root = root.path().join("System/Library/Frameworks/Bar.framework");
        fs::create_dir_all(&bundle_root).expect("bundle root should be creatable");
        fs::write(
            bundle_root.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Bar</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.Bar</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#,
        )
        .expect("bundle metadata plist should be writable");

        let metadata = inspect_framework_metadata(&bundle_root)
            .expect("expected plist-backed framework metadata");
        assert_eq!(metadata.cf_bundle_executable.as_deref(), Some("Bar"));
        assert_eq!(metadata.expected_executable_exists_as_file, Some(false));
        assert!(
            metadata
                .notes
                .iter()
                .any(|note| note.contains("runtime-backed implementation")),
            "expected a conservative note about the missing executable"
        );
    }

    #[test]
    fn versioned_framework_executable_does_not_trigger_runtime_backed_note() {
        let root = temp_root("framework-versioned-executable");
        let bundle_root = root.path().join("System/Library/Frameworks/Baz.framework");
        let versioned_dir = bundle_root.join("Versions/A");
        fs::create_dir_all(&versioned_dir).expect("versioned framework dir should exist");
        fs::create_dir_all(versioned_dir.join("Resources"))
            .expect("versioned resources dir should exist");
        fs::write(
            versioned_dir.join("Resources/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Baz</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.Baz</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#,
        )
        .expect("versioned plist should be writable");
        fs::write(versioned_dir.join("Baz"), b"stub")
            .expect("versioned framework executable should be writable");

        let metadata = inspect_framework_metadata(&bundle_root)
            .expect("expected plist-backed framework metadata");
        assert_eq!(
            metadata.expected_executable.as_deref(),
            Some(
                versioned_dir
                    .join("Baz")
                    .to_str()
                    .expect("path should be utf-8")
            )
        );
        assert_eq!(metadata.expected_executable_exists_as_file, Some(true));
        assert!(
            !metadata
                .notes
                .iter()
                .any(|note| note.contains("runtime-backed implementation")),
            "expected versioned framework layouts to be treated as present on disk"
        );
    }

    #[test]
    fn multiple_version_frameworks_choose_a_deterministic_version() {
        let root = temp_root("framework-deterministic-version-choice");
        let bundle_root = root
            .path()
            .join("System/Library/Frameworks/Deterministic.framework");
        for version in ["B", "A"] {
            let version_dir = bundle_root.join("Versions").join(version);
            fs::create_dir_all(version_dir.join("Resources"))
                .expect("versioned resources dir should exist");
            fs::write(
                version_dir.join("Resources/Info.plist"),
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Deterministic</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.{version}</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#
                ),
            )
            .expect("versioned plist should be writable");
            fs::write(version_dir.join("Deterministic"), version.as_bytes())
                .expect("versioned executable should be writable");
        }

        let metadata = inspect_framework_metadata(&bundle_root)
            .expect("expected plist-backed framework metadata");
        assert_eq!(
            metadata.info_plist,
            bundle_root
                .join("Versions/A/Resources/Info.plist")
                .display()
                .to_string()
        );
        assert_eq!(
            metadata.expected_executable.as_deref(),
            Some(
                bundle_root
                    .join("Versions/A/Deterministic")
                    .to_str()
                    .expect("path should be utf-8")
            )
        );
        assert_eq!(
            metadata.cf_bundle_identifier.as_deref(),
            Some("com.example.A")
        );
    }

    #[test]
    fn version_directories_are_sorted_deterministically() {
        let root = temp_root("framework-version-order");
        let bundle_root = root
            .path()
            .join("System/Library/Frameworks/Order.framework");
        for version in ["B", "Current", "A"] {
            fs::create_dir_all(bundle_root.join("Versions").join(version))
                .expect("version dir should be creatable");
        }

        let names = version_directories(&bundle_root)
            .into_iter()
            .map(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .expect("version name should be utf-8")
                    .to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["Current", "A", "B"]);
    }

    #[test]
    fn utf16_xml_plist_is_parsed_without_platform_fallbacks() {
        let root = temp_root("framework-utf16-plist");
        let bundle_root = root
            .path()
            .join("System/Library/Frameworks/Utf16.framework");
        fs::create_dir_all(&bundle_root).expect("bundle root should be creatable");
        let utf16_xml = "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>CFBundleExecutable</key>\n\
    <string>Utf16</string>\n\
    <key>CFBundleIdentifier</key>\n\
    <string>com.example.Utf16</string>\n\
    <key>CFBundlePackageType</key>\n\
    <string>FMWK</string>\n\
</dict>\n\
</plist>\n";
        let utf16_bytes: Vec<u8> = utf16_xml
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        fs::write(bundle_root.join("Info.plist"), utf16_bytes)
            .expect("utf16 plist should be writable");

        let loaded = load_plist_text(&bundle_root.join("Info.plist"))
            .expect("expected utf16 plist text to load directly");
        assert!(
            loaded.note.is_none(),
            "expected direct XML decoding, not fallback tooling"
        );

        let metadata = inspect_framework_metadata(&bundle_root)
            .expect("expected plist-backed framework metadata");
        assert_eq!(metadata.cf_bundle_executable.as_deref(), Some("Utf16"));
        assert_eq!(
            metadata.cf_bundle_identifier.as_deref(),
            Some("com.example.Utf16")
        );
        assert_eq!(metadata.cf_bundle_package_type.as_deref(), Some("FMWK"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binary_plist_fallback_parses_framework_metadata_via_plutil() {
        let root = temp_root("framework-binary-plist");
        let bundle_root = root.path().join("System/Library/Frameworks/Qux.framework");
        let xml_plist = bundle_root.join("Info.xml.plist");
        let binary_plist = bundle_root.join("Info.plist");
        fs::create_dir_all(&bundle_root).expect("bundle root should be creatable");
        fs::write(
            &xml_plist,
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Qux</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.Qux</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#,
        )
        .expect("xml plist should be writable");
        let status = Command::new("plutil")
            .args([
                "-convert",
                "binary1",
                "-o",
                binary_plist
                    .to_str()
                    .expect("binary plist path should be utf-8"),
                xml_plist.to_str().expect("xml plist path should be utf-8"),
            ])
            .status()
            .expect("plutil should run");
        assert!(status.success(), "plutil should create a binary plist");

        let metadata = inspect_framework_metadata(&bundle_root)
            .expect("expected plist-backed framework metadata");
        assert_eq!(metadata.cf_bundle_executable.as_deref(), Some("Qux"));
        assert_eq!(
            metadata.cf_bundle_identifier.as_deref(),
            Some("com.example.Qux")
        );
        assert_eq!(metadata.cf_bundle_package_type.as_deref(), Some("FMWK"));
    }
}
