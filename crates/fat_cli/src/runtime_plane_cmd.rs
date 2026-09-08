use crate::bundle_reality_cmd::inspect_framework_metadata;
use crate::handoff_evidence::{
    extract_entrypoint_clues, framework_bundle_root, infer_runtime_root,
};
use fat_query::adapters::traits::QueryKind;
use serde::Serialize;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub(crate) struct RuntimePlaneReport {
    pub(crate) binary: String,
    pub(crate) runtime_root: Option<String>,
    pub(crate) linked_libraries: Vec<String>,
    pub(crate) entrypoint_clues: Vec<String>,
    pub(crate) semantic_profile: Option<String>,
    pub(crate) semantic_profile_terms: Vec<String>,
    pub(crate) primary_family: Option<String>,
    pub(crate) supporting_families: Vec<String>,
    pub(crate) objects: Vec<RuntimePlaneObject>,
    pub(crate) evidence_notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuntimePlaneObject {
    pub(crate) linked_library: String,
    pub(crate) candidate_path: String,
    pub(crate) score: i32,
    pub(crate) semantic_family: String,
    pub(crate) exists_as_file: bool,
    pub(crate) likely_runtime_backed: bool,
    pub(crate) bundle_identifier: Option<String>,
    pub(crate) notes: Vec<String>,
}

pub fn run(file: &Path, json: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let report = collect_report(file)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text_report(&report);
    }
    Ok(())
}

pub(crate) fn collect_report(file: &Path) -> DynResult<RuntimePlaneReport> {
    let mut evidence_notes = vec![crate::adapter_routing::adapter_plan_note(
        file,
        QueryKind::RuntimePlane,
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
    let entrypoint = match fat_taint::recon::r2::entrypoint_disassembly(file, 40) {
        Ok(entrypoint) => entrypoint,
        Err(err) => {
            evidence_notes.push(format!(
                "entrypoint disassembly could not be collected cleanly: {err}"
            ));
            String::new()
        }
    };

    Ok(build_report(
        file,
        linked_libraries,
        entrypoint,
        evidence_notes,
    ))
}

fn build_report(
    file: &Path,
    linked_libraries: Vec<String>,
    entrypoint: String,
    evidence_notes: Vec<String>,
) -> RuntimePlaneReport {
    let runtime_root = infer_runtime_root(file).map(|path| path.display().to_string());
    let entrypoint_clues = extract_entrypoint_clues(&entrypoint);
    let semantic_context = crate::semantic_profile::detect_semantic_context(
        file,
        &linked_libraries,
        &entrypoint_clues,
    );
    let candidates = crate::handoff_evidence::rank_downstream_candidates_with_context(
        file,
        &linked_libraries,
        &semantic_context,
    );
    let objects = candidates
        .into_iter()
        .map(|candidate| {
            let candidate_semantics = crate::semantic_profile::classify_candidate(
                &candidate.linked,
                &candidate.path,
                &semantic_context,
            );
            let bundle_metadata = framework_bundle_root(&candidate.path)
                .as_ref()
                .and_then(|bundle_root| inspect_framework_metadata(bundle_root));
            let exists_as_file = candidate.path.is_file();
            let likely_runtime_backed = !exists_as_file
                || bundle_metadata
                    .as_ref()
                    .and_then(|meta| meta.expected_executable_exists_as_file)
                    == Some(false);
            RuntimePlaneObject {
                linked_library: candidate.linked,
                candidate_path: candidate.path.display().to_string(),
                score: candidate.score,
                semantic_family: candidate_semantics.family.to_string(),
                exists_as_file,
                likely_runtime_backed,
                bundle_identifier: bundle_metadata
                    .as_ref()
                    .and_then(|meta| meta.cf_bundle_identifier.clone()),
                notes: {
                    let mut notes = bundle_metadata.map(|meta| meta.notes).unwrap_or_default();
                    notes.extend(candidate_semantics.reasons);
                    notes
                },
            }
        })
        .collect::<Vec<_>>();

    let supporting_families = objects
        .iter()
        .map(|object| object.semantic_family.clone())
        .filter(|family| {
            semantic_context
                .profile
                .as_ref()
                .map(|profile| family != profile.primary_family)
                .unwrap_or(true)
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    RuntimePlaneReport {
        binary: file.display().to_string(),
        runtime_root,
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
        supporting_families,
        objects,
        evidence_notes,
    }
}

fn render_text_report(report: &RuntimePlaneReport) {
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        render_text_report_plain(report, &palette);
        return;
    }

    // Observed candidate scores top out at 130 (perfect family + bundle match);
    // normalize against it so the bar has a stable full-scale reference.
    const SCORE_CEILING: f32 = 130.0;

    let mut lines = Vec::new();
    lines.push(palette.kv("binary", &report.binary));
    if let Some(runtime_root) = &report.runtime_root {
        lines.push(palette.kv("runtime root", runtime_root));
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
    if !report.supporting_families.is_empty() {
        lines.push(palette.muted(format!(
            "supporting families: {}",
            report.supporting_families.join(", ")
        )));
    }
    if !report.evidence_notes.is_empty() {
        for note in &report.evidence_notes {
            lines.push(format!("{} {}", palette.dot_warn(), palette.warn(note)));
        }
    }

    lines.push(palette.heading("Candidates"));
    if report.objects.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.warn("No runtime-plane objects were resolved from current evidence.")
        ));
    }
    for object in &report.objects {
        lines.push(format!(
            "{} {}  {} {}",
            if object.likely_runtime_backed {
                palette.dot_ok()
            } else {
                palette.dot_warn()
            },
            palette.key(&object.linked_library),
            palette.bar(object.score as f32 / SCORE_CEILING, 8),
            palette.muted(format!("score={}", object.score)),
        ));
        lines.push(format!(
            "· {}  {}",
            palette.muted(format!("candidate {}", object.candidate_path)),
            palette.muted(format!("family: {}", object.semantic_family)),
        ));
        if let Some(identifier) = &object.bundle_identifier {
            lines.push(format!(
                "· {}",
                palette.muted(format!("bundle id: {identifier}"))
            ));
        }
        for note in &object.notes {
            lines.push(format!("· {}", palette.muted(note)));
        }
    }

    println!("{}", palette.panel("Runtime Plane", &lines));
    if !report.objects.is_empty() {
        println!(
            "{}",
            palette
                .next_hint("fat bundle-reality --file <file> to inspect bundle-backed candidates")
        );
    }
}

/// Plain `key:`/`-` rendering; byte-identical to the historical output so
/// scripts and piped output keep parsing the same shape.
fn render_text_report_plain(report: &RuntimePlaneReport, palette: &crate::style::Palette) {
    println!("{}", palette.heading("Runtime Plane"));
    println!("{}", palette.kv("binary", &report.binary));
    if let Some(runtime_root) = &report.runtime_root {
        println!("{}", palette.kv("runtime root", runtime_root));
    }
    if !report.entrypoint_clues.is_empty() {
        println!(
            "{}",
            palette.kv("entrypoint clues", report.entrypoint_clues.join(", "))
        );
    }
    if let Some(profile) = &report.semantic_profile {
        println!("{}", palette.kv("semantic profile", profile));
    }
    if let Some(primary_family) = &report.primary_family {
        println!("{}", palette.kv("primary family", primary_family));
    }
    if !report.semantic_profile_terms.is_empty() {
        println!(
            "{}",
            palette.kv("profile terms", report.semantic_profile_terms.join(", "))
        );
    }
    if !report.supporting_families.is_empty() {
        println!(
            "{}",
            palette.kv("supporting families", report.supporting_families.join(", "))
        );
    }
    if !report.evidence_notes.is_empty() {
        println!("{}", palette.heading("Evidence Notes"));
        for note in &report.evidence_notes {
            println!("  {} {}", palette.bullet("-"), palette.warn(note));
        }
    }
    if report.objects.is_empty() {
        println!(
            "{}",
            palette.warn("No runtime-plane objects were resolved from current evidence.")
        );
    }
    for object in &report.objects {
        println!("{}", palette.heading(&object.linked_library));
        println!("  {}", palette.kv("candidate", &object.candidate_path));
        println!("  {}", palette.kv("score", object.score.to_string()));
        println!(
            "  {}",
            palette.kv("semantic family", &object.semantic_family)
        );
        println!(
            "  {}",
            palette.kv(
                "runtime backed",
                palette.status_word(if object.likely_runtime_backed {
                    "yes"
                } else {
                    "no"
                })
            )
        );
        if let Some(identifier) = &object.bundle_identifier {
            println!("  {}", palette.kv("bundle id", identifier));
        }
        for note in &object.notes {
            println!("  {} {}", palette.bullet("-"), palette.muted(note));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_plane_marks_missing_framework_executable_as_runtime_backed() {
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
            "bl sym.imp._objc_autoreleasePoolPush".into(),
            Vec::new(),
        );

        assert_eq!(report.objects.len(), 1);
        assert!(report.objects[0].likely_runtime_backed);
        assert_eq!(
            report.objects[0].bundle_identifier.as_deref(),
            Some("com.example.ExampleRuntimeKit")
        );
    }
}
