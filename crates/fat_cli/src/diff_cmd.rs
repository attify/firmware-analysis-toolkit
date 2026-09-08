use crate::identify_launcher_cmd::collect_report as collect_launcher_report;
use crate::runtime_plane_cmd::collect_report as collect_runtime_plane_report;
use fat_query::adapters::traits::QueryKind;
use serde::Serialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub(crate) struct RoleDiffReport {
    left: String,
    right: String,
    adapter_notes: Vec<String>,
    left_assessment: String,
    right_assessment: String,
    shared_handoff_targets: Vec<String>,
    shared_runtime_plane_ids: Vec<String>,
    same_role: bool,
    notes: Vec<String>,
}

pub(crate) fn run_role(left: &Path, right: &Path, json: bool) -> DynResult<()> {
    if !left.is_file() {
        return Err(format!("left file not found: {}", left.display()).into());
    }
    if !right.is_file() {
        return Err(format!("right file not found: {}", right.display()).into());
    }

    let report = build_role_diff(left, right)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text_report(&report);
    }
    Ok(())
}

fn build_role_diff(left: &Path, right: &Path) -> DynResult<RoleDiffReport> {
    let left_launcher = collect_launcher_report(left)?;
    let right_launcher = collect_launcher_report(right)?;
    let left_plane = collect_runtime_plane_report(left)?;
    let right_plane = collect_runtime_plane_report(right)?;

    let adapter_notes = vec![
        crate::adapter_routing::adapter_plan_note(left, QueryKind::RoleDiff),
        crate::adapter_routing::adapter_plan_note(right, QueryKind::RoleDiff),
    ];

    let shared_handoff_targets = intersect(
        left_launcher
            .likely_handoff_target
            .iter()
            .filter_map(|path| {
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|v| v.to_str())
            })
            .map(|v| v.to_string())
            .collect::<Vec<_>>(),
        right_launcher
            .likely_handoff_target
            .iter()
            .filter_map(|path| {
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|v| v.to_str())
            })
            .map(|v| v.to_string())
            .collect::<Vec<_>>(),
    );

    let shared_runtime_plane_ids = intersect(
        left_plane
            .objects
            .iter()
            .map(|object| {
                object
                    .bundle_identifier
                    .clone()
                    .unwrap_or_else(|| object.linked_library.clone())
            })
            .collect::<Vec<_>>(),
        right_plane
            .objects
            .iter()
            .map(|object| {
                object
                    .bundle_identifier
                    .clone()
                    .unwrap_or_else(|| object.linked_library.clone())
            })
            .collect::<Vec<_>>(),
    );

    let same_assessment = left_launcher.assessment == right_launcher.assessment;
    let same_role = same_assessment
        && (!shared_handoff_targets.is_empty() || !shared_runtime_plane_ids.is_empty());

    let notes = if same_role {
        vec![
            "Both binaries converge on the same downstream role signals and should be treated as role-neighbors."
                .to_string(),
        ]
    } else {
        vec![
            "The binaries do not currently converge on enough launcher/runtime-plane evidence to claim the same role."
                .to_string(),
        ]
    };

    Ok(RoleDiffReport {
        left: left.display().to_string(),
        right: right.display().to_string(),
        adapter_notes,
        left_assessment: format!("{:?}", left_launcher.assessment),
        right_assessment: format!("{:?}", right_launcher.assessment),
        shared_handoff_targets,
        shared_runtime_plane_ids,
        same_role,
        notes,
    })
}

fn render_text_report(report: &RoleDiffReport) {
    let palette = crate::style::Palette::stdout();
    println!("{}", palette.heading("Role Diff"));
    println!("{}", palette.kv("left", &report.left));
    println!("{}", palette.kv("right", &report.right));
    println!(
        "{}",
        palette.kv(
            "same role",
            palette.status_word(if report.same_role { "yes" } else { "no" })
        )
    );
    println!("{}", palette.kv("left assessment", &report.left_assessment));
    println!(
        "{}",
        palette.kv("right assessment", &report.right_assessment)
    );
    if !report.shared_handoff_targets.is_empty() {
        println!(
            "{}",
            palette.kv(
                "shared handoff targets",
                report.shared_handoff_targets.join(", ")
            )
        );
    }
    if !report.shared_runtime_plane_ids.is_empty() {
        println!(
            "{}",
            palette.kv(
                "shared runtime-plane ids",
                report.shared_runtime_plane_ids.join(", ")
            )
        );
    }
    if !report.adapter_notes.is_empty() {
        println!("{}", palette.heading("Adapter Notes"));
        for note in &report.adapter_notes {
            println!("  {} {}", palette.bullet("-"), palette.muted(note));
        }
    }
}

fn intersect(left: Vec<String>, right: Vec<String>) -> Vec<String> {
    let right_set = right.into_iter().collect::<BTreeSet<_>>();
    left.into_iter()
        .filter(|value| right_set.contains(value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_diff_reports_matching_assessments_for_identical_files() {
        let binary = if cfg!(target_os = "macos") {
            Path::new("/usr/bin/true")
        } else {
            Path::new("/bin/true")
        };
        let report = build_role_diff(binary, binary).expect("role diff");
        assert_eq!(report.left_assessment, report.right_assessment);
    }
}
