use std::error::Error;
use std::path::Path;

use fat_taint::profile::{core_source_hints, CatalogProvenance, ExternalTaintProfile};
use fat_taint::recon::source_map::{analyze_rootfs, SourceMapReport};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(rootfs: &Path, source_profile: Option<&Path>, json: bool) -> DynResult<()> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }

    // Which symbol names indicate request data is a per-target claim, so the
    // hint set is the specified models plus whatever profile the operator named.
    let selected = source_profile.map(ExternalTaintProfile::load).transpose()?;
    let hints = selected
        .as_ref()
        .map(ExternalTaintProfile::source_hints_with_core)
        .unwrap_or_else(core_source_hints);
    let provenance = selected
        .as_ref()
        .map(|profile| profile.provenance().clone())
        .unwrap_or(CatalogProvenance::Core);
    let mut report = analyze_rootfs(rootfs, &hints).map_err(|e| -> Box<dyn Error> { e.into() })?;
    report.model_provenance = Some(provenance);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_report(&report);
    }
    Ok(())
}

fn render_report(report: &SourceMapReport) {
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        render_report_plain(report, &palette);
        return;
    }

    let mut lines = vec![format!(
        "{} {} frontend surfaces, {} backend candidates",
        palette.dot_ok(),
        report.frontend_surfaces.len(),
        report.backend_candidates.len()
    )];

    lines.push(palette.heading("Frontend Surfaces"));
    if report.frontend_surfaces.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("none found")
        ));
    }
    for surface in &report.frontend_surfaces {
        lines.push(format!(
            "{} {} [{}] {}",
            palette.dot_ok(),
            palette.info(&surface.path),
            palette.code(&surface.kind),
            surface.endpoint
        ));
        if !surface.methods.is_empty() {
            lines.push(format!(
                "· {}",
                palette.muted(format!("methods: {}", surface.methods.join(", ")))
            ));
        }
        for parameter in &surface.parameters {
            let detail = match &parameter.constraint {
                Some(constraint) => format!(
                    "{} ({}={})",
                    parameter.name, constraint.kind, constraint.value
                ),
                None => parameter.name.clone(),
            };
            lines.push(format!("· {}", palette.muted(format!("param: {detail}"))));
        }
    }

    lines.push(palette.heading("Backend Candidates"));
    if report.backend_candidates.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("none found")
        ));
    }
    for candidate in &report.backend_candidates {
        lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            palette.info(&candidate.path),
            palette.muted(format!(
                "score={} exact={} fuzzy={}",
                candidate.score, candidate.exact_matches, candidate.fuzzy_matches
            ))
        ));
        if !candidate.matched_terms.is_empty() {
            lines.push(format!(
                "· {}",
                palette.muted(format!("terms: {}", candidate.matched_terms.join(", ")))
            ));
        }
        if !candidate.source_hints.is_empty() {
            let hints = candidate
                .source_hints
                .iter()
                .map(|hint| format!("{}:{}", hint.function, hint.taint_kind))
                .collect::<Vec<_>>();
            lines.push(format!(
                "· {}",
                palette.muted(format!("source hints: {}", hints.join(", ")))
            ));
        }
    }

    println!("{}", palette.panel("Source Map", &lines));
    if report.frontend_surfaces.is_empty() && report.backend_candidates.is_empty() {
        println!(
            "{}",
            palette.next_hint("fat extract <project> to surface source boundaries")
        );
    } else {
        println!(
            "{}",
            palette.next_hint("fat taint <file> to trace dataflow across these surfaces")
        );
    }
}

/// Plain `-`/`key:` rendering; byte-identical to the historical output so
/// scripts and piped output keep parsing the same shape.
fn render_report_plain(report: &SourceMapReport, palette: &crate::style::Palette) {
    println!("{}", palette.heading("Source Map"));
    println!(
        "{}",
        palette.kv(
            "summary",
            format!(
                "{} frontend surfaces, {} backend candidates",
                report.frontend_surfaces.len(),
                report.backend_candidates.len()
            )
        )
    );
    println!();

    if !report.frontend_surfaces.is_empty() {
        println!("{}", palette.heading("Frontend Surfaces"));
        for surface in &report.frontend_surfaces {
            println!(
                "  {} [{}] {}",
                palette.info(&surface.path),
                palette.code(&surface.kind),
                surface.endpoint
            );
            if !surface.methods.is_empty() {
                println!(
                    "    {} {}",
                    palette.key("Methods:"),
                    surface.methods.join(", ")
                );
            }
            for parameter in &surface.parameters {
                if let Some(constraint) = &parameter.constraint {
                    println!(
                        "    {} {} ({}={})",
                        palette.key("Param:"),
                        parameter.name,
                        constraint.kind,
                        constraint.value
                    );
                } else {
                    println!("    {} {}", palette.key("Param:"), parameter.name);
                }
            }
        }
        println!();
    }

    if !report.backend_candidates.is_empty() {
        println!("{}", palette.heading("Backend Candidates"));
        for candidate in &report.backend_candidates {
            println!(
                "  {} [score={}, exact={}, fuzzy={}]",
                palette.info(&candidate.path),
                palette.good(candidate.score.to_string()),
                candidate.exact_matches,
                candidate.fuzzy_matches
            );
            if !candidate.matched_terms.is_empty() {
                println!(
                    "    {} {}",
                    palette.key("Terms:"),
                    candidate.matched_terms.join(", ")
                );
            }
            if !candidate.source_hints.is_empty() {
                let hints = candidate
                    .source_hints
                    .iter()
                    .map(|hint| format!("{}:{}", hint.function, hint.taint_kind))
                    .collect::<Vec<_>>();
                println!("    {} {}", palette.key("Source hints:"), hints.join(", "));
            }
        }
    }
}
