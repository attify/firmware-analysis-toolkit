//! `fat identify-launcher` — determine whether a binary is likely a thin launcher.

use crate::handoff_evidence::{
    extract_entrypoint_clues, filter_non_runtime_libraries, rank_downstream_candidates,
    resolve_linked_target,
};
use fat_query::adapters::traits::QueryKind;
use fat_taint::recon::r2::{self, FunctionInfo};
use serde::Serialize;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum LauncherAssessment {
    LikelyThinLauncher,
    LikelySubstantiveBinary,
    Inconclusive,
}

#[derive(Debug, Serialize)]
pub(crate) struct LauncherReport {
    pub(crate) binary: String,
    pub(crate) assessment: LauncherAssessment,
    pub(crate) confidence: f32,
    pub(crate) evidence: Vec<String>,
    pub(crate) evidence_notes: Vec<String>,
    pub(crate) likely_handoff_target: Option<String>,
    pub(crate) entrypoint_clues: Vec<String>,
    pub(crate) execution_reality_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct Classification {
    assessment: LauncherAssessment,
    confidence: f32,
    evidence: Vec<String>,
    likely_handoff_target: Option<String>,
    entrypoint_clues: Vec<String>,
    execution_reality_notes: Vec<String>,
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

pub(crate) fn collect_report(file: &Path) -> DynResult<LauncherReport> {
    Ok(build_report(
        file,
        r2::function_list(file).map_err(|e| format!("function_list: {e}")),
        r2::linked_libraries(file).map_err(|e| format!("linked_libraries: {e}")),
        r2::entrypoint_disassembly(file, 40).map_err(|e| format!("entrypoint_disassembly: {e}")),
    ))
}

fn build_report(
    file: &Path,
    functions: Result<Vec<FunctionInfo>, String>,
    libraries: Result<Vec<String>, String>,
    entrypoint: Result<String, String>,
) -> LauncherReport {
    let mut evidence_notes = vec![crate::adapter_routing::adapter_plan_note(
        file,
        QueryKind::LauncherClassification,
    )];

    let functions = match functions {
        Ok(functions) => functions,
        Err(err) => {
            evidence_notes.push(format!(
                "function complexity evidence could not be collected cleanly: {err}"
            ));
            Vec::new()
        }
    };

    let libraries = match libraries {
        Ok(libraries) => libraries,
        Err(err) => {
            evidence_notes.push(format!(
                "linked-library evidence could not be collected cleanly: {err}"
            ));
            Vec::new()
        }
    };

    let entrypoint = match entrypoint {
        Ok(entrypoint) => entrypoint,
        Err(err) => {
            evidence_notes.push(format!(
                "entrypoint disassembly could not be collected cleanly: {err}"
            ));
            String::new()
        }
    };

    let classification = classify_launcher(file, &functions, &libraries, &entrypoint);
    LauncherReport {
        binary: file.display().to_string(),
        assessment: classification.assessment,
        confidence: classification.confidence,
        evidence: classification.evidence,
        evidence_notes,
        likely_handoff_target: classification.likely_handoff_target,
        entrypoint_clues: classification.entrypoint_clues,
        execution_reality_notes: classification.execution_reality_notes,
    }
}

fn classify_launcher(
    file: &Path,
    functions: &[FunctionInfo],
    libraries: &[String],
    entrypoint: &str,
) -> Classification {
    let entrypoint_clues = extract_entrypoint_clues(entrypoint);
    let non_runtime_libraries = filter_non_runtime_libraries(libraries);
    let inferred_handoff_target =
        infer_handoff_target(file, &entrypoint_clues, &non_runtime_libraries);

    let mut evidence = Vec::new();
    let mut notes = Vec::new();
    let mut thin_score = 0u32;
    let mut substantive_score = 0u32;

    let max_cc = functions
        .iter()
        .map(|f| f.cyclomatic_complexity)
        .max()
        .unwrap_or(0);
    let high_complexity_count = functions
        .iter()
        .filter(|f| f.cyclomatic_complexity >= 10)
        .count();

    if !functions.is_empty() && functions.len() <= 20 {
        thin_score += 3;
        evidence.push(format!(
            "Only {} total functions detected, which is small for a full implementation.",
            functions.len()
        ));
    } else if functions.len() >= 60 {
        substantive_score += 3;
        evidence.push(format!(
            "{} total functions detected, suggesting substantial internal logic.",
            functions.len()
        ));
    }

    if max_cc > 0 && max_cc <= 3 {
        thin_score += 2;
        evidence.push(format!(
            "Maximum cyclomatic complexity is {max_cc}, indicating trivial internal control flow."
        ));
    } else if max_cc >= 15 {
        substantive_score += 3;
        evidence.push(format!(
            "Maximum cyclomatic complexity is {max_cc}, indicating deeper internal logic."
        ));
    }

    if high_complexity_count >= 3 {
        substantive_score += 2;
        evidence.push(format!(
            "{high_complexity_count} functions have cyclomatic complexity >= 10."
        ));
    }

    if !entrypoint_clues.is_empty() {
        thin_score += 2;
        evidence.push(format!(
            "Entrypoint exposes bootstrap/handoff clues: {}.",
            entrypoint_clues.join(", ")
        ));
    }

    if !non_runtime_libraries.is_empty() {
        thin_score += 1;
        evidence.push(format!(
            "Linked dependencies include non-runtime libraries/frameworks: {}.",
            non_runtime_libraries.join(", ")
        ));
    }

    let assessment = if thin_score >= 5 && thin_score >= substantive_score + 2 {
        LauncherAssessment::LikelyThinLauncher
    } else if substantive_score >= 5 && substantive_score >= thin_score + 2 {
        LauncherAssessment::LikelySubstantiveBinary
    } else {
        LauncherAssessment::Inconclusive
    };

    let likely_handoff_target = match assessment {
        LauncherAssessment::LikelyThinLauncher | LauncherAssessment::Inconclusive => {
            inferred_handoff_target.clone()
        }
        LauncherAssessment::LikelySubstantiveBinary => None,
    };

    if assessment == LauncherAssessment::LikelyThinLauncher {
        for lib in &non_runtime_libraries {
            if let Some(candidate) = resolve_linked_target(file, lib) {
                if !candidate.exists() {
                    notes.push(format!(
                        "Linked target is referenced but not present as a normal on-disk file relative to the inferred runtime root: {}.",
                        candidate.display()
                    ));
                }
            }
        }
    }

    let confidence = confidence_from_scores(thin_score, substantive_score, &assessment);

    Classification {
        assessment,
        confidence,
        evidence,
        likely_handoff_target,
        entrypoint_clues,
        execution_reality_notes: notes,
    }
}

fn confidence_from_scores(
    thin_score: u32,
    substantive_score: u32,
    assessment: &LauncherAssessment,
) -> f32 {
    let diff = thin_score.abs_diff(substantive_score) as f32;
    let base = match assessment {
        LauncherAssessment::LikelyThinLauncher | LauncherAssessment::LikelySubstantiveBinary => {
            0.55
        }
        LauncherAssessment::Inconclusive => 0.35,
    };
    (base + (diff * 0.08)).clamp(0.0, 0.99)
}

fn infer_handoff_target(
    file: &Path,
    entrypoint_clues: &[String],
    non_runtime_libraries: &[String],
) -> Option<String> {
    let ranked = rank_downstream_candidates(file, non_runtime_libraries);
    if let Some(candidate) = ranked.into_iter().max_by(|left, right| {
        adjusted_candidate_score(left, entrypoint_clues)
            .cmp(&adjusted_candidate_score(right, entrypoint_clues))
            .then_with(|| left.path.cmp(&right.path).reverse())
    }) {
        return Some(candidate.path.display().to_string());
    }
    entrypoint_clues.first().cloned()
}

fn adjusted_candidate_score(
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

fn render_text_report(report: &LauncherReport) {
    println!("=== Launcher Identification ===\n");
    println!("Assessment");
    println!(
        "  {:?} (confidence {:.2})",
        report.assessment, report.confidence
    );
    println!();

    println!("Evidence");
    if report.evidence.is_empty() {
        println!("  (none)");
    } else {
        for item in &report.evidence {
            println!("  - {item}");
        }
    }
    println!();

    if !report.evidence_notes.is_empty() {
        println!("Evidence collection notes");
        for note in &report.evidence_notes {
            println!("  - {note}");
        }
        println!();
    }

    println!("Likely handoff target");
    match &report.likely_handoff_target {
        Some(target) => println!("  {target}"),
        None => println!("  (none inferred)"),
    }
    println!();

    if !report.execution_reality_notes.is_empty() {
        println!("Execution reality notes");
        for note in &report.execution_reality_notes {
            println!("  - {note}");
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(name: &str, cc: u64) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            address: 0,
            size: 32,
            basic_blocks: cc.max(1),
            cyclomatic_complexity: cc,
        }
    }

    #[test]
    fn thin_launcher_classification_prefers_small_bootstrap_binary() {
        let functions = vec![
            func("main", 1),
            func("fcn.bootstrap", 1),
            func("fcn.start", 1),
        ];
        let libraries = vec![
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/usr/lib/libobjc.A.dylib".to_string(),
        ];
        let entrypoint = r#"
0x100000758      a01a40f9       ldr x0, [x21, 0x30]
; reloc.ExampleStreamManager
0x10000075c      91000094       bl fcn.1000009a0
"#;

        let classification = classify_launcher(
            Path::new("/tmp/example-rootfs/usr/libexec/service-launcher"),
            &functions,
            &libraries,
            entrypoint,
        );

        assert_eq!(
            classification.assessment,
            LauncherAssessment::LikelyThinLauncher
        );
        assert_eq!(
            classification.likely_handoff_target,
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .into()
            )
        );
        assert!(classification
            .entrypoint_clues
            .contains(&"ExampleStreamManager".to_string()));
    }

    #[test]
    fn substantive_classification_prefers_large_complex_binary() {
        let functions = vec![
            func("main", 4),
            func("parse_request", 22),
            func("dispatch_handler", 18),
            func("validate_payload", 14),
            func("crypto_path", 11),
        ]
        .into_iter()
        .chain((0..80).map(|i| func(&format!("f{i}"), 2)))
        .collect::<Vec<_>>();
        let classification =
            classify_launcher(Path::new("/tmp/rootfs/usr/sbin/httpd"), &functions, &[], "");

        assert_eq!(
            classification.assessment,
            LauncherAssessment::LikelySubstantiveBinary
        );
    }

    #[test]
    fn small_binary_with_single_complex_function_stays_inconclusive() {
        let functions = vec![
            func("main", 2),
            func("parse_request", 18),
            func("helper", 1),
            func("helper2", 1),
            func("helper3", 1),
        ];

        let classification = classify_launcher(
            Path::new("/tmp/rootfs/usr/libexec/small-agent"),
            &functions,
            &[],
            "",
        );

        assert_eq!(classification.assessment, LauncherAssessment::Inconclusive);
    }

    #[test]
    fn thin_launcher_prefers_clue_aligned_downstream_candidate() {
        let functions = vec![func("main", 1), func("bootstrap", 1)];
        let libraries = vec![
            "/System/Library/PrivateFrameworks/OtherKit.framework/OtherKit".to_string(),
            "/System/Library/PrivateFrameworks/ExampleStreamManager.framework/ExampleStreamManager"
                .to_string(),
        ];
        let entrypoint = r#"
; reloc.ExampleStreamManager
; sym.imp.dispatch_main
"#;

        let classification = classify_launcher(
            Path::new("/tmp/example-rootfs/usr/libexec/service-launcher"),
            &functions,
            &libraries,
            entrypoint,
        );

        assert_eq!(
            classification.likely_handoff_target.as_deref(),
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleStreamManager.framework/ExampleStreamManager"
            )
        );
    }

    #[test]
    fn build_report_keeps_working_when_function_evidence_fails() {
        let libraries = vec![
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
        ];
        let entrypoint = r#"
; reloc.ExampleStreamManager
; sym.imp.dispatch_main
"#;

        let report = build_report(
            Path::new("/tmp/example-rootfs/usr/libexec/service-launcher"),
            Err("r2 aflj failed".to_string()),
            Ok(libraries),
            Ok(entrypoint.to_string()),
        );

        assert_eq!(report.assessment, LauncherAssessment::Inconclusive);
        assert!(
            report
                .evidence_notes
                .iter()
                .any(|note| note
                    .contains("function complexity evidence could not be collected cleanly")),
            "expected degraded function evidence to be preserved in the report"
        );
        assert_eq!(
            report.likely_handoff_target.as_deref(),
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
            )
        );
    }
}
