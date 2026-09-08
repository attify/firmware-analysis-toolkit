use crate::adapters::registry::default_registry;
use crate::adapters::traits::{ExecutionMode, QueryKind, QueryRequest};
use crate::codeql_db::discover_codeql_databases;
use crate::parser::Query;
use crate::target_detection::{detect_path, TargetKind};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    kind: &'static str,
}

impl PlanStep {
    pub fn kind_name(&self) -> &'static str {
        self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlan {
    pub steps: Vec<PlanStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetFailurePolicy {
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudgets {
    pub per_tu_timeout_ms: u64,
    pub max_pre_repair_depth: usize,
    pub max_post_repair_depth: usize,
    pub max_neighborhood_breadth: usize,
    pub max_vendored_neighbor_scan: usize,
    pub failure_policy: BudgetFailurePolicy,
}

impl ResourceBudgets {
    pub fn for_mode(mode: ExecutionMode) -> Self {
        match mode {
            ExecutionMode::Triage => Self {
                per_tu_timeout_ms: 5_000,
                max_pre_repair_depth: 1,
                max_post_repair_depth: 0,
                max_neighborhood_breadth: 3,
                max_vendored_neighbor_scan: 0,
                failure_policy: BudgetFailurePolicy::FailOpen,
            },
            ExecutionMode::Deep => Self {
                per_tu_timeout_ms: 20_000,
                max_pre_repair_depth: 2,
                max_post_repair_depth: 2,
                max_neighborhood_breadth: 10,
                max_vendored_neighbor_scan: 5,
                failure_policy: BudgetFailurePolicy::FailClosed,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePlanStep {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAnalysisPlan {
    pub target_kind: TargetKind,
    pub analysis_root: PathBuf,
    #[serde(default)]
    pub codeql_db_root: Option<PathBuf>,
    pub query_kind: QueryKind,
    pub mode: ExecutionMode,
    pub adapter_ids: Vec<String>,
    pub budgets: ResourceBudgets,
    pub stages: Vec<SourcePlanStep>,
    #[serde(default)]
    pub notes: Vec<String>,
}

pub fn build_plan(query: &Query) -> Result<QueryPlan, String> {
    if query.kind != "path" {
        return Err(format!("unsupported query kind: {}", query.kind));
    }
    Ok(QueryPlan {
        steps: vec![
            PlanStep {
                kind: "resolve_selectors",
            },
            PlanStep {
                kind: "evaluate_path",
            },
        ],
    })
}

pub fn build_source_analysis_plan(
    target_root: &Path,
    query_kind: QueryKind,
    mode: ExecutionMode,
) -> Result<SourceAnalysisPlan, String> {
    let detected = detect_path(target_root)?;
    let (analysis_root, codeql_db_root) = match detected.kind {
        TargetKind::SourceTree => (detected.path.clone(), None),
        TargetKind::CodeQlDatabase => resolve_codeql_analysis_root(&detected.path)?,
        _ => {
            return Err(format!(
                "source analysis planning requires a source tree or CodeQL database target, got {:?}",
                detected.kind
            ));
        }
    };

    let registry = default_registry();
    let query = QueryRequest::new(query_kind.clone());
    let base_plan = registry.plan(&detected, &query)?;
    let budgets = ResourceBudgets::for_mode(mode);
    let mut adapter_ids = base_plan
        .adapter_ids
        .into_iter()
        .filter(|id| {
            registry
                .descriptors()
                .iter()
                .find(|descriptor| descriptor.id == id)
                .map(|descriptor| descriptor.modes.contains(&mode))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    let has_objcpp = has_extension_under(&analysis_root, &["mm", "m"]);
    if has_objcpp && !adapter_ids.iter().any(|id| id == "source-clang-facts") {
        adapter_ids.push("source-clang-facts".into());
    }
    if !adapter_ids.iter().any(|id| id == "source-tree-sitter-c") {
        adapter_ids.insert(0, "source-tree-sitter-c".into());
    }

    let mut stages = vec![
        SourcePlanStep {
            kind: "detect_target".into(),
            detail: format!("detected {:?}", detected.kind),
        },
        SourcePlanStep {
            kind: "resolve_tu".into(),
            detail: "resolve TU spec and toolchain profile".into(),
        },
        SourcePlanStep {
            kind: "scan".into(),
            detail: "lightweight source scanner".into(),
        },
        SourcePlanStep {
            kind: "parse".into(),
            detail: "parser-backed source facts".into(),
        },
    ];
    let mut notes = vec![format!("mode={}", mode.as_str())];
    if let Some(db_root) = codeql_db_root.as_ref() {
        notes.push(format!("codeql-db={}", db_root.display()));
    }

    if has_objcpp {
        notes.push("objective-c++ sources detected; keep clang-backed facts in the plan".into());
    }

    if mode == ExecutionMode::Deep {
        stages.extend([
            SourcePlanStep {
                kind: "pre_repair".into(),
                detail: "pre-derive slice repair".into(),
            },
            SourcePlanStep {
                kind: "derive".into(),
                detail: "derive family-pack facts with evidence basis".into(),
            },
            SourcePlanStep {
                kind: "merge".into(),
                detail: "merge evidence across adapters".into(),
            },
            SourcePlanStep {
                kind: "replay_rank".into(),
                detail: "role-based replay matching and ranking".into(),
            },
            SourcePlanStep {
                kind: "roll_resolve".into(),
                detail: "resolve dependency-roll locality".into(),
            },
            SourcePlanStep {
                kind: "variant_hunt".into(),
                detail: "expand replay hits into family-scoped neighbors".into(),
            },
            SourcePlanStep {
                kind: "post_repair".into(),
                detail: "adequacy-driven re-expansion".into(),
            },
        ]);
    }

    Ok(SourceAnalysisPlan {
        target_kind: detected.kind,
        analysis_root,
        codeql_db_root,
        query_kind,
        mode,
        adapter_ids,
        budgets,
        stages,
        notes,
    })
}

fn resolve_codeql_analysis_root(path: &Path) -> Result<(PathBuf, Option<PathBuf>), String> {
    let candidates = discover_codeql_databases(path)?;
    let Some(candidate) = candidates.first() else {
        return Err(format!(
            "no CodeQL database metadata found under {}",
            path.display()
        ));
    };
    match candidate.primary_language.as_deref() {
        Some("cpp") | Some("python") => {}
        Some(language) => {
            return Err(format!(
                "unsupported CodeQL language for source analysis planning: {language}"
            ));
        }
        None => return Err("CodeQL database primaryLanguage missing".into()),
    }
    let Some(source_root) = candidate.source_root.as_ref() else {
        return Err(format!(
            "CodeQL database {} is missing sourceLocationPrefix",
            candidate.db_root.display()
        ));
    };
    if !source_root.is_dir() {
        return Err(format!(
            "CodeQL database {} points at missing sourceLocationPrefix {}",
            candidate.db_root.display(),
            source_root.display()
        ));
    }
    Ok((source_root.clone(), Some(candidate.db_root.clone())))
}

fn has_extension_under(path: &Path, extensions: &[&str]) -> bool {
    walkdir::WalkDir::new(path)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| {
                    extensions
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(ext))
                })
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triage_mode_allows_scanner_repair_fallback() {
        let budgets = ResourceBudgets::for_mode(ExecutionMode::Triage);
        assert!(
            budgets.max_pre_repair_depth >= 1,
            "triage mode must allow at least one level of scanner repair \
             so targets without compile_commands.json can produce leads"
        );
    }

    #[test]
    fn deep_mode_has_higher_repair_budget_than_triage() {
        let triage = ResourceBudgets::for_mode(ExecutionMode::Triage);
        let deep = ResourceBudgets::for_mode(ExecutionMode::Deep);
        assert!(
            deep.max_pre_repair_depth > triage.max_pre_repair_depth,
            "deep mode should have a strictly higher repair budget than triage"
        );
    }
}
