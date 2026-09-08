use crate::adapters::source;
use crate::adapters::source_clang_facts;
use crate::adapters::traits::ExecutionMode;
use crate::derived;
use crate::fusion;
#[cfg(feature = "test-fixtures")]
use crate::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
use crate::planner;
use crate::replay;
use crate::roll_resolver;
use crate::slice_expander;
#[cfg(feature = "test-fixtures")]
use crate::store::InMemoryGraph;
use crate::variant_hunter;
use serde::Deserialize;
#[cfg(feature = "test-fixtures")]
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, serde::Serialize)]
pub struct PatchCheckResult {
    pub mode: String,
    pub required_call: String,
    pub reference_sites: Vec<String>,
    pub variant_candidates: Vec<String>,
    pub source_plan: crate::planner::SourceAnalysisPlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_analysis: Option<crate::result::SourceAnalysisSummary>,
    pub fused_source: crate::result::FusedSourceEvidence,
    pub derived: crate::result::DerivedAnalysis,
    pub slice_expansion: crate::slice_expander::SliceExpansionReport,
    pub locality: crate::result::RollResolution,
    pub replay: crate::result::ReplayAnalysis,
    pub variant_leads: Vec<crate::result::VariantLead>,
}

#[derive(Debug, Clone)]
pub struct PatchCheckOptions {
    pub mode: ExecutionMode,
    pub debug_bundle_dir: Option<std::path::PathBuf>,
}

impl Default for PatchCheckOptions {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FixtureMeta {
    patch_file: Option<String>,
}

#[cfg(feature = "test-fixtures")]
pub fn from_patch_fixture(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    let root = path.as_ref();
    let patch = read_patch(root)?;
    let reference_site = extract_reference_site(&patch).unwrap_or_else(|| "GoodOverride".into());
    let required_call = extract_required_call(&patch).unwrap_or_else(|| "enforcePermission".into());

    let mut attrs = BTreeMap::new();
    attrs.insert("reference_site".into(), reference_site.clone());
    attrs.insert("required_call".into(), required_call);

    Ok(InMemoryGraph::from_records(
        vec![
            NodeRecord {
                id: 0,
                kind: NodeKind::PatchSite,
                label: "patch reference".into(),
                attrs,
                provenance: Default::default(),
            },
            NodeRecord {
                id: 0,
                kind: NodeKind::Function,
                label: reference_site,
                attrs: BTreeMap::new(),
                provenance: Default::default(),
            },
        ],
        vec![EdgeRecord::new(EdgeKind::DerivedFromPatch, 0, 1)],
    ))
}

pub fn run_patch_check(path: impl AsRef<Path>) -> Result<PatchCheckResult, String> {
    run_patch_check_with_options(path, &PatchCheckOptions::default())
}

pub fn run_patch_check_with_options(
    path: impl AsRef<Path>,
    options: &PatchCheckOptions,
) -> Result<PatchCheckResult, String> {
    let root = path.as_ref();
    let patch = read_patch(root)?;
    let required_call = extract_required_call(&patch).unwrap_or_else(|| "enforcePermission".into());
    let reference_site = extract_reference_site(&patch).unwrap_or_else(|| "GoodOverride".into());
    let rule = format!("Every override binder method must call {required_call}()");
    let invariant = source::evaluate_invariant_rule(root, &rule)?;
    let source_plan = planner::build_source_analysis_plan(
        root,
        crate::adapters::traits::QueryKind::PatchInvariant,
        options.mode,
    )?;
    let analysis_options = source_clang_facts::SourceAnalysisOptions {
        mode: options.mode,
        debug_bundle_dir: options.debug_bundle_dir.clone(),
        budgets: Some(source_plan.budgets.clone()),
    };
    let analysis_root = source_plan.analysis_root.clone();
    let mut source_analysis = if let Some(codeql_db_root) = source_plan.codeql_db_root.as_ref() {
        source_clang_facts::maybe_analyze_codeql_database_with_options(
            &analysis_root,
            codeql_db_root,
            &analysis_options,
        )?
    } else {
        source_clang_facts::maybe_analyze_source_tree_with_options(
            &analysis_root,
            &analysis_options,
        )?
    };
    let repaired_report = if let Some(summary) = source_analysis.as_mut() {
        slice_expander::repair_source_analysis(&analysis_root, summary, &source_plan.budgets)?
    } else {
        None
    };
    let fused_source = fusion::fuse_source_analysis(source_analysis.as_ref());
    let derived = derived::derive_from_fused_source(&fused_source);
    let mut slice_expansion =
        slice_expander::evaluate_slice_expansion(source_analysis.as_ref(), &derived);
    slice_expansion.repaired_reports = repaired_report.iter().count();
    let locality = roll_resolver::resolve_roll_locality(&analysis_root)?;
    let baseline_candidates = invariant
        .violating
        .iter()
        .map(|site| site.site.clone())
        .collect::<Vec<_>>();
    let replay = replay::rank_replay_candidates(
        std::slice::from_ref(&reference_site),
        &fused_source,
        &derived,
        &baseline_candidates,
    );
    let variant_leads = variant_hunter::hunt_variants(
        &replay,
        &fused_source,
        &derived,
        &locality,
        &baseline_candidates,
        source_plan.budgets.max_neighborhood_breadth,
    );
    Ok(PatchCheckResult {
        mode: options.mode.as_str().into(),
        required_call,
        reference_sites: vec![reference_site],
        variant_candidates: baseline_candidates,
        source_plan,
        source_analysis,
        fused_source,
        derived,
        slice_expansion,
        locality,
        replay,
        variant_leads,
    })
}

fn read_patch(root: &Path) -> Result<String, String> {
    let meta_path = root.join("fixture.json");
    let meta_text = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("failed to read {}: {}", meta_path.display(), e))?;
    let meta: FixtureMeta =
        serde_json::from_str(&meta_text).map_err(|e| format!("invalid fixture meta: {e}"))?;
    let patch_name = meta.patch_file.unwrap_or_else(|| "patch.diff".into());
    let patch_path = root.join(patch_name);
    std::fs::read_to_string(&patch_path)
        .map_err(|e| format!("failed to read {}: {}", patch_path.display(), e))
}

fn extract_reference_site(diff: &str) -> Option<String> {
    for line in diff.lines() {
        let trimmed = line.trim_start_matches('+').trim();
        if trimmed.starts_with("void ") && trimmed.contains('(') {
            return trimmed
                .split('(')
                .next()
                .and_then(|prefix| prefix.split_whitespace().last())
                .map(ToOwned::to_owned);
        }
    }
    None
}

fn extract_required_call(diff: &str) -> Option<String> {
    for line in diff.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("+++") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('+') {
            let call = rest.trim();
            if !call.contains('(') {
                continue;
            }
            if let Some(name) = call.split('(').next() {
                let name = name.trim();
                if name != "void"
                    && !name.is_empty()
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}
