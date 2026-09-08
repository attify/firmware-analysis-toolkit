use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(
    fixture: Option<&Path>,
    repo: Option<&Path>,
    rule: &str,
    mode: fat_query::adapters::traits::ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let target = fixture
        .or(repo)
        .ok_or("invariant query requires --fixture or --repo")?;
    let query_kind = fat_query::adapters::traits::QueryKind::Invariant;
    let source_plan = fat_query::planner::build_source_analysis_plan(target, query_kind, mode)
        .map_err(|e| format!("source planning failed: {e}"))?;
    let analysis_root = source_plan.analysis_root.clone();
    let mut result = fat_query::adapters::source::evaluate_invariant_rule(&analysis_root, rule)
        .map_err(|e| format!("invariant query failed: {e}"))?;
    let source_options = fat_query::adapters::source_clang_facts::SourceAnalysisOptions {
        mode,
        debug_bundle_dir: debug_bundle_dir.map(|path| path.to_path_buf()),
        budgets: Some(source_plan.budgets.clone()),
    };
    let mut source_analysis = if let Some(codeql_db_root) = source_plan.codeql_db_root.as_ref() {
        fat_query::adapters::source_clang_facts::maybe_analyze_codeql_database_with_options(
            &analysis_root,
            codeql_db_root,
            &source_options,
        )
    } else {
        fat_query::adapters::source_clang_facts::maybe_analyze_source_tree_with_options(
            &analysis_root,
            &source_options,
        )
    }
    .map_err(|e| format!("source analysis failed: {e}"))?;
    let repaired_report = if let Some(summary) = source_analysis.as_mut() {
        fat_query::slice_expander::repair_source_analysis(
            &analysis_root,
            summary,
            &source_plan.budgets,
        )
        .map_err(|e| format!("slice repair failed: {e}"))?
    } else {
        None
    };
    let fused_source = fat_query::fusion::fuse_source_analysis(source_analysis.as_ref());
    let derived = fat_query::derived::derive_from_fused_source(&fused_source);
    let mut slice_expansion =
        fat_query::slice_expander::evaluate_slice_expansion(source_analysis.as_ref(), &derived);
    slice_expansion.repaired_reports = repaired_report.iter().count();
    let locality = fat_query::roll_resolver::resolve_roll_locality(&analysis_root)
        .map_err(|e| format!("roll resolution failed: {e}"))?;
    let replay = fat_query::replay::rank_replay_candidates(
        &result
            .violating
            .iter()
            .map(|site| site.site.clone())
            .collect::<Vec<_>>(),
        &fused_source,
        &derived,
        &result
            .violating
            .iter()
            .map(|site| site.site.clone())
            .collect::<Vec<_>>(),
    );
    let violating_sites = result
        .violating
        .iter()
        .map(|site| site.site.clone())
        .collect::<Vec<_>>();
    let variant_leads = fat_query::variant_hunter::hunt_variants(
        &replay,
        &fused_source,
        &derived,
        &locality,
        &violating_sites,
        1,
    );
    let mut discovery_leads =
        fat_query::discovery::build_discovery_leads(&fused_source, &derived, &locality);
    fat_query::discovery::populate_sibling_candidates(
        &mut discovery_leads,
        &fused_source,
        &derived,
        &locality,
        3,
    );
    result.source_plan = Some(source_plan);
    result.source_analysis = source_analysis;
    result.fused_source = Some(fused_source);
    result.derived = Some(derived);
    result.slice_expansion = Some(slice_expansion);
    result.locality = Some(locality);
    result.replay = Some(replay);
    result.variant_leads = Some(variant_leads);
    result.discovery_leads = Some(discovery_leads);

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let palette = crate::style::Palette::stdout();
        println!("{}", palette.kv("rule", &result.rule));
        println!(
            "{}",
            palette.kv(
                "satisfying",
                palette.good(result.satisfying.len().to_string())
            )
        );
        println!(
            "{}",
            palette.kv("violating", palette.bad(result.violating.len().to_string()))
        );
        println!(
            "{}",
            palette.kv("unknown", palette.warn(result.unknown.len().to_string()))
        );
        if let Some(plan) = &result.source_plan {
            println!("{}", palette.kv("mode", palette.accent(plan.mode.as_str())));
            println!(
                "{}",
                palette.kv("adapters", palette.info(plan.adapter_ids.join(", ")))
            );
            println!(
                "{}",
                palette.kv(
                    "budget/per_tu_timeout_ms",
                    plan.budgets.per_tu_timeout_ms.to_string()
                )
            );
        }
        if let Some(summary) = &result.source_analysis {
            println!(
                "{}",
                palette.kv(
                    "source_reports",
                    palette.accent(summary.reports.len().to_string())
                )
            );
            for report in &summary.reports {
                let key = format!("backend/{}", report.backend.as_str());
                println!(
                    "{}",
                    palette.kv(
                        &key,
                        format!(
                            "{} methods, {} calls [{} observed / {} inferred]",
                            report.methods.len(),
                            report.calls.len(),
                            report.diagnostics.observed.len(),
                            report.diagnostics.inferred.len(),
                        ),
                    )
                );
                println!(
                    "{}",
                    palette.kv(
                        &format!("provenance/{}", report.backend.as_str()),
                        format!(
                            "tu={} toolchain={}",
                            report.tu_spec_hash, report.toolchain_profile_hash
                        ),
                    )
                );
            }
            if !summary.merged_observed.is_empty() {
                println!(
                    "{}",
                    palette.kv("observed", summary.merged_observed.join(" | "))
                );
            }
            if !summary.merged_inferred.is_empty() {
                println!(
                    "{}",
                    palette.kv("inferred", summary.merged_inferred.join(" | "))
                );
            }
            if let Some(cache) = &summary.cache {
                println!(
                    "{}",
                    palette.kv(
                        "cache/source-facts",
                        format!(
                            "{} reports={} key={} [{}]",
                            cache_status_label(&cache.status),
                            cache.report_count,
                            cache.cache_key,
                            cache.backend_kinds.join(", ")
                        ),
                    )
                );
            }
        }
        if let Some(locality) = &result.locality {
            println!(
                "{}",
                palette.kv(
                    "locality",
                    format!(
                        "{:?} vendored_scan={}",
                        locality.locality, locality.allow_vendored_scan
                    ),
                )
            );
        }
        if let Some(replay) = &result.replay {
            println!(
                "{}",
                palette.kv("replay_candidates", replay.candidates.len().to_string())
            );
            if let Some(top) = replay.candidates.first() {
                println!(
                    "{}",
                    palette.kv(
                        "replay_top1",
                        format!(
                            "{} ({})",
                            top.symbol,
                            top.matched_roles
                                .iter()
                                .map(|role| role.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                );
            }
        }
        if let Some(variant_leads) = &result.variant_leads {
            println!(
                "{}",
                palette.kv("variant_candidates", variant_leads.len().to_string())
            );
            if let Some(top) = variant_leads.first() {
                println!(
                    "{}",
                    palette.kv("variant_top1", format!("{} ({})", top.symbol, top.score))
                );
            }
        }
        if let Some(discovery_leads) = &result.discovery_leads {
            println!(
                "{}",
                palette.kv("discovery_candidates", discovery_leads.len().to_string())
            );
            if let Some(top) = discovery_leads.first() {
                println!(
                    "{}",
                    palette.kv(
                        "discovery_top1",
                        format!("{} ({})", top.symbol, top.family.as_str())
                    )
                );
            }
        }
    }
    Ok(())
}

fn cache_status_label(status: &fat_query::result::SourceFactCacheStatus) -> &'static str {
    match status {
        fat_query::result::SourceFactCacheStatus::FreshWrite => "fresh-write",
        fat_query::result::SourceFactCacheStatus::ReusedCachedReports => "reused-cached-reports",
        fat_query::result::SourceFactCacheStatus::Unavailable => "unavailable",
    }
}
