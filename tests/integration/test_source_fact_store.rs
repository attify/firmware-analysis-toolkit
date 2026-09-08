use fat_query::adapters::source_clang_facts::{
    maybe_analyze_source_tree_with_options, SourceAnalysisOptions,
};
use fat_query::adapters::traits::ExecutionMode;
use fat_query::planner::ResourceBudgets;
use std::fs;

#[test]
fn source_fact_cache_round_trips_schema_versioned_reports() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("sample.mm");
    fs::write(
        &sample,
        r#"
int MakeBuffer(int x) { return x; }
void CopyBytes(int, int) {}
class TextureMtl {
public:
  void setPerSliceSubImage(int srcBytesPerImage, int pixelsDepthPitch)
  {
    auto buffer = MakeBuffer(pixelsDepthPitch);
    CopyBytes(buffer, srcBytesPerImage);
  }
};
"#,
    )
    .expect("write source");
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-target", "arm64-apple-darwin", "{}"]
}}]"#,
            root.display(),
            sample.display(),
            sample.display()
        ),
    )
    .expect("write compile commands");

    let bundle_dir = root.join("debug-bundle");
    let summary = maybe_analyze_source_tree_with_options(
        root,
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: Some(bundle_dir.clone()),
            budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
        },
    )
    .expect("analyze source tree")
    .expect("summary");
    assert_eq!(
        summary.cache.as_ref().expect("cache telemetry").status,
        fat_query::result::SourceFactCacheStatus::FreshWrite
    );

    let store_path = bundle_dir.join("source-facts.sqlite");
    let cache_key = summary
        .metadata
        .get("source_fact_cache_key")
        .expect("cache key metadata");
    let records =
        fat_query::store::load_source_fact_records(&store_path).expect("load source fact records");
    assert!(!records.is_empty());
    assert!(records.iter().any(|record| &record.cache_key == cache_key));
    assert!(records
        .iter()
        .all(|record| !record.fact_schema_version.is_empty()));

    let reused = maybe_analyze_source_tree_with_options(
        root,
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: Some(bundle_dir.clone()),
            budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
        },
    )
    .expect("reanalyze source tree")
    .expect("summary");
    assert_eq!(
        reused.cache.as_ref().expect("cache telemetry").status,
        fat_query::result::SourceFactCacheStatus::ReusedCachedReports
    );
    assert_eq!(
        reused.cache.as_ref().expect("cache telemetry").report_count,
        reused.reports.len()
    );
}
