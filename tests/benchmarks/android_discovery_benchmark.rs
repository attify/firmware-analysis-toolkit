use fat_query::android::benchmark::run_android_discovery_benchmark;
use std::path::PathBuf;

#[test]
fn android_discovery_benchmark_reports_family_hits_across_semantic_corpus() {
    let summary = run_android_discovery_benchmark(
        &benchmark_fixture_root().join("android_discovery_manifest.json"),
    )
    .expect("run android discovery benchmark");

    assert_eq!(summary.suite, "android-discovery-v1");
    assert_eq!(summary.top_k, 3);
    assert_eq!(summary.cases.len(), 6);
    assert_eq!(summary.pass_count, summary.cases.len());
    assert!(summary.family_hit_rate > 0.0);
    assert!(summary.positive_precision >= 0.8, "{summary:#?}");
}

fn benchmark_fixture_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("tests").join("fixtures").join("benchmarks");
        if candidate.exists() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "could not locate tests/fixtures/benchmarks from {}",
                env!("CARGO_MANIFEST_DIR")
            );
        }
    }
}
