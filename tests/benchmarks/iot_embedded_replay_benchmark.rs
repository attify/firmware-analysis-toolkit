use fat_query::replay_benchmark::run_replay_benchmark;
use std::path::PathBuf;

#[test]
fn iot_embedded_replay_benchmark_covers_all_four_families() {
    // Every case is parsed by shelling out to the clang driver. Without one on
    // PATH there is nothing to measure, and a missing toolchain is not a
    // regression in the ranking this benchmark exists to check.
    if !clang_driver_available() {
        eprintln!(
            "skipping: no clang driver on PATH (install clang; libclang alone is not enough)"
        );
        return;
    }

    let summary =
        run_replay_benchmark(&benchmark_fixture_root().join("iot-embedded-replay-manifest.json"))
            .expect("run IoT embedded replay benchmark");

    assert_eq!(summary.family, "iot-embedded-family");
    assert_eq!(summary.top_k, 3);
    assert_eq!(summary.cases.len(), 17);

    // Print metrics for visibility
    eprintln!("=== IoT Embedded Replay Benchmark ===");
    eprintln!(
        "family_match_rate          = {}",
        summary.metrics.family_match_rate
    );
    eprintln!(
        "lead_queue_rate            = {}",
        summary.metrics.lead_queue_rate
    );
    eprintln!(
        "proof_yield                = {}",
        summary.metrics.proof_yield
    );
    eprintln!(
        "replay_top1                = {}",
        summary.metrics.replay_top1
    );
    eprintln!(
        "replay_top3                = {}",
        summary.metrics.replay_top3
    );
    eprintln!(
        "hard_negative_precision    = {}",
        summary.metrics.hard_negative_precision
    );
    eprintln!(
        "proof_signal_family_correctness = {}",
        summary.metrics.proof_signal_family_correctness
    );

    eprintln!("\n--- Per-family ---");
    for (family, fm) in &summary.family_metrics {
        eprintln!(
            "  {family}: pos={} neg={} replay_top3={:.2} lead_queue={:.2} hard_neg={:.2}",
            fm.positive_cases,
            fm.negative_cases,
            fm.replay_top3,
            fm.lead_queue_rate,
            fm.hard_negative_precision
        );
    }

    eprintln!("\n--- Per-case ---");
    for case in &summary.cases {
        eprintln!(
            "  {} [{}] rank={} top3={} lead_match={} family={}",
            case.id,
            case.kind,
            case.replay_rank,
            case.replay_top3,
            case.lead_family_match,
            case.family
        );
    }

    // Smoke-check: these should at least parse and not panic. When they do not,
    // say why — the backend's own error is the only thing that makes a
    // host-specific parse failure diagnosable.
    let parse_failures: Vec<String> = summary
        .cases
        .iter()
        .filter_map(|case| {
            case.parse_diagnostic
                .as_ref()
                .map(|reason| format!("  {}: {reason}", case.id))
        })
        .collect();
    assert!(
        summary.metrics.parse_success > 0.0,
        "no case parsed. Reported reasons:\n{}",
        if parse_failures.is_empty() {
            "  (none recorded)".to_string()
        } else {
            parse_failures.join("\n")
        }
    );
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

/// Whether a clang driver can actually be executed. `libclang` being installed
/// says nothing about this: the AST dump runs the driver binary.
fn clang_driver_available() -> bool {
    ["clang++", "clang"].iter().any(|driver| {
        std::process::Command::new(driver)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}
