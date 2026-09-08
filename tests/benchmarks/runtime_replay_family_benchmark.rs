use fat_query::replay_benchmark::run_replay_benchmark;
use std::path::PathBuf;

#[test]
fn runtime_replay_family_benchmark_reports_live_replay_and_ablation_metrics() {
    let summary =
        run_replay_benchmark(&benchmark_fixture_root().join("runtime_replay_manifest.json"))
            .expect("run replay benchmark");

    assert_eq!(summary.family, "fat-replay-family-architecture");
    assert_eq!(summary.top_k, 3);
    assert_eq!(summary.cases.len(), 12);
    assert!(summary.metrics.replay_top3 > summary.metrics.scanner_top3);
    assert!(summary.metrics.precision_at_3 >= 0.875);
    assert!(summary.metrics.variant_top3 > 0.0);
    assert!(summary.metrics.variant_top1 > 0.0);
    assert!(summary.metrics.sibling_top3 > 0.0);
    assert!(summary.metrics.lead_queue_rate > 0.0);
    assert!(summary.metrics.harvester_expansion_rate > 0.0);
    assert!(summary.metrics.harness_attempt_validity > 0.0);
    assert!(summary.metrics.proof_yield > 0.0);
    assert!(summary.metrics.average_effective_unique_attempt_count >= 1.0);
    assert!(summary.metrics.average_unique_resolved_command_count >= 1.0);
    assert!(summary.metrics.average_unique_shape_count >= 1.0);
    assert!(summary.metrics.binding_compression_rate >= 0.0);
    assert!(summary.metrics.family_match_rate > 0.0);
    assert!(summary.metrics.hard_negative_precision >= 0.75);
    assert!(summary.metrics.locality_blocked_correctness >= 0.0);
    assert!(summary.metrics.trigger_recipe_coverage > 0.0);
    assert!(summary.metrics.proof_signal_family_correctness > 0.0);
    assert_eq!(
        summary
            .family_metrics
            .get("lifetime-ownership")
            .expect("lifetime metrics")
            .hard_negative_precision,
        1.0
    );
    assert_eq!(
        summary
            .family_metrics
            .get("bounds-size-arithmetic")
            .expect("size metrics")
            .hard_negative_precision,
        1.0
    );
    assert_eq!(
        summary
            .family_metrics
            .get("gpu-protocol-order-lifecycle")
            .expect("protocol metrics")
            .family_match_rate,
        1.0
    );
    assert_eq!(
        summary
            .family_metrics
            .get("gpu-protocol-order-lifecycle")
            .expect("protocol metrics")
            .proof_signal_family_correctness,
        1.0
    );
    assert_eq!(
        summary
            .family_metrics
            .get("validation-policy")
            .expect("validation metrics")
            .family_match_rate,
        1.0
    );
    assert_eq!(
        summary
            .family_metrics
            .get("validation-policy")
            .expect("validation metrics")
            .proof_signal_family_correctness,
        1.0
    );
    assert!(
        summary
            .family_metrics
            .get("lifetime-ownership")
            .expect("lifetime metrics")
            .positive_cases
            >= 1
    );
    assert!(
        summary
            .family_metrics
            .get("dependency-roll-upstream-hidden")
            .expect("dependency-roll metrics")
            .positive_cases
            == 2
    );
    assert_eq!(
        summary
            .family_metrics
            .get("dependency-roll-upstream-hidden")
            .expect("dependency-roll metrics")
            .negative_cases,
        1
    );
    assert!(
        summary
            .family_metrics
            .get("gpu-protocol-order-lifecycle")
            .expect("protocol metrics")
            .positive_cases
            >= 1
    );
    assert!(
        summary
            .family_metrics
            .get("validation-policy")
            .expect("validation metrics")
            .positive_cases
            >= 1
    );
    assert!(summary.ablations.contains_key("scanner"));
    assert!(summary.ablations.contains_key("replay"));
    assert!(summary.ablations.contains_key("variant"));
    assert!(summary.ablations.contains_key("discovery_siblings"));
    assert!(summary.ablations.contains_key("vendored_expansion"));
    assert!(
        summary
            .cases
            .iter()
            .filter(|case| case.kind == "negative" && case.replay_top3)
            .count()
            <= 1
    );

    println!("family: {}", summary.family);
    println!("parse_success: {:.3}", summary.metrics.parse_success);
    println!(
        "tu_resolution_success: {:.3}",
        summary.metrics.tu_resolution_success
    );
    println!("replay_top1: {:.3}", summary.metrics.replay_top1);
    println!("replay_top3: {:.3}", summary.metrics.replay_top3);
    println!("scanner_top3: {:.3}", summary.metrics.scanner_top3);
    println!("precision_at_3: {:.3}", summary.metrics.precision_at_3);
    println!("variant_top1: {:.3}", summary.metrics.variant_top1);
    println!("variant_top3: {:.3}", summary.metrics.variant_top3);
    println!(
        "variant_precision_at_3: {:.3}",
        summary.metrics.variant_precision_at_3
    );
    println!("sibling_top1: {:.3}", summary.metrics.sibling_top1);
    println!("sibling_top3: {:.3}", summary.metrics.sibling_top3);
    println!("lead_queue_rate: {:.3}", summary.metrics.lead_queue_rate);
    println!(
        "harvester_expansion_rate: {:.3}",
        summary.metrics.harvester_expansion_rate
    );
    println!(
        "harness_attempt_validity: {:.3}",
        summary.metrics.harness_attempt_validity
    );
    println!(
        "average_effective_unique_attempt_count: {:.3}",
        summary.metrics.average_effective_unique_attempt_count
    );
    println!(
        "average_unique_resolved_command_count: {:.3}",
        summary.metrics.average_unique_resolved_command_count
    );
    println!(
        "average_unique_shape_count: {:.3}",
        summary.metrics.average_unique_shape_count
    );
    println!(
        "binding_compression_rate: {:.3}",
        summary.metrics.binding_compression_rate
    );
    println!("proof_yield: {:.3}", summary.metrics.proof_yield);
    println!(
        "family_match_rate: {:.3}",
        summary.metrics.family_match_rate
    );
    println!(
        "hard_negative_precision: {:.3}",
        summary.metrics.hard_negative_precision
    );
    println!(
        "vendored_locality_accuracy: {:.3}",
        summary.metrics.vendored_locality_accuracy
    );
    println!(
        "locality_blocked_correctness: {:.3}",
        summary.metrics.locality_blocked_correctness
    );
    println!(
        "trigger_recipe_coverage: {:.3}",
        summary.metrics.trigger_recipe_coverage
    );
    println!(
        "proof_signal_family_correctness: {:.3}",
        summary.metrics.proof_signal_family_correctness
    );
    for (stage, metrics) in &summary.ablations {
        println!(
            "ablation={} pos={} neg={} top1={:.3} top3={:.3} precision_at_3={:.3}",
            stage,
            metrics.positive_cases,
            metrics.negative_cases,
            metrics.top1,
            metrics.top3,
            metrics.precision_at_3,
        );
    }

    for case in &summary.cases {
        println!(
            "case={} family={} kind={} language={} locality={} vendored_scan={} vendored_lead={} parse={} tu={} replay_rank={} replay_top1={} replay_top3={} scanner_rank={} scanner_top3={} variant_rank={} variant_top3={} sibling_rank={} sibling_top3={} queued_leads={} harvester_expansions={} harness_attempts={} harness_attempt_valid={} proof_yield={} proof_outcome={} locality_blocked_correct={} lead_family_match={} trigger_recipe_coverage={} proof_signal_family_correctness={} replay_score={} variant_score={}",
            case.id,
            case.family,
            case.kind,
            case.language,
            case.locality,
            case.allow_vendored_scan,
            case.vendored_lead_present,
            case.parse_success,
            case.tu_resolution_success,
            case.replay_rank,
            case.replay_top1,
            case.replay_top3,
            case.scanner_rank,
            case.scanner_top3,
            case.variant_rank,
            case.variant_top3,
            case.sibling_rank,
            case.sibling_top3,
            case.queued_leads,
            case.harvester_expansions,
            case.harness_attempts,
            case.harness_attempt_valid,
            case.proof_yield,
            case.proof_outcome.as_deref().unwrap_or("none"),
            case.locality_blocked_correct,
            case.lead_family_match,
            case.trigger_recipe_coverage,
            case.proof_signal_family_correctness,
            case.replay_score,
            case.variant_score,
        );
    }
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
