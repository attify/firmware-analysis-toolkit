use std::process::Command;

#[test]
fn fat_benchmark_replay_reports_phase2a_discovery_proof_metrics() {
    let manifest = format!(
        "{}/../../tests/fixtures/discovery/discovery-benchmark-smoke.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["benchmark", "replay", "--manifest", &manifest, "--json"])
        .output()
        .expect("fat benchmark replay runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"lead_queue_rate\""), "{stdout}");
    assert!(stdout.contains("\"harvester_expansion_rate\""), "{stdout}");
    assert!(stdout.contains("\"harness_attempt_validity\""), "{stdout}");
    assert!(stdout.contains("\"proof_yield\""), "{stdout}");
    assert!(stdout.contains("\"attempt_generation_rate\""), "{stdout}");
    assert!(
        stdout.contains("\"average_unique_attempt_count\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"average_effective_unique_attempt_count\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"average_unique_resolved_command_count\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"average_unique_shape_count\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"binding_compression_rate\""), "{stdout}");
    assert!(stdout.contains("\"no_signal_rate\""), "{stdout}");
    assert!(stdout.contains("\"first_signal_attempt_rank\""), "{stdout}");
    assert!(stdout.contains("\"proof_yield_per_lane\""), "{stdout}");
    assert!(stdout.contains("\"proof_yield_per_generator\""), "{stdout}");
    assert!(
        stdout.contains("\"locality_blocked_correctness\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"gpu-protocol-order-lifecycle\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"validation-policy\""), "{stdout}");
}
