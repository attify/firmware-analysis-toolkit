use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0xCAFEBABE;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xff) as u8);
    }
    out
}

#[test]
fn fat_cli_shows_inspect_envelope_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "envelope", "--help"])
        .output()
        .expect("fat inspect envelope help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("envelope"));
    assert!(stdout.contains("--file"));
    assert!(stdout.contains("evidence-first"));
    assert!(!stdout.contains("decrypt-first"));
}

#[test]
fn fat_cli_shows_detect_encryption_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["detect-encryption", "--help"])
        .output()
        .expect("fat detect-encryption help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("detect-encryption"));
    assert!(stdout.contains("--file"));
}

#[test]
fn fat_inspect_envelope_reports_opaque_wrapper_evidence() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            blob.to_str().expect("blob path"),
        ])
        .output()
        .expect("fat inspect envelope runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Envelope analysis",
        "Opaque wrapper",
        "Entropy",
        "Duplicate 16-byte blocks",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert_eq!(
        stdout.matches("Opaque wrapper likely").count(),
        1,
        "classification should be rendered once, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("ECB unlikely:"),
        "ECB interpretation must not be rendered as evidence, got:\n{stdout}"
    );
}

#[test]
fn fat_detect_encryption_reports_envelope_characteristics() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "detect-encryption",
            "--file",
            blob.to_str().expect("blob path"),
        ])
        .output()
        .expect("fat detect-encryption runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Envelope analysis"),
        "expected envelope output, got:\n{stdout}"
    );
}

#[test]
fn fat_compare_with_reference_reports_shared_prefix() {
    let dir = tempdir().expect("tempdir");
    let encrypted = dir.path().join("left.bin");
    let reference = dir.path().join("right.bin");

    let mut encrypted_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    encrypted_bytes.extend_from_slice(&pseudo_random_bytes(2048));
    let mut reference_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    reference_bytes.extend_from_slice(&[0x77; 2048]);
    std::fs::write(&encrypted, encrypted_bytes).expect("encrypted");
    std::fs::write(&reference, reference_bytes).expect("reference");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "compare",
            "--encrypted",
            encrypted.to_str().expect("encrypted path"),
            "--reference",
            reference.to_str().expect("reference path"),
        ])
        .output()
        .expect("fat compare runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Shared prefix"),
        "expected shared-prefix evidence, got:\n{stdout}"
    );
}

#[test]
fn fat_compare_help_treats_reference_as_oracle_not_proof() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["compare", "--help"])
        .output()
        .expect("fat compare help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("oracle"),
        "expected oracle wording in compare help, got:\n{stdout}"
    );
    assert!(
        stdout.contains("not as proof"),
        "expected compare help to say reference comparison is not proof, got:\n{stdout}"
    );
}

#[test]
fn fat_inspect_envelope_reference_mode_reports_shared_prefix() {
    let dir = tempdir().expect("tempdir");
    let left = dir.path().join("left.bin");
    let right = dir.path().join("right.bin");

    let mut left_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    left_bytes.extend_from_slice(&pseudo_random_bytes(2048));
    let mut right_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    right_bytes.extend_from_slice(&[0x77; 2048]);
    std::fs::write(&left, left_bytes).expect("left");
    std::fs::write(&right, right_bytes).expect("right");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            left.to_str().expect("left path"),
            "--reference",
            right.to_str().expect("right path"),
        ])
        .output()
        .expect("fat inspect envelope reference runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Shared prefix"),
        "expected shared-prefix evidence, got:\n{stdout}"
    );
}

#[test]
fn fat_inspect_envelope_json_exposes_schema_version() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            blob.to_str().expect("blob path"),
            "--json",
        ])
        .output()
        .expect("fat inspect envelope json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(
        report
            .get("schema_version")
            .and_then(|value| value.as_str()),
        Some("envelope-analysis/v1"),
        "missing or unexpected schema_version: {report}"
    );
}

#[test]
fn fat_inspect_envelope_detects_shared_plaintext_header_with_opaque_payload() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("wrapped.bin");

    let mut bytes = vec![0x55, 0xAA, 0x01, 0x02];
    bytes.extend_from_slice(&[0x10; 28]);
    bytes.extend_from_slice(&pseudo_random_bytes(8192));
    std::fs::write(&blob, bytes).expect("wrapped blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            blob.to_str().expect("blob path"),
        ])
        .output()
        .expect("fat inspect envelope runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Opaque wrapper likely",
        "Likely plaintext header span: 0x20",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_envelope_json_is_evidence_only() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            blob.to_str().expect("blob path"),
            "--json",
        ])
        .output()
        .expect("fat inspect envelope json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert!(
        report.get("classification").is_some(),
        "missing classification: {report}"
    );
    assert!(
        report.get("confidence").is_some(),
        "missing confidence: {report}"
    );
    assert!(
        report.get("recommendation").is_none(),
        "unexpected recommendation: {report}"
    );
    assert!(
        report.get("ecb_assessment").is_some(),
        "missing ecb_assessment: {report}"
    );
    assert!(report.get("reason").is_some(), "missing reason: {report}");
    assert!(
        report.get("evidence").is_some(),
        "missing evidence: {report}"
    );
}
