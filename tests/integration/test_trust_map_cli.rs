use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn fat_cli_shows_trust_map_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["trust-map", "--help"])
        .output()
        .expect("fat trust-map help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("trust-map"));
    assert!(stdout.contains("--rootfs"));
    assert!(stdout.contains("which binary governs updates?"));
}

#[test]
fn fat_cli_shows_update_path_alias_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["update-path", "--help"])
        .output()
        .expect("fat update-path help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("update-path"));
    assert!(stdout.contains("--rootfs"));
}

#[test]
fn fat_trust_map_ranks_updater_above_crypto_helper() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    std::fs::write(
        rootfs.join("sbin").join("slpupgrade"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("slpupgrade");
    std::fs::write(
        rootfs.join("usr/lib").join("libsecurity.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("libsecurity");
    std::fs::write(
        rootfs.join("usr/lib").join("libdecrypter.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("libdecrypter");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:slpupgrade)
    printf '{"imports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"}]}'
    ;;
  -lj:slpupgrade)
    printf '{"libs":["libsecurity.so","libc.so.0"]}'
    ;;
  -Ej:slpupgrade)
    printf '{"exports":[]}'
    ;;
  -ij:libsecurity.so)
    printf '{"imports":[]}'
    ;;
  -lj:libsecurity.so)
    printf '{"libs":["libc.so.0"]}'
    ;;
  -Ej:libsecurity.so)
    printf '{"exports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"},{"name":"DES_ecb_encrypt"}]}'
    ;;
  -ij:libdecrypter.so)
    printf '{"imports":[{"name":"RSA_private_decrypt"}]}'
    ;;
  -lj:libdecrypter.so)
    printf '{"libs":["libcrypto.so.1.0.0","libc.so.0"]}'
    ;;
  -Ej:libdecrypter.so)
    printf '{"exports":[]}'
    ;;
  *)
    printf '{"imports":[],"exports":[],"libs":[]}'
    ;;
esac
"#;
    std::fs::write(&rabin2_path, script).expect("fake rabin2");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&rabin2_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&rabin2_path, perms).expect("chmod");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "trust-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat trust-map runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Governing update path",
        "/sbin/slpupgrade",
        "libsecurity.so",
        "libdecrypter.so",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_trust_map_json_includes_governing_path_and_evidence_tiers() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    std::fs::write(
        rootfs.join("sbin").join("slpupgrade"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("slpupgrade");
    std::fs::write(
        rootfs.join("usr/lib").join("libsecurity.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("libsecurity");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:slpupgrade)
    printf '{"imports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"}]}'
    ;;
  -lj:slpupgrade)
    printf '{"libs":["libsecurity.so","libc.so.0"]}'
    ;;
  -Ej:slpupgrade)
    printf '{"exports":[]}'
    ;;
  -ij:libsecurity.so)
    printf '{"imports":[]}'
    ;;
  -lj:libsecurity.so)
    printf '{"libs":["libc.so.0"]}'
    ;;
  -Ej:libsecurity.so)
    printf '{"exports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"}]}'
    ;;
  *)
    printf '{"imports":[],"exports":[],"libs":[]}'
    ;;
esac
"#;
    std::fs::write(&rabin2_path, script).expect("fake rabin2");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&rabin2_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&rabin2_path, perms).expect("chmod");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "trust-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat trust-map json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    for field in ["classification", "confidence", "reason", "evidence"] {
        assert!(report.get(field).is_some(), "missing {field}: {report}");
    }
    assert!(
        report.get("recommendation").is_none(),
        "unexpected recommendation: {report}"
    );
    assert!(
        report.get("governing_update_path").is_some(),
        "missing governing_update_path: {report}"
    );
    assert_eq!(
        report
            .get("schema_version")
            .and_then(|value| value.as_str()),
        Some("trust-path-analysis/v1"),
        "missing or unexpected schema_version: {report}"
    );
    let candidates = report
        .get("candidates")
        .and_then(|value| value.as_array())
        .expect("candidates array");
    assert!(!candidates.is_empty(), "expected candidates in {report}");
    let governing = report
        .get("governing_update_path")
        .expect("governing_update_path");
    assert!(
        governing.get("candidate_classification").is_some(),
        "missing candidate_classification: {governing}"
    );
    assert!(
        governing.get("tier_counts").is_some(),
        "missing tier_counts: {governing}"
    );
    assert!(
        governing.get("score").is_some(),
        "missing score: {governing}"
    );
    assert!(governing.get("why").is_some(), "missing why: {governing}");
    assert_eq!(
        governing
            .get("candidate_classification")
            .and_then(|value| value.as_str()),
        Some("governing-updater"),
        "expected governing-updater classification: {governing}"
    );
    let first = candidates
        .iter()
        .find(|candidate| {
            candidate
                .get("path")
                .and_then(|value| value.as_str())
                .is_some_and(|path| path.ends_with("libsecurity.so"))
        })
        .expect("expected libsecurity candidate");
    assert!(
        first.get("candidate_classification").is_some(),
        "missing candidate_classification: {first}"
    );
    assert!(
        first.get("tier_counts").is_some(),
        "missing tier_counts: {first}"
    );
    assert!(
        first.get("negative_evidence").is_some(),
        "missing negative_evidence: {first}"
    );
    assert!(first.get("score").is_some(), "missing score: {first}");
    assert!(
        first.get("path_confidence").is_some(),
        "missing path_confidence: {first}"
    );
    let evidence = first
        .get("evidence")
        .and_then(|value| value.as_array())
        .expect("evidence array");
    assert!(
        evidence
            .iter()
            .any(|item| item.get("tier").and_then(|v| v.as_str()).is_some()),
        "expected evidence tier in {first}"
    );
    assert_eq!(
        first
            .get("candidate_classification")
            .and_then(|value| value.as_str()),
        Some("supporting-boundary"),
        "expected supporting-boundary classification: {first}"
    );
    assert!(
        first
            .get("negative_evidence")
            .and_then(|value| value.as_array())
            .map(|items| !items.is_empty())
            .unwrap_or(false),
        "expected negative evidence: {first}"
    );
}
