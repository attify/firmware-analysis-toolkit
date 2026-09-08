use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn is_stable_classification(value: &str) -> bool {
    matches!(
        value,
        "governing-updater"
            | "supporting-boundary"
            | "supporting-crypto-lib"
            | "helper-only"
            | "out-of-path"
    )
}

fn is_stable_confidence(value: &str) -> bool {
    matches!(
        value,
        "confirmed" | "probable" | "possible" | "context-only"
    )
}

#[test]
fn fat_cli_shows_crypto_census_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["crypto-census", "--help"])
        .output()
        .expect("fat crypto-census help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("crypto-census"));
    assert!(stdout.contains("--rootfs"));
    assert!(stdout.contains("fingerprint"));
}

#[test]
fn fat_crypto_census_reports_reuse_clusters() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let shared_blob = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BgIAAA");
        bytes.extend(std::iter::repeat_n(b'F', 220));
        bytes
    };

    let mut updater_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    updater_bytes.extend_from_slice(&shared_blob);
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), updater_bytes).expect("slpupgrade");

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(&shared_blob);
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter.so"), helper_bytes)
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
            "crypto-census",
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
        .expect("fat crypto-census runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Crypto census",
        "fingerprint",
        "candidate classifications",
        "governing path hits",
        "/sbin/slpupgrade",
        "/usr/lib/libdecrypter.so",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    assert!(
        !stdout.contains("recommendation:"),
        "expected evidence-only output, got:\n{stdout}"
    );
}

#[test]
fn fat_crypto_census_json_exposes_cluster_fields() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let mut updater_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    updater_bytes.extend_from_slice(b"BgIAAA");
    updater_bytes.extend(std::iter::repeat_n(b'G', 220));
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), updater_bytes).expect("slpupgrade");

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'G', 220));
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter.so"), helper_bytes)
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
            "crypto-census",
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
        .expect("fat crypto-census json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert!(
        report.get("recommendation").is_none(),
        "unexpected report recommendation: {report}"
    );
    assert_eq!(
        report
            .get("schema_version")
            .and_then(|value| value.as_str()),
        Some("crypto-reuse-cluster/v1"),
        "missing or unexpected schema_version: {report}"
    );
    let clusters = report
        .get("clusters")
        .and_then(|value| value.as_array())
        .expect("clusters array");
    assert!(!clusters.is_empty(), "expected clusters in {report}");
    let cluster = &clusters[0];
    for needle in ["fingerprint", "artifact_type", "confidence"] {
        assert!(cluster.get(needle).is_some(), "missing {needle}: {cluster}");
    }
    assert!(
        cluster.get("recommendation").is_none(),
        "unexpected cluster recommendation: {cluster}"
    );
    assert!(
        cluster.get("candidate_classifications").is_some(),
        "missing candidate_classifications: {cluster}"
    );
    assert!(
        cluster
            .get("confidence")
            .and_then(|value| value.as_str())
            .is_some_and(is_stable_confidence),
        "expected bounded confidence taxonomy: {cluster}"
    );
    assert_eq!(
        cluster.get("confidence").and_then(|value| value.as_str()),
        Some("context-only"),
        "expected vendor blob confidence to be context-only: {cluster}"
    );
    let classifications = cluster
        .get("candidate_classifications")
        .and_then(|value| value.as_array())
        .expect("candidate_classifications array");
    assert!(
        classifications
            .iter()
            .all(|item| item.as_str().is_some_and(is_stable_classification)),
        "expected only stable classifications: {cluster}"
    );
    let occurrences = cluster
        .get("occurrences")
        .and_then(|value| value.as_array())
        .expect("occurrences array");
    assert!(!occurrences.is_empty(), "expected occurrences in {cluster}");
    let first = &occurrences[0];
    for needle in [
        "binary_path",
        "offset",
        "trust_path_relevance",
        "candidate_role",
        "candidate_classification",
    ] {
        assert!(first.get(needle).is_some(), "missing {needle}: {first}");
    }
    assert!(
        cluster.get("governing_path_hits").is_some(),
        "missing governing_path_hits: {cluster}"
    );
    assert!(
        cluster.get("trust_summary").is_some(),
        "missing trust_summary: {cluster}"
    );
}

#[test]
fn fat_crypto_census_reports_helper_only_and_out_of_path_clusters() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'H', 220));
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter.so"), helper_bytes)
        .expect("libdecrypter");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
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
            "crypto-census",
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
        .expect("fat crypto-census json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let clusters = report
        .get("clusters")
        .and_then(|value| value.as_array())
        .expect("clusters array");
    assert!(!clusters.is_empty(), "expected clusters in {report}");
    let cluster = &clusters[0];
    assert!(
        cluster
            .get("governing_path_hits")
            .and_then(|value| value.as_array())
            .map(|items| items.is_empty())
            .unwrap_or(false),
        "expected helper-only cluster without governing hits: {cluster}"
    );
    let classifications = cluster
        .get("candidate_classifications")
        .and_then(|value| value.as_array())
        .expect("candidate_classifications array");
    assert!(
        classifications
            .iter()
            .any(|item| item.as_str().is_some_and(|value| value == "helper-only")),
        "expected helper-only classification: {cluster}"
    );
    assert!(
        cluster
            .get("trust_summary")
            .and_then(|value| value.get("summary"))
            .and_then(|value| value.as_str())
            .is_some_and(|summary| summary.contains("helper")),
        "expected helper-oriented trust summary: {cluster}"
    );
}

#[test]
fn fat_crypto_census_groups_versioned_binaries_by_fingerprint() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let shared_blob = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BgIAAA");
        bytes.extend(std::iter::repeat_n(b'Z', 220));
        bytes
    };
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter_v1.so"), {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        bytes.extend_from_slice(&shared_blob);
        bytes
    })
    .expect("libdecrypter v1");
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter_v2.so"), {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        bytes.extend_from_slice(&shared_blob);
        bytes
    })
    .expect("libdecrypter v2");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:libdecrypter_v1.so| -ij:libdecrypter_v2.so)
    printf '{"imports":[{"name":"RSA_private_decrypt"}]}'
    ;;
  -lj:libdecrypter_v1.so| -lj:libdecrypter_v2.so)
    printf '{"libs":["libcrypto.so.1.0.0","libc.so.0"]}'
    ;;
  -Ej:libdecrypter_v1.so| -Ej:libdecrypter_v2.so)
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
            "crypto-census",
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
        .expect("fat crypto-census json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let clusters = report
        .get("clusters")
        .and_then(|value| value.as_array())
        .expect("clusters array");
    assert_eq!(clusters.len(), 1, "expected one grouped cluster: {report}");
    let cluster = &clusters[0];
    let occurrences = cluster
        .get("occurrences")
        .and_then(|value| value.as_array())
        .expect("occurrences array");
    assert_eq!(
        occurrences.len(),
        2,
        "expected two versioned occurrences: {cluster}"
    );
    assert!(
        cluster
            .get("candidate_classifications")
            .and_then(|value| value.as_array())
            .map(|items| {
                !items.is_empty()
                    && items
                        .iter()
                        .all(|item| item.as_str().is_some_and(is_stable_classification))
            })
            .unwrap_or(false),
        "expected candidate classifications in versioned grouping: {cluster}"
    );
}

#[test]
fn fat_crypto_census_reports_true_out_of_path_clusters() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/bin")).expect("usr bin");

    let mut odd_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    odd_bytes.extend_from_slice(b"BgIAAA");
    odd_bytes.extend(std::iter::repeat_n(b'Q', 220));
    std::fs::write(rootfs.join("usr/bin").join("oddtool"), odd_bytes).expect("oddtool");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:oddtool)
    printf '{"imports":[]}'
    ;;
  -lj:oddtool)
    printf '{"libs":["libc.so.0"]}'
    ;;
  -Ej:oddtool)
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
            "crypto-census",
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
        .expect("fat crypto-census json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let clusters = report
        .get("clusters")
        .and_then(|value| value.as_array())
        .expect("clusters array");
    assert_eq!(
        clusters.len(),
        1,
        "expected one out-of-path cluster: {report}"
    );
    let cluster = &clusters[0];
    let classifications = cluster
        .get("candidate_classifications")
        .and_then(|value| value.as_array())
        .expect("candidate_classifications array");
    assert!(
        classifications
            .iter()
            .any(|item| item.as_str().is_some_and(|value| value == "out-of-path")),
        "expected out-of-path classification: {cluster}"
    );
    assert!(
        cluster
            .get("trust_summary")
            .and_then(|value| value.get("summary"))
            .and_then(|value| value.as_str())
            .is_some_and(|summary| summary.contains("out-of-path")),
        "expected out-of-path summary: {cluster}"
    );
    assert!(
        cluster.get("recommendation").is_none(),
        "unexpected out-of-path recommendation: {cluster}"
    );
}
