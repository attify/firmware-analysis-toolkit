use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0xA11C_E123;
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
fn fat_cli_shows_inspect_update_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "update", "--help"])
        .output()
        .expect("fat inspect update help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("update"));
    assert!(stdout.contains("--file"));
    assert!(stdout.contains("--rootfs"));
    assert!(stdout.contains("governing updater"));
}

#[test]
fn fat_inspect_update_combines_envelope_trust_and_crypto_views() {
    let firmware_dir = tempdir().expect("firmware dir");
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let firmware = firmware_dir.path().join("firmware.bin");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    std::fs::write(&firmware, pseudo_random_bytes(8192)).expect("firmware");

    let mut updater_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    updater_bytes.extend_from_slice(b"BgIAAA");
    updater_bytes.extend(std::iter::repeat_n(b'D', 220));
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), updater_bytes).expect("slpupgrade");
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
    printf '{"imports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"},{"name":"AES_ecb_encrypt"}]}'
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
            "inspect",
            "update",
            "--file",
            firmware.to_str().expect("firmware path"),
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
        .expect("fat inspect update runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Update workflow",
        "Envelope",
        "Trust path",
        "Crypto census",
        "Governing updater",
        "/sbin/slpupgrade",
        "Governing binary crypto",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
    for forbidden in ["Recommendation", "Next steps"] {
        assert!(
            !stdout.contains(forbidden),
            "expected evidence-only output without {forbidden}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_update_json_has_stable_composite_schema() {
    let firmware_dir = tempdir().expect("firmware dir");
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let firmware = firmware_dir.path().join("firmware.bin");
    let reference = firmware_dir.path().join("reference.bin");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let mut firmware_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    firmware_bytes.extend_from_slice(&pseudo_random_bytes(8192));
    let mut reference_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    reference_bytes.extend_from_slice(&[0x42; 8192]);
    std::fs::write(&firmware, firmware_bytes).expect("firmware");
    std::fs::write(&reference, reference_bytes).expect("reference");

    let mut updater_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    updater_bytes.extend_from_slice(b"BgIAAA");
    updater_bytes.extend(std::iter::repeat_n(b'E', 220));
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), updater_bytes).expect("slpupgrade");

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
            "inspect",
            "update",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--reference",
            reference.to_str().expect("reference path"),
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
        .expect("fat inspect update json runs");

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
        Some("inspect-update-report/v1"),
        "missing or unexpected schema_version: {report}"
    );
    assert!(
        report.get("firmware_file").is_some(),
        "missing firmware_file: {report}"
    );
    assert!(
        report.get("rootfs_path").is_some(),
        "missing rootfs_path: {report}"
    );
    assert!(
        report.get("envelope").is_some(),
        "missing envelope: {report}"
    );
    assert!(
        report.get("trust_path").is_some(),
        "missing trust_path: {report}"
    );
    for removed in ["recommendation", "workflow_recommendation", "next_steps"] {
        assert!(
            report.get(removed).is_none(),
            "unexpected field {removed}: {report}"
        );
    }
    assert!(
        report.get("crypto_census").is_some(),
        "missing crypto_census: {report}"
    );

    let envelope = report.get("envelope").expect("envelope");
    assert!(
        envelope.get("recommendation").is_none(),
        "unexpected envelope.recommendation: {envelope}"
    );

    let trust = report.get("trust_path").expect("trust_path");
    assert!(
        trust.get("governing_update_path").is_some(),
        "missing trust_path.governing_update_path: {trust}"
    );

    let crypto = report
        .get("governing_binary_crypto")
        .expect("governing_binary_crypto");
    assert!(
        crypto.get("trust_context").is_some(),
        "missing governing_binary_crypto.trust_context: {crypto}"
    );

    let census = report.get("crypto_census").expect("crypto_census");
    assert!(
        census.get("cluster_count").is_some(),
        "missing crypto_census.cluster_count: {census}"
    );
    assert!(
        census.get("governing_path_hit_clusters").is_some(),
        "missing crypto_census.governing_path_hit_clusters: {census}"
    );
    assert!(
        census.get("candidate_classifications").is_some(),
        "missing crypto_census.candidate_classifications: {census}"
    );
}

#[test]
fn fat_inspect_update_reports_census_summary_for_helper_only_rootfs() {
    let firmware_dir = tempdir().expect("firmware dir");
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let firmware = firmware_dir.path().join("firmware.bin");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");
    std::fs::write(&firmware, pseudo_random_bytes(4096)).expect("firmware");

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'I', 220));
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
            "inspect",
            "update",
            "--file",
            firmware.to_str().expect("firmware path"),
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
        .expect("fat inspect update json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let census = report.get("crypto_census").expect("crypto_census");
    assert!(
        census
            .get("cluster_count")
            .and_then(|value| value.as_u64())
            .is_some_and(|count| count >= 1),
        "expected at least one census cluster: {census}"
    );
    assert!(
        census
            .get("governing_path_hit_clusters")
            .and_then(|value| value.as_array())
            .map(|items| items.is_empty())
            .unwrap_or(false),
        "expected no governing-path hit clusters for helper-only rootfs: {census}"
    );
    assert!(
        census
            .get("summary")
            .and_then(|value| value.as_str())
            .is_some_and(|summary| summary.contains("helper")),
        "expected helper-oriented census summary: {census}"
    );
}

#[test]
fn fat_inspect_update_reports_out_of_path_census_summary() {
    let firmware_dir = tempdir().expect("firmware dir");
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let firmware = firmware_dir.path().join("firmware.bin");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/bin")).expect("usr bin");
    std::fs::write(&firmware, pseudo_random_bytes(4096)).expect("firmware");

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
            "inspect",
            "update",
            "--file",
            firmware.to_str().expect("firmware path"),
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
        .expect("fat inspect update json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let census = report.get("crypto_census").expect("crypto_census");
    assert!(
        census
            .get("governing_path_hit_clusters")
            .and_then(|value| value.as_array())
            .map(|items| items.is_empty())
            .unwrap_or(false),
        "expected no governing-path hit clusters for out-of-path rootfs: {census}"
    );
    assert!(
        census
            .get("candidate_classifications")
            .and_then(|value| value.as_array())
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.as_str().is_some_and(|value| value == "out-of-path"))
            }),
        "expected out-of-path classification in census summary: {census}"
    );
    assert!(
        census
            .get("summary")
            .and_then(|value| value.as_str())
            .is_some_and(|summary| {
                summary.contains("out-of-path") && !summary.contains("helper-only")
            }),
        "expected out-of-path census summary without helper-only wording: {census}"
    );
}
