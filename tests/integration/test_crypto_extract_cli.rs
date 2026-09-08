use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn fat_cli_shows_crypto_extract_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["crypto-extract", "--help"])
        .output()
        .expect("fat crypto-extract help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("crypto-extract"));
    assert!(stdout.contains("--file"));
    assert!(stdout.contains("fat trust-map"));
    assert!(stdout.contains("AES-128-hex"));
    assert!(stdout.contains("validated: true"));
    assert!(stdout.contains("ASCII-hex"));
}

#[test]
fn fat_crypto_extract_reports_trust_path_relevance_for_helper_library() {
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

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'A', 220));
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
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/lib/libdecrypter.so")
                .to_str()
                .expect("binary path"),
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
        .expect("fat crypto-extract runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Trust context",
        "relevance: low",
        "governing path: /sbin/slpupgrade",
        "not reachable from the governing updater path",
        "referenced_by: /usr/lib/libdecrypter.so",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_crypto_extract_reports_key_reuse_with_governing_updater() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let shared_blob = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BgIAAA");
        bytes.extend(std::iter::repeat_n(b'B', 220));
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
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/lib/libdecrypter.so")
                .to_str()
                .expect("binary path"),
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
        .expect("fat crypto-extract runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "key reuse: also seen in 1 other binary",
        "also_seen_in: /sbin/slpupgrade",
        "same key material also appears in the governing updater path",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_crypto_extract_json_reuses_trust_map_fields() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'C', 220));
    std::fs::write(
        rootfs.join("sbin").join("slpupgrade"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("slpupgrade");
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
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/lib/libdecrypter.so")
                .to_str()
                .expect("binary path"),
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
        .expect("fat crypto-extract json runs");

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
        Some("crypto-artifact-analysis/v1"),
        "missing or unexpected schema_version: {report}"
    );
    let embedded_keys = report
        .get("embedded_keys")
        .and_then(|value| value.as_array())
        .expect("embedded_keys array");
    assert!(
        embedded_keys.iter().all(|key| {
            matches!(
                key.get("confidence").and_then(|value| value.as_str()),
                Some("confirmed" | "probable" | "possible" | "context-only")
            )
        }),
        "expected bounded confidence taxonomy: {report}"
    );
    assert!(
        embedded_keys
            .first()
            .and_then(|key| key.get("confidence"))
            .and_then(|value| value.as_str())
            .is_some_and(|confidence| confidence == "context-only"),
        "expected vendor blob confidence to be context-only: {report}"
    );
    let context = report.get("trust_context").expect("trust_context");
    assert!(
        context.get("candidate_role").is_some(),
        "missing candidate_role: {context}"
    );
    assert!(
        context.get("candidate_classification").is_some(),
        "missing candidate_classification: {context}"
    );
    assert!(
        context.get("update_path_score").is_some(),
        "missing update_path_score: {context}"
    );
    assert!(context.get("score").is_some(), "missing score: {context}");
    assert!(
        context.get("path_confidence").is_some(),
        "missing path_confidence: {context}"
    );
    assert!(
        context.get("tier_counts").is_some(),
        "missing tier_counts: {context}"
    );
    assert!(
        context.get("negative_evidence").is_some(),
        "missing negative_evidence: {context}"
    );
    assert!(context.get("why").is_some(), "missing why: {context}");
    let evidence = context
        .get("evidence")
        .and_then(|value| value.as_array())
        .expect("evidence array");
    assert!(
        evidence
            .iter()
            .any(|item| item.get("tier").and_then(|value| value.as_str()).is_some()),
        "expected tiered evidence in {context}"
    );
    assert_eq!(
        context
            .get("candidate_classification")
            .and_then(|value| value.as_str()),
        Some("helper-only"),
        "expected helper-only classification: {context}"
    );
}

#[test]
fn fat_crypto_extract_reports_ascii_hex_aes_key_literals() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("usr/bin")).expect("usr bin");

    let mut binary = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    binary.resize(0x30, 0);
    binary.extend_from_slice(b"00112233445566778899aabbccddeeff");
    std::fs::write(rootfs.join("usr/bin").join("btgatt-server"), binary).expect("btgatt-server");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:btgatt-server)
    printf '{"imports":[{"name":"AES_set_encrypt_key"}]}'
    ;;
  -lj:btgatt-server)
    printf '{"libs":["libcrypto.so.1.0.0","libc.so.0"]}'
    ;;
  -Ej:btgatt-server)
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
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/bin/btgatt-server")
                .to_str()
                .expect("binary path"),
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
        .expect("fat crypto-extract json runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let embedded_keys = report
        .get("embedded_keys")
        .and_then(|value| value.as_array())
        .expect("embedded_keys array");
    assert_eq!(embedded_keys.len(), 1, "expected one hex key: {report}");
    let key = &embedded_keys[0];
    assert_eq!(
        key.get("key_type").and_then(|value| value.as_str()),
        Some("AES-128-hex")
    );
    assert_eq!(
        key.get("bit_length").and_then(|value| value.as_u64()),
        Some(128)
    );
    assert_eq!(
        key.get("confidence").and_then(|value| value.as_str()),
        Some("probable")
    );
    assert_eq!(
        key.get("validated").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        key.get("offset").and_then(|value| value.as_str()),
        Some("0x30")
    );

    let human_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/bin/btgatt-server")
                .to_str()
                .expect("binary path"),
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
        .expect("fat crypto-extract runs");

    assert!(
        human_output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        human_output.status,
        String::from_utf8_lossy(&human_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&human_output.stdout);
    assert!(stdout.contains("Embedded keys (1)"));
    assert!(stdout.contains("AES-128-hex  at 0x30"));
    assert!(stdout.contains("bits: 128"));
    assert!(stdout.contains("validated: yes"));
    assert!(stdout.contains("confidence: probable"));
    assert!(stdout.contains("referenced_by: /usr/bin/btgatt-server"));
    assert!(
        String::from_utf8_lossy(&human_output.stderr).is_empty(),
        "human output should not duplicate the analysis title on stderr"
    );
}

#[test]
fn fat_crypto_extract_writes_validated_rsa_pem_artifacts() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let keygen_dir = tempdir().expect("keygen dir");
    let output_dir = tempdir().expect("output dir");
    let rootfs = root.path();

    let private_pem = keygen_dir.path().join("fixture_private.pem");
    let public_pem = keygen_dir.path().join("fixture_public.pem");
    let gen_private = Command::new("openssl")
        .args([
            "genrsa",
            "-traditional",
            "-out",
            private_pem.to_str().expect("private pem"),
            "1024",
        ])
        .output()
        .expect("openssl genrsa runs");
    assert!(
        gen_private.status.success(),
        "openssl genrsa failed: {}",
        String::from_utf8_lossy(&gen_private.stderr)
    );
    let gen_public = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            private_pem.to_str().expect("private pem"),
            "-pubout",
            "-out",
            public_pem.to_str().expect("public pem"),
        ])
        .output()
        .expect("openssl rsa -pubout runs");
    assert!(
        gen_public.status.success(),
        "openssl rsa -pubout failed: {}",
        String::from_utf8_lossy(&gen_public.stderr)
    );

    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");
    let mut binary = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    binary.extend_from_slice(pem_body(&private_pem).as_bytes());
    binary.push(0);
    binary.extend_from_slice(pem_body(&public_pem).as_bytes());
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter.so"), binary).expect("libdecrypter");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:libdecrypter.so)
    printf '{"imports":[{"name":"RSA_private_decrypt"},{"name":"RSA_public_encrypt"}]}'
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
            "crypto-extract",
            "--file",
            rootfs
                .join("usr/lib/libdecrypter.so")
                .to_str()
                .expect("binary path"),
            "--output-dir",
            output_dir.path().to_str().expect("output dir"),
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
        .expect("fat crypto-extract runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("validated: yes"), "{stdout}");
    assert!(stdout.contains("wrote key artifacts: 2"), "{stdout}");

    let private_out = output_dir.path().join("rsa_private_1.pem");
    let public_out = output_dir.path().join("rsa_public_1.pem");
    let manifest = output_dir.path().join("crypto_extract_manifest.json");
    assert!(private_out.exists(), "missing {}", private_out.display());
    assert!(public_out.exists(), "missing {}", public_out.display());
    assert!(manifest.exists(), "missing {}", manifest.display());

    assert_valid_private_key(&private_out);
    assert_valid_public_key(&public_out);

    let manifest_json: Value =
        serde_json::from_slice(&std::fs::read(manifest).expect("manifest bytes"))
            .expect("manifest json");
    let artifacts = manifest_json
        .get("artifacts")
        .and_then(|value| value.as_array())
        .expect("artifacts array");
    assert_eq!(
        artifacts.len(),
        2,
        "expected two PEM artifacts: {manifest_json}"
    );
    assert!(artifacts.iter().all(|artifact| {
        artifact.get("validated").and_then(|value| value.as_bool()) == Some(true)
    }));
}

#[test]
fn fat_crypto_extract_writes_vendor_rsa_blob_artifacts() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let output_dir = tempdir().expect("output dir");
    let rootfs = root.path();
    let vendor_blob = concat!(
        "BgIAAACkAABSU0ExAAQAAAEAAQA1Ccyu85b65TawjvSQTaryGNk1gBJVn6kEIJq6m0hagsqkiy32v4ui41ucp6t",
        "Kfaoqb7AHDBq41dcEMgM6YBF2e3aRKQqZ6EwgCvAi3O81n7UbE97lD+FhvqlYxyqqMbSdvNmCiAoujheUs9DUaO",
        "CHq4K3McDxATMVOnCtT1H+wQ=="
    );

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    let mut binary = vec![0x7f, b'E', b'L', b'F', 0xff, 0xfe, 0xfd];
    binary.extend_from_slice(vendor_blob.as_bytes());
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), binary).expect("slpupgrade");

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
            "crypto-extract",
            "--file",
            rootfs
                .join("sbin/slpupgrade")
                .to_str()
                .expect("binary path"),
            "--output-dir",
            output_dir.path().to_str().expect("output dir"),
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
        .expect("fat crypto-extract runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vendor-RSA-blob  at 0x7"), "{stdout}");
    assert!(stdout.contains("wrote key artifacts: 2"), "{stdout}");

    let raw_out = output_dir.path().join("vendor_rsa_blob_1.publickeyblob");
    let pem_out = output_dir.path().join("vendor_rsa_blob_1.pem");
    let manifest = output_dir.path().join("crypto_extract_manifest.json");
    assert!(raw_out.exists(), "missing {}", raw_out.display());
    assert!(pem_out.exists(), "missing {}", pem_out.display());
    assert_eq!(std::fs::read(&raw_out).expect("raw blob").len(), 148);
    assert_valid_public_key(&pem_out);

    let manifest_json: Value =
        serde_json::from_slice(&std::fs::read(manifest).expect("manifest bytes"))
            .expect("manifest json");
    let artifacts = manifest_json
        .get("artifacts")
        .and_then(|value| value.as_array())
        .expect("artifacts array");
    assert_eq!(
        artifacts.len(),
        2,
        "expected raw and PEM artifacts: {manifest_json}"
    );
    assert!(artifacts.iter().any(|artifact| {
        artifact
            .get("artifact_format")
            .and_then(|value| value.as_str())
            == Some("ms-publickeyblob")
    }));
    assert!(artifacts.iter().any(|artifact| {
        artifact
            .get("artifact_format")
            .and_then(|value| value.as_str())
            == Some("pem")
    }));
}

fn pem_body(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .expect("pem text")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
}

fn assert_valid_private_key(path: &std::path::Path) {
    let output = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            path.to_str().expect("pem path"),
            "-check",
            "-noout",
        ])
        .output()
        .expect("openssl private validation runs");
    assert!(
        output.status.success(),
        "private PEM failed validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_valid_public_key(path: &std::path::Path) {
    let output = Command::new("openssl")
        .args([
            "rsa",
            "-pubin",
            "-in",
            path.to_str().expect("pem path"),
            "-noout",
        ])
        .output()
        .expect("openssl public validation runs");
    assert!(
        output.status.success(),
        "public PEM failed validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
