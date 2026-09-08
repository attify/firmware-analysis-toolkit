use serde_json::{json, Value};
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn pseudo_random_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xff) as u8);
    }
    out
}

fn write_fake_rabin2(path: &std::path::Path) {
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
    std::fs::write(path, script).expect("fake rabin2");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod");
    }
}

fn run_with_path(args: &[&str], path_dir: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat command runs");
    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid json")
}

fn load_fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../tests/fixtures/json/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture json")
}

fn summary_fields_present(report: &Value) -> bool {
    report.get("confidence").is_some()
        && report.get("reason").is_some()
        && report.get("evidence").is_some()
}

fn assert_advice_free(report: &Value) {
    fn visit(value: &Value, path: &str) {
        match value {
            Value::Object(object) => {
                for key in [
                    "recommendation",
                    "workflow_recommendation",
                    "next_steps",
                    "next_action",
                ] {
                    assert!(
                        !object.contains_key(key),
                        "unexpected advice field {path}.{key}: {value}"
                    );
                }
                for (key, child) in object {
                    visit(child, &format!("{path}.{key}"));
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    visit(child, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }

    visit(report, "$");
}

fn normalize_envelope_contract(report: &Value) -> Value {
    json!({
        "schema_version": report.get("schema_version"),
        "summary_fields_present": summary_fields_present(report),
        "classification": report.get("classification"),
        "ecb_assessment": report.get("ecb_assessment"),
        "reason": report.get("reason"),
    })
}

fn normalize_trust_contract(report: &Value) -> Value {
    let candidates = report
        .get("candidates")
        .and_then(|value| value.as_array())
        .expect("candidates");
    json!({
        "schema_version": report.get("schema_version"),
        "summary_fields_present": summary_fields_present(report),
        "classification": report.get("classification"),
        "confidence": report.get("confidence"),
        "governing_update_path": {
            "path": report.get("governing_update_path").and_then(|value| value.get("path")),
            "candidate_classification": report.get("governing_update_path").and_then(|value| value.get("candidate_classification")),
        },
        "candidates": candidates.iter().map(|candidate| json!({
            "path": candidate.get("path"),
            "candidate_classification": candidate.get("candidate_classification"),
        })).collect::<Vec<_>>(),
    })
}

fn normalize_crypto_contract(report: &Value) -> Value {
    let first_key = report
        .get("embedded_keys")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "schema_version": report.get("schema_version"),
        "summary_fields_present": summary_fields_present(report),
        "confidence": report.get("confidence"),
        "classification_role": report.get("classification").and_then(|value| value.get("role")),
        "trust_context": {
            "candidate_classification": report.get("trust_context").and_then(|value| value.get("candidate_classification")),
            "trust_path_relevance": report.get("trust_context").and_then(|value| value.get("trust_path_relevance")),
        },
        "first_embedded_key": {
            "key_type": first_key.get("key_type"),
            "confidence": first_key.get("confidence"),
        },
    })
}

fn normalize_census_contract(report: &Value) -> Value {
    let first_cluster = report
        .get("clusters")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "schema_version": report.get("schema_version"),
        "summary_fields_present": summary_fields_present(report),
        "confidence": report.get("confidence"),
        "cluster_count": report.get("clusters").and_then(|value| value.as_array()).map(|items| items.len()),
        "first_cluster": {
            "artifact_type": first_cluster.get("artifact_type"),
            "confidence": first_cluster.get("confidence"),
            "candidate_classifications": first_cluster.get("candidate_classifications"),
            "governing_path_hits": first_cluster.get("governing_path_hits"),
        },
    })
}

fn normalize_update_contract(report: &Value) -> Value {
    json!({
        "schema_version": report.get("schema_version"),
        "summary_fields_present": summary_fields_present(report),
        "confidence": report.get("confidence"),
        "envelope_schema_version": report.get("envelope").and_then(|value| value.get("schema_version")),
        "trust_path_schema_version": report.get("trust_path").and_then(|value| value.get("schema_version")),
        "crypto_census_present": report.get("crypto_census").is_some(),
        "governing_binary_crypto_present": report.get("governing_binary_crypto").is_some(),
    })
}

fn normalize_mcu_contract(report: &Value) -> Value {
    json!({
        "schema_version": report.get("schema_version"),
        "artifact_path_present": report.get("artifact_path").is_some(),
        "backend": report.get("analysis_provenance").and_then(|value| value.get("backend")),
        "user_base": report.get("analysis_provenance").and_then(|value| value.get("user_base")),
        "user_family": report.get("analysis_provenance").and_then(|value| value.get("user_family")),
        "fast_profile_family": report.get("fast_profile").and_then(|value| value.get("chip_family")),
        "has_address_hypotheses": report.get("address_hypotheses").is_some(),
        "has_startup_chain": report.get("startup_chain").is_some(),
        "has_execution_model": report.get("execution_model").is_some(),
        "has_security_surface": report.get("security_surface").is_some(),
        "has_integrity_checks": report.get("integrity_checks").is_some(),
    })
}

fn assert_normalized_semantic_equality(left: &Value, right: &Value) {
    assert_eq!(
        left, right,
        "expected normalized semantic equality\nleft: {left}\nright: {right}"
    );
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn thumb_b(from: u32, to: u32) -> [u8; 2] {
    let pc = from.wrapping_add(4);
    let offset = to.wrapping_sub(pc) as i32;
    let imm11 = ((offset >> 1) as u16) & 0x07ff;
    (0xe000u16 | imm11).to_le_bytes()
}

fn build_vector_table_image(reset: u32, second_step: Option<u32>, total_size: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, reset | 1);
    write_u32(&mut bytes, 0x0800_2001);
    write_u32(&mut bytes, 0x0800_3001);
    for _ in 4..32 {
        write_u32(&mut bytes, 0x0800_4001);
    }
    while bytes.len() < 0x100 {
        bytes.push(0x00);
    }
    let reset_offset = (reset - 0x0800_0000) as usize;
    if bytes.len() < reset_offset + 8 {
        bytes.resize(reset_offset + 8, 0x00);
    }
    bytes[reset_offset..reset_offset + 2].copy_from_slice(&thumb_b(reset, reset + 0x10));
    bytes[reset_offset + 2..reset_offset + 4].copy_from_slice(&[0x00, 0xBF]);
    let step1 = reset + 0x10;
    let step1_offset = (step1 - 0x0800_0000) as usize;
    if bytes.len() < step1_offset + 4 {
        bytes.resize(step1_offset + 4, 0x00);
    }
    if let Some(target) = second_step {
        bytes[step1_offset..step1_offset + 2].copy_from_slice(&thumb_b(step1, target));
        bytes[step1_offset + 2..step1_offset + 4].copy_from_slice(&[0x00, 0xBF]);
    }
    if bytes.len() < total_size {
        bytes.resize(total_size, 0xFF);
    }
    bytes
}

fn build_mcu_blob() -> Vec<u8> {
    let mut bytes = build_vector_table_image(0x0800_0200, Some(0x0800_0220), 0x900);
    let mmio_words = [0x5800_1C00u32, 0x5800_1C04, 0x4001_1000, 0x4001_1004];
    let mmio_offset = 0x180;
    for (index, word) in mmio_words.iter().enumerate() {
        let start = mmio_offset + index * 4;
        bytes[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }
    let payload = b"shared_flag irq main update ota crc32 checksum erase program uart comms flash";
    let payload_offset = 0x300;
    bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    bytes
}

fn build_layout_blob() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x220];
    bytes[0x20] = 0x5D;
    bytes[0x21..0x25].copy_from_slice(&(1u32 << 23).to_le_bytes());
    bytes[0x25..0x2D].copy_from_slice(&(111_464u64).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"hsqs");
    bytes[0x84..0x88].copy_from_slice(&1_064u32.to_le_bytes());
    bytes[0x88..0x8C].copy_from_slice(&1_636_595_875u32.to_le_bytes());
    bytes[0x8C..0x90].copy_from_slice(&262_144u32.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&4u16.to_le_bytes());
    bytes[0x9C..0x9E].copy_from_slice(&4u16.to_le_bytes());
    bytes[0xA8..0xB0].copy_from_slice(&5_955_826u64.to_le_bytes());
    bytes
}

#[test]
fn envelope_contract_matches_golden_fixture() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192, 0xCAFEBABE)).expect("blob");

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
    assert!(output.status.success(), "inspect envelope failed");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_advice_free(&report);

    assert_eq!(
        normalize_envelope_contract(&report),
        load_fixture("envelope_analysis_v1.json")
    );
}

#[test]
fn mcu_contract_matches_golden_fixture() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            blob.to_str().expect("blob path"),
            "--base",
            "0x08000000",
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect mcu json runs");
    assert!(output.status.success(), "inspect mcu failed");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_advice_free(&report);

    assert_eq!(
        normalize_mcu_contract(&report),
        load_fixture("mcu_inspection_report_v1.json")
    );
}

#[test]
fn layout_contract_is_recursively_advice_free() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("layout.bin");
    std::fs::write(&blob, build_layout_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            blob.to_str().expect("blob path"),
            "--json",
        ])
        .output()
        .expect("fat inspect layout json runs");
    assert!(output.status.success(), "inspect layout failed: {output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");

    assert_advice_free(&report);
    assert!(report.get("summary").is_some());
    assert!(report
        .get("regions")
        .and_then(Value::as_array)
        .is_some_and(|regions| !regions.is_empty()));
}

#[test]
fn trust_contract_matches_golden_fixture() {
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
    let mut helper_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    helper_bytes.extend_from_slice(b"BgIAAA");
    helper_bytes.extend(std::iter::repeat_n(b'H', 220));
    std::fs::write(rootfs.join("usr/lib").join("libdecrypter.so"), helper_bytes)
        .expect("libdecrypter");

    let rabin2_path = path_dir.path().join("rabin2");
    write_fake_rabin2(&rabin2_path);
    let report = run_with_path(
        &[
            "trust-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs"),
            "--json",
        ],
        path_dir.path(),
    );
    assert_advice_free(&report);

    assert_eq!(
        normalize_trust_contract(&report),
        load_fixture("trust_path_analysis_v1.json")
    );
}

#[test]
fn crypto_contract_matches_golden_fixture() {
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
    helper_bytes.extend(std::iter::repeat_n(b'C', 220));
    let helper = rootfs.join("usr/lib").join("libdecrypter.so");
    std::fs::write(&helper, helper_bytes).expect("libdecrypter");

    let rabin2_path = path_dir.path().join("rabin2");
    write_fake_rabin2(&rabin2_path);
    let report = run_with_path(
        &[
            "crypto",
            "--file",
            helper.to_str().expect("helper"),
            "--json",
        ],
        path_dir.path(),
    );

    assert_advice_free(&report);

    assert_eq!(
        normalize_crypto_contract(&report),
        load_fixture("crypto_artifact_analysis_v1.json")
    );
}

#[test]
fn census_contract_matches_golden_fixture() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");

    let shared_blob = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BgIAAA");
        bytes.extend(std::iter::repeat_n(b'G', 220));
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
    write_fake_rabin2(&rabin2_path);
    let report = run_with_path(
        &[
            "crypto-census",
            "--rootfs",
            rootfs.to_str().expect("rootfs"),
            "--json",
        ],
        path_dir.path(),
    );
    assert_advice_free(&report);

    assert_eq!(
        normalize_census_contract(&report),
        load_fixture("crypto_reuse_cluster_v1.json")
    );
}

#[test]
fn inspect_update_contract_matches_golden_fixture_and_embeds_submodels() {
    let firmware_dir = tempdir().expect("firmware dir");
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let firmware = firmware_dir.path().join("firmware.bin");
    let reference = firmware_dir.path().join("reference.bin");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");
    let mut firmware_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    firmware_bytes.extend_from_slice(&pseudo_random_bytes(8192, 0xA11C_E123));
    let mut reference_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    reference_bytes.extend_from_slice(&[0x42; 8192]);
    std::fs::write(&firmware, firmware_bytes).expect("firmware");
    std::fs::write(&reference, reference_bytes).expect("reference");

    let mut updater_bytes = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    updater_bytes.extend_from_slice(b"BgIAAA");
    updater_bytes.extend(std::iter::repeat_n(b'E', 220));
    std::fs::write(rootfs.join("sbin").join("slpupgrade"), updater_bytes).expect("slpupgrade");
    std::fs::write(
        rootfs.join("usr/lib").join("libsecurity.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("libsecurity");

    let rabin2_path = path_dir.path().join("rabin2");
    write_fake_rabin2(&rabin2_path);

    let update_report = run_with_path(
        &[
            "inspect",
            "update",
            "--file",
            firmware.to_str().expect("firmware"),
            "--rootfs",
            rootfs.to_str().expect("rootfs"),
            "--reference",
            reference.to_str().expect("reference"),
            "--json",
        ],
        path_dir.path(),
    );
    let envelope_report = serde_json::from_slice::<Value>(
        &Command::new(env!("CARGO_BIN_EXE_fat"))
            .args([
                "inspect",
                "envelope",
                "--file",
                firmware.to_str().expect("firmware"),
                "--reference",
                reference.to_str().expect("reference"),
                "--json",
            ])
            .output()
            .expect("envelope")
            .stdout,
    )
    .expect("envelope json");
    let trust_report = run_with_path(
        &[
            "trust-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs"),
            "--json",
        ],
        path_dir.path(),
    );

    assert_advice_free(&update_report);
    assert_advice_free(&envelope_report);
    assert_advice_free(&trust_report);

    assert_eq!(
        normalize_update_contract(&update_report),
        load_fixture("inspect_update_report_v1.json")
    );
    assert_normalized_semantic_equality(
        update_report.get("envelope").expect("update envelope"),
        &envelope_report,
    );
    assert_normalized_semantic_equality(
        update_report.get("trust_path").expect("update trust"),
        &trust_report,
    );
}
