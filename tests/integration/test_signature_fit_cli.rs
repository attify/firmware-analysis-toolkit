use sha2::{Digest, Sha256};
use std::process::Command;
use tempfile::tempdir;

#[test]
fn fat_signature_fit_reports_rsa_pss_sha256_fit() {
    let tmp = tempdir().expect("tempdir");
    let signature_offset = 4usize;
    let signature_len = 80usize;

    let mut firmware = vec![0x41; signature_offset + signature_len + 12];
    firmware[signature_offset..signature_offset + signature_len].fill(0);
    let message_hash = sha256_with_zeroed_range(&firmware, signature_offset, signature_len);
    let em = pss_sha256_em(&message_hash, signature_len, b"12345678");
    firmware[signature_offset..signature_offset + signature_len]
        .copy_from_slice(&em.iter().rev().copied().collect::<Vec<_>>());

    let firmware_path = tmp.path().join("firmware.bin");
    let key_path = tmp.path().join("public.publickeyblob");
    std::fs::write(&firmware_path, firmware).expect("firmware write");
    std::fs::write(
        &key_path,
        ms_publickeyblob((signature_len * 8) as u32, 1, &vec![0xff; signature_len]),
    )
    .expect("key write");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "signature-fit",
            "--firmware",
            firmware_path.to_str().expect("firmware path"),
            "--key-blob",
            key_path.to_str().expect("key path"),
            "--signature-offset",
            "0x4",
            "--signature-size",
            "80",
            "--signature-byte-order",
            "little",
            "--zero-range",
            "0x4:80",
        ])
        .output()
        .expect("fat signature-fit runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "Signature fit",
        "scheme: rsa-pss-sha256",
        "key: RSA-640 e=1",
        "signature: 0x4..0x54 (80 bytes, little-endian)",
        "pss_trailer: ok",
        "pss_db: ok",
        "pss_hash: ok",
        "verdict: fit",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_signature_fit_exports_only_verified_signature_evidence() {
    let tmp = tempdir().expect("tempdir");
    let signature_offset = 4usize;
    let signature_len = 80usize;
    let salt = b"1234567890abcdefABCDEFGHIJKLMNOP";

    let mut firmware = vec![0x41; signature_offset + signature_len + 12];
    firmware[signature_offset..signature_offset + signature_len].fill(0);
    let message_hash = sha256_with_zeroed_range(&firmware, signature_offset, signature_len);
    let em = pss_sha256_em(&message_hash, signature_len, salt);
    firmware[signature_offset..signature_offset + signature_len]
        .copy_from_slice(&em.iter().rev().copied().collect::<Vec<_>>());

    let firmware_path = tmp.path().join("firmware.bin");
    let key_path = tmp.path().join("public.publickeyblob");
    let output_dir = tmp.path().join("fit-output");
    std::fs::write(&firmware_path, firmware).expect("firmware write");
    std::fs::write(
        &key_path,
        ms_publickeyblob((signature_len * 8) as u32, 1, &vec![0xff; signature_len]),
    )
    .expect("key write");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "signature-fit",
            "--firmware",
            firmware_path.to_str().expect("firmware path"),
            "--key-blob",
            key_path.to_str().expect("key path"),
            "--signature-offset",
            "0x4",
            "--signature-size",
            "80",
            "--signature-byte-order",
            "little",
            "--zero-range",
            "0x4:80",
            "--output-dir",
            output_dir.to_str().expect("output dir"),
        ])
        .output()
        .expect("fat signature-fit runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exported_salt:"));
    assert!(!stdout.contains("exported_aes_key:"));
    assert!(!stdout.contains("exported_aes_iv:"));

    assert_eq!(
        std::fs::read(output_dir.join("pss_salt.bin")).expect("salt file"),
        salt
    );
    assert!(!output_dir.join("v3_pss_salt.bin").exists());
    assert!(!output_dir.join("v3_aes_key.bin").exists());
    assert!(!output_dir.join("v3_aes_iv.bin").exists());
    assert_eq!(
        std::fs::read_to_string(output_dir.join("zeroed_firmware_sha256.txt"))
            .expect("firmware hash file"),
        hex_for_test(&message_hash)
    );
    let manifest = std::fs::read_to_string(output_dir.join("signature_fit_manifest.json"))
        .expect("manifest file");
    assert!(manifest.contains("\"schema_version\": \"signature-fit-artifacts/v2\""));
    assert!(manifest.contains("\"schema_version\": \"signature-fit/v2\""));
    assert!(!manifest.contains("aes_key_path"));
    assert!(!manifest.contains("aes_iv_path"));
}

fn sha256_with_zeroed_range(firmware: &[u8], offset: usize, length: usize) -> [u8; 32] {
    let mut normalized = firmware.to_vec();
    normalized[offset..offset + length].fill(0);
    Sha256::digest(&normalized).into()
}

fn pss_sha256_em(message_hash: &[u8; 32], em_len: usize, salt: &[u8]) -> Vec<u8> {
    let hash_len = 32;
    let db_len = em_len - hash_len - 1;
    let ps_len = db_len - salt.len() - 1;

    let mut h_input = Vec::new();
    h_input.extend_from_slice(&[0u8; 8]);
    h_input.extend_from_slice(message_hash);
    h_input.extend_from_slice(salt);
    let h: [u8; 32] = Sha256::digest(&h_input).into();

    let mut db = vec![0u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(salt);

    let mask = mgf1_sha256(&h, db_len);
    let masked_db = db
        .iter()
        .zip(mask)
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();

    let mut em = masked_db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    em
}

fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(length);
    let mut counter = 0u32;
    while mask.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        mask.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    mask.truncate(length);
    mask
}

fn ms_publickeyblob(bit_length: u32, public_exponent: u32, modulus_le: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x06, 0x02, 0x00, 0x00, 0x0c, 0x24, 0x00, 0x00]);
    blob.extend_from_slice(b"RSA1");
    blob.extend_from_slice(&bit_length.to_le_bytes());
    blob.extend_from_slice(&public_exponent.to_le_bytes());
    blob.extend_from_slice(modulus_le);
    blob
}

fn hex_for_test(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
