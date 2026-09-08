//! `fat crypto` — detect, classify, and extract crypto artifacts from firmware binaries.
//!
//! Drives rabin2 to extract imports, exports, and linked libraries, then classifies
//! crypto usage, detects weaknesses, and extracts embedded key material.

use crate::schema_versions;
use crate::style::Palette;
use crate::trust_boundary_cmd::{
    build_trust_map_json_report, linked_from_governing_path, TrustTierCounts,
};
use fat_package::keys::{find_ascii_hex_aes_keys, find_ms_publickeyblob_base64_blobs};
use fat_taint::recon::r2;
use fat_taint::recon::trust_boundary::{analyze_rootfs, TrustBoundaryReport};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

type DynResult<T> = Result<T, Box<dyn Error>>;

// ── Report structures ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CryptoReport {
    pub schema_version: &'static str,
    pub binary: String,
    pub confidence: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub crypto_imports: Vec<CryptoImport>,
    pub crypto_exports: Vec<CryptoExport>,
    pub classification: CryptoClassification,
    pub external_crypto_library: Option<String>,
    pub weaknesses: Vec<CryptoWeakness>,
    pub trust_context: Option<CryptoTrustContext>,
    pub embedded_keys: Vec<EmbeddedKey>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CryptoImport {
    pub name: String,
    pub category: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CryptoExport {
    pub name: String,
    pub size: u64,
    pub category: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CryptoClassification {
    pub role: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CryptoWeakness {
    pub weakness: String,
    pub severity: String,
    pub evidence: String,
    pub function: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct EmbeddedKey {
    pub key_type: String,
    pub bit_length: Option<u32>,
    pub offset: String,
    pub confidence: String,
    pub fingerprint: Option<String>,
    pub pem_data: Option<String>,
    pub validated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_exponent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulus_bytes: Option<usize>,
    #[serde(skip_serializing)]
    pub artifact_data: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub artifact_extension: Option<String>,
    pub referenced_by: Option<String>,
    pub trust_path_relevance: Option<String>,
    pub reason: Option<String>,
    pub also_seen_in: Vec<String>,
}

#[derive(Debug, Serialize)]
struct KeyArtifactManifest {
    schema_version: &'static str,
    source_binary: String,
    artifacts: Vec<KeyArtifactRecord>,
}

#[derive(Debug, Serialize)]
struct KeyArtifactRecord {
    filename: String,
    key_type: String,
    bit_length: Option<u32>,
    offset: String,
    fingerprint: Option<String>,
    validated: bool,
    confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_format: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CryptoTrustContext {
    pub rootfs_path: String,
    pub binary_path: String,
    pub governing_update_binary: Option<String>,
    pub candidate_role: Option<String>,
    pub candidate_classification: Option<String>,
    pub score: Option<f64>,
    pub update_path_score: Option<f64>,
    pub path_confidence: Option<String>,
    pub tier_counts: Option<TrustTierCounts>,
    pub negative_evidence: Vec<String>,
    pub why: Vec<String>,
    pub trust_path_relevance: String,
    pub reason: String,
    pub evidence: Vec<fat_taint::recon::trust_boundary::Evidence>,
}

#[derive(Debug, Clone)]
struct DecompileTarget {
    name: String,
    addr: String,
}

// ── Constants ──────────────────────────────────────────────────────────────

const CRYPTO_PATTERNS: &[(&str, &str)] = &[
    // OpenSSL
    ("RSA_private_decrypt", "asymmetric"),
    ("RSA_public_encrypt", "asymmetric"),
    ("RSA_verify", "asymmetric"),
    ("RSA_sign", "asymmetric"),
    ("RSA_size", "asymmetric"),
    ("RSA_free", "asymmetric"),
    ("AES_set_encrypt_key", "symmetric"),
    ("AES_set_decrypt_key", "symmetric"),
    ("AES_cbc_encrypt", "symmetric"),
    ("AES_ecb_encrypt", "symmetric"),
    ("EVP_DecryptInit_ex", "symmetric"),
    ("EVP_EncryptInit_ex", "symmetric"),
    ("EVP_DigestInit_ex", "hash"),
    ("EVP_DigestUpdate", "hash"),
    ("EVP_PKEY_sign", "asymmetric"),
    ("EVP_VerifyFinal", "asymmetric"),
    ("DES_set_key", "symmetric"),
    ("DES_ecb_encrypt", "symmetric"),
    ("MD5_Init", "hash"),
    ("MD5_Update", "hash"),
    ("MD5_Final", "hash"),
    ("SHA1_Init", "hash"),
    ("SHA256_Init", "hash"),
    ("SHA512_Init", "hash"),
    ("SHA256", "hash"),
    ("SHA1", "hash"),
    ("RAND_bytes", "random"),
    ("RAND_pseudo_bytes", "random"),
    ("PKCS5_PBKDF2_HMAC", "kdf"),
    // mbedTLS
    ("mbedtls_rsa_pkcs1_decrypt", "asymmetric"),
    ("mbedtls_aes_crypt_cbc", "symmetric"),
    ("mbedtls_sha256", "hash"),
    ("mbedtls_md5", "hash"),
    // wolfSSL
    ("wc_RsaPrivateDecrypt", "asymmetric"),
    ("wc_AesCbcDecrypt", "symmetric"),
    // Vendor wrappers
    ("rsaVerifySign", "asymmetric"),
    ("rsaDecrypt", "asymmetric"),
    ("rsa_decrypt", "asymmetric"),
    ("private_decrypt", "asymmetric"),
    ("AesEncrypt", "symmetric"),
    ("AesDecrypt", "symmetric"),
    ("AesCtxIni", "symmetric"),
    ("AesGenKeySched", "symmetric"),
    // Weak
    ("rand", "random"),
    ("srand", "random"),
    ("random", "random"),
];

// ── Pure logic functions ───────────────────────────────────────────────────

/// Classify a list of raw imports against known crypto function patterns.
fn classify_imports(imports: &[r2::Import]) -> Vec<CryptoImport> {
    let mut result = Vec::new();
    for imp in imports {
        for &(pattern, category) in CRYPTO_PATTERNS {
            if imp.name == pattern || imp.name.contains(pattern) {
                result.push(CryptoImport {
                    name: imp.name.clone(),
                    category: category.to_string(),
                });
                break;
            }
        }
    }
    result
}

/// Classify a list of raw exports against known crypto function patterns.
fn classify_exports(exports: &[r2::Export]) -> Vec<CryptoExport> {
    let mut result = Vec::new();
    for exp in exports {
        for &(pattern, category) in CRYPTO_PATTERNS {
            if exp.name == pattern || exp.name.contains(pattern) {
                result.push(CryptoExport {
                    name: exp.name.clone(),
                    size: exp.size,
                    category: category.to_string(),
                });
                break;
            }
        }
    }
    result
}

/// Detect which crypto library is linked, if any.
fn detect_crypto_library(libs: &[String]) -> Option<String> {
    for lib in libs {
        let lower = lib.to_lowercase();
        if lower.contains("libssl") || lower.contains("libcrypto") {
            return Some("OpenSSL".into());
        }
        if lower.contains("mbedtls") || lower.contains("mbedcrypto") {
            return Some("mbedTLS".into());
        }
        if lower.contains("wolfssl") || lower.contains("wolfcrypt") {
            return Some("wolfSSL".into());
        }
        if lower.contains("gcrypt") {
            return Some("libgcrypt".into());
        }
    }
    None
}

/// Classify the overall crypto role of the binary.
fn classify_crypto(
    imports: &[CryptoImport],
    exports: &[CryptoExport],
    external_lib: &Option<String>,
) -> CryptoClassification {
    let mut evidence = Vec::new();

    let has_verify = imports
        .iter()
        .any(|i| i.name.contains("Verify") || i.name.contains("verify"));
    let has_decrypt = imports
        .iter()
        .any(|i| i.name.contains("decrypt") || i.name.contains("Decrypt"));
    let has_bulk_crypto = imports.iter().any(|i| i.category == "symmetric");
    let has_rsa = imports
        .iter()
        .any(|i| i.name.contains("RSA") || i.name.contains("rsa"));

    let role = if has_verify && !has_decrypt && !has_bulk_crypto {
        evidence.push("Imports signature verification but no decryption".into());
        "signature-verifier"
    } else if has_verify && has_bulk_crypto {
        evidence.push("Imports both verification and bulk crypto".into());
        "firmware-decryptor"
    } else if has_rsa && has_decrypt && !has_bulk_crypto {
        evidence.push("RSA decrypt without bulk crypto — likely small token decryptor".into());
        "bounded-string-decryptor"
    } else if !imports.is_empty() || !exports.is_empty() {
        "general-crypto"
    } else {
        "no-crypto"
    };

    if external_lib.is_none() && !exports.is_empty() {
        evidence.push("No external crypto library linked — crypto is custom/static".into());
    }

    CryptoClassification {
        role: role.into(),
        evidence,
    }
}

/// Detect crypto weaknesses from classified imports, exports, and library info.
fn detect_weaknesses(
    imports: &[CryptoImport],
    exports: &[CryptoExport],
    external_lib: &Option<String>,
) -> Vec<CryptoWeakness> {
    let mut weaknesses = Vec::new();

    // Custom AES without standard library
    let has_custom_aes = exports.iter().any(|e| {
        e.name.contains("AesEncrypt")
            || e.name.contains("AesDecrypt")
            || e.name.contains("AesCtxIni")
            || e.name.contains("AesGenKeySched")
    });
    if has_custom_aes && external_lib.is_none() {
        weaknesses.push(CryptoWeakness {
            weakness: "custom-aes-no-standard-library".into(),
            severity: "high".into(),
            evidence: "Binary exports AES functions but does not link any standard crypto library"
                .into(),
            function: exports
                .iter()
                .find(|e| e.name.contains("Aes"))
                .map(|e| e.name.clone()),
        });
    }

    // Weak PRNG alongside crypto
    let has_weak_prng = imports
        .iter()
        .any(|i| i.name == "rand" || i.name == "srand" || i.name == "random");
    let has_any_crypto = imports
        .iter()
        .any(|i| i.category == "symmetric" || i.category == "asymmetric");
    if has_weak_prng && has_any_crypto {
        weaknesses.push(CryptoWeakness {
            weakness: "weak-prng-rand".into(),
            severity: "medium".into(),
            evidence: "Uses rand/srand alongside cryptographic functions".into(),
            function: imports
                .iter()
                .find(|i| i.name == "rand" || i.name == "srand" || i.name == "random")
                .map(|i| i.name.clone()),
        });
    }

    // Hand-rolled crypto: exports crypto functions but no external library
    let has_crypto_exports = !exports.is_empty();
    if has_crypto_exports && external_lib.is_none() && !has_custom_aes {
        // Only emit if we didn't already flag custom-aes
        weaknesses.push(CryptoWeakness {
            weakness: "hand-rolled-crypto".into(),
            severity: "medium".into(),
            evidence: "Binary exports crypto functions without linking a standard crypto library"
                .into(),
            function: exports.first().map(|e| e.name.clone()),
        });
    }

    // Potential ECB mode usage
    let has_ecb = imports
        .iter()
        .any(|i| i.name.contains("ecb") || i.name.contains("ECB") || i.name.contains("Ecb"));
    if has_ecb {
        weaknesses.push(CryptoWeakness {
            weakness: "potential-ecb-mode".into(),
            severity: "medium".into(),
            evidence: "Binary imports ECB-mode encryption function".into(),
            function: imports
                .iter()
                .find(|i| {
                    i.name.contains("ecb") || i.name.contains("ECB") || i.name.contains("Ecb")
                })
                .map(|i| i.name.clone()),
        });
    }

    let partial_encryption_export = exports.iter().find(|e| {
        let lower = e.name.to_ascii_lowercase();
        lower.contains("partial") && lower.contains("encrypt")
    });
    if let Some(export) = partial_encryption_export {
        weaknesses.push(CryptoWeakness {
            weakness: "partial-encryption-control".into(),
            severity: "medium".into(),
            evidence:
                "Binary exports a partial encryption control surface; selective encryption modes deserve manual review"
                    .into(),
            function: Some(export.name.clone()),
        });
    }

    weaknesses
}

fn build_decompile_script(targets: &[DecompileTarget]) -> String {
    let mut script = String::from("aaa\n");
    for target in targets {
        writeln!(script, "echo ===FAT_FUNC:{}===", target.name).unwrap();
        writeln!(script, "s {}", target.addr).unwrap();
        script.push_str("pdg\n");
    }
    script
}

fn strip_ansi(s: &str) -> String {
    let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(s, "").to_string()
}

fn parse_decompile_output(output: &str) -> std::collections::HashMap<String, String> {
    let cleaned = strip_ansi(output);
    let marker_re = regex::Regex::new(r"===FAT_FUNC:([^=]+)===").unwrap();
    let mut map = std::collections::HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_lines = Vec::new();

    for line in cleaned.lines() {
        if let Some(caps) = marker_re.captures(line) {
            if let Some(name) = current_name.take() {
                let body = current_lines.join("\n").trim().to_string();
                if !body.is_empty() {
                    map.insert(name, body);
                }
            }
            current_name = Some(caps[1].to_string());
            current_lines.clear();
        } else if current_name.is_some() {
            current_lines.push(line);
        }
    }

    if let Some(name) = current_name {
        let body = current_lines.join("\n").trim().to_string();
        if !body.is_empty() {
            map.insert(name, body);
        }
    }

    map
}

fn function_matches_export_name(function_name: &str, export_name: &str) -> bool {
    let normalized = function_name
        .strip_prefix("sym.")
        .or_else(|| function_name.strip_prefix("sym.imp."))
        .unwrap_or(function_name);
    normalized == export_name || normalized.ends_with(export_name)
}

fn normalize_function_name(function_name: &str) -> &str {
    function_name
        .strip_prefix("sym.")
        .or_else(|| function_name.strip_prefix("sym.imp."))
        .unwrap_or(function_name)
}

fn is_random_candidate_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("rand")
        || lower.contains("random")
        || lower.contains("nonce")
        || lower.contains("sessionid")
        || lower.contains("shortid")
        || lower.contains("tokenid")
        || lower.contains("genid")
}

fn is_aes_candidate_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("aes_encrypt")
        || lower.contains("aesencrypt")
        || lower.contains("aes_decrypt")
        || lower.contains("aesdecrypt")
        || lower.contains("aes") && lower.contains("crypt")
}

fn select_decompile_targets(
    raw_imports: &[r2::Import],
    raw_exports: &[r2::Export],
    functions: &[r2::FunctionInfo],
) -> Vec<DecompileTarget> {
    let has_weak_prng_import = raw_imports
        .iter()
        .any(|imp| matches!(imp.name.as_str(), "rand" | "srand" | "random"));

    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for export in raw_exports {
        let lower = export.name.to_ascii_lowercase();
        let suspicious_aes = is_aes_candidate_name(&lower);
        let suspicious_random = has_weak_prng_import
            && (lower.contains("random")
                || lower.contains("rand")
                || lower.contains("nonce")
                || lower.contains("sessionid")
                || lower.contains("shortid"));

        if !(suspicious_aes || suspicious_random) {
            continue;
        }

        if let Some(function) = functions
            .iter()
            .find(|func| function_matches_export_name(&func.name, &export.name))
        {
            if !seen.insert(function.name.clone()) {
                continue;
            }
            targets.push(DecompileTarget {
                name: export.name.clone(),
                addr: format!("{:#x}", function.address),
            });
        }
    }

    if has_weak_prng_import {
        for function in functions {
            let normalized = normalize_function_name(&function.name);
            if !is_random_candidate_name(normalized) {
                continue;
            }
            if seen.insert(function.name.clone()) {
                targets.push(DecompileTarget {
                    name: normalized.to_string(),
                    addr: format!("{:#x}", function.address),
                });
            }
        }
    }

    targets
}

fn decompile_functions(
    binary: &Path,
    targets: &[DecompileTarget],
) -> std::collections::HashMap<String, String> {
    if targets.is_empty() {
        return std::collections::HashMap::new();
    }

    if Command::new("r2").arg("-v").output().is_err() {
        eprintln!("warning: r2 not found in PATH; skipping crypto decompilation heuristics");
        return std::collections::HashMap::new();
    }

    let script = build_decompile_script(targets);
    let mut tmp = match tempfile::NamedTempFile::new() {
        Ok(file) => file,
        Err(_) => return std::collections::HashMap::new(),
    };
    if tmp.write_all(script.as_bytes()).is_err() {
        return std::collections::HashMap::new();
    }

    let output = Command::new("r2")
        .args(["-q", "-e", "scr.color=0", "-e", "log.level=0", "-i"])
        .arg(tmp.path())
        .arg(binary)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            parse_decompile_output(&String::from_utf8_lossy(&out.stdout))
        }
        _ => std::collections::HashMap::new(),
    }
}

fn detect_decompiled_ecb_weakness(function_name: &str, decomp: &str) -> Option<CryptoWeakness> {
    let lower_name = function_name.to_ascii_lowercase();
    let is_aes_like_target = lower_name.contains("aes") && lower_name.contains("encrypt");
    let lower = decomp.to_ascii_lowercase();
    let has_loop = lower.contains("for (") || lower.contains("while (");
    let has_block_counter =
        lower.contains("+ 0x10") || lower.contains("+ 0x10UL") || lower.contains("+16");
    let has_block_store = lower.matches("+ 0x10").count() >= 2
        || lower.matches("+ 16").count() >= 2
        || (lower.contains("+ 0x10;") && lower.contains("+ 0x10h"));
    let crypto_call = lower.contains("aes_encrypt")
        || lower.contains("aesencrypt")
        || is_aes_like_target
        || lower.contains("aes");
    let has_possible_iv_like_feedback =
        lower.contains("memcpy(iv") || lower.contains("xor ") || lower.contains("mode");
    let mentions_chaining = lower.contains("cbc")
        || lower.contains("ctr")
        || lower.contains("gcm")
        || lower.contains("cfb")
        || lower.contains("ofb")
        || lower.contains("xor_block")
        || lower.contains("feedback")
        || lower.contains("iv");

    if has_loop
        && crypto_call
        && has_block_counter
        && has_block_store
        && !has_possible_iv_like_feedback
        && !mentions_chaining
    {
        return Some(CryptoWeakness {
            weakness: "decompiled-ecb-block-loop".into(),
            severity: "high".into(),
            evidence:
                "Decompiled AES wrapper iterates over 16-byte blocks without visible chaining state or IV updates"
                    .into(),
            function: Some(function_name.to_string()),
        });
    }

    None
}

fn detect_decompiled_weak_prng_weakness(
    function_name: &str,
    decomp: &str,
) -> Option<CryptoWeakness> {
    let lower_name = function_name.to_ascii_lowercase();
    if !(lower_name.contains("random") || lower_name.contains("rand") || lower_name.contains("id"))
    {
        return None;
    }

    let lower = decomp.to_ascii_lowercase();
    let truncates_to_short = lower.contains("0xffff")
        || lower.contains("65535")
        || lower.contains("uint16")
        || lower.contains("ushort")
        || lower.contains("0xff")
        || lower.contains("0x0000ffff")
        || lower.contains("0x0000ffffu")
        || lower.contains("% 0x10000")
        || lower.contains("% 65536")
        || lower.contains("short random");

    let random_call = lower.contains("rand()") || lower.contains("random()");
    if random_call && truncates_to_short {
        return Some(CryptoWeakness {
            weakness: "weak-prng-short-random-id".into(),
            severity: "high".into(),
            evidence:
                "Decompiled random-ID helper reduces rand() output to a short-width value (<32 bits), making brute force practical"
                    .into(),
            function: Some(function_name.to_string()),
        });
    }

    None
}

fn detect_decompilation_weaknesses(
    file: &Path,
    raw_imports: &[r2::Import],
    raw_exports: &[r2::Export],
) -> Vec<CryptoWeakness> {
    let functions = match r2::function_list(file) {
        Ok(functions) => functions,
        Err(_) => return Vec::new(),
    };

    let targets = select_decompile_targets(raw_imports, raw_exports, &functions);
    let decomp_map = decompile_functions(file, &targets);
    let mut weaknesses = Vec::new();

    for target in targets {
        let Some(source) = decomp_map.get(&target.name) else {
            continue;
        };

        if let Some(weakness) = detect_decompiled_ecb_weakness(&target.name, source) {
            weaknesses.push(weakness);
        }
        if let Some(weakness) = detect_decompiled_weak_prng_weakness(&target.name, source) {
            weaknesses.push(weakness);
        }
    }

    weaknesses
}

/// Extract embedded key material from binary data.
fn extract_keys(data: &[u8]) -> Vec<EmbeddedKey> {
    extract_keys_with_context(data, false)
}

fn extract_keys_for_crypto_context(
    data: &[u8],
    crypto_imports: &[CryptoImport],
) -> Vec<EmbeddedKey> {
    let has_symmetric_crypto = crypto_imports
        .iter()
        .any(|import| import.category == "symmetric");
    extract_keys_with_context(data, has_symmetric_crypto)
}

fn extract_keys_with_context(data: &[u8], has_symmetric_crypto: bool) -> Vec<EmbeddedKey> {
    let mut keys = Vec::new();

    // RSA private key (MIIC pattern = PKCS#8 or PKCS#1 DER base64, ~1024-bit)
    if let Ok(re) = regex::bytes::Regex::new(r"(MIIC[A-Za-z0-9+/=]{700,})") {
        for cap in re.find_iter(data) {
            let offset = cap.start();
            let Ok(base64_str) = std::str::from_utf8(cap.as_bytes()) else {
                continue;
            };
            let pem = format_pem("RSA PRIVATE KEY", base64_str);

            let validated = validate_key_with_openssl(&pem, "rsa");
            let confidence = key_confidence(validated, false);

            keys.push(EmbeddedKey {
                key_type: "RSA-private".into(),
                bit_length: Some(1024),
                offset: format!("0x{offset:X}"),
                confidence,
                fingerprint: Some(key_fingerprint(base64_str.as_bytes())),
                pem_data: Some(pem),
                validated,
                blob_format: None,
                public_exponent: None,
                modulus_bytes: None,
                artifact_data: None,
                artifact_extension: None,
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            });
        }
    }

    // RSA public key (MIGf pattern, ~1024-bit)
    if let Ok(re) = regex::bytes::Regex::new(r"(MIGf[A-Za-z0-9+/=]{150,})") {
        for cap in re.find_iter(data) {
            let offset = cap.start();
            let Ok(base64_str) = std::str::from_utf8(cap.as_bytes()) else {
                continue;
            };
            let pem = format_pem("PUBLIC KEY", base64_str);
            let validated = validate_key_with_openssl(&pem, "public");
            let confidence = key_confidence(validated, false);

            keys.push(EmbeddedKey {
                key_type: "RSA-public".into(),
                bit_length: Some(1024),
                offset: format!("0x{offset:X}"),
                confidence,
                fingerprint: Some(key_fingerprint(base64_str.as_bytes())),
                pem_data: Some(pem),
                validated,
                blob_format: None,
                public_exponent: None,
                modulus_bytes: None,
                artifact_data: None,
                artifact_extension: None,
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            });
        }
    }

    // Larger RSA public keys (MIIBIj for 2048-bit public)
    if let Ok(re) = regex::bytes::Regex::new(r"(MIIBIj[A-Za-z0-9+/=]{300,})") {
        for cap in re.find_iter(data) {
            let offset = cap.start();
            keys.push(EmbeddedKey {
                key_type: "RSA-public-2048".into(),
                bit_length: Some(2048),
                offset: format!("0x{offset:X}"),
                confidence: key_confidence(false, false),
                fingerprint: Some(key_fingerprint(cap.as_bytes())),
                pem_data: None,
                validated: false,
                blob_format: None,
                public_exponent: None,
                modulus_bytes: None,
                artifact_data: None,
                artifact_extension: None,
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            });
        }
    }

    // Larger RSA private keys (MIIE for 2048-bit private)
    let rsa_2048_pattern = concat!(r"(MI", r"IE[A-Za-z0-9+/=]{2000,})");
    if let Ok(re) = regex::bytes::Regex::new(rsa_2048_pattern) {
        for cap in re.find_iter(data) {
            let offset = cap.start();
            keys.push(EmbeddedKey {
                key_type: concat!("RSA-private-", "2048").into(),
                bit_length: Some(2048),
                offset: format!("0x{offset:X}"),
                confidence: key_confidence(false, false),
                fingerprint: Some(key_fingerprint(cap.as_bytes())),
                pem_data: None,
                validated: false,
                blob_format: None,
                public_exponent: None,
                modulus_bytes: None,
                artifact_data: None,
                artifact_extension: None,
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            });
        }
    }

    // Vendor RSA blobs (BgIAAA pattern — NETGEAR/TP-Link updaters)
    let parsed_vendor_blobs = find_ms_publickeyblob_base64_blobs(data)
        .into_iter()
        .map(|blob| (blob.offset, blob.parsed))
        .collect::<BTreeMap<_, _>>();
    if let Ok(re) = regex::bytes::Regex::new(r"(BgIAAA[A-Za-z0-9+/=]{180,400})") {
        for cap in re.find_iter(data) {
            let offset = cap.start();
            let parsed = parsed_vendor_blobs.get(&offset);
            let bit_length = parsed.map(|blob| blob.bit_length).or_else(|| {
                if cap.as_bytes().len() > 240 {
                    Some(2048)
                } else {
                    Some(1024)
                }
            });
            let fingerprint_data = parsed
                .map(|blob| blob.raw.as_slice())
                .unwrap_or_else(|| cap.as_bytes());
            keys.push(EmbeddedKey {
                key_type: "vendor-RSA-blob".into(),
                bit_length,
                offset: format!("0x{offset:X}"),
                confidence: key_confidence(false, true),
                fingerprint: Some(key_fingerprint(fingerprint_data)),
                pem_data: parsed.map(|blob| blob.pem_data.clone()),
                validated: parsed.is_some(),
                blob_format: parsed.map(|_| "ms-publickeyblob".into()),
                public_exponent: parsed.map(|blob| blob.public_exponent),
                modulus_bytes: parsed.map(|blob| blob.modulus_bytes),
                artifact_data: parsed.map(|blob| blob.raw.clone()),
                artifact_extension: parsed.map(|_| "publickeyblob".into()),
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            });
        }
    }

    keys.extend(
        find_ascii_hex_aes_keys(data, has_symmetric_crypto)
            .into_iter()
            .map(|key| EmbeddedKey {
                key_type: format!("AES-{}-hex", key.bit_length),
                bit_length: Some(key.bit_length),
                offset: format!("0x{:X}", key.offset),
                confidence: key.confidence,
                fingerprint: Some(key_fingerprint(&key.decoded)),
                pem_data: None,
                validated: key.validated,
                blob_format: None,
                public_exponent: None,
                modulus_bytes: None,
                artifact_data: None,
                artifact_extension: None,
                referenced_by: None,
                trust_path_relevance: None,
                reason: None,
                also_seen_in: Vec::new(),
            }),
    );
    keys
}

fn key_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn key_confidence(validated: bool, is_vendor_blob: bool) -> String {
    if is_vendor_blob {
        return "context-only".into();
    }
    if validated {
        "confirmed".into()
    } else {
        "probable".into()
    }
}

/// Format a raw base64 string into PEM with 64-char line wrapping.
fn format_pem(label: &str, base64_str: &str) -> String {
    let wrapped: String = base64_str
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----")
}

/// Validate a PEM key using openssl.
fn validate_key_with_openssl(pem: &str, key_type: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let child = match key_type {
        "rsa" => Command::new("openssl")
            .args(["rsa", "-check", "-noout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(),
        "public" => Command::new("openssl")
            .args(["rsa", "-pubin", "-noout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(),
        _ => return false,
    };

    match child {
        Ok(mut c) => {
            if let Some(stdin) = c.stdin.as_mut() {
                let _ = stdin.write_all(pem.as_bytes());
            }
            c.wait().map(|s| s.success()).unwrap_or(false)
        }
        Err(_) => false,
    }
}

pub(crate) fn infer_rootfs_context(file: &Path) -> Option<(PathBuf, String)> {
    let parent = file.parent()?;
    for ancestor in parent.ancestors() {
        let basename = ancestor.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(basename, "bin" | "sbin" | "usr" | "lib") {
            continue;
        }
        let relative = file.strip_prefix(ancestor).ok()?;
        let normalized = format!("/{}", relative.to_string_lossy().replace('\\', "/"));
        if is_rootfs_binary_path(&normalized) {
            return Some((ancestor.to_path_buf(), normalized));
        }
    }
    None
}

fn is_rootfs_binary_path(path: &str) -> bool {
    [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/lib/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

fn is_elf(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

pub(crate) fn collect_rootfs_elfs(rootfs: &Path) -> Vec<PathBuf> {
    let mut elfs = Vec::new();
    for dir in ["bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib"] {
        let full = rootfs.join(dir);
        if !full.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(full)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if path.is_file() && is_elf(path) {
                elfs.push(path.to_path_buf());
            }
        }
    }
    elfs
}

fn scan_rootfs_key_reuse(
    rootfs: &Path,
    binary_path: &str,
    current_keys: &[EmbeddedKey],
) -> BTreeMap<String, Vec<String>> {
    let fingerprints: HashSet<String> = current_keys
        .iter()
        .filter_map(|key| key.fingerprint.clone())
        .collect();
    if fingerprints.is_empty() {
        return BTreeMap::new();
    }

    let mut seen_in: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for elf in collect_rootfs_elfs(rootfs) {
        let Ok(relative) = elf.strip_prefix(rootfs) else {
            continue;
        };
        let relative = format!("/{}", relative.to_string_lossy().replace('\\', "/"));
        if relative == binary_path {
            continue;
        }
        let Ok(data) = std::fs::read(&elf) else {
            continue;
        };
        for key in extract_keys(&data) {
            let Some(fingerprint) = key.fingerprint else {
                continue;
            };
            if fingerprints.contains(&fingerprint) {
                seen_in
                    .entry(fingerprint)
                    .or_default()
                    .push(relative.clone());
            }
        }
    }
    for values in seen_in.values_mut() {
        values.sort();
        values.dedup();
    }
    seen_in
}

pub(crate) fn build_trust_context_for_binary(
    report: &TrustBoundaryReport,
    binary_path: &str,
) -> Option<CryptoTrustContext> {
    let trust_map = build_trust_map_json_report(report);
    let governing = trust_map.governing_update_path.as_ref();
    let governing_path = governing.map(|candidate| candidate.path.clone());
    let governing_score = governing.map(|candidate| candidate.update_path_score);
    let governing_libs = governing
        .map(|candidate| candidate.linked_libraries.clone())
        .unwrap_or_default();

    let matching_candidate = trust_map
        .candidates
        .iter()
        .find(|candidate| candidate.path == binary_path);

    if let Some(candidate) = matching_candidate {
        if candidate.on_governing_path {
            return Some(CryptoTrustContext {
                rootfs_path: report.rootfs_path.clone(),
                binary_path: binary_path.into(),
                governing_update_binary: governing_path,
                candidate_role: Some(candidate.candidate_role.clone()),
                candidate_classification: Some(candidate.candidate_classification.clone()),
                score: Some(candidate.score),
                update_path_score: Some(candidate.update_path_score),
                path_confidence: Some(candidate.path_confidence.clone()),
                tier_counts: Some(candidate.tier_counts.clone()),
                negative_evidence: candidate.negative_evidence.clone(),
                why: candidate.why.clone(),
                trust_path_relevance: "high".into(),
                reason: "binary is itself on the governing updater path".into(),
                evidence: candidate.evidence.clone(),
            });
        }
    }

    let linked_from_governing_path = linked_from_governing_path(
        binary_path,
        governing_path.as_deref(),
        &governing_libs,
        &report.dependency_chains,
    );

    if linked_from_governing_path {
        let mut evidence = vec![fat_taint::recon::trust_boundary::Evidence {
            tier: "linked-dependency".into(),
            kind: "library-link".into(),
            strength: "medium".into(),
            detail: "binary is linked directly from the governing updater path".into(),
        }];
        if let Some(candidate) = matching_candidate {
            evidence.extend(candidate.evidence.iter().take(2).cloned());
        }
        let linked_summary = matching_candidate
            .as_ref()
            .map(|candidate| {
                (
                    Some(candidate.candidate_role.clone()),
                    Some(candidate.candidate_classification.clone()),
                    Some(candidate.score),
                    Some(candidate.path_confidence.clone()),
                    Some(candidate.tier_counts.clone()),
                    candidate.negative_evidence.clone(),
                    candidate.why.clone(),
                )
            })
            .unwrap_or_else(|| {
                (
                    None,
                    Some("supporting-boundary".into()),
                    Some(governing_score.unwrap_or(0.45).max(0.45)),
                    Some("medium".into()),
                    Some(TrustTierCounts {
                        linked_dependency: 1,
                        ..TrustTierCounts::default()
                    }),
                    vec!["not on the governing updater path".into()],
                    vec!["binary is linked directly from the governing updater path".into()],
                )
            });
        return Some(CryptoTrustContext {
            rootfs_path: report.rootfs_path.clone(),
            binary_path: binary_path.into(),
            governing_update_binary: governing_path,
            candidate_role: linked_summary.0,
            candidate_classification: linked_summary.1,
            score: linked_summary.2,
            update_path_score: governing_score,
            path_confidence: linked_summary.3,
            tier_counts: linked_summary.4,
            negative_evidence: linked_summary.5,
            why: linked_summary.6,
            trust_path_relevance: "medium".into(),
            reason: "binary is linked from the governing updater path".into(),
            evidence,
        });
    }

    matching_candidate.map(|candidate| CryptoTrustContext {
        rootfs_path: report.rootfs_path.clone(),
        binary_path: binary_path.into(),
        governing_update_binary: governing_path,
        candidate_role: Some(candidate.candidate_role.clone()),
        candidate_classification: Some(candidate.candidate_classification.clone()),
        score: Some(candidate.score),
        update_path_score: Some(candidate.update_path_score),
        path_confidence: Some(candidate.path_confidence.clone()),
        tier_counts: Some(candidate.tier_counts.clone()),
        negative_evidence: candidate.negative_evidence.clone(),
        why: candidate.why.clone(),
        trust_path_relevance: "low".into(),
        reason: "binary is not reachable from the governing updater path".into(),
        evidence: candidate.evidence.clone(),
    })
}

fn trust_context_for_file(file: &Path) -> Option<CryptoTrustContext> {
    let (rootfs, binary_path) = infer_rootfs_context(file)?;
    let report = analyze_rootfs(&rootfs).ok()?;
    build_trust_context_for_binary(&report, &binary_path)
}

fn annotate_keys_with_trust_context(
    keys: &mut [EmbeddedKey],
    trust_context: Option<&CryptoTrustContext>,
    default_reference: &str,
    key_reuse: &BTreeMap<String, Vec<String>>,
) {
    for key in keys {
        key.referenced_by = Some(default_reference.to_string());
        if let Some(fingerprint) = &key.fingerprint {
            key.also_seen_in = key_reuse.get(fingerprint).cloned().unwrap_or_default();
        }
        if let Some(context) = trust_context {
            let reused_with_governing_path = context
                .governing_update_binary
                .as_ref()
                .is_some_and(|governing| key.also_seen_in.iter().any(|path| path == governing));
            if reused_with_governing_path {
                key.trust_path_relevance = Some("medium".into());
                key.reason =
                    Some("same key material also appears in the governing updater path".into());
            } else {
                key.trust_path_relevance = Some(context.trust_path_relevance.clone());
                key.reason = Some(context.reason.clone());
            }
        }
    }
}

// ── Public entry point ─────────────────────────────────────────────────────

pub fn run(file: &Path, json_output: bool, output_dir: Option<&Path>, full: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file does not exist or is not a file: {}", file.display()).into());
    }

    if json_output {
        eprintln!("Crypto analysis: {}", file.display());
    }

    let report = analyze_crypto(file)?;
    let written_artifacts = output_dir
        .map(|dir| write_embedded_key_artifacts(&report, dir))
        .transpose()?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if let Some(written) = written_artifacts {
            eprintln!(
                "wrote key artifacts: {} to {}",
                written.artifacts.len(),
                written.output_dir.display()
            );
        }
    } else {
        render_report(&report, full);
        if let Some(written) = written_artifacts {
            println!();
            println!("Key artifact export");
            println!("  output_dir: {}", written.output_dir.display());
            println!("  wrote key artifacts: {}", written.artifacts.len());
            println!("  manifest: {}", written.manifest_path.display());
            for artifact in written.artifacts {
                println!(
                    "    {}  {}  validated: {}",
                    artifact.key_type,
                    artifact.path.display(),
                    if artifact.validated { "yes" } else { "no" }
                );
            }
        }
    }

    Ok(())
}

struct WrittenKeyArtifacts {
    output_dir: PathBuf,
    manifest_path: PathBuf,
    artifacts: Vec<WrittenKeyArtifact>,
}

struct WrittenKeyArtifact {
    path: PathBuf,
    key_type: String,
    validated: bool,
}

fn write_embedded_key_artifacts(
    report: &CryptoReport,
    output_dir: &Path,
) -> DynResult<WrittenKeyArtifacts> {
    fs::create_dir_all(output_dir)?;

    let mut per_type_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut written = Vec::new();
    let mut manifest_records = Vec::new();

    for key in &report.embedded_keys {
        if key.pem_data.is_none() && key.artifact_data.is_none() {
            continue;
        }
        let basename = artifact_basename(&key.key_type);
        let counter = per_type_counts.entry(basename.clone()).or_insert(0);
        *counter += 1;
        let index = *counter;

        if let Some(raw_data) = key.artifact_data.as_deref() {
            let extension = key
                .artifact_extension
                .as_deref()
                .filter(|extension| {
                    extension
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
                .unwrap_or("bin");
            let filename = format!("{basename}_{index}.{extension}");
            let path = output_dir.join(&filename);
            fs::write(&path, raw_data)?;

            written.push(WrittenKeyArtifact {
                path,
                key_type: key.key_type.clone(),
                validated: key.validated,
            });
            manifest_records.push(KeyArtifactRecord {
                filename,
                key_type: key.key_type.clone(),
                bit_length: key.bit_length,
                offset: key.offset.clone(),
                fingerprint: key.fingerprint.clone(),
                validated: key.validated,
                confidence: key.confidence.clone(),
                artifact_format: key.blob_format.clone().or_else(|| Some("raw".into())),
            });
        }

        if let Some(pem_data) = key.pem_data.as_deref() {
            let filename = format!("{basename}_{index}.pem");
            let path = output_dir.join(&filename);
            fs::write(&path, format!("{pem_data}\n"))?;

            written.push(WrittenKeyArtifact {
                path,
                key_type: key.key_type.clone(),
                validated: key.validated,
            });
            manifest_records.push(KeyArtifactRecord {
                filename,
                key_type: key.key_type.clone(),
                bit_length: key.bit_length,
                offset: key.offset.clone(),
                fingerprint: key.fingerprint.clone(),
                validated: key.validated,
                confidence: key.confidence.clone(),
                artifact_format: Some("pem".into()),
            });
        }
    }

    let manifest = KeyArtifactManifest {
        schema_version: "crypto-key-artifact-export/v1",
        source_binary: report.binary.clone(),
        artifacts: manifest_records,
    };
    let manifest_path = output_dir.join("crypto_extract_manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    Ok(WrittenKeyArtifacts {
        output_dir: output_dir.to_path_buf(),
        manifest_path,
        artifacts: written,
    })
}

fn artifact_basename(key_type: &str) -> String {
    let mut name = String::new();
    for ch in key_type.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_lowercase());
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name.trim_matches('_');
    if name.is_empty() {
        "key".into()
    } else {
        name.into()
    }
}

/// Run the full crypto analysis pipeline.
pub(crate) fn analyze_crypto(file: &Path) -> DynResult<CryptoReport> {
    let mut report = analyze_crypto_shallow(file)?;
    let inferred_rootfs = infer_rootfs_context(file);
    let trust_context = trust_context_for_file(file);
    let key_reference = trust_context
        .as_ref()
        .map(|context| context.binary_path.as_str())
        .unwrap_or(&report.binary);
    let key_reuse = inferred_rootfs
        .as_ref()
        .map(|(rootfs, binary_path)| {
            scan_rootfs_key_reuse(rootfs, binary_path, &report.embedded_keys)
        })
        .unwrap_or_default();
    annotate_keys_with_trust_context(
        &mut report.embedded_keys,
        trust_context.as_ref(),
        key_reference,
        &key_reuse,
    );
    report.trust_context = trust_context;
    refresh_crypto_contract_fields(&mut report);
    Ok(report)
}

pub(crate) fn analyze_crypto_shallow(file: &Path) -> DynResult<CryptoReport> {
    let raw_imports = r2::imports(file).map_err(|e| -> Box<dyn Error> { e.into() })?;
    let raw_exports = r2::exports(file).map_err(|e| -> Box<dyn Error> { e.into() })?;
    let libs = r2::linked_libraries(file).map_err(|e| -> Box<dyn Error> { e.into() })?;

    let crypto_imports = classify_imports(&raw_imports);
    let crypto_exports = classify_exports(&raw_exports);
    let external_crypto_library = detect_crypto_library(&libs);
    let classification =
        classify_crypto(&crypto_imports, &crypto_exports, &external_crypto_library);
    let mut weaknesses =
        detect_weaknesses(&crypto_imports, &crypto_exports, &external_crypto_library);
    weaknesses.extend(detect_decompilation_weaknesses(
        file,
        &raw_imports,
        &raw_exports,
    ));

    let data = std::fs::read(file).unwrap_or_default();
    let embedded_keys = extract_keys_for_crypto_context(&data, &crypto_imports);

    let binary = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.display().to_string());

    let mut report = CryptoReport {
        schema_version: schema_versions::CRYPTO_ARTIFACT_ANALYSIS_V1,
        binary,
        confidence: String::new(),
        reason: String::new(),
        evidence: Vec::new(),
        crypto_imports,
        crypto_exports,
        classification,
        external_crypto_library,
        weaknesses,
        trust_context: None,
        embedded_keys,
    };
    refresh_crypto_contract_fields(&mut report);
    Ok(report)
}

fn refresh_crypto_contract_fields(report: &mut CryptoReport) {
    let confidence = report
        .embedded_keys
        .iter()
        .map(|key| confidence_rank(&key.confidence))
        .max()
        .map(confidence_label)
        .unwrap_or_else(|| {
            if report.crypto_imports.is_empty() && report.crypto_exports.is_empty() {
                "context-only".into()
            } else {
                "possible".into()
            }
        });

    let reason = if let Some(context) = &report.trust_context {
        if !report.embedded_keys.is_empty() {
            format!(
                "{}; {} embedded artifact(s) observed",
                context.reason,
                report.embedded_keys.len()
            )
        } else {
            context.reason.clone()
        }
    } else if !report.embedded_keys.is_empty() {
        format!(
            "{} embedded artifact(s) observed without trust-path context",
            report.embedded_keys.len()
        )
    } else if !report.weaknesses.is_empty() {
        report.weaknesses[0].evidence.clone()
    } else if let Some(line) = report.classification.evidence.first() {
        line.clone()
    } else {
        "no strong crypto artifact pivot identified".into()
    };

    let mut evidence = report.classification.evidence.clone();
    evidence.extend(
        report
            .weaknesses
            .iter()
            .take(2)
            .map(|weakness| weakness.evidence.clone()),
    );
    if let Some(context) = &report.trust_context {
        evidence.extend(context.why.iter().take(2).cloned());
    }
    if evidence.is_empty() {
        evidence.push("no strong crypto evidence extracted".into());
    }

    report.confidence = confidence;
    report.reason = reason;
    report.evidence = evidence;
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "confirmed" => 3,
        "probable" => 2,
        "possible" => 1,
        _ => 0,
    }
}

fn confidence_label(rank: u8) -> String {
    match rank {
        3 => "confirmed",
        2 => "probable",
        1 => "possible",
        _ => "context-only",
    }
    .into()
}

// ── Text rendering ─────────────────────────────────────────────────────────

fn render_report(report: &CryptoReport, full: bool) {
    let palette = Palette::stdout();
    if !palette.enabled() {
        render_report_plain(report);
        return;
    }
    render_report_panel(report, &palette, full);
}

/// Legacy plain renderer (piped output, `NO_COLOR`, JSON paths). Kept
/// verbatim so redirected output stays byte-identical and uncapped.
fn render_report_plain(report: &CryptoReport) {
    let palette = Palette::stdout();
    println!(
        "{}  {}",
        palette.heading("Crypto analysis"),
        palette.code(&report.binary)
    );
    println!(
        "  {}  {}  {}",
        palette.kv("confidence", palette.status_word(&report.confidence)),
        palette.kv("role", palette.info(&report.classification.role)),
        palette.kv(
            "library",
            report
                .external_crypto_library
                .as_deref()
                .map(|lib| palette.good(lib))
                .unwrap_or_else(|| palette.muted("none"))
        )
    );
    println!("  {}", palette.kv("reason", &report.reason));
    println!();

    println!("{}", palette.heading("Crypto surface"));
    if !report.crypto_imports.is_empty() {
        println!(
            "  {}",
            palette.kv("imports", report.crypto_imports.len().to_string())
        );
        for imp in &report.crypto_imports {
            println!(
                "    {:<11} {}",
                palette.muted(format!("[{:<9}]", imp.category)),
                palette.code(&imp.name)
            );
        }
    } else {
        println!("  {}", palette.kv("imports", palette.muted("none")));
    }
    if !report.crypto_exports.is_empty() {
        println!(
            "  {}",
            palette.kv("exports", report.crypto_exports.len().to_string())
        );
        for exp in &report.crypto_exports {
            println!(
                "    {:<11} {} {}",
                palette.muted(format!("[{:<9}]", exp.category)),
                palette.code(&exp.name),
                palette.muted(format!("size={}", exp.size))
            );
        }
    } else {
        println!("  {}", palette.kv("exports", palette.muted("none")));
    }
    println!();

    if let Some(context) = &report.trust_context {
        println!("{}", palette.heading("Trust context"));
        println!("  {}", palette.kv("binary path", &context.binary_path));
        if let Some(governing) = &context.governing_update_binary {
            println!("  {}", palette.kv("governing path", governing));
        }
        if let Some(role) = &context.candidate_role {
            println!("  {}", palette.kv("candidate role", role));
        }
        if let Some(classification) = &context.candidate_classification {
            println!("  {}", palette.kv("classification", classification));
        }
        println!(
            "  {}",
            palette.kv(
                "relevance",
                trust_relevance_label(&palette, &context.trust_path_relevance)
            )
        );
        println!("  {}", palette.kv("reason", &context.reason));
        if let Some(score) = context.score {
            println!("  {}", palette.kv("score", format!("{score:.2}")));
        }
        if let Some(score) = context.update_path_score {
            println!(
                "  {}",
                palette.kv("update-path score", format!("{score:.2}"))
            );
        }
        if let Some(path_confidence) = &context.path_confidence {
            println!("  {}", palette.kv("path confidence", path_confidence));
        }
        if !context.negative_evidence.is_empty() {
            println!("  {}", palette.key("negative evidence"));
            for item in context.negative_evidence.iter().take(3) {
                println!("    {} {}", palette.bullet("-"), item);
            }
        }
        for evidence in context.evidence.iter().take(3) {
            println!(
                "  {} {}",
                palette.kv("evidence", palette.muted(format!("[{}]", evidence.tier))),
                evidence.detail
            );
        }
        println!();
    }

    if !report.weaknesses.is_empty() {
        println!(
            "{}",
            palette.heading(format!("Weaknesses ({})", report.weaknesses.len()))
        );
        for w in &report.weaknesses {
            let func = w
                .function
                .as_deref()
                .map(|f| format!(" ({f})"))
                .unwrap_or_default();
            println!(
                "  {} {}{}",
                severity_label(&palette, &w.severity),
                palette.warn(&w.weakness),
                func
            );
            println!("    {}", wrapped_detail(&w.evidence, 4));
        }
    } else {
        println!(
            "{}  {}",
            palette.heading("Weaknesses"),
            palette.good("none detected")
        );
    }
    println!();

    if !report.embedded_keys.is_empty() {
        println!(
            "{}",
            palette.heading(format!("Embedded keys ({})", report.embedded_keys.len()))
        );
        for key in &report.embedded_keys {
            println!(
                "  {}  at {}",
                palette.code(&key.key_type),
                palette.info(&key.offset)
            );
            println!(
                "    {}  {}  {}",
                palette.kv(
                    "bits",
                    key.bit_length
                        .map(|bit_length| bit_length.to_string())
                        .unwrap_or_else(|| "unknown".into())
                ),
                palette.kv(
                    "validated",
                    if key.validated {
                        palette.good("yes")
                    } else {
                        palette.warn("no")
                    }
                ),
                palette.kv("confidence", palette.status_word(&key.confidence))
            );
            if let Some(reference) = &key.referenced_by {
                println!("    {}", palette.kv("referenced_by", reference));
            }
            if let Some(blob_format) = &key.blob_format {
                println!("    {}", palette.kv("blob_format", blob_format));
            }
            if let Some(public_exponent) = key.public_exponent {
                println!(
                    "    {}",
                    palette.kv("public_exponent", public_exponent.to_string())
                );
            }
            if let Some(modulus_bytes) = key.modulus_bytes {
                println!(
                    "    {}",
                    palette.kv("modulus_bytes", modulus_bytes.to_string())
                );
            }
            if !key.also_seen_in.is_empty() {
                println!(
                    "    {}",
                    palette.kv(
                        "key reuse",
                        format!(
                            "also seen in {} other binary{}",
                            key.also_seen_in.len(),
                            if key.also_seen_in.len() == 1 {
                                ""
                            } else {
                                "ies"
                            }
                        )
                    )
                );
                for path in &key.also_seen_in {
                    println!("      {}", palette.kv("also_seen_in", path));
                }
            }
            if let Some(relevance) = &key.trust_path_relevance {
                println!(
                    "    {}",
                    palette.kv(
                        "trust_path_relevance",
                        trust_relevance_label(&palette, relevance)
                    )
                );
            }
            if let Some(reason) = &key.reason {
                println!("    {}", palette.kv("reason", reason));
            }
        }
    } else {
        println!(
            "{}  {}",
            palette.heading("Embedded keys"),
            palette.muted("none found")
        );
    }
}

/// Panel-mode cap for list-like sections. `--full` disables capping; plain
/// piped output is never capped.
const PANEL_CAP: usize = 12;

/// Append `items` to `lines`, capped at `PANEL_CAP` unless `full`; the
/// overflow becomes a dimmed `… N more` pointer at `--full`.
fn push_capped(lines: &mut Vec<String>, palette: &Palette, full: bool, items: Vec<String>) {
    if full || items.len() <= PANEL_CAP {
        lines.extend(items);
        return;
    }
    let overflow = items.len() - PANEL_CAP;
    lines.extend(items.into_iter().take(PANEL_CAP));
    lines.push(palette.muted(format!("… {overflow} more — use --full to expand")));
}

/// Decode rabin2's escaped demangled-Rust form for display: `$LT$`→`<`,
/// `$GT$`→`>`, `$u20$`→space, `$u7b$`/`$u7d$`→braces, `..`→`::`.
fn decode_r2_escapes(name: &str) -> String {
    name.replace("$LT$", "<")
        .replace("$GT$", ">")
        .replace("$u20$", " ")
        .replace("$u7b$", "{")
        .replace("$u7d$", "}")
        .replace("..", "::")
}

/// Demangled, length-limited display form for a (possibly mangled) symbol.
/// Mach-O prefixes one extra underscore (`__ZN...`); legacy Rust hash tails
/// (`::h<16hex>()`) are dropped, and un-demangleable names are truncated.
fn display_symbol(name: &str) -> String {
    const MAX: usize = 72;
    let candidate = name
        .strip_prefix("__Z")
        .map(|rest| format!("_Z{rest}"))
        .unwrap_or_else(|| name.to_string());
    let demangled = crate::r2_triage_cmd::demangle_cpp_symbol(&candidate);
    let mut text = if demangled == candidate {
        name.to_string()
    } else {
        demangled
    };
    if text.contains('$') || text.contains("..") {
        text = decode_r2_escapes(&text);
    }
    if let Some(pos) = text.rfind("::") {
        let after = &text[pos + 2..];
        let tail = after.strip_suffix("()").unwrap_or(after);
        if tail.len() == 17
            && tail.starts_with('h')
            && tail[1..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            text = format!("{}()", &text[..pos]);
        }
    }
    if text.chars().count() > MAX {
        let truncated: String = text.chars().take(MAX).collect();
        format!("{truncated}…")
    } else {
        text
    }
}

/// Shared design-language severity tag (CRIT/HIGH/MED/LOW/INFO) for a
/// plain-string weakness severity.
fn severity_tag_label(palette: &Palette, severity: &str) -> String {
    use fat_core::finding::FindingSeverity;
    let severity = match severity.to_ascii_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    };
    palette.severity_tag(&severity)
}

/// Panel-mode report body (colored TTY only; plain output stays verbatim).
fn render_report_panel(report: &CryptoReport, palette: &Palette, full: bool) {
    // Header block followed by the first surface heading.
    let mut lines = vec![
        palette.kv("confidence", palette.status_word(&report.confidence)),
        palette.kv("role", palette.info(&report.classification.role)),
        palette.kv(
            "library",
            report
                .external_crypto_library
                .as_deref()
                .map(|lib| palette.good(lib))
                .unwrap_or_else(|| palette.muted("none")),
        ),
        palette.kv("reason", palette.info(&report.reason)),
        String::new(),
        palette.heading("Crypto surface"),
    ];
    if report.crypto_imports.is_empty() {
        lines.push(palette.muted("imports: none"));
    } else {
        lines.push(palette.muted(format!("imports ({}):", report.crypto_imports.len())));
        let items = report
            .crypto_imports
            .iter()
            .map(|imp| {
                format!(
                    "  {} {} {}",
                    palette.dot_ok(),
                    palette.muted(format!("[{:<9}]", imp.category)),
                    palette.code(display_symbol(&imp.name)),
                )
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    if report.crypto_exports.is_empty() {
        lines.push(palette.muted("exports: none"));
    } else {
        lines.push(palette.muted(format!("exports ({}):", report.crypto_exports.len())));
        let items = report
            .crypto_exports
            .iter()
            .map(|exp| {
                format!(
                    "  {} {} {} {}",
                    palette.dot_ok(),
                    palette.muted(format!("[{:<9}]", exp.category)),
                    palette.code(display_symbol(&exp.name)),
                    palette.muted(format!("size={}", exp.size)),
                )
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    lines.push(String::new());

    // Trust context
    if let Some(context) = &report.trust_context {
        lines.push(palette.heading("Trust context"));
        lines.push(palette.kv("binary path", &context.binary_path));
        if let Some(governing) = &context.governing_update_binary {
            lines.push(palette.kv("governing path", governing));
        }
        if let Some(role) = &context.candidate_role {
            lines.push(palette.kv("candidate role", role));
        }
        if let Some(classification) = &context.candidate_classification {
            lines.push(palette.kv("classification", classification));
        }
        lines.push(palette.kv(
            "relevance",
            trust_relevance_label(palette, &context.trust_path_relevance),
        ));
        lines.push(palette.kv("reason", palette.info(&context.reason)));
        if let Some(score) = context.score {
            lines.push(palette.kv("score", format!("{score:.2}")));
        }
        if let Some(score) = context.update_path_score {
            lines.push(palette.kv("update-path score", format!("{score:.2}")));
        }
        if let Some(path_confidence) = &context.path_confidence {
            lines.push(palette.kv("path confidence", path_confidence));
        }
        for item in context.negative_evidence.iter().take(3) {
            lines.push(palette.muted(format!("  - {item}")));
        }
        for evidence in context.evidence.iter().take(3) {
            lines.push(palette.muted(format!("  [{}] {}", evidence.tier, evidence.detail)));
        }
        lines.push(String::new());
    }

    // Weaknesses
    if report.weaknesses.is_empty() {
        lines.push(palette.heading("Weaknesses"));
        lines.push(palette.good("none detected"));
    } else {
        lines.push(palette.heading(format!("Weaknesses ({})", report.weaknesses.len())));
        let items = report
            .weaknesses
            .iter()
            .map(|w| {
                let detail = match w.function.as_deref() {
                    Some(function) => {
                        format!("({}) — {}", display_symbol(function), w.evidence)
                    }
                    None => w.evidence.clone(),
                };
                format!(
                    "  {} {} {}",
                    severity_tag_label(palette, &w.severity),
                    palette.warn(&w.weakness),
                    palette.muted(&detail),
                )
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
        lines.push(String::new());
    }

    // Embedded keys
    if report.embedded_keys.is_empty() {
        lines.push(palette.heading("Embedded keys"));
        lines.push(palette.muted("none found"));
    } else {
        lines.push(palette.heading(format!("Embedded keys ({})", report.embedded_keys.len())));
        let items = report
            .embedded_keys
            .iter()
            .map(|key| {
                let mut line = format!(
                    "  {} {} at {}",
                    if key.validated {
                        palette.dot_ok()
                    } else {
                        palette.dot_warn()
                    },
                    palette.code(&key.key_type),
                    palette.muted(&key.offset),
                );
                line.push_str(&palette.muted(format!(
                    "  bits={} validated={} confidence={}",
                    key.bit_length
                        .map(|bit_length| bit_length.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    if key.validated { "yes" } else { "no" },
                    key.confidence,
                )));
                if !key.also_seen_in.is_empty() {
                    line.push_str(&palette.muted(format!(
                        "  reuse: {} other binary{}",
                        key.also_seen_in.len(),
                        if key.also_seen_in.len() == 1 {
                            ""
                        } else {
                            "ies"
                        },
                    )));
                }
                line
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
    }

    println!(
        "{}",
        palette.panel(&format!("fat crypto · {}", report.binary), &lines)
    );
}

fn severity_label(palette: &Palette, severity: &str) -> String {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => palette.bad(severity.to_ascii_uppercase()),
        "medium" => palette.warn("MEDIUM"),
        "low" => palette.info("LOW"),
        _ => palette.muted(severity.to_ascii_uppercase()),
    }
}

fn trust_relevance_label(palette: &Palette, relevance: &str) -> String {
    match relevance.to_ascii_lowercase().as_str() {
        "high" => palette.good(relevance),
        "medium" => palette.warn(relevance),
        "low" => palette.muted(relevance),
        _ => palette.info(relevance),
    }
}

fn wrapped_detail(text: &str, indent: usize) -> String {
    const WIDTH: usize = 88;
    if text.len() <= WIDTH {
        return text.to_string();
    }

    let prefix = " ".repeat(indent);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > WIDTH {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }

    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line
            } else {
                format!("{prefix}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fat_taint::recon::r2::{Export, FunctionInfo, Import};

    // ── classify_imports ───────────────────────────────────────────────

    #[test]
    fn test_classify_imports_openssl_rsa() {
        let imports = vec![
            Import {
                name: "RSA_private_decrypt".into(),
            },
            Import {
                name: "RSA_size".into(),
            },
            Import {
                name: "printf".into(),
            },
        ];
        let classified = classify_imports(&imports);
        assert_eq!(classified.len(), 2);
        assert_eq!(classified[0].name, "RSA_private_decrypt");
        assert_eq!(classified[0].category, "asymmetric");
        assert_eq!(classified[1].name, "RSA_size");
        assert_eq!(classified[1].category, "asymmetric");
    }

    #[test]
    fn test_classify_imports_mixed_categories() {
        let imports = vec![
            Import {
                name: "AES_set_encrypt_key".into(),
            },
            Import {
                name: "SHA256".into(),
            },
            Import {
                name: "RAND_bytes".into(),
            },
            Import {
                name: "PKCS5_PBKDF2_HMAC".into(),
            },
        ];
        let classified = classify_imports(&imports);
        assert_eq!(classified.len(), 4);
        assert_eq!(classified[0].category, "symmetric");
        assert_eq!(classified[1].category, "hash");
        assert_eq!(classified[2].category, "random");
        assert_eq!(classified[3].category, "kdf");
    }

    #[test]
    fn test_classify_imports_no_crypto() {
        let imports = vec![
            Import {
                name: "printf".into(),
            },
            Import {
                name: "malloc".into(),
            },
            Import {
                name: "strcpy".into(),
            },
        ];
        let classified = classify_imports(&imports);
        assert!(classified.is_empty());
    }

    #[test]
    fn test_classify_imports_vendor_wrappers() {
        let imports = vec![
            Import {
                name: "AesEncrypt".into(),
            },
            Import {
                name: "AesDecrypt".into(),
            },
            Import {
                name: "rsaVerifySign".into(),
            },
        ];
        let classified = classify_imports(&imports);
        assert_eq!(classified.len(), 3);
        assert_eq!(classified[0].category, "symmetric");
        assert_eq!(classified[1].category, "symmetric");
        assert_eq!(classified[2].category, "asymmetric");
    }

    #[test]
    fn test_classify_imports_mbedtls() {
        let imports = vec![
            Import {
                name: "mbedtls_rsa_pkcs1_decrypt".into(),
            },
            Import {
                name: "mbedtls_sha256".into(),
            },
        ];
        let classified = classify_imports(&imports);
        assert_eq!(classified.len(), 2);
        assert_eq!(classified[0].category, "asymmetric");
        assert_eq!(classified[1].category, "hash");
    }

    // ── classify_exports ───────────────────────────────────────────────

    #[test]
    fn test_classify_exports_custom_aes() {
        let exports = vec![
            Export {
                name: "AesEncrypt".into(),
                size: 256,
            },
            Export {
                name: "AesDecrypt".into(),
                size: 128,
            },
            Export {
                name: "init_module".into(),
                size: 64,
            },
        ];
        let classified = classify_exports(&exports);
        assert_eq!(classified.len(), 2);
        assert_eq!(classified[0].name, "AesEncrypt");
        assert_eq!(classified[0].category, "symmetric");
        assert_eq!(classified[0].size, 256);
    }

    #[test]
    fn test_classify_exports_no_crypto() {
        let exports = vec![
            Export {
                name: "main".into(),
                size: 512,
            },
            Export {
                name: "httpd_handler".into(),
                size: 128,
            },
        ];
        let classified = classify_exports(&exports);
        assert!(classified.is_empty());
    }

    // ── detect_crypto_library ──────────────────────────────────────────

    #[test]
    fn test_detect_crypto_library_openssl() {
        let libs = vec![
            "libc.so.6".into(),
            "libcrypto.so.1.0.0".into(),
            "libpthread.so.0".into(),
        ];
        assert_eq!(detect_crypto_library(&libs), Some("OpenSSL".into()));
    }

    #[test]
    fn test_detect_crypto_library_libssl() {
        let libs = vec!["libssl.so.1.1".into()];
        assert_eq!(detect_crypto_library(&libs), Some("OpenSSL".into()));
    }

    #[test]
    fn test_detect_crypto_library_mbedtls() {
        let libs = vec!["libmbedtls.so.12".into()];
        assert_eq!(detect_crypto_library(&libs), Some("mbedTLS".into()));
    }

    #[test]
    fn test_detect_crypto_library_mbedcrypto() {
        let libs = vec!["libmbedcrypto.so.3".into()];
        assert_eq!(detect_crypto_library(&libs), Some("mbedTLS".into()));
    }

    #[test]
    fn test_detect_crypto_library_wolfssl() {
        let libs = vec!["libwolfssl.so.24".into()];
        assert_eq!(detect_crypto_library(&libs), Some("wolfSSL".into()));
    }

    #[test]
    fn test_detect_crypto_library_gcrypt() {
        let libs = vec!["libgcrypt.so.20".into()];
        assert_eq!(detect_crypto_library(&libs), Some("libgcrypt".into()));
    }

    #[test]
    fn test_detect_crypto_library_none() {
        let libs = vec!["libc.so.6".into(), "libpthread.so.0".into()];
        assert_eq!(detect_crypto_library(&libs), None);
    }

    #[test]
    fn test_detect_crypto_library_empty() {
        let libs: Vec<String> = vec![];
        assert_eq!(detect_crypto_library(&libs), None);
    }

    // ── classify_crypto ────────────────────────────────────────────────

    #[test]
    fn test_classify_crypto_bounded_string_decryptor() {
        let imports = vec![
            CryptoImport {
                name: "RSA_private_decrypt".into(),
                category: "asymmetric".into(),
            },
            CryptoImport {
                name: "RSA_size".into(),
                category: "asymmetric".into(),
            },
        ];
        let exports = vec![];
        let lib = Some("OpenSSL".into());
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "bounded-string-decryptor");
        assert!(!class.evidence.is_empty());
        assert!(class.evidence[0].contains("RSA decrypt without bulk crypto"));
    }

    #[test]
    fn test_classify_crypto_signature_verifier() {
        let imports = vec![CryptoImport {
            name: "EVP_VerifyFinal".into(),
            category: "asymmetric".into(),
        }];
        let exports = vec![];
        let lib = Some("OpenSSL".into());
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "signature-verifier");
        assert!(class.evidence[0].contains("verification but no decryption"));
    }

    #[test]
    fn test_classify_crypto_firmware_decryptor() {
        let imports = vec![
            CryptoImport {
                name: "RSA_verify".into(),
                category: "asymmetric".into(),
            },
            CryptoImport {
                name: "AES_cbc_encrypt".into(),
                category: "symmetric".into(),
            },
        ];
        let exports = vec![];
        let lib = Some("OpenSSL".into());
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "firmware-decryptor");
        assert!(class.evidence[0].contains("verification and bulk crypto"));
    }

    #[test]
    fn test_classify_crypto_general() {
        let imports = vec![CryptoImport {
            name: "SHA256".into(),
            category: "hash".into(),
        }];
        let exports = vec![];
        let lib = None;
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "general-crypto");
    }

    #[test]
    fn test_classify_crypto_no_crypto() {
        let imports: Vec<CryptoImport> = vec![];
        let exports: Vec<CryptoExport> = vec![];
        let lib = None;
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "no-crypto");
    }

    #[test]
    fn test_classify_crypto_custom_static_evidence() {
        let imports: Vec<CryptoImport> = vec![];
        let exports = vec![CryptoExport {
            name: "AesEncrypt".into(),
            size: 256,
            category: "symmetric".into(),
        }];
        let lib = None;
        let class = classify_crypto(&imports, &exports, &lib);
        assert_eq!(class.role, "general-crypto");
        assert!(class.evidence.iter().any(|e| e.contains("custom/static")));
    }

    // ── detect_weaknesses ──────────────────────────────────────────────

    #[test]
    fn test_weakness_custom_aes_no_standard_library() {
        let imports: Vec<CryptoImport> = vec![];
        let exports = vec![
            CryptoExport {
                name: "AesEncrypt".into(),
                size: 256,
                category: "symmetric".into(),
            },
            CryptoExport {
                name: "AesDecrypt".into(),
                size: 128,
                category: "symmetric".into(),
            },
        ];
        let lib = None;
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses
            .iter()
            .any(|w| w.weakness == "custom-aes-no-standard-library"));
        let custom_aes = weaknesses
            .iter()
            .find(|w| w.weakness == "custom-aes-no-standard-library")
            .unwrap();
        assert_eq!(custom_aes.severity, "high");
    }

    #[test]
    fn test_weakness_custom_aes_not_flagged_with_library() {
        let imports: Vec<CryptoImport> = vec![];
        let exports = vec![CryptoExport {
            name: "AesEncrypt".into(),
            size: 256,
            category: "symmetric".into(),
        }];
        let lib = Some("OpenSSL".into());
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(!weaknesses
            .iter()
            .any(|w| w.weakness == "custom-aes-no-standard-library"));
    }

    #[test]
    fn test_weakness_weak_prng_with_crypto() {
        let imports = vec![
            CryptoImport {
                name: "rand".into(),
                category: "random".into(),
            },
            CryptoImport {
                name: "AES_set_encrypt_key".into(),
                category: "symmetric".into(),
            },
        ];
        let exports: Vec<CryptoExport> = vec![];
        let lib = Some("OpenSSL".into());
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses.iter().any(|w| w.weakness == "weak-prng-rand"));
        let prng = weaknesses
            .iter()
            .find(|w| w.weakness == "weak-prng-rand")
            .unwrap();
        assert_eq!(prng.severity, "medium");
    }

    #[test]
    fn test_weakness_weak_prng_without_crypto_not_flagged() {
        let imports = vec![CryptoImport {
            name: "rand".into(),
            category: "random".into(),
        }];
        let exports: Vec<CryptoExport> = vec![];
        let lib = None;
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(!weaknesses.iter().any(|w| w.weakness == "weak-prng-rand"));
    }

    #[test]
    fn test_weakness_hand_rolled_crypto() {
        let imports: Vec<CryptoImport> = vec![];
        let exports = vec![CryptoExport {
            name: "RSA_verify".into(),
            size: 512,
            category: "asymmetric".into(),
        }];
        let lib = None;
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses
            .iter()
            .any(|w| w.weakness == "hand-rolled-crypto"));
    }

    #[test]
    fn test_weakness_ecb_mode() {
        let imports = vec![CryptoImport {
            name: "AES_ecb_encrypt".into(),
            category: "symmetric".into(),
        }];
        let exports: Vec<CryptoExport> = vec![];
        let lib = Some("OpenSSL".into());
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses
            .iter()
            .any(|w| w.weakness == "potential-ecb-mode"));
    }

    #[test]
    fn test_weakness_des_ecb_mode() {
        let imports = vec![CryptoImport {
            name: "DES_ecb_encrypt".into(),
            category: "symmetric".into(),
        }];
        let exports: Vec<CryptoExport> = vec![];
        let lib = Some("OpenSSL".into());
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses
            .iter()
            .any(|w| w.weakness == "potential-ecb-mode"));
    }

    #[test]
    fn test_weakness_partial_encryption_control_surface() {
        let imports: Vec<CryptoImport> = vec![];
        let exports = vec![CryptoExport {
            name: "IOTC_Set_Partial_Encryption".into(),
            size: 257,
            category: "symmetric".into(),
        }];
        let lib = None;
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses.iter().any(|w| {
            w.weakness == "partial-encryption-control"
                && w.evidence.contains("partial encryption")
                && w.function.as_deref() == Some("IOTC_Set_Partial_Encryption")
        }));
    }

    #[test]
    fn test_detect_decompiled_ecb_block_loop() {
        let decomp = r#"
for (var_ch = 0; var_ch < arg_14h; var_ch = var_ch + 0x10) {
    fcn.00004a40(arg_8h, arg_ch, arg_10h);
    arg_10h = arg_10h + 0x10;
    arg_ch = arg_ch + 0x10;
}
"#;

        let weakness = detect_decompiled_ecb_weakness("AesEncrypt", decomp)
            .expect("ECB loop should be detected");
        assert_eq!(weakness.weakness, "decompiled-ecb-block-loop");
        assert_eq!(weakness.function.as_deref(), Some("AesEncrypt"));
    }

    #[test]
    fn test_detect_decompiled_ecb_skips_iv_chaining_modes() {
        let decomp = r#"
for (i = 0; i < len; i = i + 0x10) {
    xor_block(buf + i, iv);
    AES_encrypt(ctx, out + i, buf + i);
    memcpy(iv, out + i, 16);
}
"#;

        assert!(detect_decompiled_ecb_weakness("AesEncrypt", decomp).is_none());
    }

    #[test]
    fn test_detect_decompiled_weak_random_id_width() {
        let decomp = r#"
iVar1 = rand();
var_ah = iVar1 + iVar1 / 0xffff;
if (var_ah == 0) var_ah = 1;
return var_ah;
"#;

        let weakness = detect_decompiled_weak_prng_weakness("GenShortRandomID", decomp)
            .expect("rand truncation should be detected");
        assert_eq!(weakness.weakness, "weak-prng-short-random-id");
        assert_eq!(weakness.function.as_deref(), Some("GenShortRandomID"));
    }

    #[test]
    fn test_select_decompile_targets_includes_internal_prng_functions() {
        let imports = vec![Import {
            name: "rand".into(),
        }];
        let exports = vec![];
        let functions = vec![FunctionInfo {
            name: "sym.gen_short_random_id".into(),
            address: 0x2200,
            size: 120,
            basic_blocks: 4,
            cyclomatic_complexity: 2,
        }];

        let targets = select_decompile_targets(&imports, &exports, &functions);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "gen_short_random_id");
        assert_eq!(targets[0].addr, "0x2200");
    }

    #[test]
    fn test_detects_partial_encryption_control_surface() {
        let imports = vec![CryptoImport {
            name: "rand".into(),
            category: "random".into(),
        }];
        let exports = vec![CryptoExport {
            name: "IOTC_Set_Partial_Encryption".into(),
            size: 64,
            category: "symmetric".into(),
        }];
        let lib = None;
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);

        let partial = weaknesses
            .iter()
            .find(|w| w.weakness == "partial-encryption-control");
        assert!(partial.is_some());
        assert_eq!(
            partial.and_then(|w| w.function.as_deref()),
            Some("IOTC_Set_Partial_Encryption")
        );
    }

    #[test]
    fn test_weakness_no_weaknesses_clean_binary() {
        let imports = vec![
            CryptoImport {
                name: "AES_cbc_encrypt".into(),
                category: "symmetric".into(),
            },
            CryptoImport {
                name: "RAND_bytes".into(),
                category: "random".into(),
            },
        ];
        let exports: Vec<CryptoExport> = vec![];
        let lib = Some("OpenSSL".into());
        let weaknesses = detect_weaknesses(&imports, &exports, &lib);
        assert!(weaknesses.is_empty());
    }

    // ── extract_keys ───────────────────────────────────────────────────

    #[test]
    fn test_extract_keys_no_keys_in_text() {
        let data = b"Hello, this is just some normal binary data without any keys.";
        let keys = extract_keys(data);
        assert!(keys.is_empty());
    }

    #[test]
    fn test_extract_keys_finds_miic_pattern() {
        // Build a fake MIIC... pattern that's long enough (700+ base64 chars after MIIC)
        let fake_key = format!("MIIC{}", "A".repeat(800));
        let data = format!("some prefix data {fake_key}some suffix data");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "RSA-private");
        assert_eq!(keys[0].bit_length, Some(1024));
        assert!(keys[0].offset.starts_with("0x"));
        assert!(keys[0].pem_data.is_some());
        let pem = keys[0].pem_data.as_ref().unwrap();
        assert!(pem.contains(&format!("-----BEGIN {}-----", "RSA PRIVATE KEY")));
        assert!(pem.contains(&format!("-----END {}-----", "RSA PRIVATE KEY")));
        assert_eq!(keys[0].confidence, "probable");
    }

    #[test]
    fn test_extract_keys_finds_migf_pattern() {
        let fake_key = format!("MIGf{}", "B".repeat(200));
        let data = format!("prefix{fake_key}suffix");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "RSA-public");
        assert_eq!(keys[0].bit_length, Some(1024));
        assert!(keys[0].pem_data.is_some());
        let pem = keys[0].pem_data.as_ref().unwrap();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(keys[0].confidence, "probable");
    }

    #[test]
    fn test_extract_keys_finds_miibij_pattern() {
        let fake_key = format!("MIIBIj{}", "C".repeat(350));
        let data = format!("prefix{fake_key}suffix");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "RSA-public-2048");
        assert_eq!(keys[0].bit_length, Some(2048));
        assert_eq!(keys[0].confidence, "probable");
    }

    #[test]
    fn test_extract_keys_vendor_rsa_blob() {
        let fake_key = format!("BgIAAA{}", "D".repeat(200));
        let data = format!("prefix{fake_key}suffix");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "vendor-RSA-blob");
        assert_eq!(keys[0].confidence, "context-only");
    }

    #[test]
    fn test_extract_keys_vendor_rsa_blob_size_classification() {
        // Short blob -> 1024-bit
        let short_key = format!("BgIAAA{}", "D".repeat(200));
        let data = format!("prefix{short_key}suffix");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys[0].bit_length, Some(1024));

        // Long blob -> 2048-bit (total length > 240)
        let long_key = format!("BgIAAA{}", "D".repeat(300));
        let data = format!("prefix{long_key}suffix");
        let keys = extract_keys(data.as_bytes());
        assert_eq!(keys[0].bit_length, Some(2048));
    }

    #[test]
    fn test_extract_keys_reports_binary_offsets_not_lossy_text_offsets() {
        let fake_key = format!("BgIAAA{}", "D".repeat(200));
        let mut data = vec![0xff, 0xfe, 0xfd];
        data.extend_from_slice(fake_key.as_bytes());

        let keys = extract_keys(&data);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].offset, "0x3");
    }

    #[test]
    fn test_extract_keys_parses_vendor_publickeyblob_metadata() {
        let vendor_blob = concat!(
            "BgIAAACkAABSU0ExAAQAAAEAAQA1Ccyu85b65TawjvSQTaryGNk1gBJVn6kEIJq6m0hagsqkiy32v4ui41ucp6t",
            "Kfaoqb7AHDBq41dcEMgM6YBF2e3aRKQqZ6EwgCvAi3O81n7UbE97lD+FhvqlYxyqqMbSdvNmCiAoujheUs9DUaO",
            "CHq4K3McDxATMVOnCtT1H+wQ=="
        );
        let keys = extract_keys(vendor_blob.as_bytes());

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "vendor-RSA-blob");
        assert_eq!(keys[0].blob_format.as_deref(), Some("ms-publickeyblob"));
        assert_eq!(keys[0].bit_length, Some(1024));
        assert_eq!(keys[0].public_exponent, Some(65537));
        assert_eq!(keys[0].modulus_bytes, Some(128));
        assert!(keys[0].pem_data.is_some());
        assert!(keys[0].artifact_data.is_some());
        assert_eq!(keys[0].artifact_extension.as_deref(), Some("publickeyblob"));
        assert!(keys[0].validated);
    }

    #[test]
    fn test_extract_keys_finds_ascii_hex_aes_128_key() {
        let data = b"\0KEY=00112233445566778899aabbccddeeff\0";
        let keys = extract_keys_for_crypto_context(
            data,
            &[CryptoImport {
                name: "AES_set_encrypt_key".into(),
                category: "symmetric".into(),
            }],
        );

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "AES-128-hex");
        assert_eq!(keys[0].bit_length, Some(128));
        assert_eq!(keys[0].offset, "0x5");
        assert_eq!(keys[0].confidence, "probable");
        assert!(keys[0].validated);
        assert!(keys[0].fingerprint.is_some());
    }

    #[test]
    fn test_extract_keys_does_not_slice_longer_hex_strings_as_aes_keys() {
        let data = b"\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0";
        let keys = extract_keys_for_crypto_context(
            data,
            &[CryptoImport {
                name: "AES_set_encrypt_key".into(),
                category: "symmetric".into(),
            }],
        );

        assert!(keys.is_empty());
    }

    // ── format_pem ─────────────────────────────────────────────────────

    #[test]
    fn test_format_pem_wraps_at_64_chars() {
        let base64 = "A".repeat(128);
        let pem = format_pem("RSA PRIVATE KEY", &base64);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], format!("-----BEGIN {}-----", "RSA PRIVATE KEY"));
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2].len(), 64);
        assert_eq!(lines[3], format!("-----END {}-----", "RSA PRIVATE KEY"));
    }

    #[test]
    fn test_format_pem_short_key() {
        let base64 = "ABCD";
        let pem = format_pem("PUBLIC KEY", base64);
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("ABCD"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_trust_context_fallback_uses_coherent_supporting_summary() {
        let report = fat_taint::recon::trust_boundary::TrustBoundaryReport {
            rootfs_path: "/tmp/rootfs".into(),
            binaries_scanned: 1,
            update_binaries: vec![fat_taint::recon::trust_boundary::BinaryRole {
                path: "/sbin/slpupgrade".into(),
                role: "firmware-update".into(),
                evidence: vec![fat_taint::recon::trust_boundary::Evidence {
                    tier: "executed-entrypoint".into(),
                    kind: "init-script".into(),
                    strength: "strong".into(),
                    detail: "slpupgrade is the updater entrypoint".into(),
                }],
                linked_libraries: vec!["libfoo.so".into()],
            }],
            auth_binaries: Vec::new(),
            crypto_binaries: Vec::new(),
            dependency_chains: Vec::new(),
        };

        let context = build_trust_context_for_binary(&report, "/usr/lib/libfoo.so")
            .expect("expected linked fallback trust context");

        assert_eq!(
            context.candidate_classification.as_deref(),
            Some("supporting-boundary")
        );
        assert!(context.candidate_role.is_none());
        let tier_counts = context.tier_counts.expect("tier counts");
        assert_eq!(tier_counts.linked_dependency, 1);
        assert!(tier_counts.executed_entrypoint == 0);
        assert_eq!(context.path_confidence.as_deref(), Some("medium"));
        assert!(context
            .negative_evidence
            .iter()
            .all(|item| item != "helper-only crypto library"));
        assert!(
            context
                .why
                .iter()
                .any(|item| item.contains("linked directly from the governing updater path")),
            "expected linked-path rationale: {:?}",
            context.why
        );
    }
}
