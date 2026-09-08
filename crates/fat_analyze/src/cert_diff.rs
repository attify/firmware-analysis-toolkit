use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateDiff {
    pub path: String,
    pub base_subject: Option<String>,
    pub head_subject: Option<String>,
    pub base_key_bits: Option<u32>,
    pub head_key_bits: Option<u32>,
    pub base_signature_algorithm: Option<String>,
    pub head_signature_algorithm: Option<String>,
    pub base_not_after: Option<String>,
    pub head_not_after: Option<String>,
    pub key_rotated: bool,
    pub base_modulus_hash: Option<String>,
    pub head_modulus_hash: Option<String>,
}

/// Parsed certificate information extracted from openssl x509 output.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub not_after: String,
    pub key_bits: u32,
    pub sig_alg: String,
    pub modulus_hash: String,
}

/// Parse the text output of `openssl x509 -noout -subject -dates -modulus -text`
/// and extract the relevant certificate fields.
pub fn parse_x509_output(output: &str) -> Result<CertInfo, String> {
    let subject = parse_field(output, "subject=").unwrap_or_default();
    let not_after = parse_field(output, "notAfter=").unwrap_or_default();
    let key_bits = parse_key_bits(output).unwrap_or(0);
    let sig_alg = parse_signature_algorithm(output).unwrap_or_default();
    let modulus_hash = parse_modulus_hash(output);

    Ok(CertInfo {
        subject,
        not_after,
        key_bits,
        sig_alg,
        modulus_hash,
    })
}

/// Build a `CertificateDiff` by comparing two already-parsed `CertInfo` values.
pub fn diff_certificates_from_info(
    path: &str,
    base: &CertInfo,
    head: &CertInfo,
) -> CertificateDiff {
    CertificateDiff {
        path: path.to_string(),
        base_subject: Some(base.subject.clone()),
        head_subject: Some(head.subject.clone()),
        base_key_bits: Some(base.key_bits),
        head_key_bits: Some(head.key_bits),
        base_signature_algorithm: Some(base.sig_alg.clone()),
        head_signature_algorithm: Some(head.sig_alg.clone()),
        base_not_after: Some(base.not_after.clone()),
        head_not_after: Some(head.not_after.clone()),
        key_rotated: base.modulus_hash != head.modulus_hash,
        base_modulus_hash: Some(base.modulus_hash.clone()),
        head_modulus_hash: Some(head.modulus_hash.clone()),
    }
}

/// Compare two X.509 certificate files and produce a diff.
///
/// Shells out to `openssl x509` for parsing. Returns an IO error if openssl
/// is not found on PATH or fails to execute.
pub fn diff_certificates(base_cert: &Path, head_cert: &Path) -> io::Result<CertificateDiff> {
    let base_output = run_openssl_x509(base_cert)?;
    let head_output = run_openssl_x509(head_cert)?;

    let base_info = parse_x509_output(&base_output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse base certificate: {e}"),
        )
    })?;
    let head_info = parse_x509_output(&head_output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse head certificate: {e}"),
        )
    })?;

    let path_str = base_cert.display().to_string();
    Ok(diff_certificates_from_info(
        &path_str, &base_info, &head_info,
    ))
}

/// Run `openssl x509` on the given certificate file and return stdout as a string.
fn run_openssl_x509(cert_path: &Path) -> io::Result<String> {
    let output = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &cert_path.display().to_string(),
            "-noout",
            "-subject",
            "-dates",
            "-modulus",
            "-text",
        ])
        .output()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "openssl not found on PATH or failed to execute: {e}. \
                     Install openssl to enable certificate diff."
                ),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!("openssl x509 failed: {stderr}")));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- Internal parsing helpers ---

/// Extract a field value that appears after a prefix on its own line.
fn parse_field(output: &str, prefix: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Extract the public key size in bits from `Public-Key: (N bit)`.
fn parse_key_bits(output: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Public-Key:") {
            // e.g., "Public-Key: (2048 bit)"
            if let Some(start) = trimmed.find('(') {
                if let Some(end) = trimmed.find(" bit") {
                    let num_str = &trimmed[start + 1..end];
                    return num_str.trim().parse::<u32>().ok();
                }
            }
        }
    }
    None
}

/// Extract the Signature Algorithm value.
fn parse_signature_algorithm(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Signature Algorithm:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Extract the Modulus value and compute a simple hash for comparison.
///
/// The hash is a lowercase hex digest of the modulus string itself, used
/// to detect key rotation (different keys = different modulus = different hash).
fn parse_modulus_hash(output: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Modulus=") {
            // Simple hash: use the modulus string itself as the "hash".
            // For a real implementation we would pipe through md5/sha256,
            // but for comparison purposes the raw value is sufficient.
            return rest.trim().to_lowercase();
        }
    }
    String::new()
}
