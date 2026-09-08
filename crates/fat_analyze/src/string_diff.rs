// String security classification and comparison for binary diff.
//
// Classifies strings extracted from binaries into security-relevant categories:
// DANGEROUS_CALL, CREDENTIAL, ENDPOINT, CRYPTO, DEBUG, NETWORK.
// Also extracts embedded library version strings (OpenSSL, curl, BusyBox, etc.).

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A string with an optional security classification tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClassifiedString {
    pub value: String,
    pub tag: Option<String>,
}

/// Result of diffing two classified string sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClassifiedStringDiff {
    pub added: Vec<ClassifiedString>,
    pub removed: Vec<ClassifiedString>,
}

/// Classify a string into a security-relevant category.
///
/// Returns a static tag string or `None` if the string has no security relevance.
/// Categories are checked in priority order: DANGEROUS_CALL, ENDPOINT,
/// CREDENTIAL, CRYPTO, DEBUG, NETWORK. ENDPOINT is checked before CREDENTIAL
/// because path-like strings (e.g. "/cgi-bin/admin") should be classified by
/// their structural role, not by incidental keyword matches.
pub fn classify_string(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();

    // DANGEROUS_CALL: functions that execute shell commands or processes
    const DANGEROUS_PATTERNS: &[&str] = &[
        "system", "popen", "exec", "execve", "execvp", "dlopen", "eval",
    ];
    for pat in DANGEROUS_PATTERNS {
        if lower.contains(pat) {
            return Some("DANGEROUS_CALL");
        }
    }

    // ENDPOINT: web/CGI paths and handlers (checked before CREDENTIAL so
    // that paths like "/cgi-bin/admin" are classified as ENDPOINT, not CREDENTIAL)
    if lower.contains("/cgi") || lower.contains("/setform") || lower.contains("/stream/") {
        return Some("ENDPOINT");
    }

    // CREDENTIAL: authentication and secret material
    const CREDENTIAL_PATTERNS: &[&str] = &[
        "password",
        "passwd",
        "admin",
        "secret",
        "credential",
        "token",
        "login",
    ];
    for pat in CREDENTIAL_PATTERNS {
        if lower.contains(pat) {
            return Some("CREDENTIAL");
        }
    }

    // CRYPTO: cryptographic primitives and key material
    const CRYPTO_PATTERNS: &[&str] = &[
        "md5",
        "sha",
        "aes",
        "rsa",
        "certificate",
        "cipher",
        "encrypt",
        "decrypt",
        "hmac",
    ];
    for pat in CRYPTO_PATTERNS {
        if lower.contains(pat) {
            return Some("CRYPTO");
        }
    }

    // DEBUG: debugging and test interfaces
    const DEBUG_PATTERNS: &[&str] = &["debug", "dbg", "test"];
    for pat in DEBUG_PATTERNS {
        if lower.contains(pat) {
            return Some("DEBUG");
        }
    }

    // NETWORK: URLs, sockets, and network operations
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some("NETWORK");
    }
    const NETWORK_PATTERNS: &[&str] = &["socket", "bind", "listen", "connect"];
    for pat in NETWORK_PATTERNS {
        if lower.contains(pat) {
            return Some("NETWORK");
        }
    }

    None
}

/// Embedded library version extracted from binary strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LibraryVersionDiff {
    pub library: String,
    pub base_version: Option<String>,
    pub head_version: Option<String>,
    pub changed: bool,
}

/// Well-known version patterns for embedded libraries.
const VERSION_PATTERNS: &[(&str, &str)] = &[
    (r"OpenSSL \d+\.\d+\.\d+[a-z]?", "OpenSSL"),
    (r"curl/\d+\.\d+\.\d+", "curl"),
    (r"BusyBox v\d+\.\d+\.\d+", "BusyBox"),
    (r"dropbear_\d{4}\.\d+", "Dropbear"),
    (r"lighttpd/\d+\.\d+\.\d+", "lighttpd"),
    (r"Linux version \d+\.\d+\.\d+", "kernel"),
    (r"wolfSSL \d+\.\d+\.\d+", "wolfSSL"),
    (r"mbedTLS \d+\.\d+\.\d+", "mbedTLS"),
    (r"nginx/\d+\.\d+\.\d+", "nginx"),
    (r"miniupnp[cd]/\d+\.\d+", "miniupnp"),
];

/// Extract library versions from a set of strings.
fn extract_versions(strings: &[String]) -> Vec<(String, String)> {
    let mut versions = Vec::new();

    for (pattern_str, library_name) in VERSION_PATTERNS {
        let re = match Regex::new(pattern_str) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for s in strings {
            if let Some(m) = re.find(s) {
                versions.push((library_name.to_string(), m.as_str().to_string()));
                break; // One match per library per binary
            }
        }
    }

    versions
}

/// Compare library versions between two sets of strings.
pub fn diff_library_versions(
    base_strings: &[String],
    head_strings: &[String],
) -> Vec<LibraryVersionDiff> {
    let base_versions = extract_versions(base_strings);
    let head_versions = extract_versions(head_strings);

    let mut diffs = Vec::new();

    // Collect all unique library names
    let mut all_libs: BTreeSet<&str> = BTreeSet::new();
    for (lib, _) in &base_versions {
        all_libs.insert(lib);
    }
    for (lib, _) in &head_versions {
        all_libs.insert(lib);
    }

    for lib in all_libs {
        let base_ver = base_versions
            .iter()
            .find(|(l, _)| l == lib)
            .map(|(_, v)| v.clone());
        let head_ver = head_versions
            .iter()
            .find(|(l, _)| l == lib)
            .map(|(_, v)| v.clone());

        let changed = base_ver != head_ver;

        diffs.push(LibraryVersionDiff {
            library: lib.to_string(),
            base_version: base_ver,
            head_version: head_ver,
            changed,
        });
    }

    diffs
}

/// Diff two string slices and return classified additions and removals.
///
/// Strings present in `head` but not in `base` are classified as added.
/// Strings present in `base` but not in `head` are classified as removed.
pub fn diff_classified_strings(base: &[String], head: &[String]) -> ClassifiedStringDiff {
    let base_set: BTreeSet<&str> = base.iter().map(|s| s.as_str()).collect();
    let head_set: BTreeSet<&str> = head.iter().map(|s| s.as_str()).collect();

    let added = head_set
        .difference(&base_set)
        .map(|s| ClassifiedString {
            value: s.to_string(),
            tag: classify_string(s).map(|t| t.to_string()),
        })
        .collect();

    let removed = base_set
        .difference(&head_set)
        .map(|s| ClassifiedString {
            value: s.to_string(),
            tag: classify_string(s).map(|t| t.to_string()),
        })
        .collect();

    ClassifiedStringDiff { added, removed }
}
