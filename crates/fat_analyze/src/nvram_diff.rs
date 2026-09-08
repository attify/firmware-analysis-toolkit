use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NvramKeyRef {
    pub key_name: String,
    pub source_file: String,
    pub access_type: String, // "get" or "set"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NvramKeyDiff {
    pub key_name: String,
    pub status: String, // "added", "removed", "unchanged"
    pub base_source: Option<String>,
    pub head_source: Option<String>,
    pub security_relevance: Option<String>,
}

/// Directories under a rootfs to scan for shell scripts.
const SCAN_DIRS: &[&str] = &["sbin", "etc", "etc_ro"];

/// Extract NVRAM key references from shell scripts in a firmware rootfs.
///
/// Walks `sbin/`, `etc/`, and `etc_ro/` looking for `.sh` files that contain
/// `nvram_get` or `nvram_set` invocations. Results are deduplicated by key name.
pub fn extract_nvram_keys(rootfs: &Path) -> std::io::Result<Vec<NvramKeyRef>> {
    let re_get_numeric = Regex::new(r"nvram_get\s+\d+\s+(\w+)").expect("valid regex");
    let re_get_quoted = Regex::new(r#"nvram_get\s+"([^"]+)""#).expect("valid regex");
    let re_set_numeric = Regex::new(r"nvram_set\s+\d+\s+(\w+)").expect("valid regex");

    // Use BTreeMap to deduplicate by key_name, keeping first occurrence.
    let mut seen: BTreeMap<String, NvramKeyRef> = BTreeMap::new();

    for scan_dir in SCAN_DIRS {
        let dir = rootfs.join(scan_dir);
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            // Accept .sh files and also files without extension that live in these dirs
            let is_shell = path.extension().map(|ext| ext == "sh").unwrap_or(false);
            if !is_shell {
                continue;
            }

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue, // skip unreadable files (e.g., binary)
            };

            let rel_path = path
                .strip_prefix(rootfs)
                .unwrap_or(path)
                .display()
                .to_string();

            for cap in re_get_numeric.captures_iter(&content) {
                let key = cap[1].to_string();
                seen.entry(key.clone()).or_insert_with(|| NvramKeyRef {
                    key_name: key,
                    source_file: rel_path.clone(),
                    access_type: "get".into(),
                });
            }

            for cap in re_get_quoted.captures_iter(&content) {
                let key = cap[1].to_string();
                seen.entry(key.clone()).or_insert_with(|| NvramKeyRef {
                    key_name: key,
                    source_file: rel_path.clone(),
                    access_type: "get".into(),
                });
            }

            for cap in re_set_numeric.captures_iter(&content) {
                let key = cap[1].to_string();
                seen.entry(key.clone()).or_insert_with(|| NvramKeyRef {
                    key_name: key,
                    source_file: rel_path.clone(),
                    access_type: "set".into(),
                });
            }
        }
    }

    let keys: Vec<NvramKeyRef> = seen.into_values().collect();
    Ok(keys)
}

/// Classify the security relevance of an NVRAM key by its name.
///
/// Returns a category string or `None` if the key has no special relevance.
pub fn classify_security_relevance(key_name: &str) -> Option<String> {
    let lower = key_name.to_lowercase();
    if lower.contains("password")
        || lower.contains("key")
        || lower.contains("secret")
        || lower.contains("passwd")
        || lower.contains("credential")
        || lower.contains("token")
    {
        return Some("credential".into());
    }
    if lower.contains("ip")
        || lower.contains("gateway")
        || lower.contains("dns")
        || lower.contains("subnet")
        || lower.contains("netmask")
        || lower.contains("wan")
        || lower.contains("lan")
    {
        return Some("network".into());
    }
    if lower.contains("debug") || lower.contains("level") || lower.contains("log") {
        return Some("debug".into());
    }
    if lower.contains("enable") || lower.contains("disable") || lower.contains("mode") {
        return Some("feature".into());
    }
    None
}

/// Compare two sets of NVRAM key references and produce a diff.
///
/// Keys present only in `head_keys` are marked "added".
/// Keys present only in `base_keys` are marked "removed".
/// Keys in both are marked "unchanged".
pub fn diff_nvram_keys(base_keys: &[NvramKeyRef], head_keys: &[NvramKeyRef]) -> Vec<NvramKeyDiff> {
    let base_map: BTreeMap<&str, &NvramKeyRef> =
        base_keys.iter().map(|k| (k.key_name.as_str(), k)).collect();
    let head_map: BTreeMap<&str, &NvramKeyRef> =
        head_keys.iter().map(|k| (k.key_name.as_str(), k)).collect();

    let mut diffs = Vec::new();

    // Keys in head
    for (name, head_ref) in &head_map {
        if let Some(base_ref) = base_map.get(name) {
            diffs.push(NvramKeyDiff {
                key_name: name.to_string(),
                status: "unchanged".into(),
                base_source: Some(base_ref.source_file.clone()),
                head_source: Some(head_ref.source_file.clone()),
                security_relevance: classify_security_relevance(name),
            });
        } else {
            diffs.push(NvramKeyDiff {
                key_name: name.to_string(),
                status: "added".into(),
                base_source: None,
                head_source: Some(head_ref.source_file.clone()),
                security_relevance: classify_security_relevance(name),
            });
        }
    }

    // Keys only in base (removed)
    for (name, base_ref) in &base_map {
        if !head_map.contains_key(name) {
            diffs.push(NvramKeyDiff {
                key_name: name.to_string(),
                status: "removed".into(),
                base_source: Some(base_ref.source_file.clone()),
                head_source: None,
                security_relevance: classify_security_relevance(name),
            });
        }
    }

    diffs.sort_by(|a, b| a.key_name.cmp(&b.key_name));
    diffs
}
