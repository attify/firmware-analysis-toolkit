use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

// ===== Layer 1: Filesystem =====

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FilesystemDiff {
    pub base_file_count: usize,
    pub head_file_count: usize,
    pub added: Vec<FileDiffEntry>,
    pub removed: Vec<FileDiffEntry>,
    pub changed: Vec<FileDiffEntry>,
    pub permissions_changed: Vec<PermissionDiffEntry>,
    pub symlinks_changed: Vec<SymlinkDiffEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FileDiffEntry {
    pub path: String,
    pub file_type: String,
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_size_bytes: Option<u64>,
    pub hash: Option<String>,
    pub security_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PermissionDiffEntry {
    pub path: String,
    pub base_mode: String,
    pub head_mode: String,
    pub security_impact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SymlinkDiffEntry {
    pub path: String,
    pub base_target: Option<String>,
    pub head_target: Option<String>,
}

// ===== Layer 2: Configuration =====

/// Credential hash comparison between firmware versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialDiff {
    pub path: String,
    pub user: String,
    pub base_hash_algorithm: Option<String>,
    pub head_hash_algorithm: Option<String>,
    pub base_salt: Option<String>,
    pub head_salt: Option<String>,
    pub hash_identical: bool,
    pub algorithm_weakness: Option<String>,
}

/// Init script line-level change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScriptDiff {
    pub path: String,
    pub added_lines: Vec<ClassifiedLine>,
    pub removed_lines: Vec<ClassifiedLine>,
}

/// A classified line from an init script diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClassifiedLine {
    pub line_number: usize,
    pub content: String,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigDiff {
    pub certificate_changes: Vec<CertificateDiff>,
    pub nvram_key_changes: Vec<NvramKeyDiff>,
    pub web_endpoint_changes: WebEndpointDiff,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_changes: Vec<CredentialDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_changes: Vec<ScriptDiff>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NvramKeyDiff {
    pub key_name: String,
    pub status: String,
    pub base_binary: Option<String>,
    pub head_binary: Option<String>,
    pub security_relevance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WebEndpointDiff {
    pub added_endpoints: Vec<String>,
    pub removed_endpoints: Vec<String>,
    pub changed_handlers: Vec<String>,
}

// ===== Persistent weakness detection =====

/// A weakness present in both firmware versions (unchanged and bad).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PersistentWeakness {
    pub category: String,
    pub description: String,
    pub path: String,
    pub base_evidence: String,
    pub head_evidence: String,
}

// ===== Library absorption detection =====

/// A candidate for library absorption (static linking of a previously dynamic library).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LibraryAbsorptionCandidate {
    pub removed_library: String,
    pub removed_library_size: u64,
    pub absorbing_binary: String,
    pub binary_base_size: u64,
    pub binary_head_size: u64,
    pub matched_exports: Vec<String>,
    pub matched_exports_ratio: f64,
    pub confidence: String,
}

// ===== Partition-grouped filesystem diff =====

/// A labeled filesystem diff for one partition (e.g. "rootfs", "app").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PartitionDiff {
    pub label: String,
    pub diff: FilesystemDiff,
}

// ===== Top-level report =====

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirmwareDiffReport {
    pub base_project: String,
    pub head_project: String,
    pub base_version: Option<String>,
    pub head_version: Option<String>,
    pub diff_timestamp: String,
    pub filesystem: Option<FilesystemDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partitions: Vec<PartitionDiff>,
    pub config: Option<ConfigDiff>,
    #[serde(default)]
    pub binaries: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library_absorption: Vec<LibraryAbsorptionCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persistent_weaknesses: Vec<PersistentWeakness>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiffSummary {
    pub total_files_changed: usize,
    pub security_relevant_changes: usize,
    pub new_attack_surface_count: usize,
    pub removed_attack_surface_count: usize,
    pub crypto_changes: usize,
    pub debug_changes_added: usize,
    pub debug_changes_removed: usize,
    pub overall_security_direction: String,
}

// ===== Internal metadata for walking =====

#[derive(Debug, Clone)]
struct FileMetadata {
    size: u64,
    is_file: bool,
    is_symlink: bool,
    symlink_target: Option<PathBuf>,
    hash: String,
    permissions: String,
}

// ===== Filesystem diff algorithm =====

pub fn diff_filesystems(
    base_root: &Path,
    head_root: &Path,
) -> Result<FilesystemDiff, Box<dyn std::error::Error>> {
    let base_files = walk_rootfs(base_root)?;
    let head_files = walk_rootfs(head_root)?;

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut permissions_changed = Vec::new();
    let mut symlinks_changed = Vec::new();

    for (path, head_meta) in &head_files {
        match base_files.get(path) {
            None => {
                added.push(classify_file(path, head_meta));
            }
            Some(base_meta) => {
                // Content change (only compare hashes for regular files)
                if base_meta.is_file && head_meta.is_file && base_meta.hash != head_meta.hash {
                    let mut entry = classify_file(path, head_meta);
                    entry.base_size_bytes = Some(base_meta.size);
                    changed.push(entry);
                }

                // Permission change (tracked independently of content)
                if base_meta.permissions != head_meta.permissions {
                    permissions_changed.push(PermissionDiffEntry {
                        path: path.clone(),
                        base_mode: base_meta.permissions.clone(),
                        head_mode: head_meta.permissions.clone(),
                        security_impact: classify_permission_change(
                            &base_meta.permissions,
                            &head_meta.permissions,
                        ),
                    });
                }

                // Symlink target change (tracked independently)
                if base_meta.symlink_target != head_meta.symlink_target
                    && (base_meta.is_symlink || head_meta.is_symlink)
                {
                    symlinks_changed.push(SymlinkDiffEntry {
                        path: path.clone(),
                        base_target: base_meta
                            .symlink_target
                            .as_ref()
                            .map(|p| p.display().to_string()),
                        head_target: head_meta
                            .symlink_target
                            .as_ref()
                            .map(|p| p.display().to_string()),
                    });
                }
            }
        }
    }

    for (path, base_meta) in &base_files {
        if !head_files.contains_key(path) {
            removed.push(classify_file(path, base_meta));
        }
    }

    // Count only regular files (not directories) for file counts
    let base_file_count = base_files
        .values()
        .filter(|m| m.is_file || m.is_symlink)
        .count();
    let head_file_count = head_files
        .values()
        .filter(|m| m.is_file || m.is_symlink)
        .count();

    Ok(FilesystemDiff {
        base_file_count,
        head_file_count,
        added,
        removed,
        changed,
        permissions_changed,
        symlinks_changed,
    })
}

/// Compute a summary from aggregate change statistics.
pub fn diff_summary(
    total_files_changed: usize,
    security_relevant_changes: usize,
    new_attack_surface_count: usize,
    removed_attack_surface_count: usize,
    crypto_changes: usize,
    debug_changes_added: usize,
    debug_changes_removed: usize,
) -> DiffSummary {
    let direction = if security_relevant_changes == 0
        && new_attack_surface_count == 0
        && removed_attack_surface_count == 0
        && debug_changes_added == 0
        && debug_changes_removed == 0
        && crypto_changes == 0
    {
        "unchanged".to_string()
    } else {
        let regressions = new_attack_surface_count + debug_changes_added;
        let improvements = removed_attack_surface_count + debug_changes_removed;

        if regressions > 0 && improvements > 0 {
            "mixed".to_string()
        } else if regressions > 0 {
            "degraded".to_string()
        } else if improvements > 0 {
            "improved".to_string()
        } else {
            // Only crypto changes or generic security changes, no clear direction
            "mixed".to_string()
        }
    };

    DiffSummary {
        total_files_changed,
        security_relevant_changes,
        new_attack_surface_count,
        removed_attack_surface_count,
        crypto_changes,
        debug_changes_added,
        debug_changes_removed,
        overall_security_direction: direction,
    }
}

// ===== Internal helpers =====

fn walk_rootfs(root: &Path) -> Result<BTreeMap<String, FileMetadata>, Box<dyn std::error::Error>> {
    let mut files = BTreeMap::new();

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(root)?;
        let rel_str = rel_path.to_string_lossy().into_owned();

        // Skip the root directory itself
        if rel_str.is_empty() {
            continue;
        }

        let metadata = entry.metadata()?;
        let is_symlink = entry.path_is_symlink();

        let hash = if metadata.is_file() && !is_symlink {
            sha256_file(entry.path())?
        } else {
            String::new()
        };

        let symlink_target = if is_symlink {
            std::fs::read_link(entry.path()).ok()
        } else {
            None
        };

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", metadata.permissions().mode())
        };
        #[cfg(not(unix))]
        let permissions = String::from("unknown");

        files.insert(
            rel_str,
            FileMetadata {
                size: metadata.len(),
                is_file: metadata.is_file(),
                is_symlink,
                symlink_target,
                hash,
                permissions,
            },
        );
    }

    Ok(files)
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}

fn classify_file(path: &str, meta: &FileMetadata) -> FileDiffEntry {
    let mut tags = Vec::new();

    // Attack surface detection
    if path.contains("/cgi") || path.ends_with(".cgi") {
        tags.push("ATTACK_SURFACE".to_string());
    }
    if path.contains("upload") {
        tags.push("UPLOAD_ENDPOINT".to_string());
    }

    // Crypto detection
    if path.ends_with(".pem") || path.ends_with(".key") || path.ends_with(".crt") {
        tags.push("CRYPTO_CHANGE".to_string());
    }

    // Init/config — broadened to cover app-partition init scripts
    if path.contains("rcS")
        || path.contains("init.d")
        || path.contains("internet.sh")
        || path.ends_with("_init.sh")
        || path.ends_with("_start.sh")
        || path.ends_with("startup.sh")
        || path.contains("inittab")
    {
        tags.push("CONFIG_CHANGE".to_string());
    }

    // Debug
    if path.contains("debug") || path.contains("dbg") || path.contains("telnet") {
        tags.push("DEBUG_INTERFACE".to_string());
    }

    FileDiffEntry {
        path: path.to_string(),
        file_type: detect_file_type(path, meta),
        size_bytes: if meta.is_file { Some(meta.size) } else { None },
        base_size_bytes: None,
        hash: if !meta.hash.is_empty() {
            Some(meta.hash.clone())
        } else {
            None
        },
        security_tags: tags,
    }
}

fn detect_file_type(path: &str, meta: &FileMetadata) -> String {
    if meta.is_symlink {
        return "symlink".to_string();
    }
    if !meta.is_file {
        return "directory".to_string();
    }

    if path.ends_with(".sh") || path.contains("rcS") || path.contains("init.d") {
        return "shell-script".to_string();
    }
    if path.ends_with(".cgi") {
        return "cgi-script".to_string();
    }
    if path.ends_with(".pem") || path.ends_with(".key") || path.ends_with(".crt") {
        return "certificate".to_string();
    }
    if path.ends_with(".conf") || path.ends_with(".cfg") || path.ends_with(".ini") {
        return "config".to_string();
    }
    if path.ends_with(".so") || path.contains(".so.") || path.ends_with(".ko") {
        return "shared-library".to_string();
    }

    "file".to_string()
}

// ===== Certificate diff =====

/// Parsed certificate information from openssl x509 output.
#[derive(Debug, Clone)]
struct CertInfo {
    subject: String,
    key_bits: u32,
    sig_alg: String,
    not_after: String,
    modulus_hash: String,
}

/// Compare two X.509 certificates by shelling out to `openssl x509`.
pub fn diff_certificates(
    base_cert: &Path,
    head_cert: &Path,
) -> Result<CertificateDiff, Box<dyn std::error::Error>> {
    let base = parse_x509(base_cert)?;
    let head = parse_x509(head_cert)?;

    Ok(CertificateDiff {
        path: base_cert.display().to_string(),
        base_subject: Some(base.subject.clone()),
        head_subject: Some(head.subject.clone()),
        base_key_bits: Some(base.key_bits),
        head_key_bits: Some(head.key_bits),
        base_signature_algorithm: Some(base.sig_alg.clone()),
        head_signature_algorithm: Some(head.sig_alg.clone()),
        base_not_after: Some(base.not_after.clone()),
        head_not_after: Some(head.not_after.clone()),
        key_rotated: base.modulus_hash != head.modulus_hash,
        base_modulus_hash: Some(base.modulus_hash),
        head_modulus_hash: Some(head.modulus_hash),
    })
}

fn parse_x509(path: &Path) -> Result<CertInfo, Box<dyn std::error::Error>> {
    // Get subject, dates, signature algorithm
    let text_output = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &path.display().to_string(),
            "-noout",
            "-subject",
            "-dates",
            "-text",
        ])
        .output()?;

    if !text_output.status.success() {
        return Err(format!(
            "openssl x509 failed: {}",
            String::from_utf8_lossy(&text_output.stderr)
        )
        .into());
    }

    let text = String::from_utf8_lossy(&text_output.stdout);

    let subject = extract_openssl_field(&text, "subject=")
        .or_else(|| extract_openssl_field(&text, "Subject:"))
        .unwrap_or_default();

    let not_after = extract_openssl_field(&text, "notAfter=").unwrap_or_default();

    let sig_alg = extract_openssl_field(&text, "Signature Algorithm:").unwrap_or_default();

    // Extract key size from "Public-Key: (2048 bit)" or "RSA Public-Key: (2048 bit)"
    let key_bits = text
        .lines()
        .find(|line| line.contains("Public-Key:") || line.contains("Public Key:"))
        .and_then(|line| {
            line.split('(')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
        })
        .unwrap_or(0);

    // Get modulus and hash it for key rotation detection
    let modulus_output = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &path.display().to_string(),
            "-noout",
            "-modulus",
        ])
        .output()?;

    let modulus_text = String::from_utf8_lossy(&modulus_output.stdout);
    let modulus_hash = {
        let mut hasher = Sha256::new();
        hasher.update(modulus_text.trim().as_bytes());
        format!("{:x}", hasher.finalize())
    };

    Ok(CertInfo {
        subject,
        key_bits,
        sig_alg,
        not_after,
        modulus_hash,
    })
}

fn extract_openssl_field(text: &str, prefix: &str) -> Option<String> {
    text.lines()
        .find(|line| line.contains(prefix))
        .map(|line| line.split(prefix).nth(1).unwrap_or("").trim().to_string())
}

// ===== NVRAM key extraction and diff =====

/// A reference to an NVRAM key found in a script or binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NvramKeyRef {
    pub key_name: String,
    pub source_file: String,
    pub access_type: String,
}

/// Extract NVRAM key references from shell scripts in a rootfs tree.
/// Matches patterns like `nvram_get 2860 <key>` and `nvram_set 2860 <key>`.
pub fn extract_nvram_keys_from_scripts(
    rootfs: &Path,
) -> Result<Vec<NvramKeyRef>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();

    for entry in WalkDir::new(rootfs).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        // Read file content, skip binary files
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = entry
            .path()
            .strip_prefix(rootfs)
            .unwrap_or(entry.path())
            .display()
            .to_string();

        // Match nvram_get patterns: nvram_get 2860 <key>, nvram_get(<key>), nvram_get <key>
        for line in content.lines() {
            // Pattern: nvram_get 2860 <key>
            if let Some(key) = extract_nvram_key_from_line(line, "nvram_get") {
                keys.push(NvramKeyRef {
                    key_name: key,
                    source_file: rel_path.clone(),
                    access_type: "get".to_string(),
                });
            }
            if let Some(key) = extract_nvram_key_from_line(line, "nvram_set") {
                keys.push(NvramKeyRef {
                    key_name: key,
                    source_file: rel_path.clone(),
                    access_type: "set".to_string(),
                });
            }
        }
    }

    // Deduplicate by key_name
    keys.sort_by(|a, b| a.key_name.cmp(&b.key_name));
    keys.dedup_by(|a, b| a.key_name == b.key_name);

    Ok(keys)
}

fn extract_nvram_key_from_line(line: &str, func: &str) -> Option<String> {
    let trimmed = line.trim();
    // Find the function call in the line
    let idx = trimmed.find(func)?;
    let after = &trimmed[idx + func.len()..];

    // Skip whitespace and optional arguments like "2860"
    let parts: Vec<&str> = after.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // If first arg is a number (like "2860"), the key is the next arg
    let key_part = if parts[0].chars().all(|c| c.is_ascii_digit()) {
        parts.get(1)?
    } else {
        &parts[0]
    };

    // Clean up the key: remove quotes, parentheses, $() wrappers, trailing chars
    let key = key_part
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')' || c == '$')
        .to_string();

    if key.is_empty() || key.contains(' ') {
        return None;
    }

    Some(key)
}

/// Compare two sets of NVRAM key references, producing a diff.
pub fn diff_nvram_keys(base_keys: &[NvramKeyRef], head_keys: &[NvramKeyRef]) -> Vec<NvramKeyDiff> {
    let base_set: BTreeMap<&str, &NvramKeyRef> =
        base_keys.iter().map(|k| (k.key_name.as_str(), k)).collect();
    let head_set: BTreeMap<&str, &NvramKeyRef> =
        head_keys.iter().map(|k| (k.key_name.as_str(), k)).collect();

    let mut diffs = Vec::new();

    for (key, head_ref) in &head_set {
        if !base_set.contains_key(key) {
            diffs.push(NvramKeyDiff {
                key_name: key.to_string(),
                status: "added".to_string(),
                base_binary: None,
                head_binary: Some(head_ref.source_file.clone()),
                security_relevance: classify_nvram_key(key),
            });
        }
    }

    for (key, base_ref) in &base_set {
        if !head_set.contains_key(key) {
            diffs.push(NvramKeyDiff {
                key_name: key.to_string(),
                status: "removed".to_string(),
                base_binary: Some(base_ref.source_file.clone()),
                head_binary: None,
                security_relevance: classify_nvram_key(key),
            });
        }
    }

    diffs
}

fn classify_nvram_key(key: &str) -> Option<String> {
    let lower = key.to_ascii_lowercase();
    if lower.contains("password") || lower.contains("passwd") || lower.contains("secret") {
        Some("credential".to_string())
    } else if lower.contains("admin") || lower.contains("auth") {
        Some("authentication".to_string())
    } else if lower.contains("wan") || lower.contains("lan") || lower.contains("ip") {
        Some("network-config".to_string())
    } else {
        None
    }
}

// ===== Web endpoint diff =====

/// Discover web endpoints (CGI scripts, form handlers) in a rootfs tree.
pub fn discover_web_endpoints(
    rootfs: &Path,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut endpoints = BTreeSet::new();

    for entry in WalkDir::new(rootfs).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let rel_path = entry
            .path()
            .strip_prefix(rootfs)
            .unwrap_or(entry.path())
            .display()
            .to_string();

        // CGI scripts
        if rel_path.ends_with(".cgi")
            || rel_path.contains("/cgi-bin/")
            || rel_path.contains("/cgi/")
        {
            endpoints.insert(rel_path.clone());
        }

        // Form handlers (common patterns in IoT firmware)
        if rel_path.contains("setform") || rel_path.contains("upload") {
            endpoints.insert(rel_path.clone());
        }
    }

    Ok(endpoints)
}

/// Diff web endpoints between two rootfs trees.
pub fn diff_web_endpoints(
    base_root: &Path,
    head_root: &Path,
) -> Result<WebEndpointDiff, Box<dyn std::error::Error>> {
    let base_endpoints = discover_web_endpoints(base_root)?;
    let head_endpoints = discover_web_endpoints(head_root)?;

    let added: Vec<String> = head_endpoints
        .difference(&base_endpoints)
        .cloned()
        .collect();
    let removed: Vec<String> = base_endpoints
        .difference(&head_endpoints)
        .cloned()
        .collect();

    Ok(WebEndpointDiff {
        added_endpoints: added,
        removed_endpoints: removed,
        changed_handlers: Vec::new(),
    })
}

fn classify_permission_change(base: &str, head: &str) -> Option<String> {
    // Parse octal permission strings
    let base_mode = u32::from_str_radix(base, 8).unwrap_or(0);
    let head_mode = u32::from_str_radix(head, 8).unwrap_or(0);

    // Check if world-writable bit was added
    let base_world_write = base_mode & 0o002 != 0;
    let head_world_write = head_mode & 0o002 != 0;

    // Check if setuid/setgid was added
    let base_setuid = base_mode & 0o4000 != 0;
    let head_setuid = head_mode & 0o4000 != 0;

    if !base_world_write && head_world_write {
        Some("world-writable added".to_string())
    } else if !base_setuid && head_setuid {
        Some("setuid added".to_string())
    } else if base_world_write && !head_world_write {
        Some("world-writable removed (hardening)".to_string())
    } else {
        None
    }
}

// ===== Credential hash parsing and diff =====

/// Parsed credential entry from /etc/passwd or /etc/shadow.
#[derive(Debug, Clone)]
struct CredentialEntry {
    user: String,
    hash_field: String,
    algorithm_id: Option<String>,
    salt: Option<String>,
}

/// Map crypt algorithm IDs to human-readable names.
fn crypt_algorithm_name(id: &str) -> &str {
    match id {
        "1" => "MD5-crypt",
        "2" | "2a" | "2b" | "2y" => "bcrypt",
        "5" => "SHA-256-crypt",
        "6" => "SHA-512-crypt",
        "y" => "yescrypt",
        _ => "unknown",
    }
}

/// Classify weakness of a crypt algorithm.
fn crypt_weakness(id: &str) -> Option<String> {
    match id {
        "1" => Some("MD5-crypt: crackable in seconds on modern GPU".to_string()),
        _ => None,
    }
}

/// Parse credential entries from a passwd/shadow-format file.
fn parse_credential_file(path: &Path) -> Vec<CredentialEntry> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 2 {
                return None;
            }
            let user = fields[0].to_string();
            let hash_field = fields[1].to_string();

            // Parse $id$salt$hash format
            let (algorithm_id, salt) = if hash_field.starts_with('$') {
                let parts: Vec<&str> = hash_field.split('$').collect();
                // parts[0] = "", parts[1] = id, parts[2] = salt, parts[3] = hash
                if parts.len() >= 3 {
                    (Some(parts[1].to_string()), Some(parts[2].to_string()))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Skip entries with no real password hash (*, !, x, empty)
            if hash_field == "*" || hash_field == "!" || hash_field == "x" || hash_field.is_empty()
            {
                return None;
            }

            Some(CredentialEntry {
                user,
                hash_field,
                algorithm_id,
                salt,
            })
        })
        .collect()
}

/// Compare credential hashes between two rootfs trees.
pub fn diff_credentials(base_root: &Path, head_root: &Path) -> Vec<CredentialDiff> {
    let credential_files = ["etc/passwd", "etc/shadow"];
    let mut diffs = Vec::new();

    for rel_path in &credential_files {
        let base_path = base_root.join(rel_path);
        let head_path = head_root.join(rel_path);

        if !base_path.exists() && !head_path.exists() {
            continue;
        }

        let base_entries = parse_credential_file(&base_path);
        let head_entries = parse_credential_file(&head_path);

        // Match by username
        for base_entry in &base_entries {
            let head_entry = head_entries.iter().find(|h| h.user == base_entry.user);

            if let Some(head_entry) = head_entry {
                let hash_identical = base_entry.hash_field == head_entry.hash_field;
                let algorithm_weakness =
                    base_entry.algorithm_id.as_deref().and_then(crypt_weakness);

                diffs.push(CredentialDiff {
                    path: rel_path.to_string(),
                    user: base_entry.user.clone(),
                    base_hash_algorithm: base_entry
                        .algorithm_id
                        .as_deref()
                        .map(|id| crypt_algorithm_name(id).to_string()),
                    head_hash_algorithm: head_entry
                        .algorithm_id
                        .as_deref()
                        .map(|id| crypt_algorithm_name(id).to_string()),
                    base_salt: base_entry.salt.clone(),
                    head_salt: head_entry.salt.clone(),
                    hash_identical,
                    algorithm_weakness,
                });
            }
        }
    }

    diffs
}

// ===== Init script line-level diffing =====

/// Classify a line from an init script by keyword.
fn classify_script_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    if trimmed.contains("mkdaemon")
        || trimmed.contains("start-stop-daemon")
        || trimmed.contains("procd")
        || trimmed.contains("service ")
    {
        return Some("service-management".to_string());
    }
    if trimmed.contains("insmod") || trimmed.contains("modprobe") || trimmed.contains("rmmod") {
        return Some("module-loading".to_string());
    }
    if trimmed.contains("ifconfig")
        || trimmed.contains("iptables")
        || trimmed.contains("route ")
        || trimmed.contains("brctl")
        || trimmed.contains("ip addr")
        || trimmed.contains("ip link")
    {
        return Some("network-config".to_string());
    }
    if trimmed.starts_with("export ") || (trimmed.contains('=') && !trimmed.contains("==")) {
        return Some("environment".to_string());
    }

    None
}

/// Diff two init/startup scripts and return classified line changes.
pub fn diff_config_scripts(
    base_root: &Path,
    head_root: &Path,
    changed_scripts: &[String],
) -> Vec<ScriptDiff> {
    let mut diffs = Vec::new();

    for script_path in changed_scripts {
        let base_path = base_root.join(script_path);
        let head_path = head_root.join(script_path);

        let base_content = std::fs::read_to_string(&base_path).unwrap_or_default();
        let head_content = std::fs::read_to_string(&head_path).unwrap_or_default();

        let base_lines: BTreeSet<&str> = base_content
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .collect();
        let head_lines: BTreeSet<&str> = head_content
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .collect();

        let added_lines: Vec<ClassifiedLine> = head_content
            .lines()
            .enumerate()
            .filter(|(_, l)| !base_lines.contains(l))
            .filter(|(_, l)| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .map(|(i, l)| ClassifiedLine {
                line_number: i + 1,
                content: l.to_string(),
                category: classify_script_line(l),
            })
            .collect();

        let removed_lines: Vec<ClassifiedLine> = base_content
            .lines()
            .enumerate()
            .filter(|(_, l)| !head_lines.contains(l))
            .filter(|(_, l)| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .map(|(i, l)| ClassifiedLine {
                line_number: i + 1,
                content: l.to_string(),
                category: classify_script_line(l),
            })
            .collect();

        if !added_lines.is_empty() || !removed_lines.is_empty() {
            diffs.push(ScriptDiff {
                path: script_path.clone(),
                added_lines,
                removed_lines,
            });
        }
    }

    diffs
}

// ===== Persistent weakness scanning =====

/// Scan both rootfs trees for known-bad patterns that are present in BOTH versions.
pub fn scan_persistent_weaknesses(base_root: &Path, head_root: &Path) -> Vec<PersistentWeakness> {
    let mut weaknesses = Vec::new();

    // Check for telnet init scripts in both
    check_pattern_in_both(
        base_root,
        head_root,
        &["etc/init.d"],
        |path| path.to_string_lossy().contains("telnet"),
        "debug-surface",
        "telnet init script present in both versions",
        &mut weaknesses,
    );

    // Check for weak credential hashes in /etc/passwd
    check_weak_credentials(base_root, head_root, "etc/passwd", &mut weaknesses);
    check_weak_credentials(base_root, head_root, "etc/shadow", &mut weaknesses);

    // Check for world-readable sensitive files
    check_world_readable(base_root, head_root, "etc/shadow", &mut weaknesses);

    // Check for telnetd references in init scripts (commented or not)
    check_content_pattern_both(
        base_root,
        head_root,
        "telnetd",
        "debug-surface",
        "telnetd reference present in init scripts in both versions",
        &mut weaknesses,
    );

    // Check for command injection patterns (e.g., unquoted variable expansion in commands)
    for script_name in &["wifi.sh", "internet.sh"] {
        check_injection_pattern(base_root, head_root, script_name, &mut weaknesses);
    }

    weaknesses
}

fn check_pattern_in_both(
    base_root: &Path,
    head_root: &Path,
    search_dirs: &[&str],
    matcher: impl Fn(&Path) -> bool,
    category: &str,
    description: &str,
    weaknesses: &mut Vec<PersistentWeakness>,
) {
    for dir in search_dirs {
        let base_dir = base_root.join(dir);
        let head_dir = head_root.join(dir);
        if !base_dir.is_dir() || !head_dir.is_dir() {
            continue;
        }

        // Find matching files in base
        let base_matches: Vec<_> = WalkDir::new(&base_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file() && matcher(e.path()))
            .collect();

        for base_entry in &base_matches {
            let rel = base_entry
                .path()
                .strip_prefix(base_root)
                .unwrap_or(base_entry.path());
            let head_path = head_root.join(rel);
            if head_path.exists() {
                weaknesses.push(PersistentWeakness {
                    category: category.to_string(),
                    description: description.to_string(),
                    path: rel.display().to_string(),
                    base_evidence: "present".to_string(),
                    head_evidence: "present".to_string(),
                });
            }
        }
    }
}

fn check_weak_credentials(
    base_root: &Path,
    head_root: &Path,
    rel_path: &str,
    weaknesses: &mut Vec<PersistentWeakness>,
) {
    let base_path = base_root.join(rel_path);
    let head_path = head_root.join(rel_path);

    if !base_path.exists() || !head_path.exists() {
        return;
    }

    let base_entries = parse_credential_file(&base_path);
    let head_entries = parse_credential_file(&head_path);

    for base_entry in &base_entries {
        if let Some(ref alg_id) = base_entry.algorithm_id {
            // Only flag weak algorithms
            if crypt_weakness(alg_id).is_none() {
                continue;
            }
            if let Some(head_entry) = head_entries.iter().find(|h| h.user == base_entry.user) {
                if base_entry.hash_field == head_entry.hash_field {
                    let salt_info = base_entry
                        .salt
                        .as_deref()
                        .map(|s| format!(", salt={s}"))
                        .unwrap_or_default();
                    weaknesses.push(PersistentWeakness {
                        category: "credential".to_string(),
                        description: format!(
                            "{} password hash identical across versions ({}{})",
                            base_entry.user,
                            crypt_algorithm_name(alg_id),
                            salt_info
                        ),
                        path: rel_path.to_string(),
                        base_evidence: format!("${alg_id}$..."),
                        head_evidence: format!("${alg_id}$... (identical)"),
                    });
                }
            }
        }
    }
}

fn check_world_readable(
    base_root: &Path,
    head_root: &Path,
    rel_path: &str,
    weaknesses: &mut Vec<PersistentWeakness>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let base_path = base_root.join(rel_path);
        let head_path = head_root.join(rel_path);

        if !base_path.exists() || !head_path.exists() {
            return;
        }

        let base_mode = std::fs::metadata(&base_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0);
        let head_mode = std::fs::metadata(&head_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0);

        let base_world_readable = base_mode & 0o004 != 0;
        let head_world_readable = head_mode & 0o004 != 0;

        if base_world_readable && head_world_readable {
            weaknesses.push(PersistentWeakness {
                category: "file-permissions".to_string(),
                description: format!("{rel_path} is world-readable in both versions"),
                path: rel_path.to_string(),
                base_evidence: format!("mode {:o}", base_mode & 0o7777),
                head_evidence: format!("mode {:o}", head_mode & 0o7777),
            });
        }
    }
}

fn check_content_pattern_both(
    base_root: &Path,
    head_root: &Path,
    pattern: &str,
    category: &str,
    description: &str,
    weaknesses: &mut Vec<PersistentWeakness>,
) {
    let init_dirs = ["etc/init.d", "etc/rc.d", "init", "system/init"];
    for dir in &init_dirs {
        let base_dir = base_root.join(dir);
        let head_dir = head_root.join(dir);
        if !base_dir.is_dir() || !head_dir.is_dir() {
            continue;
        }

        for entry in WalkDir::new(&base_dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let base_content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            if !base_content.contains(pattern) {
                continue;
            }

            let rel = entry.path().strip_prefix(base_root).unwrap_or(entry.path());
            let head_path = head_root.join(rel);

            let head_content = std::fs::read_to_string(&head_path).unwrap_or_default();
            if head_content.contains(pattern) {
                weaknesses.push(PersistentWeakness {
                    category: category.to_string(),
                    description: description.to_string(),
                    path: rel.display().to_string(),
                    base_evidence: format!("contains '{pattern}'"),
                    head_evidence: format!("contains '{pattern}'"),
                });
                return; // One finding per pattern is enough
            }
        }
    }
}

fn check_injection_pattern(
    base_root: &Path,
    head_root: &Path,
    script_name: &str,
    weaknesses: &mut Vec<PersistentWeakness>,
) {
    // Search for the script in common locations
    let search_dirs = [
        "",
        "init",
        "system/init",
        "etc/init.d",
        "bin",
        "sbin",
        "usr/bin",
    ];
    for dir in &search_dirs {
        let base_path = base_root.join(dir).join(script_name);
        let head_path = head_root.join(dir).join(script_name);

        if !base_path.is_file() || !head_path.is_file() {
            continue;
        }

        let base_content = std::fs::read_to_string(&base_path).unwrap_or_default();
        let head_content = std::fs::read_to_string(&head_path).unwrap_or_default();

        // Look for unquoted variable expansion in command/config rewrite context.
        let has_injection = |content: &str| -> bool {
            content.lines().any(|line| {
                let trimmed = line.trim();
                let lower = trimmed.to_ascii_lowercase();
                !trimmed.starts_with('#')
                    && (lower.contains("$ssid")
                        || lower.contains("${ssid")
                        || lower.contains("$wifissid")
                        || lower.contains("$wifipasswd")
                        || (lower.contains("sed -i")
                            && lower.contains("$key")
                            && lower.contains("$newvalue"))
                        || (lower.contains("rewrite_config_value")
                            && (lower.contains("wifissid") || lower.contains("wifipasswd")))
                        || (lower.contains("eval ") && trimmed.contains('$')))
            })
        };

        if has_injection(&base_content) && has_injection(&head_content) {
            let rel = base_path.strip_prefix(base_root).unwrap_or(&base_path);
            weaknesses.push(PersistentWeakness {
                category: "injection".to_string(),
                description: format!(
                    "command injection pattern present in {script_name} in both versions"
                ),
                path: rel.display().to_string(),
                base_evidence: "unquoted variable expansion in command".to_string(),
                head_evidence: "unquoted variable expansion in command".to_string(),
            });
            return;
        }
    }
}
