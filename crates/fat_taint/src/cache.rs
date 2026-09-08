//! Content-addressed result cache for taint analysis findings.
//!
//! Cache key = sha256(binary_contents + sorted_profile_contents), truncated to
//! 16 hex chars. Cache location = ~/.fat/cache/taint/<key>.json.
//!
//! The cache is purely an optimisation — if it fails (permissions, disk full,
//! corrupt data) callers silently fall back to running angr.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Compute the cache key from binary contents + profile contents.
///
/// The key is the first 16 hex characters of
/// `sha256(binary_bytes || sorted_profile_contents)`.
pub fn compute_cache_key(binary_path: &Path, profile_contents: &[&str]) -> String {
    let mut hasher = Sha256::new();
    // Hash the binary contents
    let binary_bytes = std::fs::read(binary_path).unwrap_or_default();
    hasher.update(&binary_bytes);
    // Hash all loaded profile contents (sorted for determinism)
    let mut sorted_profiles: Vec<&str> = profile_contents.to_vec();
    sorted_profiles.sort();
    for profile in sorted_profiles {
        hasher.update(profile.as_bytes());
    }
    let result = hasher.finalize();
    hex::encode(&result[..8]) // first 8 bytes = 16 hex chars
}

/// Get the cache directory path.
/// Uses ~/.fat/cache/taint/ by default.
pub fn cache_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fat")
        .join("cache")
        .join("taint")
}

/// Get the cache file path for a given key within the given directory.
pub fn cache_path_in(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{key}.json"))
}

/// Get the cache file path for a given key using the default cache dir.
pub fn cache_path(key: &str) -> PathBuf {
    cache_path_in(&cache_dir(), key)
}

/// Try to load cached findings from a specific directory.
pub fn load_from(dir: &Path, key: &str) -> Option<String> {
    let path = cache_path_in(dir, key);
    std::fs::read_to_string(path).ok()
}

/// Try to load cached findings from the default cache directory.
pub fn load(key: &str) -> Option<String> {
    load_from(&cache_dir(), key)
}

/// Save findings to a specific cache directory. Creates directories if needed.
/// Writes atomically via temp file + rename.
pub fn save_to(dir: &Path, key: &str, json: &str) -> std::io::Result<()> {
    let path = cache_path_in(dir, key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Write atomically: temp file then rename
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Save findings to the default cache directory. Creates directories if needed.
/// Writes atomically via temp file + rename.
pub fn save(key: &str, json: &str) -> std::io::Result<()> {
    save_to(&cache_dir(), key, json)
}

/// Get cache file age from a specific directory.
pub fn cache_age_in(dir: &Path, key: &str) -> Option<std::time::Duration> {
    let path = cache_path_in(dir, key);
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    std::time::SystemTime::now().duration_since(modified).ok()
}

/// Get cache file metadata (for displaying age) from the default cache dir.
pub fn cache_age(key: &str) -> Option<std::time::Duration> {
    cache_age_in(&cache_dir(), key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // compute_cache_key
    // -------------------------------------------------------------------

    #[test]
    fn test_same_input_produces_same_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello binary").unwrap();

        let key1 = compute_cache_key(tmp.path(), &["profile_a", "profile_b"]);
        let key2 = compute_cache_key(tmp.path(), &["profile_a", "profile_b"]);

        assert_eq!(key1, key2, "same inputs must produce the same cache key");
        assert!(!key1.is_empty(), "cache key must not be empty");
        assert_eq!(key1.len(), 16, "cache key must be 16 hex chars (8 bytes)");
    }

    #[test]
    fn test_different_binary_produces_different_key() {
        let tmp1 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp1.path(), b"binary_A").unwrap();

        let tmp2 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp2.path(), b"binary_B").unwrap();

        let profiles = &["profile_a"];
        let key1 = compute_cache_key(tmp1.path(), profiles);
        let key2 = compute_cache_key(tmp2.path(), profiles);

        assert_ne!(
            key1, key2,
            "different binary contents must produce different keys"
        );
    }

    #[test]
    fn test_different_profiles_produces_different_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"same binary").unwrap();

        let key1 = compute_cache_key(tmp.path(), &["profile_v1"]);
        let key2 = compute_cache_key(tmp.path(), &["profile_v2"]);

        assert_ne!(
            key1, key2,
            "different profile contents must produce different keys"
        );
    }

    #[test]
    fn test_profile_order_does_not_matter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"binary").unwrap();

        let key1 = compute_cache_key(tmp.path(), &["alpha", "beta", "gamma"]);
        let key2 = compute_cache_key(tmp.path(), &["gamma", "alpha", "beta"]);

        assert_eq!(
            key1, key2,
            "profile order must not affect the cache key (sorted internally)"
        );
    }

    #[test]
    fn test_empty_profiles_is_valid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"binary").unwrap();

        let key = compute_cache_key(tmp.path(), &[]);
        assert_eq!(
            key.len(),
            16,
            "cache key must be 16 hex chars even with no profiles"
        );
    }

    // -------------------------------------------------------------------
    // save_to / load_from round-trip
    // -------------------------------------------------------------------

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_id = "fixture-cache-id";
        let json = r#"[{"id":"TAINT-001","title":"test"}]"#;

        save_to(dir.path(), cache_id, json).unwrap();
        let loaded = load_from(dir.path(), cache_id);
        assert_eq!(
            loaded.as_deref(),
            Some(json),
            "round-trip must preserve content"
        );
    }

    #[test]
    fn test_save_creates_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deep").join("nested").join("cache");
        let key = "abc123";
        let json = "{}";

        save_to(&nested, key, json).unwrap();
        let loaded = load_from(&nested, key);
        assert_eq!(
            loaded.as_deref(),
            Some(json),
            "save must create parent directories"
        );
    }

    #[test]
    fn test_save_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let key = "overwrite_test";

        save_to(dir.path(), key, "old").unwrap();
        save_to(dir.path(), key, "new").unwrap();

        let loaded = load_from(dir.path(), key);
        assert_eq!(
            loaded.as_deref(),
            Some("new"),
            "save must overwrite existing cache entries"
        );
    }

    #[test]
    fn test_load_returns_none_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_from(dir.path(), "nonexistent_key");
        assert!(
            result.is_none(),
            "load must return None for missing cache entries"
        );
    }

    #[test]
    fn test_no_temp_file_left_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let key = "cleanup_test";
        save_to(dir.path(), key, "data").unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only the final .json file should remain, no .tmp"
        );
        let name = entries[0].file_name();
        assert!(
            name.to_string_lossy().ends_with(".json"),
            "remaining file must be .json, got: {name:?}"
        );
    }

    // -------------------------------------------------------------------
    // cache_age_in
    // -------------------------------------------------------------------

    #[test]
    fn test_cache_age_none_for_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = cache_age_in(dir.path(), "nonexistent");
        assert!(
            result.is_none(),
            "cache_age must return None for missing entries"
        );
    }

    #[test]
    fn test_cache_age_some_for_existing() {
        let dir = tempfile::tempdir().unwrap();
        let key = "age_test";
        save_to(dir.path(), key, "data").unwrap();

        let age = cache_age_in(dir.path(), key);
        assert!(
            age.is_some(),
            "cache_age must return Some for existing entries"
        );
        // The age should be very small (just written)
        let secs = age.unwrap().as_secs();
        assert!(
            secs < 5,
            "freshly written cache should be less than 5 seconds old, got: {secs}"
        );
    }

    // -------------------------------------------------------------------
    // cache_dir
    // -------------------------------------------------------------------

    #[test]
    fn test_cache_dir_ends_with_expected_path() {
        let dir = cache_dir();
        assert!(
            dir.ends_with(".fat/cache/taint"),
            "cache_dir must end with .fat/cache/taint, got: {}",
            dir.display()
        );
    }
}
