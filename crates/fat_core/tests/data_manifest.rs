use std::path::Path;

use fat_core::data_manifest::{DataFileEntry, DataManifest, SUPPORTED_DATA_SCHEMA_VERSION};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn entry(path: &str, bytes: &[u8], required: bool) -> DataFileEntry {
    DataFileEntry {
        path: path.to_string(),
        sha256: digest(bytes),
        required,
    }
}

fn manifest(files: Vec<DataFileEntry>) -> DataManifest {
    DataManifest {
        schema_version: SUPPORTED_DATA_SCHEMA_VERSION,
        data_version: "2.0.0-alpha.3".to_string(),
        compatible_fat: ">=2.0.0-alpha.1,<2.1.0".to_string(),
        files,
    }
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn valid_manifest_verifies_compatible_tree() {
    let temp = tempdir().unwrap();
    let profile = b"id: acme/router\n";
    write(temp.path(), "profiles/rehosting/acme/router.yaml", profile);
    let manifest = manifest(vec![entry(
        "profiles/rehosting/acme/router.yaml",
        profile,
        true,
    )]);

    let report = manifest.verify_tree(temp.path(), "2.0.0-alpha.1").unwrap();

    assert_eq!(report.verified_files, 1);
    assert_eq!(report.missing_optional_files, 0);
}

#[test]
fn manifest_rejects_unsupported_schema_and_incompatible_fat_version() {
    let mut unsupported = manifest(Vec::new());
    unsupported.schema_version = SUPPORTED_DATA_SCHEMA_VERSION + 1;
    assert!(unsupported
        .verify_tree(Path::new("."), "2.0.0-alpha.1")
        .unwrap_err()
        .to_string()
        .contains("schema"));

    let incompatible = manifest(Vec::new());
    assert!(incompatible
        .verify_tree(Path::new("."), "1.9.0")
        .unwrap_err()
        .to_string()
        .contains("not compatible"));
}

#[test]
fn manifest_rejects_duplicate_absolute_and_parent_paths() {
    let duplicate = manifest(vec![
        entry("profiles/a.yaml", b"a", true),
        entry("profiles/a.yaml", b"a", true),
    ]);
    assert!(duplicate
        .verify_tree(Path::new("."), "2.0.0-alpha.1")
        .unwrap_err()
        .to_string()
        .contains("duplicate"));

    for unsafe_path in ["/etc/passwd", "profiles/../private/secret.yaml"] {
        let unsafe_manifest = manifest(vec![entry(unsafe_path, b"x", true)]);
        assert!(unsafe_manifest
            .verify_tree(Path::new("."), "2.0.0-alpha.1")
            .unwrap_err()
            .to_string()
            .contains("unsafe"));
    }
}

#[test]
fn manifest_rejects_digest_mismatch_and_missing_required_file() {
    let temp = tempdir().unwrap();
    write(temp.path(), "schemas/profile.json", b"changed");
    let mismatched = manifest(vec![entry("schemas/profile.json", b"expected", true)]);
    assert!(mismatched
        .verify_tree(temp.path(), "2.0.0-alpha.1")
        .unwrap_err()
        .to_string()
        .contains("SHA-256"));

    let missing = manifest(vec![entry("profiles/missing.yaml", b"missing", true)]);
    assert!(missing
        .verify_tree(temp.path(), "2.0.0-alpha.1")
        .unwrap_err()
        .to_string()
        .contains("required"));
}

#[test]
fn missing_optional_file_is_reported_but_allowed() {
    let temp = tempdir().unwrap();
    let manifest = manifest(vec![entry("examples/optional.yaml", b"optional", false)]);

    let report = manifest.verify_tree(temp.path(), "2.0.0-alpha.1").unwrap();

    assert_eq!(report.verified_files, 0);
    assert_eq!(report.missing_optional_files, 1);
}
