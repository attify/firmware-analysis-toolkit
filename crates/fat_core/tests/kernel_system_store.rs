use std::fs;
use std::path::Path;

use fat_core::kernel_system::{
    verify_bundle_directory, ArtifactFile, KernelArtifactBundleManifest, KernelArtifactStore,
    KernelClass, SupportTier,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn write(path: &Path, content: &[u8]) -> ArtifactFile {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create artifact parent");
    }
    fs::write(path, content).expect("write artifact");
    ArtifactFile {
        path: path.file_name().unwrap().to_string_lossy().into_owned(),
        digest: digest(content),
        role: "test-artifact".into(),
    }
}

fn fixture_bundle(root: &Path) -> KernelArtifactBundleManifest {
    let kernel_image = write(&root.join("vmlinux"), b"kernel");
    let final_config = write(&root.join("config.final"), b"CONFIG_TEST=y\n");
    let build_log = write(&root.join("build.log"), b"build succeeded\n");
    KernelArtifactBundleManifest {
        schema_version: "1.0".into(),
        id: String::new(),
        recipe_id: "krc-0123456789abcdef".into(),
        class: KernelClass::Mips32O32LeR1Page4k,
        support_tier: SupportTier::Experimental,
        source_lock_id: "ksl-0123456789abcdef".into(),
        builder_id: "kbi-0123456789abcdef".into(),
        kernel_image,
        final_config,
        build_log,
        declared_files: vec![],
        attribution: vec![],
        recipe_reproducible: true,
        bit_reproducible: false,
    }
    .seal()
    .expect("fixture manifest")
}

#[test]
fn verifies_exact_declared_bundle_content() {
    let source = tempdir().expect("source");
    let manifest = fixture_bundle(source.path());

    let report = verify_bundle_directory(source.path(), &manifest).expect("valid bundle");

    assert_eq!(report.verified_files, 3);
    assert_eq!(report.bundle_id, manifest.id);
}

#[test]
fn rejects_tampered_and_undeclared_files() {
    let source = tempdir().expect("source");
    let manifest = fixture_bundle(source.path());
    fs::write(source.path().join("vmlinux"), b"tampered").expect("tamper kernel");
    fs::write(source.path().join("surprise.bin"), b"undeclared").expect("extra file");

    let errors = verify_bundle_directory(source.path(), &manifest).expect_err("tamper must fail");

    assert!(errors
        .iter()
        .any(|error| error.code == "artifact-digest-mismatch"));
    assert!(errors.iter().any(|error| error.code == "undeclared-file"));
}

#[test]
fn install_is_atomic_immutable_and_idempotent() {
    let source = tempdir().expect("source");
    let store_root = tempdir().expect("store");
    let manifest = fixture_bundle(source.path());
    let store = KernelArtifactStore::new(store_root.path());

    let first = store
        .install(source.path(), &manifest)
        .expect("first install");
    let second = store
        .install(source.path(), &manifest)
        .expect("idempotent install");

    assert!(first.installed);
    assert!(!second.installed);
    assert_eq!(first.bundle_dir, second.bundle_dir);
    assert!(first.bundle_dir.join("manifest.json").is_file());
    assert_eq!(
        store
            .active_bundle(KernelClass::Mips32O32LeR1Page4k)
            .unwrap(),
        Some(manifest.id)
    );
    assert!(store_root
        .path()
        .join("active/mips32-o32-le-r1-page4k.json")
        .is_file());
    assert!(!store_root.path().join("staging").exists());
}

#[test]
fn failed_install_does_not_publish_or_activate_partial_content() {
    let source = tempdir().expect("source");
    let store_root = tempdir().expect("store");
    let manifest = fixture_bundle(source.path());
    fs::write(source.path().join("config.final"), b"corrupt").expect("corrupt config");
    let store = KernelArtifactStore::new(store_root.path());

    store
        .install(source.path(), &manifest)
        .expect_err("invalid bundle");

    assert!(!store_root
        .path()
        .join("bundles")
        .join(&manifest.id)
        .exists());
    assert_eq!(
        store
            .active_bundle(KernelClass::Mips32O32LeR1Page4k)
            .unwrap(),
        None
    );
}

#[test]
fn existing_corrupt_bundle_is_never_treated_as_idempotent() {
    let source = tempdir().expect("source");
    let store_root = tempdir().expect("store");
    let manifest = fixture_bundle(source.path());
    let destination = store_root.path().join("bundles").join(&manifest.id);
    fs::create_dir_all(&destination).expect("fake destination");
    fs::write(destination.join("vmlinux"), b"wrong").expect("wrong existing content");
    let store = KernelArtifactStore::new(store_root.path());

    let errors = store
        .install(source.path(), &manifest)
        .expect_err("conflict must fail");

    assert!(errors
        .iter()
        .any(|error| error.code == "immutable-bundle-conflict"));
}
