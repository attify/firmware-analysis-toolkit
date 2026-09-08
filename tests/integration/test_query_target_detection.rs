use std::fs;

use tempfile::tempdir;

#[test]
fn detect_target_kind_distinguishes_wave1_artifacts() {
    let dir = tempdir().expect("tempdir");

    let elf_path = dir.path().join("demo.elf");
    fs::write(&elf_path, [0x7f, b'E', b'L', b'F', 0, 0, 0, 0]).expect("elf");

    let macho_path = dir.path().join("service-launcher");
    fs::write(&macho_path, [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).expect("macho");

    let blob_path = dir.path().join("firmware.bin");
    fs::write(&blob_path, [0x00, 0x11, 0x22, 0x33]).expect("blob");

    let source_dir = dir.path().join("src-repo");
    fs::create_dir_all(source_dir.join("src")).expect("source dir");
    fs::write(
        source_dir.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .expect("cargo");
    fs::write(source_dir.join("src/main.rs"), "fn main() {}\n").expect("rs");

    let rootfs_dir = dir.path().join("rootfs");
    fs::create_dir_all(rootfs_dir.join("bin")).expect("bin");
    fs::create_dir_all(rootfs_dir.join("etc")).expect("etc");
    fs::create_dir_all(rootfs_dir.join("usr")).expect("usr");

    assert_eq!(
        fat_query::target_detection::detect_path(&elf_path)
            .expect("elf detection")
            .kind,
        fat_query::target_detection::TargetKind::ElfBinary
    );
    assert_eq!(
        fat_query::target_detection::detect_path(&macho_path)
            .expect("macho detection")
            .kind,
        fat_query::target_detection::TargetKind::MachOBinary
    );
    assert_eq!(
        fat_query::target_detection::detect_path(&blob_path)
            .expect("blob detection")
            .kind,
        fat_query::target_detection::TargetKind::RawBlob
    );
    assert_eq!(
        fat_query::target_detection::detect_path(&source_dir)
            .expect("source detection")
            .kind,
        fat_query::target_detection::TargetKind::SourceTree
    );
    assert_eq!(
        fat_query::target_detection::detect_path(&rootfs_dir)
            .expect("rootfs detection")
            .kind,
        fat_query::target_detection::TargetKind::Rootfs
    );
}

#[test]
fn detect_target_kind_resolves_cpp_codeql_database_to_source_tree() {
    let dir = tempdir().expect("tempdir");
    let source_root = dir.path().join("kernel-src");
    let db_root = dir.path().join("binder-db");
    fs::create_dir_all(source_root.join("drivers/android")).expect("source root");
    fs::create_dir_all(&db_root).expect("db root");
    fs::write(
        source_root.join("drivers/android/binder.c"),
        "int binder() { return 0; }\n",
    )
    .expect("source file");
    fs::write(
        db_root.join("codeql-database.yml"),
        format!(
            "---\nsourceLocationPrefix: {}\nprimaryLanguage: cpp\nfinalised: true\n",
            source_root.display()
        ),
    )
    .expect("codeql metadata");

    let detected = fat_query::target_detection::detect_path(&db_root).expect("codeql detection");
    assert_eq!(
        detected.kind,
        fat_query::target_detection::TargetKind::CodeQlDatabase
    );
    assert_eq!(detected.path, db_root);
}

#[test]
fn detect_target_kind_recognizes_python_codeql_database() {
    let dir = tempdir().expect("tempdir");
    let source_root = dir.path().join("spot-sdk");
    let db_root = dir.path().join("spot-codeql");
    fs::create_dir_all(&source_root).expect("source root");
    fs::create_dir_all(&db_root).expect("db root");
    fs::write(
        db_root.join("codeql-database.yml"),
        format!(
            "---\nsourceLocationPrefix: {}\nprimaryLanguage: python\nfinalised: true\n",
            source_root.display()
        ),
    )
    .expect("codeql metadata");

    let detected = fat_query::target_detection::detect_path(&db_root).expect("python codeql");
    assert_eq!(
        detected.kind,
        fat_query::target_detection::TargetKind::CodeQlDatabase
    );
    assert_eq!(detected.path, db_root);
}

#[test]
fn detect_target_kind_rejects_ambiguous_multi_codeql_directory() {
    let dir = tempdir().expect("tempdir");
    let source_root = dir.path().join("android-kernel");
    let first_db = dir.path().join("codeql-db/binder-db");
    let second_db = dir.path().join("codeql-db/pkvm-db");
    fs::create_dir_all(&source_root).expect("source root");
    fs::create_dir_all(&first_db).expect("first db");
    fs::create_dir_all(&second_db).expect("second db");
    fs::write(
        first_db.join("codeql-database.yml"),
        format!(
            "---\nsourceLocationPrefix: {}\nprimaryLanguage: cpp\nfinalised: true\n",
            source_root.display()
        ),
    )
    .expect("first metadata");
    fs::write(
        second_db.join("codeql-database.yml"),
        format!(
            "---\nsourceLocationPrefix: {}\nprimaryLanguage: cpp\nfinalised: true\n",
            source_root.display()
        ),
    )
    .expect("second metadata");

    let error = fat_query::target_detection::detect_path(&dir.path().join("codeql-db"))
        .expect_err("multi-db rejected");
    assert!(
        error.contains("contains multiple CodeQL databases"),
        "{error}"
    );
    assert!(error.contains("binder-db"), "{error}");
    assert!(error.contains("pkvm-db"), "{error}");
}
