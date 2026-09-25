use fat_extract::manifest::{
    EngineReport, EngineStatus, ExtractedFilesystemTree, ExtractionManifest,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn extraction_manifest_records_rootfs_and_artifacts() {
    let manifest = ExtractionManifest {
        rootfs_path: Some("extracted/rootfs".into()),
        kernel_paths: vec!["extracted/kernel.bin".into()],
        file_count: 42,
        filesystem_trees: vec![ExtractedFilesystemTree {
            role: "rootfs".into(),
            path: "extracted/rootfs".into(),
            tree_kind: "rootfs".into(),
        }],
        ..Default::default()
    };
    let json = serde_json::to_value(&manifest).unwrap();

    assert_eq!(
        manifest.rootfs_path.as_deref(),
        Some(PathBuf::from("extracted/rootfs").as_path())
    );
    assert_eq!(manifest.file_count, 42);
    assert_eq!(manifest.kernel_paths.len(), 1);
    assert_eq!(json["rootfs_path"], "extracted/rootfs");
    assert_eq!(json["kernel_paths"][0], "extracted/kernel.bin");
    assert_eq!(json["filesystem_trees"][0]["role"], "rootfs");
}

#[test]
fn legacy_extraction_manifest_defaults_filesystem_trees() {
    let manifest: ExtractionManifest = serde_json::from_value(serde_json::json!({
        "rootfs_path": "extracted/rootfs",
        "kernel_paths": [],
        "file_count": 3
    }))
    .unwrap();

    assert!(manifest.filesystem_trees.is_empty());
    // Manifests written before engine provenance existed stay loadable and
    // simply claim no engine.
    assert!(manifest.engine.is_none());
    assert!(manifest.engine_reports.is_empty());
}

#[test]
fn extraction_manifest_round_trips_engine_provenance() {
    let manifest = ExtractionManifest {
        engine: Some("binwalk".into()),
        engine_reports: vec![
            EngineReport::new("native", EngineStatus::Skipped)
                .with_detail("no supported regions in the image"),
            EngineReport::new("binwalk", EngineStatus::Succeeded).with_detail("carved a rootfs"),
            EngineReport::new("unblob", EngineStatus::Failed),
        ],
        ..Default::default()
    };

    let json = serde_json::to_value(&manifest).unwrap();
    assert_eq!(json["engine"], "binwalk");
    assert_eq!(json["engine_reports"][0]["status"], "skipped");
    assert_eq!(
        json["engine_reports"][0]["detail"],
        "no supported regions in the image"
    );
    // A report with no detail omits the key rather than writing null.
    assert!(json["engine_reports"][2].get("detail").is_none());

    let restored: ExtractionManifest = serde_json::from_value(json).unwrap();
    assert_eq!(restored, manifest);
    assert_eq!(
        restored.engine_reports[1].summary_line(),
        "binwalk: succeeded (carved a rootfs)"
    );
    assert_eq!(restored.engine_reports[2].summary_line(), "unblob: failed");
}

#[test]
fn find_all_trees_distinguishes_wyze_rootfs_and_app_partition() {
    let extracted = unique_temp_dir("fat-extract-wyze-trees");
    let rootfs = extracted.join("2031680-4849728.squashfs_v4_le_extract");
    fs::create_dir_all(rootfs.join("sbin")).unwrap();
    fs::create_dir_all(rootfs.join("etc")).unwrap();
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::write(rootfs.join("sbin/init"), b"#!/bin/sh\n").unwrap();

    let app = extracted.join("6029376-9367616.squashfs_v4_le_extract");
    fs::create_dir_all(app.join("init")).unwrap();
    fs::create_dir_all(app.join("bin")).unwrap();
    fs::create_dir_all(app.join("lib")).unwrap();
    fs::write(app.join("init/app_init.sh"), b"#!/bin/sh\n").unwrap();
    fs::write(app.join("bin/iCamera"), b"ELF").unwrap();

    let trees = fat_extract::rootfs::find_all_trees(&extracted);

    assert_eq!(trees, vec![("app".into(), app), ("rootfs".into(), rootfs)]);
}

#[test]
fn find_rootfs_discovers_nested_rootfs_directory() {
    let root = unique_temp_dir("fat-extract-rootfs");
    let nested_rootfs = root.join("firmware").join("extracted").join("rootfs");
    fs::create_dir_all(&nested_rootfs).unwrap();
    fs::create_dir_all(nested_rootfs.join("bin")).unwrap();
    fs::write(nested_rootfs.join("bin/busybox"), b"ELF").unwrap();

    let found = fat_extract::rootfs::find_rootfs(root.join("firmware"));

    assert_eq!(found.as_deref(), Some(nested_rootfs.as_path()));
}

#[test]
fn find_rootfs_accepts_a_rootfs_directory_as_input() {
    let root = unique_temp_dir("fat-extract-rootfs-direct");
    let rootfs = root.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::write(rootfs.join("bin/busybox"), b"ELF").unwrap();

    let found = fat_extract::rootfs::find_rootfs(&rootfs);

    assert_eq!(found.as_deref(), Some(rootfs.as_path()));
}

#[test]
fn find_rootfs_accepts_a_jffs2_root_directory_as_input() {
    let root = unique_temp_dir("fat-extract-jffs2-rootfs-direct");
    let rootfs = root.join("jffs2-root");
    fs::create_dir_all(&rootfs).unwrap();
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::write(rootfs.join("bin/busybox"), b"ELF").unwrap();

    let found = fat_extract::rootfs::find_rootfs(&rootfs);

    assert_eq!(found.as_deref(), Some(rootfs.as_path()));
}

#[cfg(unix)]
#[test]
fn find_rootfs_skips_symlink_cycles() {
    use std::os::unix::fs::symlink;

    let root = unique_temp_dir("fat-extract-rootfs-symlink");
    let nested = root.join("firmware").join("extracted");
    let nested_rootfs = nested.join("rootfs");
    fs::create_dir_all(&nested_rootfs).unwrap();
    fs::create_dir_all(nested_rootfs.join("bin")).unwrap();
    fs::write(nested_rootfs.join("bin/busybox"), b"ELF").unwrap();
    symlink(root.join("firmware"), nested.join("loop")).unwrap();

    let found = fat_extract::rootfs::find_rootfs(root.join("firmware"));

    assert_eq!(found.as_deref(), Some(nested_rootfs.as_path()));
}

#[test]
fn unblob_handler_names_identify_the_filesystem_they_unpacked() {
    use fat_extract::rootfs::unblob_filesystem_kind;

    assert_eq!(
        unblob_filesystem_kind("0-1048576.squashfs_v4_le_extract"),
        Some("squashfs")
    );
    assert_eq!(
        unblob_filesystem_kind("2031680-4849728.cramfs_extract"),
        Some("cramfs")
    );
    assert_eq!(
        unblob_filesystem_kind("0-512.jffs2_new_extract"),
        Some("jffs2")
    );
    // Envelope handlers unpack a container, not a filesystem, so they are a
    // directory to walk into rather than a tree to report.
    assert_eq!(unblob_filesystem_kind("0-4096.gzip_extract"), None);
    assert_eq!(unblob_filesystem_kind("0-4096.lzma_extract"), None);
    // binwalk's own naming must not be mistaken for unblob's.
    assert_eq!(unblob_filesystem_kind("_firmware.bin.extracted"), None);
    assert_eq!(unblob_filesystem_kind("squashfs-root"), None);
}

#[test]
fn find_rootfs_recognizes_an_unblob_tree_content_sniffing_would_miss() {
    let root = unique_temp_dir("fat-extract-unblob-layout");
    // A tree with none of the anchors the content heuristics look for: no
    // sbin/init, no etc/inittab, and only one of the marker directories.
    let tree = root.join("0-1048576.squashfs_v4_le_extract");
    fs::create_dir_all(tree.join("bin")).unwrap();
    fs::create_dir_all(tree.join("www")).unwrap();
    fs::write(tree.join("bin/busybox"), b"ELF").unwrap();

    let found = fat_extract::rootfs::find_rootfs(&root);

    assert_eq!(found.as_deref(), Some(tree.as_path()));
}

#[test]
fn an_empty_unblob_extract_directory_is_not_reported_as_a_tree() {
    let root = unique_temp_dir("fat-extract-unblob-empty");
    // A handler that matched but unpacked nothing must not look like a rootfs.
    fs::create_dir_all(root.join("0-1048576.squashfs_v4_le_extract")).unwrap();

    assert_eq!(fat_extract::rootfs::find_rootfs(&root), None);
}

#[test]
fn find_all_trees_labels_unblob_trees_by_handler() {
    let root = unique_temp_dir("fat-extract-unblob-trees");
    let tree = root.join("0-1048576.squashfs_v4_le_extract");
    fs::create_dir_all(tree.join("bin")).unwrap();
    fs::create_dir_all(tree.join("www")).unwrap();
    fs::write(tree.join("bin/busybox"), b"ELF").unwrap();

    let trees = fat_extract::rootfs::find_all_trees(&root);

    assert_eq!(trees, vec![("squashfs".to_string(), tree)]);
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let unique = format!(
        "{}-{}-{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    dir.push(unique);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn empty_named_directories_are_not_recovered_filesystems() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("squashfs-root")).unwrap();
    assert!(fat_extract::rootfs::find_rootfs(temp.path()).is_none());
    assert!(fat_extract::rootfs::find_all_trees(temp.path()).is_empty());
}

#[test]
fn a_directory_name_and_readme_do_not_prove_rootfs_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("rootfs");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("readme"), b"firmware package").unwrap();
    assert!(fat_extract::rootfs::find_rootfs(temp.path()).is_none());
    assert_eq!(
        fat_extract::rootfs::find_all_trees(temp.path())[0].0,
        "filesystem"
    );
}
