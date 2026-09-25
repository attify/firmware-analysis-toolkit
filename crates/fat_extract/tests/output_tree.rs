use std::path::Path;

use fat_extract::output::{ExtractionLimits, OutputTree};

#[test]
fn output_is_published_only_after_finish() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("tree");
    let mut tree = OutputTree::new(&destination, ExtractionLimits::default()).unwrap();
    tree.create_dir(Path::new("etc"), 0o755).unwrap();
    tree.write_file(Path::new("etc/config"), b"ready\n", 0o644)
        .unwrap();
    assert!(!destination.exists());
    let stats = tree.finish().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 6);
    assert_eq!(
        std::fs::read(destination.join("etc/config")).unwrap(),
        b"ready\n"
    );
}

#[test]
fn failed_or_abandoned_output_does_not_publish() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("tree");
    let limits = ExtractionLimits {
        max_output_bytes: 3,
        ..Default::default()
    };
    let mut tree = OutputTree::new(&destination, limits).unwrap();
    assert!(tree.write_file(Path::new("large"), b"four", 0o644).is_err());
    assert!(tree
        .write_file(Path::new("../outside"), b"x", 0o644)
        .is_err());
    drop(tree);
    assert!(!destination.exists());
    assert!(!temp.path().join("outside").exists());
}

#[cfg(unix)]
#[test]
fn links_are_preserved_without_following_them_during_writes() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("tree");
    let mut tree = OutputTree::new(&destination, ExtractionLimits::default()).unwrap();
    tree.write_symlink(Path::new("sbin/init"), Path::new("../bin/busybox"))
        .unwrap();
    tree.write_file(Path::new("bin/busybox"), b"ELF", 0o755)
        .unwrap();
    tree.finish().unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("sbin/init")).unwrap(),
        Path::new("../bin/busybox")
    );
    assert_eq!(
        std::fs::read(destination.join("sbin/init")).unwrap(),
        b"ELF"
    );
}

#[test]
fn a_link_cannot_be_used_as_an_output_parent() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("tree");
    let mut tree = OutputTree::new(&destination, ExtractionLimits::default()).unwrap();
    tree.write_symlink(Path::new("outside"), temp.path())
        .unwrap();
    assert!(tree
        .write_file(Path::new("outside/escape"), b"x", 0o644)
        .is_err());
    assert!(!temp.path().join("escape").exists());
}

#[test]
fn entries_and_individual_files_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let limits = ExtractionLimits {
        max_entries: 2,
        max_file_bytes: 2,
        ..Default::default()
    };
    let mut tree = OutputTree::new(&temp.path().join("tree"), limits).unwrap();
    assert!(tree.write_file(Path::new("large"), b"123", 0o644).is_err());
    tree.write_file(Path::new("one"), b"12", 0o644).unwrap();
    assert!(tree.write_file(Path::new("two"), b"1", 0o644).is_err());
}

#[test]
fn symlink_targets_share_the_output_budget() {
    let temp = tempfile::tempdir().unwrap();
    let limits = ExtractionLimits {
        max_output_bytes: 5,
        ..Default::default()
    };
    let mut tree = OutputTree::new(&temp.path().join("tree"), limits).unwrap();
    tree.write_symlink(Path::new("link"), Path::new("12345"))
        .unwrap();
    assert_eq!(tree.stats().bytes, 5);
    assert!(tree
        .write_symlink(Path::new("second"), Path::new("x"))
        .is_err());
    assert!(tree.write_file(Path::new("file"), b"x", 0o644).is_err());
}
