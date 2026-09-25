use std::fs;
use std::path::{Path, PathBuf};

const ROOTFS_CANDIDATES: &[&str] = &["rootfs", "filesystem", "squashfs-root", "jffs2-root"];

/// Well-known filesystem extraction directory name patterns produced by binwalk/unblob.
const FS_EXTRACTION_PATTERNS: &[&str] = &[
    "squashfs-root",
    "jffs2-root",
    "cramfs-root",
    "romfs-root",
    "cpio-root",
    "rootfs",
    "filesystem",
];

/// unblob names every unpacked chunk `<start>-<end>.<handler>_extract`, so the
/// handler that produced a tree is stated in its directory name. Reading that
/// name is how an unblob-only extraction gets first-class detection instead of
/// falling through to content sniffing, which mislabels multi-partition images.
fn unblob_extract_handler(dir_name: &str) -> Option<&str> {
    let stem = dir_name.strip_suffix("_extract")?;
    let handler = stem.rsplit('.').next()?;
    (!handler.is_empty()).then_some(handler)
}

/// Map an unblob handler name onto the filesystem it unpacks. Handlers that do
/// not produce a filesystem (gzip, lzma, tar envelopes) deliberately return
/// `None` — their `_extract` directory is a container to walk into, not a tree.
pub fn unblob_filesystem_kind(dir_name: &str) -> Option<&'static str> {
    let handler = unblob_extract_handler(dir_name)?;
    [
        ("squashfs", "squashfs"),
        ("cramfs", "cramfs"),
        ("jffs2", "jffs2"),
        ("ubifs", "ubifs"),
        ("romfs", "romfs"),
        ("yaffs", "yaffs"),
        ("cpio", "cpio"),
        ("extfs", "ext"),
        ("ext2", "ext"),
        ("ext3", "ext"),
        ("ext4", "ext"),
        ("fat16", "fat"),
        ("fat32", "fat"),
        ("iso9660", "iso9660"),
    ]
    .into_iter()
    .find_map(|(marker, kind)| handler.contains(marker).then_some(kind))
}

/// A filesystem tree unblob unpacked: named by a filesystem handler and holding
/// something. The emptiness check keeps a failed unpack from being reported as a
/// recovered tree.
fn is_unblob_filesystem_tree(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if unblob_filesystem_kind(&name.to_ascii_lowercase()).is_none() {
        return false;
    }
    has_tree_content(path)
}

fn has_tree_content(path: &Path) -> bool {
    walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| entry.file_type().is_file() || entry.file_type().is_symlink())
}

pub fn find_rootfs(dir: impl AsRef<Path>) -> Option<PathBuf> {
    let mut to_visit = vec![dir.as_ref().to_path_buf()];

    while let Some(current_dir) = to_visit.pop() {
        if is_rootfs_dir(&current_dir) {
            return Some(current_dir);
        }

        let Ok(entries) = fs::read_dir(&current_dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                let path = entry.path();
                if is_rootfs_dir(&path) {
                    return Some(path);
                }

                to_visit.push(path);
            }
        }
    }

    None
}

/// Discover all extracted filesystem trees under a directory.
///
/// Returns `Vec<(label, path)>` where label is a human-readable partition
/// identifier (e.g. "rootfs", "app", "squashfs-root-0"). Searches up to 4
/// levels deep and matches:
/// 1. Directories with well-known FS extraction names (squashfs-root, jffs2-root, etc.)
/// 2. Directories that look like a rootfs tree (sbin/init or etc/inittab + bin/lib/etc)
/// 3. Directories that look like an app partition (bin/ or lib/ present, no sbin/init)
pub fn find_all_trees(dir: impl AsRef<Path>) -> Vec<(String, PathBuf)> {
    let mut trees = Vec::new();
    let mut to_visit = vec![(dir.as_ref().to_path_buf(), 0u32)];

    while let Some((current_dir, depth)) = to_visit.pop() {
        if depth > 4 {
            continue;
        }

        let Ok(entries) = fs::read_dir(&current_dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if !file_type.is_dir() {
                continue;
            }

            let path = entry.path();
            let dir_name = entry.file_name().to_string_lossy().to_ascii_lowercase();

            // Check if this is a known FS extraction directory
            let is_known_fs = FS_EXTRACTION_PATTERNS
                .iter()
                .any(|pat| dir_name == *pat || dir_name.starts_with(&format!("{pat}-")))
                || is_unblob_filesystem_tree(&path);

            if is_known_fs && has_tree_content(&path) {
                let label = infer_tree_label(&path, &dir_name);
                // Don't add duplicates (same canonical path)
                if !trees.iter().any(|(_, p)| p == &path) {
                    trees.push((label, path.clone()));
                }
                // Don't recurse into matched trees
                continue;
            }

            // Check if the directory is a rootfs or app-like tree
            if looks_like_rootfs_tree(&path) {
                let label = infer_tree_label(&path, &dir_name);
                if !trees.iter().any(|(_, p)| p == &path) {
                    trees.push((label, path.clone()));
                }
                continue;
            }

            if looks_like_app_tree(&path) {
                let label = infer_tree_label(&path, &dir_name);
                if !trees.iter().any(|(_, p)| p == &path) {
                    trees.push((label, path.clone()));
                }
                continue;
            }

            // Recurse deeper
            to_visit.push((path, depth + 1));
        }
    }

    // Sort by label for deterministic output
    trees.sort_by(|a, b| a.0.cmp(&b.0));
    trees
}

fn is_rootfs_dir(path: &Path) -> bool {
    let name_matched = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| ROOTFS_CANDIDATES.contains(&name.to_ascii_lowercase().as_str()))
        .unwrap_or(false);
    looks_like_rootfs_tree(path)
        || ((name_matched || is_unblob_filesystem_tree(path))
            && has_file_entry(&path.join("bin/busybox")))
}

fn has_file_entry(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() || metadata.file_type().is_symlink())
}

fn looks_like_rootfs_tree(path: &Path) -> bool {
    let has_boot_anchor = has_file_entry(&path.join("sbin/init"))
        || has_file_entry(&path.join("etc/inittab"))
        || has_file_entry(&path.join("init"));
    if !has_boot_anchor {
        return false;
    }

    path.join("bin").is_dir() || path.join("lib").is_dir() || path.join("etc").is_dir()
}

/// Detect app-partition-like trees: have bin/ or lib/ but no sbin/init.
/// Must have at least two of: bin/, lib/, etc/ to avoid false positives.
fn looks_like_app_tree(path: &Path) -> bool {
    // Must NOT be a rootfs tree (already checked)
    if looks_like_rootfs_tree(path) {
        return false;
    }

    let markers = ["bin", "lib", "etc", "sbin", "usr"];
    let count = markers.iter().filter(|m| path.join(m).is_dir()).count();
    count >= 2
}

/// Infer a human-readable label for a tree based on its path and contents.
fn infer_tree_label(path: &Path, dir_name: &str) -> String {
    // If it looks like a rootfs, label it "rootfs"
    if looks_like_rootfs_tree(path) {
        return "rootfs".to_string();
    }
    if dir_name == "rootfs" && !is_rootfs_dir(path) {
        return "filesystem".to_string();
    }

    // If dir_name is a known FS pattern, use it directly
    for pat in FS_EXTRACTION_PATTERNS {
        if dir_name == *pat || dir_name.starts_with(&format!("{pat}-")) {
            // Check if it's really an app partition (has bin/iCamera-like binaries, no sbin/init)
            if looks_like_app_tree(path) {
                return "app".to_string();
            }
            return dir_name.to_string();
        }
    }

    // For app-like trees not matching known patterns
    if looks_like_app_tree(path) {
        return "app".to_string();
    }

    // unblob directory names carry their handler, which is a better label than
    // the offset-prefixed directory name.
    if let Some(kind) = unblob_filesystem_kind(dir_name) {
        return kind.to_string();
    }

    dir_name.to_string()
}
