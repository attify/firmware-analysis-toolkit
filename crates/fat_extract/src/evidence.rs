use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::rootfs::find_rootfs;

/// What an extractor actually recovered, measured from its output tree rather
/// than inferred from its exit code. Skip decisions and reported details both
/// read from this, so they can never disagree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarvedEvidence {
    pub rootfs: Option<PathBuf>,
    pub filesystem_images: usize,
    pub boot_artifacts: bool,
    pub file_count: usize,
}

impl CarvedEvidence {
    pub fn survey(root: &Path) -> Self {
        Self {
            rootfs: find_rootfs(root),
            filesystem_images: squashfs_candidates(root).len(),
            boot_artifacts: has_boot_artifact_dir(root),
            file_count: file_count(root),
        }
    }

    pub fn has_rootfs(&self) -> bool {
        self.rootfs.is_some()
    }

    /// True when the tree holds something a later stage could still work with.
    pub fn has_carved_candidates(&self) -> bool {
        self.has_rootfs() || self.boot_artifacts || self.filesystem_images > 0
    }

    /// How the run is described in the summary: `binwalk: succeeded (<this>)`.
    pub fn summary(&self) -> &'static str {
        if self.has_rootfs() {
            "carved a rootfs"
        } else if self.boot_artifacts {
            "carved boot artifacts"
        } else if self.filesystem_images > 0 {
            "carved candidate filesystem images"
        } else if self.file_count > 0 {
            "carved evidence without a rootfs"
        } else {
            "carved no recoverable evidence"
        }
    }

    /// How the run is described when it preempts a later extractor:
    /// `skipped unblob because binwalk already <this>`.
    pub fn precedence_phrase(&self) -> Option<&'static str> {
        if self.has_rootfs() {
            Some("recovered a rootfs")
        } else if self.boot_artifacts {
            Some("carved boot artifacts")
        } else if self.filesystem_images > 0 {
            Some("carved candidate filesystem images")
        } else {
            None
        }
    }
}

pub fn file_count(root: &Path) -> usize {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .count()
}

pub fn squashfs_candidates(root: &Path) -> Vec<PathBuf> {
    let mut images = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if name.ends_with(".squashfs_v4_le")
            || name.ends_with(".squashfs")
            || name.ends_with(".sqsh")
            || name.contains("squashfs")
        {
            images.push(path.to_path_buf());
        }
    }

    images.sort();
    images.dedup();
    images
}

pub fn has_boot_artifact_dir(root: &Path) -> bool {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_dir())
        .any(|entry| directory_contains_boot_artifacts(entry.path()))
}

/// A bootloader and a kernel side by side is the signature of a carved boot
/// partition, which is worth preserving even without a rootfs.
fn directory_contains_boot_artifacts(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };

    let mut has_bootloader = false;
    let mut has_kernel = false;

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();

        if matches!(name.as_str(), "u-boot.bin" | "uboot.bin" | "uboot.img") {
            has_bootloader = true;
        }

        if matches!(name.as_str(), "uimage" | "zimage" | "image" | "vmlinuz")
            || name.ends_with(".itb")
            || name.ends_with(".fit")
            || name.ends_with(".dtb")
        {
            has_kernel = true;
        }
    }

    has_bootloader && has_kernel
}
