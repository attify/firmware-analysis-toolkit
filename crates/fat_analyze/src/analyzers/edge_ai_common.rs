use super::model_metadata::metadata;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Record only the filename and four-byte ELF signature actually observed.
/// Neither identifies an installed runtime or an embedded model format.
pub(crate) fn inference_filename_finding(
    path: &Path,
    base_root: &Path,
    pattern: &str,
    id: String,
    plugin: &str,
) -> Option<Finding> {
    let filename = path.file_name()?.to_str()?;
    if !filename
        .to_ascii_lowercase()
        .contains(&pattern.to_ascii_lowercase())
    {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic).ok()?;
    if magic != *b"\x7fELF" {
        return None;
    }
    let rel_path = path
        .strip_prefix(base_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    Some(Finding::new(
        id,
        format!("ELF filename matches a published inference-runtime library name: {filename} (matched {pattern})"),
        FindingSeverity::Info,
        FindingSubject::File { rel_path },
    ).with_metadata(metadata([
        ("artifact_kind", "filename-match".to_string()),
        ("matched_pattern", pattern.to_string()),
        ("evidence", "filename and ELF magic".to_string()),
    ])).with_plugin_id(plugin))
}

pub(crate) fn find_extracted_root(
    snapshot: &fat_core::inventory::AnalysisSnapshot,
) -> Option<PathBuf> {
    snapshot
        .binaries
        .iter()
        .find_map(|binary| infer_extracted_root_from_observed_path(Path::new(&binary.rel_path)))
}

pub(crate) fn infer_extracted_root_from_observed_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() && !path.is_file() {
        return None;
    }

    for ancestor in path.ancestors() {
        if is_filesystem_root(ancestor) {
            continue;
        }
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if ancestor.join("bin").is_dir() || ancestor.join("lib").is_dir() {
            return Some(ancestor.to_path_buf());
        }
    }

    None
}

fn is_filesystem_root(path: &Path) -> bool {
    path.parent().is_none() && path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::infer_extracted_root_from_observed_path;

    #[test]
    fn absolute_synthetic_firmware_path_does_not_resolve_host_root() {
        let root = infer_extracted_root_from_observed_path(std::path::Path::new("/bin/httpd"));

        assert_eq!(root, None);
    }

    #[test]
    fn existing_absolute_binary_path_resolves_enclosing_rootfs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs");
        let bin = rootfs.join("bin");
        std::fs::create_dir_all(&bin).expect("bin dir");
        let binary = bin.join("httpd");
        std::fs::write(&binary, b"demo").expect("binary");

        let root = infer_extracted_root_from_observed_path(&binary);

        assert_eq!(root.as_deref(), Some(rootfs.as_path()));
    }
}
