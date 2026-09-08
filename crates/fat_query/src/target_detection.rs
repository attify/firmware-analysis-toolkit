use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    SourceTree,
    CodeQlDatabase,
    ElfBinary,
    RawBlob,
    MachOBinary,
    Rootfs,
    RuntimeSession,
    PatchInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedTarget {
    pub kind: TargetKind,
    pub path: PathBuf,
}

impl DetectedTarget {
    pub fn new(kind: TargetKind, path: impl Into<PathBuf>) -> Self {
        Self {
            kind,
            path: path.into(),
        }
    }
}

pub fn detect_path(path: &Path) -> Result<DetectedTarget, String> {
    if path.is_dir() {
        if looks_like_source_tree(path) {
            return Ok(DetectedTarget::new(TargetKind::SourceTree, path));
        }
        if looks_like_codeql_database(path)? {
            return Ok(DetectedTarget::new(TargetKind::CodeQlDatabase, path));
        }
        if looks_like_rootfs(path) {
            return Ok(DetectedTarget::new(TargetKind::Rootfs, path));
        }
        return Err(format!(
            "could not determine target kind for directory {}",
            path.display()
        ));
    }

    if path.is_file() {
        let bytes =
            fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if is_elf(&bytes) {
            return Ok(DetectedTarget::new(TargetKind::ElfBinary, path));
        }
        if is_macho(&bytes) {
            return Ok(DetectedTarget::new(TargetKind::MachOBinary, path));
        }
        return Ok(DetectedTarget::new(TargetKind::RawBlob, path));
    }

    Err(format!("path does not exist: {}", path.display()))
}

fn looks_like_source_tree(path: &Path) -> bool {
    path.join("Cargo.toml").is_file()
        || path.join("compile_commands.json").is_file()
        || path.join("compile_flags.txt").is_file()
        || has_extension_under(
            path,
            &["c", "cc", "cpp", "cxx", "m", "mm", "h", "hpp", "rs", "py"],
        )
}

fn looks_like_rootfs(path: &Path) -> bool {
    let names = ["bin", "sbin", "usr", "etc", "www"];
    let count = names.iter().filter(|name| path.join(name).exists()).count();
    count >= 2
}

fn has_extension_under(path: &Path, extensions: &[&str]) -> bool {
    WalkDir::new(path)
        .max_depth(3)
        .into_iter()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| {
                    extensions
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(ext))
                })
                .unwrap_or(false)
        })
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x7f, b'E', b'L', b'F'])
}

fn is_macho(bytes: &[u8]) -> bool {
    const MACHO_MAGICS: [[u8; 4]; 6] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ];
    bytes.len() >= 4 && MACHO_MAGICS.iter().any(|magic| bytes.starts_with(magic))
}

fn looks_like_codeql_database(path: &Path) -> Result<bool, String> {
    let candidates = crate::codeql_db::discover_codeql_databases(path)?;
    if candidates.is_empty() {
        return Ok(false);
    }
    if candidates.len() > 1 {
        let detail = candidates
            .iter()
            .map(|candidate| {
                let language = candidate
                    .primary_language
                    .as_deref()
                    .unwrap_or("unknown-language");
                format!("{} ({language})", candidate.db_root.display())
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "directory {} contains multiple CodeQL databases: {}. Point --repo at a specific database directory or the underlying source root.",
            path.display(),
            detail
        ));
    }

    let candidate = &candidates[0];
    match candidate.primary_language.as_deref() {
        Some("cpp") | Some("python") => {}
        Some(language) => {
            return Err(format!(
                "directory {} is a CodeQL database for primaryLanguage={} but public source discovery currently supports C/C++ and Python only",
                path.display(),
                language
            ));
        }
        None => {
            return Err(format!(
                "directory {} looks like a CodeQL database but primaryLanguage is missing",
                path.display()
            ));
        }
    }
    Ok(true)
}
