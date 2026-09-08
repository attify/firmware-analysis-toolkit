//! Bounded extraction for untrusted tar payloads.

use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use tar::EntryType;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub const MAX_TAR_ENTRIES: usize = 4_096;
pub const MAX_TAR_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TAR_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;

/// Safely unpack a tar archive into `dest`, returning the number of regular
/// files written. Rejects entries that would escape `dest` via absolute paths,
/// `..` components, platform prefixes, or link targets that resolve outside the
/// destination. Unsupported entry types are skipped deliberately.
pub fn safe_untar(tar_bytes: &[u8], dest: &Path) -> DynResult<usize> {
    reject_gnu_sparse_tar(tar_bytes)?;
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut written = 0usize;
    let mut entry_count = 0usize;
    let mut logical_bytes = 0_u64;
    let mut streamed_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count += 1;
        if entry_count > MAX_TAR_ENTRIES {
            return Err(format!(
                "archive payload has too many tar entries: exceeds {MAX_TAR_ENTRIES}"
            )
            .into());
        }
        let raw_path = entry.path()?.into_owned();
        let rel = sanitize_relative_path(&raw_path).ok_or_else(|| -> Box<dyn Error> {
            format!("refusing unsafe tar entry path: {}", raw_path.display()).into()
        })?;
        let out_path = dest.join(&rel);

        match entry.header().entry_type() {
            EntryType::Directory => {
                fs::create_dir_all(&out_path)?;
            }
            EntryType::GNUSparse => {
                return Err(
                    format!("refusing GNU sparse tar entry: {}", raw_path.display()).into(),
                );
            }
            EntryType::Regular => {
                let logical_size = entry.header().size()?;
                if logical_size > MAX_TAR_ENTRY_BYTES {
                    return Err(format!(
                        "tar entry {} exceeds per-entry byte limit of {}",
                        raw_path.display(),
                        MAX_TAR_ENTRY_BYTES
                    )
                    .into());
                }
                logical_bytes = logical_bytes
                    .checked_add(logical_size)
                    .ok_or("tar logical byte count overflowed")?;
                if logical_bytes > MAX_TAR_EXPANDED_BYTES {
                    return Err(format!(
                        "tar exceeds cumulative byte limit of {MAX_TAR_EXPANDED_BYTES}"
                    )
                    .into());
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out = fs::File::create(&out_path)?;
                copy_entry_with_limits(&mut entry, &mut out, &mut streamed_bytes)?;
                drop(out);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = entry.header().mode()? & 0o777;
                    fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))?;
                }
                written += 1;
            }
            EntryType::Symlink | EntryType::Link => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| -> Box<dyn Error> {
                        format!("link entry {} has no target", raw_path.display()).into()
                    })?
                    .into_owned();
                let base = rel.parent().unwrap_or_else(|| Path::new(""));
                if !resolves_within_dest(base, &target) {
                    return Err(format!(
                        "refusing link {} -> {} that escapes the extraction root",
                        raw_path.display(),
                        target.display()
                    )
                    .into());
                }
            }
            _ => {
                // Character/block devices, fifos, etc. are intentionally ignored.
            }
        }
    }
    Ok(written)
}

fn reject_gnu_sparse_tar(tar_bytes: &[u8]) -> DynResult<()> {
    let mut offset = 0usize;
    while offset
        .checked_add(512)
        .is_some_and(|end| end <= tar_bytes.len())
    {
        let header = &tar_bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        let entry_type = header[156];
        if entry_type == b'S' {
            return Err("refusing GNU sparse tar entry in archive payload".into());
        }
        let size = parse_tar_octal(&header[124..136])
            .ok_or("unsupported tar size encoding in archive payload")?;
        if matches!(entry_type, b'x' | b'g') {
            return Err("refusing unsupported PAX tar entry in archive payload".into());
        }
        let padded = size
            .checked_add(511)
            .map(|value| value / 512 * 512)
            .ok_or("tar entry size overflowed")?;
        let next = 512_u64
            .checked_add(padded)
            .and_then(|advance| (offset as u64).checked_add(advance))
            .ok_or("tar offset overflowed")?;
        offset = usize::try_from(next).map_err(|_| "tar offset is too large")?;
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(field).ok()?.trim_matches(['\0', ' ']);
    if text.is_empty() {
        Some(0)
    } else {
        u64::from_str_radix(text, 8).ok()
    }
}

fn copy_entry_with_limits<R: Read>(
    reader: &mut R,
    writer: &mut fs::File,
    cumulative_bytes: &mut u64,
) -> DynResult<()> {
    let mut entry_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let entry_remaining = MAX_TAR_ENTRY_BYTES.saturating_sub(entry_bytes);
        let total_remaining = MAX_TAR_EXPANDED_BYTES.saturating_sub(*cumulative_bytes);
        let allowed = entry_remaining.min(total_remaining);
        let read_limit = usize::try_from(allowed.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            return Ok(());
        }
        if read as u64 > entry_remaining {
            return Err(
                format!("tar entry exceeds per-entry byte limit of {MAX_TAR_ENTRY_BYTES}").into(),
            );
        }
        if read as u64 > total_remaining {
            return Err(
                format!("tar exceeds cumulative byte limit of {MAX_TAR_EXPANDED_BYTES}").into(),
            );
        }
        std::io::Write::write_all(writer, &buffer[..read])?;
        entry_bytes += read as u64;
        *cumulative_bytes += read as u64;
    }
}

fn sanitize_relative_path(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn resolves_within_dest(base: &Path, target: &Path) -> bool {
    use std::path::Component;
    if target.is_absolute() {
        return false;
    }
    let mut depth = base
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{resolves_within_dest, sanitize_relative_path};
    use std::path::{Path, PathBuf};

    #[test]
    fn relative_paths_reject_escapes() {
        assert_eq!(
            sanitize_relative_path(Path::new("a/b/c.txt")),
            Some(PathBuf::from("a/b/c.txt"))
        );
        assert_eq!(sanitize_relative_path(Path::new("../escape")), None);
        assert_eq!(sanitize_relative_path(Path::new("a/../../escape")), None);
        assert_eq!(sanitize_relative_path(Path::new("/etc/passwd")), None);
        assert_eq!(
            sanitize_relative_path(Path::new("./a/./b")),
            Some(PathBuf::from("a/b"))
        );
        assert_eq!(sanitize_relative_path(Path::new(".")), None);
    }

    #[test]
    fn link_resolution_blocks_escapes() {
        assert!(resolves_within_dest(
            Path::new("sub"),
            Path::new("../peer/file")
        ));
        assert!(!resolves_within_dest(
            Path::new("sub"),
            Path::new("../../etc/passwd")
        ));
        assert!(!resolves_within_dest(
            Path::new("sub"),
            Path::new("/etc/passwd")
        ));
    }
}
