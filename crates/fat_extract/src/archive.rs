use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

use crate::output::OutputTree;

pub(crate) fn is_tar(bytes: &[u8]) -> bool {
    let Some(block) = bytes.get(..512) else {
        return false;
    };
    let header = tar::Header::from_byte_slice(block);
    let Ok(expected) = header.cksum() else {
        return false;
    };
    let sum = block
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                *b as u32
            }
        })
        .sum::<u32>();
    expected == sum && expected != 0
}

pub(crate) fn unpack_tar(bytes: &[u8], output: &mut OutputTree) -> io::Result<Vec<PathBuf>> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut children = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let kind = entry.header().entry_type();
        let mode = entry.header().mode()?;
        if kind.is_dir() {
            output.create_dir(&path, mode)?;
        } else if kind.is_file() {
            output.write_reader(&path, &mut entry, mode)?;
            children.push(path);
        } else if kind.is_symlink() {
            let target = entry
                .link_name()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing link target"))?;
            output.write_symlink(&path, &target)?;
        } else if kind.is_block_special() || kind.is_character_special() || kind.is_fifo() {
            output.skip_special()?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported TAR entry type",
            ));
        }
    }
    Ok(children)
}

pub(crate) fn unpack_zip(bytes: &[u8], output: &mut OutputTree) -> io::Result<Vec<PathBuf>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    if archive.len() as u64 > output.limits().max_entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry budget exceeded",
        ));
    }
    let mut children = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let path = entry.enclosed_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP path leaves the extraction tree",
            )
        })?;
        let mode = entry.unix_mode().unwrap_or(0o644);
        if entry.is_dir() {
            output.create_dir(&path, mode | 0o700)?;
        } else if mode & 0o170000 == 0o120000 {
            let mut target = Vec::new();
            entry.by_ref().take(4097).read_to_end(&mut target)?;
            if target.len() > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "link target exceeds limit",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                output.write_symlink(&path, Path::new(std::ffi::OsStr::from_bytes(&target)))?;
            }
            #[cfg(not(unix))]
            output.write_symlink(
                &path,
                Path::new(std::str::from_utf8(&target).map_err(io::Error::other)?),
            )?;
        } else {
            output.write_reader(&path, &mut entry, mode)?;
            children.push(path);
        }
    }
    Ok(children)
}
