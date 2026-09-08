use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::bufread::GzDecoder;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct GzipExtractionOptions {
    pub original_name: Option<String>,
    pub max_output: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipExtractionResult {
    pub member_path: PathBuf,
    pub decompressed_path: PathBuf,
    pub decompressed_size: u64,
}

pub fn extract_gzip_member(
    member: &[u8],
    destination: &Path,
    options: GzipExtractionOptions,
) -> io::Result<GzipExtractionResult> {
    if member.len() < 18 {
        return Err(invalid_data("gzip member is too short"));
    }
    let read_limit = options
        .max_output
        .checked_add(1)
        .ok_or_else(|| invalid_input("gzip output limit is too large"))?;

    let cursor = Cursor::new(member);
    let mut decoder = GzDecoder::new(cursor);
    let mut output = Vec::new();
    decoder.by_ref().take(read_limit).read_to_end(&mut output)?;
    if output.len() as u64 > options.max_output {
        return Err(invalid_data("gzip output exceeds configured limit"));
    }
    if decoder.get_ref().position() != member.len() as u64 {
        return Err(invalid_data(
            "gzip input contains bytes beyond the validated member",
        ));
    }

    let trailer = member
        .get(member.len() - 8..)
        .ok_or_else(|| invalid_data("gzip trailer is missing"))?;
    let stored_crc = u32::from_le_bytes(
        trailer[..4]
            .try_into()
            .map_err(|_| invalid_data("gzip CRC32 is malformed"))?,
    );
    let stored_size = u32::from_le_bytes(
        trailer[4..]
            .try_into()
            .map_err(|_| invalid_data("gzip ISIZE is malformed"))?,
    );
    if crc32fast::hash(&output) != stored_crc {
        return Err(invalid_data("gzip CRC32 mismatch"));
    }
    if output.len() as u32 != stored_size {
        return Err(invalid_data("gzip ISIZE mismatch"));
    }

    fs::create_dir_all(destination)?;
    let output_name = options
        .original_name
        .as_deref()
        .filter(|name| safe_leaf_name(name))
        .unwrap_or("gzip-member.bin");
    let decompressed_path = destination.join(output_name);
    let member_path = destination.join(format!("{output_name}.gz"));
    ensure_absent(&decompressed_path)?;
    ensure_absent(&member_path)?;

    let staged_member = write_staged(destination, output_name, "member", member)?;
    let staged_output = match write_staged(destination, output_name, "output", &output) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(&staged_member);
            return Err(error);
        }
    };

    if let Err(error) = fs::rename(&staged_member, &member_path) {
        let _ = fs::remove_file(&staged_member);
        let _ = fs::remove_file(&staged_output);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staged_output, &decompressed_path) {
        let _ = fs::remove_file(&staged_output);
        let _ = fs::remove_file(&member_path);
        return Err(error);
    }

    Ok(GzipExtractionResult {
        member_path,
        decompressed_path,
        decompressed_size: output.len() as u64,
    })
}

fn safe_leaf_name(name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\', '\0']) || matches!(name, "." | "..") {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    if path.exists() {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite {}", path.display()),
        ))
    } else {
        Ok(())
    }
}

fn write_staged(
    destination: &Path,
    output_name: &str,
    kind: &str,
    bytes: &[u8],
) -> io::Result<PathBuf> {
    for _ in 0..32 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = destination.join(format!(
            ".{output_name}.fat-{}-{sequence}-{kind}.tmp",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique gzip staging file",
    ))
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
