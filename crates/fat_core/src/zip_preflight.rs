use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
const MAX_EOCD_SEARCH: u64 = 65_535 + 22;

#[derive(Debug, Clone, Copy)]
pub struct ZipPreflightLimits {
    pub max_file_bytes: u64,
    pub max_entries: u64,
    pub max_central_directory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipPreflight {
    pub file_bytes: u64,
    pub entries: u64,
    pub central_directory_bytes: u64,
}

pub fn preflight_zip_file(
    file: &mut File,
    limits: ZipPreflightLimits,
) -> Result<ZipPreflight, String> {
    let result = preflight_zip_file_inner(file, limits);
    let rewind = file
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string());
    match (result, rewind) {
        (Ok(report), Ok(_)) => Ok(report),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(format!("ZIP preflight could not rewind input: {error}")),
    }
}

fn preflight_zip_file_inner(
    file: &mut File,
    limits: ZipPreflightLimits,
) -> Result<ZipPreflight, String> {
    let file_bytes = file.metadata().map_err(|error| error.to_string())?.len();
    if file_bytes > limits.max_file_bytes {
        return Err(format!(
            "ZIP preflight: archive size {file_bytes} exceeds {} bytes",
            limits.max_file_bytes
        ));
    }
    let tail_len = file_bytes.min(MAX_EOCD_SEARCH);
    file.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|error| error.to_string())?;
    let mut tail = vec![0_u8; tail_len as usize];
    file.read_exact(&mut tail)
        .map_err(|error| error.to_string())?;
    let eocd_index = tail
        .windows(4)
        .rposition(|window| window == EOCD_SIGNATURE)
        .ok_or_else(|| "ZIP preflight: end-of-central-directory record not found".to_string())?;
    if eocd_index + 22 > tail.len() {
        return Err("ZIP preflight: truncated end-of-central-directory record".into());
    }
    let eocd = &tail[eocd_index..];
    let comment_len = le_u16(&eocd[20..22]) as usize;
    if eocd_index + 22 + comment_len != tail.len() {
        return Err("ZIP preflight: invalid end-of-central-directory comment length".into());
    }
    if le_u16(&eocd[4..6]) != 0 || le_u16(&eocd[6..8]) != 0 {
        return Err("ZIP preflight: multi-disk archives are unsupported".into());
    }

    let eocd_absolute = file_bytes - tail_len + eocd_index as u64;
    let standard_entries_on_disk = le_u16(&eocd[8..10]);
    let standard_entries = le_u16(&eocd[10..12]);
    if standard_entries_on_disk != standard_entries {
        return Err("ZIP preflight: inconsistent ZIP entry count".into());
    }
    let standard_cd_size = le_u32(&eocd[12..16]);
    let standard_cd_offset = le_u32(&eocd[16..20]);
    let uses_zip64 = standard_entries == u16::MAX
        || standard_cd_size == u32::MAX
        || standard_cd_offset == u32::MAX;
    let (entries, central_directory_bytes, central_directory_offset, directory_end_limit) =
        if uses_zip64 {
            parse_zip64(file, eocd_absolute)?
        } else {
            (
                standard_entries as u64,
                standard_cd_size as u64,
                standard_cd_offset as u64,
                eocd_absolute,
            )
        };

    if entries > limits.max_entries {
        return Err(format!(
            "ZIP preflight: too many entries: {entries} exceeds {}",
            limits.max_entries
        ));
    }
    if central_directory_bytes > limits.max_central_directory_bytes {
        return Err(format!(
            "ZIP preflight: central directory size {central_directory_bytes} exceeds {} bytes",
            limits.max_central_directory_bytes
        ));
    }
    let central_directory_end = central_directory_offset
        .checked_add(central_directory_bytes)
        .ok_or_else(|| "ZIP preflight: central directory offset overflow".to_string())?;
    if central_directory_end > directory_end_limit || central_directory_end > file_bytes {
        return Err("ZIP preflight: central directory lies outside the archive".into());
    }
    Ok(ZipPreflight {
        file_bytes,
        entries,
        central_directory_bytes,
    })
}

fn parse_zip64(file: &mut File, eocd_absolute: u64) -> Result<(u64, u64, u64, u64), String> {
    let locator_offset = eocd_absolute
        .checked_sub(20)
        .ok_or_else(|| "ZIP preflight: ZIP64 locator is missing".to_string())?;
    file.seek(SeekFrom::Start(locator_offset))
        .map_err(|error| error.to_string())?;
    let mut locator = [0_u8; 20];
    file.read_exact(&mut locator)
        .map_err(|error| error.to_string())?;
    if &locator[..4] != ZIP64_LOCATOR_SIGNATURE {
        return Err("ZIP preflight: ZIP64 locator is missing".into());
    }
    if le_u32(&locator[4..8]) != 0 || le_u32(&locator[16..20]) != 1 {
        return Err("ZIP preflight: multi-disk ZIP64 archives are unsupported".into());
    }
    let zip64_offset = le_u64(&locator[8..16]);
    if zip64_offset >= locator_offset {
        return Err("ZIP preflight: invalid ZIP64 record offset".into());
    }
    file.seek(SeekFrom::Start(zip64_offset))
        .map_err(|error| error.to_string())?;
    let mut record = [0_u8; 56];
    file.read_exact(&mut record)
        .map_err(|error| error.to_string())?;
    let record_payload_bytes = le_u64(&record[4..12]);
    let record_bytes = record_payload_bytes
        .checked_add(12)
        .ok_or_else(|| "ZIP preflight: ZIP64 record extent overflow".to_string())?;
    let record_end = zip64_offset
        .checked_add(record_bytes)
        .ok_or_else(|| "ZIP preflight: ZIP64 record extent overflow".to_string())?;
    if &record[..4] != ZIP64_EOCD_SIGNATURE || record_payload_bytes < 44 {
        return Err("ZIP preflight: invalid ZIP64 end-of-central-directory record".into());
    }
    if record_end != locator_offset {
        return Err("ZIP preflight: invalid ZIP64 record extent".into());
    }
    if le_u32(&record[16..20]) != 0 || le_u32(&record[20..24]) != 0 {
        return Err("ZIP preflight: multi-disk ZIP64 archives are unsupported".into());
    }
    let entries_on_disk = le_u64(&record[24..32]);
    let entries = le_u64(&record[32..40]);
    if entries_on_disk != entries {
        return Err("ZIP preflight: inconsistent ZIP64 entry count".into());
    }
    Ok((
        entries,
        le_u64(&record[40..48]),
        le_u64(&record[48..56]),
        zip64_offset,
    ))
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("two-byte field"))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte field"))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight-byte field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn rejects_inconsistent_classic_entry_counts() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("inconsistent.zip");
        let mut archive = File::create(&archive_path).unwrap();
        archive
            .write_all(&[
                b'P', b'K', 5, 6, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])
            .unwrap();
        drop(archive);

        let mut archive = File::open(&archive_path).unwrap();
        let error = preflight_zip_file(
            &mut archive,
            ZipPreflightLimits {
                max_file_bytes: 1024,
                max_entries: 16,
                max_central_directory_bytes: 1024,
            },
        )
        .expect_err("inconsistent per-disk and total entry counts must fail");
        assert!(error.contains("inconsistent ZIP entry count"), "{error}");
    }

    #[test]
    fn rejects_overflowing_zip64_record_extent() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("overflowing-zip64.zip");
        let mut bytes = vec![0_u8; 98];
        bytes[..4].copy_from_slice(ZIP64_EOCD_SIGNATURE);
        bytes[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[56..60].copy_from_slice(ZIP64_LOCATOR_SIGNATURE);
        bytes[64..72].copy_from_slice(&0_u64.to_le_bytes());
        bytes[72..76].copy_from_slice(&1_u32.to_le_bytes());
        bytes[76..80].copy_from_slice(EOCD_SIGNATURE);
        bytes[84..86].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[86..88].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&archive_path, bytes).unwrap();

        let mut archive = File::open(&archive_path).unwrap();
        let error = preflight_zip_file(
            &mut archive,
            ZipPreflightLimits {
                max_file_bytes: 1024,
                max_entries: 16,
                max_central_directory_bytes: 1024,
            },
        )
        .expect_err("overflowing ZIP64 record extent must fail");
        assert!(error.contains("ZIP64 record extent overflow"), "{error}");
    }
}
