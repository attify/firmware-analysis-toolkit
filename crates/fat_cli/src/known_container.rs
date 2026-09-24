use crate::envelope_cmd;
use fat_extract::safe_tar::{safe_untar, MAX_TAR_EXPANDED_BYTES};
use fat_package::unitree_upk;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{remove_existing_path_if_present, DynResult};

const CONTAINER_PROBE_BYTES: usize = 64 * 1024;
const MAX_UTPK_CONTAINER_BYTES: u64 =
    unitree_upk::HEADER_LEN as u64 + unitree_upk::TEA_MARKER.len() as u64 + MAX_TAR_EXPANDED_BYTES;

/// A container FAT can both recognize and extract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownContainer {
    Utpk,
}

impl KnownContainer {
    const ALL: [Self; 1] = [Self::Utpk];

    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Utpk => "Unitree UTPK",
        }
    }

    pub(crate) fn short_name(self) -> &'static str {
        match self {
            Self::Utpk => "UTPK",
        }
    }

    pub(crate) fn decryption_log(self, project_dir: &Path) -> PathBuf {
        match self {
            Self::Utpk => project_dir.join("work").join("unitree-upk.log"),
        }
    }

    pub(crate) fn unpacked_dir(self, extraction_root: &Path) -> PathBuf {
        match self {
            Self::Utpk => extraction_root.join("unitree-upk").join("unpacked"),
        }
    }

    fn has_cached_extraction(self, project_dir: &Path, extraction_root: &Path) -> bool {
        self.decryption_log(project_dir).is_file() && self.unpacked_dir(extraction_root).is_dir()
    }
}

pub(crate) struct ContainerProbe {
    pub(crate) container: Option<KnownContainer>,
    pub(crate) envelope: envelope_cmd::EnvelopeReport,
}

/// Map format signatures to an actionable handler. This is deliberately not a general
/// signature table: every returned variant must have an extraction arm.
pub(crate) fn detect_known_container(bytes: &[u8]) -> Option<KnownContainer> {
    match bytes.get(..4)? {
        b"UTPK"
            if bytes.get(
                unitree_upk::HEADER_LEN..unitree_upk::HEADER_LEN + unitree_upk::TEA_MARKER.len(),
            ) == Some(unitree_upk::TEA_MARKER.as_slice()) =>
        {
            Some(KnownContainer::Utpk)
        }
        _ => None,
    }
}

/// Probe a bounded prefix for known format signatures independently of byte
/// statistics. Repetition and entropy cannot veto a format parser. Unknown inputs remain
/// eligible for native and generic extraction; the envelope is retained for a
/// factual fallback diagnostic if every extractor recovers zero files.
pub(crate) fn probe_known_container_file(path: &Path) -> DynResult<ContainerProbe> {
    let input = fs::File::open(path)?;
    let mut sample = Vec::with_capacity(CONTAINER_PROBE_BYTES);
    input
        .take(CONTAINER_PROBE_BYTES as u64)
        .read_to_end(&mut sample)?;
    let envelope = envelope_cmd::analyze_envelope(&sample, None);
    let container = detect_known_container(&sample);
    Ok(ContainerProbe {
        container,
        envelope,
    })
}

pub(crate) fn detect_cached_container(
    project_dir: &Path,
    extraction_root: &Path,
) -> Option<KnownContainer> {
    KnownContainer::ALL
        .into_iter()
        .find(|container| container.has_cached_extraction(project_dir, extraction_root))
}

pub(crate) fn extract_container(
    container: KnownContainer,
    firmware_path: &Path,
    extraction_root: &Path,
    project_dir: &Path,
    report: &dyn Fn(String),
) -> DynResult<()> {
    match container {
        KnownContainer::Utpk => extract_utpk(firmware_path, extraction_root, project_dir, report),
    }
}

fn extract_utpk(
    firmware_path: &Path,
    extraction_root: &Path,
    project_dir: &Path,
    report: &dyn Fn(String),
) -> DynResult<()> {
    let file_size = fs::metadata(firmware_path)?.len();
    if file_size > MAX_UTPK_CONTAINER_BYTES {
        return Err(format!(
            "recognized UTPK container exceeds maximum supported size of {MAX_UTPK_CONTAINER_BYTES} bytes"
        )
        .into());
    }
    let minimum_size = (unitree_upk::HEADER_LEN + unitree_upk::TEA_MARKER.len()) as u64;
    if file_size < minimum_size {
        return Err(format!(
            "recognized UTPK container is truncated: {file_size} bytes is less than {minimum_size}"
        )
        .into());
    }
    let mut input = fs::File::open(firmware_path)?;
    let mut header_bytes = vec![0_u8; unitree_upk::HEADER_LEN + unitree_upk::TEA_MARKER.len()];
    input.read_exact(&mut header_bytes)?;
    let header = unitree_upk::parse_header(&header_bytes)?;
    if header.payload_type != unitree_upk::PAYLOAD_TYPE_TAR {
        return Err(format!("unsupported UTPK payload type {:#04x}", header.payload_type).into());
    }
    let declared_tar_bytes = header
        .declared_payload_size
        .checked_sub(unitree_upk::TEA_MARKER.len() as u64)
        .ok_or("invalid UTPK declared payload size")?;
    if declared_tar_bytes > MAX_TAR_EXPANDED_BYTES {
        return Err(format!(
            "recognized UTPK decrypted tar exceeds maximum size of {MAX_TAR_EXPANDED_BYTES} bytes"
        )
        .into());
    }
    if declared_tar_bytes == 0 || !declared_tar_bytes.is_multiple_of(8) {
        return Err("UTPK ciphertext is empty or not TEA block-aligned".into());
    }
    let actual_payload_size = file_size - unitree_upk::HEADER_LEN as u64;
    if header.declared_payload_size != actual_payload_size {
        return Err(format!(
            "UTPK declared payload size {} does not match actual {actual_payload_size}",
            header.declared_payload_size
        )
        .into());
    }
    if header_bytes[unitree_upk::HEADER_LEN..] != unitree_upk::TEA_MARKER {
        return Err("UTPK payload is missing the TEA marker".into());
    }
    let mut bytes = Vec::with_capacity(file_size as usize);
    bytes.extend_from_slice(&header_bytes);
    input.read_to_end(&mut bytes)?;
    let decoded = unitree_upk::decode(&bytes).map_err(|err| -> Box<dyn Error> {
        format!("recognized UTPK container, but it failed validation: {err}").into()
    })?;

    let upk_dir = extraction_root.join("unitree-upk");
    let staging_dir = extraction_root.join(".unitree-upk-staging");
    remove_existing_path_if_present(&staging_dir)?;
    remove_existing_path_if_present(&upk_dir)?;
    fs::create_dir_all(&staging_dir)?;

    let tar_name = format!("{}.tar", sanitize_name_component(&decoded.header.name));
    let extraction_result = (|| -> DynResult<usize> {
        fs::write(staging_dir.join(&tar_name), &decoded.payload)?;
        let unpack_dir = staging_dir.join("unpacked");
        fs::create_dir_all(&unpack_dir)?;
        safe_untar(&decoded.payload, &unpack_dir)
    })();
    let count = match extraction_result {
        Ok(count) => count,
        Err(err) => {
            let _ = remove_existing_path_if_present(&staging_dir);
            return Err(err);
        }
    };
    if count == 0 {
        remove_existing_path_if_present(&staging_dir)?;
        return Err("recognized UTPK container decrypted, but its tar contained no files".into());
    }
    fs::rename(&staging_dir, &upk_dir)?;

    fs::write(
        project_dir.join("work").join("unitree-upk.log"),
        format!(
            "decrypted UTPK '{}' (seed {:#04x}) -> {} bytes, unpacked {count} file(s)\n",
            decoded.header.name,
            decoded.header.seed_byte(),
            decoded.payload.len(),
        ),
    )?;
    report("container: Unitree UTPK".to_string());
    report(format!(
        "decryption: completed (seed {:#04x})",
        decoded.header.seed_byte()
    ));
    report(format!("payload: {}", upk_dir.join(tar_name).display()));
    report(format!("unpacked_files: {count}"));
    Ok(())
}

fn sanitize_name_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.');
    if trimmed.is_empty() {
        "unitree-package".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_known_container, sanitize_name_component, KnownContainer};

    #[test]
    fn detection_returns_an_actionable_handler() {
        let mut bytes = vec![0; fat_package::unitree_upk::HEADER_LEN];
        bytes[..4].copy_from_slice(b"UTPK");
        bytes.extend_from_slice(&fat_package::unitree_upk::TEA_MARKER);
        assert_eq!(detect_known_container(&bytes), Some(KnownContainer::Utpk));
        assert_eq!(detect_known_container(b"UTPK plain text"), None);
        assert_eq!(detect_known_container(b"hsqs structured payload"), None);
        assert_eq!(detect_known_container(b"UTP"), None);
    }

    #[test]
    fn container_name_sanitization_strips_separators() {
        assert_eq!(
            sanitize_name_component("network_manager"),
            "network_manager"
        );
        assert_eq!(sanitize_name_component("../../evil"), "_.._evil");
        assert_eq!(sanitize_name_component("a/b"), "a_b");
        assert_eq!(sanitize_name_component(""), "unitree-package");
        assert_eq!(sanitize_name_component("..."), "unitree-package");
    }
}
