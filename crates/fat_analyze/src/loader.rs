use std::fs;
use std::path::Path;

use crate::mcu::detect_cortex_m_ivt;
use crate::mcu_inspect::{inspect_file, McuInspectRequest};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoaderHints {
    pub arch: Option<String>,
    pub bits: Option<u32>,
    pub base: Option<u32>,
    pub family: Option<String>,
    pub cpu: Option<String>,
    pub is_raw_blob: bool,
}

pub fn resolve_loader_hints(
    file: &Path,
    user_arch: Option<&str>,
    user_base: Option<u32>,
    user_family: Option<&str>,
) -> Result<LoaderHints, String> {
    let bytes =
        fs::read(file).map_err(|err| format!("failed to read {}: {err}", file.display()))?;

    if is_elf_binary(&bytes) {
        return Ok(LoaderHints {
            arch: user_arch.map(|value| value.to_string()),
            bits: None,
            base: user_base,
            family: user_family.map(|value| value.to_string()),
            cpu: None,
            is_raw_blob: false,
        });
    }

    if let Some(arch) = user_arch {
        if arch.eq_ignore_ascii_case("cortex-m") {
            return Ok(LoaderHints {
                arch: Some("arm".to_string()),
                bits: Some(16),
                base: user_base,
                family: user_family.map(|value| value.to_string()),
                cpu: Some("cortex".to_string()),
                is_raw_blob: true,
            });
        }

        return Ok(LoaderHints {
            arch: Some(arch.to_string()),
            bits: None,
            base: user_base,
            family: user_family.map(|value| value.to_string()),
            cpu: None,
            is_raw_blob: true,
        });
    }

    if let Some(profile) = detect_cortex_m_ivt(&bytes) {
        let mut family = user_family
            .map(|value| value.to_string())
            .or_else(|| Some(profile.chip_family.clone()));
        let mut base = user_base.or(Some(profile.flash_base));

        if let Ok(report) = inspect_file(&McuInspectRequest {
            file: file.to_path_buf(),
            user_base,
            user_family: user_family.map(|value| value.to_string()),
            bundle_root: None,
            backend_preference: None,
        }) {
            if let Some(primary) = report
                .address_hypotheses
                .as_ref()
                .and_then(|items| items.iter().find(|item| item.is_primary))
            {
                base = Some(primary.base);
            }
            if family.is_none() {
                family = report
                    .fast_profile
                    .as_ref()
                    .map(|fast| fast.chip_family.clone());
            }
        }

        return Ok(LoaderHints {
            arch: Some("arm".to_string()),
            bits: Some(16),
            base,
            family,
            cpu: Some("cortex".to_string()),
            is_raw_blob: true,
        });
    }

    Ok(LoaderHints {
        arch: None,
        bits: None,
        base: user_base,
        family: user_family.map(|value| value.to_string()),
        cpu: None,
        is_raw_blob: true,
    })
}

fn is_elf_binary(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"\x7fELF"
}
