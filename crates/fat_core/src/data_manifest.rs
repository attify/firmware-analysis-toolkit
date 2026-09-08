use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SUPPORTED_DATA_SCHEMA_VERSION: u32 = 1;
pub const DATA_MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFileEntry {
    pub path: String,
    pub sha256: String,
    #[serde(default = "required_by_default")]
    pub required: bool,
}

fn required_by_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataManifest {
    pub schema_version: u32,
    pub data_version: String,
    pub compatible_fat: String,
    #[serde(default)]
    pub files: Vec<DataFileEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataVerificationReport {
    pub verified_files: usize,
    pub missing_optional_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataManifestError {
    message: String,
}

impl DataManifestError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DataManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DataManifestError {}

impl DataManifest {
    pub fn from_json(text: &str) -> Result<Self, DataManifestError> {
        serde_json::from_str(text)
            .map_err(|error| DataManifestError::new(format!("invalid FAT data manifest: {error}")))
    }

    pub fn load(root: &Path) -> Result<Self, DataManifestError> {
        let path = root.join(DATA_MANIFEST_FILE);
        let text = std::fs::read_to_string(&path).map_err(|error| {
            DataManifestError::new(format!(
                "failed to read FAT data manifest {}: {error}",
                path.display()
            ))
        })?;
        Self::from_json(&text)
    }

    pub fn verify_tree(
        &self,
        root: &Path,
        fat_version: &str,
    ) -> Result<DataVerificationReport, DataManifestError> {
        self.validate_compatibility(fat_version)?;

        let mut seen = BTreeSet::new();
        for entry in &self.files {
            let relative = Path::new(&entry.path);
            if !is_safe_relative_path(relative) {
                return Err(DataManifestError::new(format!(
                    "unsafe FAT data manifest path: {}",
                    entry.path
                )));
            }
            if !seen.insert(entry.path.clone()) {
                return Err(DataManifestError::new(format!(
                    "duplicate FAT data manifest path: {}",
                    entry.path
                )));
            }
            if !is_sha256(&entry.sha256) {
                return Err(DataManifestError::new(format!(
                    "invalid SHA-256 value for {}",
                    entry.path
                )));
            }
        }

        let mut verified_files = 0;
        let mut missing_optional_files = 0;
        for entry in &self.files {
            let relative = Path::new(&entry.path);
            let path = root.join(relative);
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !entry.required => {
                    missing_optional_files += 1;
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(DataManifestError::new(format!(
                        "required FAT data file is missing: {}",
                        entry.path
                    )));
                }
                Err(error) => {
                    return Err(DataManifestError::new(format!(
                        "failed to inspect FAT data file {}: {error}",
                        path.display()
                    )));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(DataManifestError::new(format!(
                    "unsafe FAT data entry is not a regular file: {}",
                    entry.path
                )));
            }

            let actual = sha256_file(&path)?;
            if !actual.eq_ignore_ascii_case(&entry.sha256) {
                return Err(DataManifestError::new(format!(
                    "SHA-256 mismatch for {}: expected {}, got {}",
                    entry.path, entry.sha256, actual
                )));
            }
            verified_files += 1;
        }

        Ok(DataVerificationReport {
            verified_files,
            missing_optional_files,
        })
    }

    fn validate_compatibility(&self, fat_version: &str) -> Result<(), DataManifestError> {
        if self.schema_version != SUPPORTED_DATA_SCHEMA_VERSION {
            return Err(DataManifestError::new(format!(
                "unsupported FAT data schema version {}; supported version is {}",
                self.schema_version, SUPPORTED_DATA_SCHEMA_VERSION
            )));
        }
        Version::parse(&self.data_version).map_err(|error| {
            DataManifestError::new(format!(
                "invalid FAT data version '{}': {error}",
                self.data_version
            ))
        })?;
        let requirement = VersionReq::parse(&self.compatible_fat).map_err(|error| {
            DataManifestError::new(format!(
                "invalid compatible_fat requirement '{}': {error}",
                self.compatible_fat
            ))
        })?;
        let version = Version::parse(fat_version).map_err(|error| {
            DataManifestError::new(format!("invalid FAT version '{fat_version}': {error}"))
        })?;
        if !requirement.matches(&version) {
            return Err(DataManifestError::new(format!(
                "FAT data {} is not compatible with FAT {}; requires {}",
                self.data_version, fat_version, self.compatible_fat
            )));
        }
        Ok(())
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> Result<String, DataManifestError> {
    let mut file = File::open(path).map_err(|error| {
        DataManifestError::new(format!(
            "failed to open FAT data file {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            DataManifestError::new(format!(
                "failed to read FAT data file {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
