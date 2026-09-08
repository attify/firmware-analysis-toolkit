use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;

use fat_core::data_dir::{DataResolutionError, DataResolver};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootloaderProfile {
    pub name: String,
    pub prompt: String,
    pub bootdelay: u32,
    pub loadaddr: String,
    pub bootcmd: String,
    pub bootargs: String,
    pub verify: String,
    pub sig_check: String,
    pub recovery_mode: String,
    pub rollback_ctr: String,
    pub rollback_idx: String,
    #[serde(default)]
    pub qemu_binary: Option<String>,
    #[serde(default)]
    pub qemu_machine: Option<String>,
}

#[derive(Debug)]
pub enum BootloaderProfileError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    UnsupportedProfile(String),
    Data(DataResolutionError),
}

impl fmt::Display for BootloaderProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::UnsupportedProfile(name) => {
                write!(f, "unsupported bootloader profile: {name}")
            }
            Self::Data(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BootloaderProfileError {}

impl From<std::io::Error> for BootloaderProfileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BootloaderProfileError {
    fn from(error: serde_json::Error) -> Self {
        Self::Parse(error)
    }
}

/// A profile name must be a single path segment of ASCII alphanumerics, `-`,
/// `_` or `.`, and must not be `.` or `..`. This keeps a caller-supplied name
/// from escaping the bootloader profile directory.
fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub fn load_profile(name: &str) -> Result<BootloaderProfile, BootloaderProfileError> {
    load_profile_with_resolver(name, &DataResolver::for_current_process(None))
}

pub fn load_profile_with_resolver(
    name: &str,
    resolver: &DataResolver,
) -> Result<BootloaderProfile, BootloaderProfileError> {
    // The loader is data-driven: any validated profile in the configured data
    // directory loads. `name` becomes a path segment, so it is checked for
    // shape — not against a list of blessed profile names.
    if !is_profile_name(name) {
        return Err(BootloaderProfileError::UnsupportedProfile(name.to_string()));
    }
    let relative = format!("profiles/bootloader/{name}.json");
    let resolved = resolver
        .resolve_required(&relative)
        .map_err(BootloaderProfileError::Data)?;
    let contents = fs::read_to_string(resolved.path)?;
    let profile: BootloaderProfile = serde_json::from_str(&contents)?;

    if profile.name != name {
        return Err(BootloaderProfileError::UnsupportedProfile(name.to_string()));
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn resolver_rooted_at(root: &std::path::Path) -> DataResolver {
        DataResolver::from_paths(Some(root.to_path_buf()), None, None, None, None)
    }

    fn write_profile(root: &std::path::Path, name: &str) -> PathBuf {
        let dir = root.join("profiles").join("bootloader");
        fs::create_dir_all(&dir).expect("profile dir");
        let path = dir.join(format!("{name}.json"));
        let profile = format!(
            r#"{{"name":"{name}","prompt":"=> ","bootdelay":1,"loadaddr":"0x80000000",
                 "bootcmd":"bootm","bootargs":"console=ttyS0","verify":"n",
                 "sig_check":"none","recovery_mode":"none","rollback_ctr":"none",
                 "rollback_idx":"none"}}"#
        );
        fs::write(&path, profile).expect("profile file");
        path
    }

    /// The loader used to accept exactly two hard-coded profile names, so a
    /// perfectly valid profile placed in the data directory could not be used.
    #[test]
    fn any_validated_profile_in_the_data_directory_loads() {
        let root = tempfile::tempdir().expect("data root");
        write_profile(root.path(), "operator-supplied-board");

        let profile =
            load_profile_with_resolver("operator-supplied-board", &resolver_rooted_at(root.path()))
                .expect("an arbitrary validated profile loads");
        assert_eq!(profile.name, "operator-supplied-board");
    }

    #[test]
    fn profile_names_that_are_not_a_single_safe_segment_are_rejected() {
        let root = tempfile::tempdir().expect("data root");
        for name in ["../escape", "nested/name", "", ".", "..", "has space"] {
            let error = load_profile_with_resolver(name, &resolver_rooted_at(root.path()))
                .expect_err("unsafe profile name must be rejected");
            assert!(
                matches!(error, BootloaderProfileError::UnsupportedProfile(_)),
                "{name:?} produced {error:?}"
            );
        }
    }

    #[test]
    fn a_profile_whose_body_disagrees_with_its_name_is_rejected() {
        let root = tempfile::tempdir().expect("data root");
        let path = write_profile(root.path(), "declared-name");
        fs::rename(&path, path.with_file_name("requested-name.json")).expect("rename");

        let error = load_profile_with_resolver("requested-name", &resolver_rooted_at(root.path()))
            .expect_err("mismatched profile name must be rejected");
        assert!(matches!(
            error,
            BootloaderProfileError::UnsupportedProfile(_)
        ));
    }
}
