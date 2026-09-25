use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::data_manifest::DataManifest;

pub const FAT_DATA_DIR_ENV: &str = "FAT_DATA_DIR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRootOrigin {
    Explicit,
    Environment,
    ExecutableRelative,
    User,
    Development,
}

impl fmt::Display for DataRootOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Explicit => "explicit",
            Self::Environment => "environment",
            Self::ExecutableRelative => "executable-relative",
            Self::User => "user",
            Self::Development => "development",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRoot {
    pub path: PathBuf,
    pub origin: DataRootOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDataPath {
    pub path: PathBuf,
    pub root: PathBuf,
    pub origin: DataRootOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataResolutionError {
    pub relative_path: PathBuf,
    pub searched: Vec<DataRoot>,
}

impl fmt::Display for DataResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FAT runtime resource '{}' was not found",
            self.relative_path.display()
        )?;
        if self.searched.is_empty() {
            return formatter.write_str("; no valid data roots were available");
        }
        formatter.write_str("; searched:")?;
        for candidate in &self.searched {
            write!(
                formatter,
                "\n  - {} ({})",
                candidate.path.join(&self.relative_path).display(),
                candidate.origin
            )?;
        }
        Ok(())
    }
}

impl Error for DataResolutionError {}

#[derive(Debug, Clone, Default)]
pub struct DataResolver {
    roots: Vec<DataRoot>,
}

impl DataResolver {
    pub fn from_paths(
        explicit_root: Option<PathBuf>,
        environment_root: Option<PathBuf>,
        executable: Option<PathBuf>,
        user_root: Option<PathBuf>,
        development_root: Option<PathBuf>,
    ) -> Self {
        let executable_root = executable
            .as_deref()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(|prefix| prefix.join("share").join("fat"));
        let portable_root = executable
            .as_deref()
            .and_then(Path::parent)
            .map(|directory| directory.join("share").join("fat"));
        let development_root = development_root.filter(|root| is_development_checkout(root));

        let candidates = [
            explicit_root.map(|path| (path, DataRootOrigin::Explicit)),
            environment_root.map(|path| (path, DataRootOrigin::Environment)),
            portable_root.map(|path| (path, DataRootOrigin::ExecutableRelative)),
            executable_root.map(|path| (path, DataRootOrigin::ExecutableRelative)),
            user_root.map(|path| (path, DataRootOrigin::User)),
            development_root.map(|path| (path, DataRootOrigin::Development)),
        ];

        let mut seen = BTreeSet::new();
        let roots = candidates
            .into_iter()
            .flatten()
            .filter_map(|(path, origin)| {
                if seen.insert(path.clone()) {
                    Some(DataRoot { path, origin })
                } else {
                    None
                }
            })
            .collect();
        Self { roots }
    }

    pub fn from_process(explicit_root: Option<PathBuf>, development_root: Option<PathBuf>) -> Self {
        Self::from_paths(
            explicit_root,
            env::var_os(FAT_DATA_DIR_ENV).map(PathBuf::from),
            env::current_exe().ok(),
            default_user_data_root(),
            development_root,
        )
    }

    /// Build the normal runtime resolver. The compile-time path is considered
    /// only as the final development fallback and is discarded unless the
    /// expected workspace markers still exist at runtime.
    pub fn for_current_process(explicit_root: Option<PathBuf>) -> Self {
        Self::from_process(explicit_root, development_checkout_root())
    }

    pub fn roots(&self) -> &[DataRoot] {
        &self.roots
    }

    pub fn resolve_required(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<ResolvedDataPath, DataResolutionError> {
        let relative_path = relative_path.as_ref();
        for (index, root) in self.roots.iter().enumerate() {
            let active_path = root.path.join("active.json");
            let candidate_roots = match std::fs::symlink_metadata(&active_path) {
                Ok(_) => match active_version_root(&root.path) {
                    Some(active_root) => vec![active_root],
                    None => {
                        return Err(DataResolutionError {
                            relative_path: relative_path.to_path_buf(),
                            searched: self.roots[..=index].to_vec(),
                        });
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    vec![root.path.clone()]
                }
                Err(_) => {
                    return Err(DataResolutionError {
                        relative_path: relative_path.to_path_buf(),
                        searched: self.roots[..=index].to_vec(),
                    });
                }
            };
            for candidate_root in candidate_roots {
                let candidate = candidate_root.join(relative_path);
                if candidate.exists() {
                    return Ok(ResolvedDataPath {
                        path: candidate,
                        root: candidate_root,
                        origin: root.origin,
                    });
                }
            }
        }
        Err(DataResolutionError {
            relative_path: relative_path.to_path_buf(),
            searched: self.roots.clone(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct ActiveDataRecord {
    data_version: String,
    relative_path: PathBuf,
}

fn active_version_root(root: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(root.join("active.json")).ok()?;
    let active: ActiveDataRecord = serde_json::from_str(&text).ok()?;
    if active.relative_path.is_absolute()
        || active
            .relative_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let candidate = root.join(active.relative_path);
    if !candidate.is_dir() {
        return None;
    }
    let manifest = DataManifest::load(&candidate).ok()?;
    if manifest.data_version != active.data_version
        || manifest
            .verify_tree(&candidate, env!("CARGO_PKG_VERSION"))
            .is_err()
    {
        return None;
    }
    Some(candidate)
}

#[cfg(debug_assertions)]
fn development_checkout_root() -> Option<PathBuf> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../..").canonicalize().ok()
}

#[cfg(not(debug_assertions))]
fn development_checkout_root() -> Option<PathBuf> {
    None
}

fn is_development_checkout(root: &Path) -> bool {
    root.join("Cargo.toml").is_file() && root.join("profiles").is_dir()
}

pub fn default_user_data_root() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        return env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("FAT"));
    }

    #[cfg(target_os = "macos")]
    {
        return env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join("Library").join("Application Support").join("FAT"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(path) = env::var_os("XDG_DATA_HOME") {
            return Some(PathBuf::from(path).join("fat"));
        }
        return env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join(".local").join("share").join("fat"));
    }

    #[allow(unreachable_code)]
    None
}
