use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolchainProfile {
    #[serde(default)]
    pub source: ToolchainProfileSource,
    pub target_triple: Option<String>,
    pub sdk_root: Option<PathBuf>,
    #[serde(default)]
    pub framework_paths: Vec<PathBuf>,
    #[serde(default)]
    pub runtime_hints: Vec<String>,
    #[serde(default)]
    pub inferred_from_arguments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ToolchainProfileSource {
    #[default]
    Unknown,
    FixtureMetadata,
    CompileArguments,
}

impl ToolchainProfile {
    pub fn from_arguments(arguments: &[String]) -> Self {
        let mut profile = ToolchainProfile {
            source: ToolchainProfileSource::CompileArguments,
            ..Self::default()
        };
        let mut iter = arguments.iter().peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-target" => {
                    if let Some(value) = iter.next() {
                        profile.target_triple = Some(value.clone());
                    }
                }
                "-isysroot" => {
                    if let Some(value) = iter.next() {
                        profile.sdk_root = Some(PathBuf::from(value));
                    }
                }
                "-F" | "-iframework" => {
                    if let Some(value) = iter.next() {
                        profile.framework_paths.push(PathBuf::from(value));
                    }
                }
                _ => {}
            }
        }
        profile.inferred_from_arguments = true;
        profile
    }

    pub fn merge(self, fixture: Option<ToolchainProfile>) -> Self {
        if let Some(fixture) = fixture {
            ToolchainProfile {
                source: fixture.source,
                target_triple: fixture.target_triple.or(self.target_triple),
                sdk_root: fixture.sdk_root.or(self.sdk_root),
                framework_paths: if fixture.framework_paths.is_empty() {
                    self.framework_paths
                } else {
                    fixture.framework_paths
                },
                runtime_hints: if fixture.runtime_hints.is_empty() {
                    self.runtime_hints
                } else {
                    fixture.runtime_hints
                },
                inferred_from_arguments: self.inferred_from_arguments
                    || fixture.inferred_from_arguments,
            }
        } else {
            self
        }
    }

    pub fn is_complete(&self) -> bool {
        self.target_triple.is_some() || self.sdk_root.is_some() || !self.framework_paths.is_empty()
    }

    pub fn hash(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json);
        format!("{:x}", hasher.finalize())
    }
}

pub fn load_toolchain_profile(root: &Path) -> Result<Option<ToolchainProfile>, String> {
    let fixture_path = root.join("fat-toolchain-profile.json");
    if !fixture_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&fixture_path)
        .map_err(|e| format!("failed to read {}: {}", fixture_path.display(), e))?;
    let mut profile: ToolchainProfile =
        serde_json::from_str(&text).map_err(|e| format!("invalid toolchain profile: {e}"))?;
    profile.source = ToolchainProfileSource::FixtureMetadata;
    Ok(Some(profile))
}
