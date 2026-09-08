use crate::bootloader_image::{BootloaderCompatibility, BootloaderImage};
use crate::bootplan::{build_boot_plan, BootArtifact, BootArtifactSet, BootPlan};
use crate::compatibility::evaluate_true_boot_chain;
use crate::discovery::discover_boot_artifacts;
use crate::env::render_env;
use crate::profile::{load_profile, BootloaderProfile, BootloaderProfileError};
use fat_core::bootloader::BootloaderSnapshot;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootloaderWorkspaceManifest {
    pub mode: String,
    pub profile_name: String,
    pub profile: BootloaderProfile,
    pub imported_snapshot: Option<BootloaderSnapshot>,
    pub bootloader_image: Option<BootloaderImage>,
    pub compatibility: Option<BootloaderCompatibility>,
    pub selected_artifacts: Option<BootArtifactSet>,
    pub alternates: Vec<BootArtifactSet>,
    pub boot_plan: Option<BootPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootloaderWorkspace {
    pub bootloader_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub env_path: PathBuf,
    pub boot_plan_path: PathBuf,
}

#[derive(Debug)]
pub enum BootloaderWorkspaceError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    Profile(BootloaderProfileError),
    MissingProject(PathBuf),
    StrictRealRejected(String),
}

impl fmt::Display for BootloaderWorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::Profile(error) => write!(f, "{error}"),
            Self::MissingProject(path) => {
                write!(
                    f,
                    "bootloader project path does not exist: {}",
                    path.display()
                )
            }
            Self::StrictRealRejected(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for BootloaderWorkspaceError {}

impl From<std::io::Error> for BootloaderWorkspaceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BootloaderWorkspaceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Parse(error)
    }
}

impl From<BootloaderProfileError> for BootloaderWorkspaceError {
    fn from(error: BootloaderProfileError) -> Self {
        Self::Profile(error)
    }
}

pub fn materialize_workspace(
    project_dir: &Path,
    profile_name: &str,
) -> Result<BootloaderWorkspace, BootloaderWorkspaceError> {
    if !project_dir.is_dir() {
        return Err(BootloaderWorkspaceError::MissingProject(
            project_dir.to_path_buf(),
        ));
    }

    let profile = load_profile(profile_name)?;
    let imported_snapshot = load_imported_snapshot(project_dir)?;
    let discovery = discover_boot_artifacts(project_dir)
        .map_err(|error| BootloaderWorkspaceError::Io(std::io::Error::other(error.to_string())))?;
    let selected_artifacts = discovery.primary.clone().ok_or_else(|| {
        BootloaderWorkspaceError::StrictRealRejected(strict_real_rejection(
            &discovery.rejection_reasons,
        ))
    })?;
    let selected_bootloader = discovery.bootloader_images.first().cloned();
    let compatibility = selected_bootloader
        .as_ref()
        .map(|image| evaluate_true_boot_chain(image, Some(&selected_artifacts), None));
    let mode = compatibility
        .as_ref()
        .map(|result| {
            if result.compatible {
                result.mode.clone()
            } else {
                "hybrid-boot-chain".to_string()
            }
        })
        .unwrap_or_else(|| "hybrid-boot-chain".to_string());
    let boot_plan = build_boot_plan(&selected_artifacts, imported_snapshot.as_ref(), &profile);
    let bootloader_dir = project_dir.join("bootloader");
    let storage_dir = bootloader_dir.join("storage");
    fs::create_dir_all(&bootloader_dir)?;
    fs::create_dir_all(&storage_dir)?;

    let copied_bootloader = selected_bootloader
        .as_ref()
        .zip(compatibility.as_ref())
        .filter(|(_, result)| result.compatible)
        .map(|(image, _)| materialize_bootloader_image(&storage_dir, image))
        .transpose()?;
    let copied_artifacts = materialize_artifacts(&storage_dir, &selected_artifacts)?;
    let boot_plan = remap_boot_plan_storage(boot_plan, &copied_artifacts);

    let manifest = BootloaderWorkspaceManifest {
        mode,
        profile_name: profile_name.to_string(),
        profile: profile.clone(),
        imported_snapshot: imported_snapshot.clone(),
        bootloader_image: copied_bootloader,
        compatibility,
        selected_artifacts: Some(copied_artifacts.clone()),
        alternates: discovery.alternates,
        boot_plan: Some(boot_plan.clone()),
    };
    let manifest_path = bootloader_dir.join("profile.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    let env_path = bootloader_dir.join("env.txt");
    fs::write(
        &env_path,
        render_env(&profile, imported_snapshot.as_ref()).unwrap(),
    )?;

    let boot_plan_path = bootloader_dir.join("boot-plan.json");
    fs::write(&boot_plan_path, serde_json::to_vec_pretty(&boot_plan)?)?;

    Ok(BootloaderWorkspace {
        bootloader_dir,
        storage_dir,
        manifest_path,
        env_path,
        boot_plan_path,
    })
}

fn materialize_bootloader_image(
    storage_dir: &Path,
    image: &BootloaderImage,
) -> Result<BootloaderImage, BootloaderWorkspaceError> {
    let source = Path::new(&image.path);
    let destination = storage_dir.join("bootloader").join(
        source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("bootloader.bin"),
    );
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, &destination)?;

    let mut materialized = image.clone();
    materialized.path = destination.display().to_string();
    Ok(materialized)
}

fn load_imported_snapshot(
    project_dir: &Path,
) -> Result<Option<BootloaderSnapshot>, BootloaderWorkspaceError> {
    let path = project_dir.join("analysis").join("bootloader.json");
    if !path.is_file() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;
    let snapshot = serde_json::from_slice(&bytes)?;
    Ok(Some(snapshot))
}

fn strict_real_rejection(reasons: &[String]) -> String {
    if reasons.is_empty() {
        "no viable strict-real boot artifact set found".into()
    } else {
        reasons.join("; ")
    }
}

fn materialize_artifacts(
    storage_dir: &Path,
    selected: &BootArtifactSet,
) -> Result<BootArtifactSet, BootloaderWorkspaceError> {
    let primary = selected
        .primary
        .as_ref()
        .map(|artifact| materialize_artifact(storage_dir, artifact))
        .transpose()?;
    let alternates = selected
        .alternates
        .iter()
        .map(|artifact| materialize_artifact(storage_dir, artifact))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(BootArtifactSet {
        primary,
        alternates,
        missing_requirements: selected.missing_requirements.clone(),
        selection_rationale: selected.selection_rationale.clone(),
    })
}

fn materialize_artifact(
    storage_dir: &Path,
    artifact: &BootArtifact,
) -> Result<BootArtifact, BootloaderWorkspaceError> {
    let source = Path::new(&artifact.path);
    let destination = storage_destination(storage_dir, artifact, source);
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        copy_tree(source, &destination)?;
    } else if metadata.file_type().is_symlink() {
        copy_symlink(source, &destination)?;
    } else {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, &destination)?;
    }

    let mut materialized = artifact.clone();
    materialized.path = destination.display().to_string();
    Ok(materialized)
}

fn storage_destination(storage_dir: &Path, artifact: &BootArtifact, source: &Path) -> PathBuf {
    let kind_dir = storage_dir.join(&artifact.kind);
    let leaf = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    kind_dir.join(leaf)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), BootloaderWorkspaceError> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.file_type().is_symlink() {
            copy_symlink(&source_path, &destination_path)?;
        } else {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn copy_symlink(source: &Path, destination: &Path) -> Result<(), BootloaderWorkspaceError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let target = fs::read_link(source)?;

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, destination)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        if target.is_file() {
            fs::copy(source, destination)?;
            return Ok(());
        }
        Err(BootloaderWorkspaceError::Io(std::io::Error::other(
            "symlink copying is unsupported on this platform",
        )))
    }
}

fn remap_boot_plan_storage(plan: BootPlan, selected: &BootArtifactSet) -> BootPlan {
    let dtb = selected
        .alternates
        .iter()
        .find(|artifact| artifact.kind == "dtb")
        .cloned()
        .map(|mut artifact| {
            artifact.load_addr = artifact
                .load_addr
                .or_else(|| plan.dtb.as_ref().and_then(|value| value.load_addr.clone()));
            artifact.entry_addr = artifact
                .entry_addr
                .or_else(|| plan.dtb.as_ref().and_then(|value| value.entry_addr.clone()));
            artifact
        });
    let rootfs = selected
        .alternates
        .iter()
        .find(|artifact| artifact.kind == "rootfs")
        .cloned()
        .map(|mut artifact| {
            artifact.load_addr = artifact.load_addr.or_else(|| {
                plan.rootfs
                    .as_ref()
                    .and_then(|value| value.load_addr.clone())
            });
            artifact.entry_addr = artifact.entry_addr.or_else(|| {
                plan.rootfs
                    .as_ref()
                    .and_then(|value| value.entry_addr.clone())
            });
            artifact
        });
    BootPlan {
        kernel: selected
            .primary
            .as_ref()
            .filter(|artifact| artifact.kind == "kernel")
            .cloned(),
        fit: selected
            .primary
            .as_ref()
            .filter(|artifact| artifact.kind == "fit")
            .cloned(),
        dtb,
        rootfs,
        ..plan
    }
}
