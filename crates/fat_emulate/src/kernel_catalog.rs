use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use fat_core::data_dir::DataResolver;
use fat_core::kernel_system::{verify_bundle_directory, KernelArtifactBundleManifest, KernelClass};
use fat_core::target_model::TargetModel;

pub const SYSTEM_KERNEL_DIR_ENV: &str = "FAT_SYSTEM_KERNEL_DIR";
pub const MANAGED_KERNEL_STORE_ENV: &str = "FAT_KERNEL_STORE";
pub const EXPERIMENTAL_KERNELS_ENV: &str = "FAT_EXPERIMENTAL_KERNELS";
const KERNEL_CATALOG_PATH: &str = "profiles/kernels/catalog.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelProfile {
    pub profile_id: String,
    pub architecture: String,
    pub family_hint: String,
    pub tier: u8,
    pub image_hint: String,
    pub support_tier: String,
    pub compatibility_note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_class: Option<KernelClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_machine_profile: Option<String>,
    /// Every machine profile this kernel has been fixture-validated on, the
    /// required one included. `required_machine_profile` names the preferred
    /// profile; this names the whole acceptable set, so a host running a
    /// different-but-validated QEMU is served rather than refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compatible_machine_profiles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelMachineProfile {
    pub schema_version: String,
    pub id: String,
    pub qemu_version: String,
    pub machine: String,
    pub cpu: String,
    pub console: String,
    pub classes: Vec<KernelClass>,
    pub capability_tier: String,
}

impl KernelProfile {
    pub fn new(
        profile_id: impl Into<String>,
        architecture: impl Into<String>,
        family_hint: impl Into<String>,
        tier: u8,
        image_hint: impl Into<String>,
        support_tier: impl Into<String>,
        compatibility_note: impl Into<String>,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            architecture: architecture.into(),
            family_hint: family_hint.into(),
            tier,
            image_hint: image_hint.into(),
            support_tier: support_tier.into(),
            compatibility_note: compatibility_note.into(),
            compatibility_class: None,
            managed_bundle_id: None,
            artifact_digest: None,
            promotion_state: None,
            required_machine_profile: None,
            compatible_machine_profiles: Vec::new(),
        }
    }
}

pub fn load_embedded_kernel_catalog() -> Result<Vec<KernelProfile>, String> {
    load_kernel_catalog(&DataResolver::for_current_process(None))
}

pub fn load_kernel_catalog(resolver: &DataResolver) -> Result<Vec<KernelProfile>, String> {
    let resolved = resolver
        .resolve_required(KERNEL_CATALOG_PATH)
        .map_err(|error| error.to_string())?;
    let contents = std::fs::read_to_string(&resolved.path)
        .map_err(|error| format!("read kernel catalog {}: {error}", resolved.path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("parse kernel catalog {}: {error}", resolved.path.display()))
}

pub fn load_required_machine_profile(
    profile: &KernelProfile,
) -> Result<Option<KernelMachineProfile>, String> {
    load_machine_profile_for_host(profile, None)
}

/// Read the QEMU version a binary reports, or `None` if it cannot be asked.
///
/// Used to pick among a kernel's validated machine profiles. A failure here is
/// not fatal: resolution falls back to the declared preference, and the launch
/// path still refuses a mismatched QEMU before spawning anything.
pub fn host_qemu_version(binary: &str) -> Option<String> {
    let output = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next()?;
    let (_, suffix) = first.split_once("version ")?;
    suffix.split_whitespace().next().map(str::to_string)
}

/// Resolve the machine profile a managed kernel should run under.
///
/// `required_machine_profile` is the declared preference and
/// `compatible_machine_profiles` the rest of the validated set. When the host's
/// QEMU version is known and matches one of them, that profile wins; otherwise
/// the preference is returned unchanged so the caller's version check produces
/// its usual, specific error.
///
/// This keeps the acceptance gate intact -- an unvalidated QEMU is still
/// refused -- while no longer rejecting a combination the fixture matrix has
/// already shown to work.
pub fn load_machine_profile_for_host(
    profile: &KernelProfile,
    host_qemu_version: Option<&str>,
) -> Result<Option<KernelMachineProfile>, String> {
    let Some(required_id) = profile.required_machine_profile.as_deref() else {
        return Ok(None);
    };
    let mut candidate_ids = vec![required_id.to_string()];
    for id in &profile.compatible_machine_profiles {
        if !candidate_ids.iter().any(|known| known == id) {
            candidate_ids.push(id.clone());
        }
    }
    let class = profile.compatibility_class.ok_or_else(|| {
        format!(
            "kernel profile {} binds a machine without a compatibility class",
            profile.profile_id
        )
    })?;
    let resolver = DataResolver::for_current_process(None);
    let directory = resolver
        .resolve_required("profiles/kernels/machines")
        .map_err(|error| error.to_string())?;
    let entries = std::fs::read_dir(&directory.path).map_err(|error| {
        format!(
            "read machine profiles {}: {error}",
            directory.path.display()
        )
    })?;
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read machine profile entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("read machine profile {}: {error}", path.display()))?;
        let machine: KernelMachineProfile = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse machine profile {}: {error}", path.display()))?;
        if machine.schema_version != "1.0"
            || machine.id.trim().is_empty()
            || machine.qemu_version.trim().is_empty()
            || machine.machine.trim().is_empty()
            || machine.cpu.trim().is_empty()
            || machine.console.trim().is_empty()
            || machine.classes.is_empty()
            || machine.capability_tier.trim().is_empty()
        {
            return Err(format!(
                "machine profile {} has an incomplete or unsupported contract",
                path.display()
            ));
        }
        if !candidate_ids.iter().any(|id| id == &machine.id) {
            continue;
        }
        // Only the declared preference is required to serve the class; a
        // compatible entry that does not is a data error worth surfacing, not
        // something to silently skip.
        if !machine.classes.contains(&class) {
            return Err(format!(
                "machine profile {} does not declare kernel class {}",
                machine.id,
                class.as_str()
            ));
        }
        matches.push(machine);
    }

    if matches.is_empty() {
        return Err(format!(
            "required machine profile {required_id} was not found for {}",
            profile.profile_id
        ));
    }
    let duplicated = matches.iter().enumerate().any(|(index, machine)| {
        matches
            .iter()
            .skip(index + 1)
            .any(|other| other.id == machine.id)
    });
    if duplicated {
        return Err(format!(
            "a machine profile for {} is declared more than once",
            profile.profile_id
        ));
    }

    if let Some(version) = host_qemu_version {
        if let Some(position) = matches
            .iter()
            .position(|machine| machine.qemu_version == version)
        {
            return Ok(Some(matches.swap_remove(position)));
        }
    }
    let preferred = matches
        .iter()
        .position(|machine| machine.id == required_id)
        .ok_or_else(|| {
            format!(
                "required machine profile {required_id} was not found for {}",
                profile.profile_id
            )
        })?;
    Ok(Some(matches.swap_remove(preferred)))
}

pub fn select_kernel_profile(target_model: &TargetModel) -> Option<KernelProfile> {
    let catalog = load_embedded_kernel_catalog().ok()?;
    let store = std::env::var_os(MANAGED_KERNEL_STORE_ENV).map(PathBuf::from);
    let allow_experimental = std::env::var(EXPERIMENTAL_KERNELS_ENV)
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    select_kernel_profile_with_artifacts(
        &catalog,
        target_model,
        &[],
        store.as_deref(),
        allow_experimental,
    )
}

pub fn select_kernel_profile_with_demotions(
    catalog: &[KernelProfile],
    target_model: &TargetModel,
    demoted_profile_ids: &[String],
) -> Option<KernelProfile> {
    select_kernel_profile_with_artifacts(catalog, target_model, demoted_profile_ids, None, false)
}

pub fn select_kernel_profile_with_artifacts(
    catalog: &[KernelProfile],
    target_model: &TargetModel,
    demoted_profile_ids: &[String],
    managed_store: Option<&Path>,
    allow_experimental: bool,
) -> Option<KernelProfile> {
    let architecture = target_model.architecture.as_deref()?;
    let family_id = target_model.family_id.as_deref().unwrap_or("linux-");
    let mut candidates = catalog
        .iter()
        .filter(|profile| profile.architecture == architecture)
        .filter(|profile| {
            profile_available(profile, target_model, managed_store, allow_experimental)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        kernel_profile_rank(left, family_id, demoted_profile_ids)
            .cmp(&kernel_profile_rank(right, family_id, demoted_profile_ids))
            .then(left.profile_id.cmp(&right.profile_id))
    });
    candidates.into_iter().next()
}

pub fn resolve_kernel_asset_source(profile: &KernelProfile) -> PathBuf {
    if let (Some(bundle_id), Some(store)) = (
        profile.managed_bundle_id.as_deref(),
        std::env::var_os(MANAGED_KERNEL_STORE_ENV),
    ) {
        let candidate = PathBuf::from(store)
            .join("bundles")
            .join(bundle_id)
            .join(&profile.image_hint);
        if candidate.exists() {
            return candidate;
        }
    }
    if let Ok(dir) = std::env::var(SYSTEM_KERNEL_DIR_ENV) {
        let candidate = PathBuf::from(dir).join(&profile.image_hint);
        if candidate.exists() {
            return candidate;
        }
    }

    let resolver = DataResolver::for_current_process(None);
    resolver
        .resolve_required(PathBuf::from("profiles/kernels").join(&profile.image_hint))
        .map(|resolved| resolved.path)
        .unwrap_or_else(|_| PathBuf::from("profiles/kernels").join(&profile.image_hint))
}

fn profile_available(
    profile: &KernelProfile,
    target_model: &TargetModel,
    managed_store: Option<&Path>,
    allow_experimental: bool,
) -> bool {
    let Some(bundle_id) = profile.managed_bundle_id.as_deref() else {
        return true;
    };
    let Some(class) = profile.compatibility_class else {
        return false;
    };
    if !target_model
        .evidence
        .iter()
        .any(|evidence| evidence == &format!("kernel-class:{}", class.as_str()))
    {
        return false;
    }
    match profile.support_tier.as_str() {
        "supported" if profile.promotion_state.as_deref() == Some("promoted") => {}
        "experimental" if allow_experimental => {}
        _ => return false,
    }
    let Some(store) = managed_store else {
        return false;
    };
    if !matches!(load_required_machine_profile(profile), Ok(Some(_))) {
        return false;
    }
    let bundle_dir = store.join("bundles").join(bundle_id);
    let Ok(bytes) = std::fs::read(bundle_dir.join("manifest.json")) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_slice::<KernelArtifactBundleManifest>(&bytes) else {
        return false;
    };
    manifest.id == bundle_id
        && manifest.class == class
        && profile.artifact_digest.as_deref() == Some(manifest.kernel_image.digest.as_str())
        && profile.image_hint == manifest.kernel_image.path
        && verify_bundle_directory(&bundle_dir, &manifest).is_ok()
}

fn kernel_profile_rank(
    profile: &KernelProfile,
    family_id: &str,
    demoted_profile_ids: &[String],
) -> (u8, u8, u8) {
    let demoted = demoted_profile_ids
        .iter()
        .any(|profile_id| profile_id == &profile.profile_id);
    let family_rank = if family_id.starts_with(&profile.family_hint) {
        0
    } else if profile.family_hint == "linux-" {
        2
    } else {
        1
    };
    let demotion_rank = if demoted { 1 } else { 0 };
    (demotion_rank, family_rank, profile.tier)
}
