use crate::bootloader_image::BootloaderImage;
use crate::bootplan::{BootArtifact, BootArtifactSet};
use fat_core::bootloader::BootloaderSnapshot;
use fat_extract::manifest::ExtractionManifest;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootArtifactDiscovery {
    pub artifacts: Vec<BootArtifact>,
    pub bootloader_images: Vec<BootloaderImage>,
    pub primary: Option<BootArtifactSet>,
    pub alternates: Vec<BootArtifactSet>,
    pub rejection_reasons: Vec<String>,
}

#[derive(Debug)]
pub enum BootDiscoveryError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    MissingProject(PathBuf),
}

impl fmt::Display for BootDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
            Self::MissingProject(path) => {
                write!(
                    f,
                    "bootloader project path does not exist: {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for BootDiscoveryError {}

impl From<std::io::Error> for BootDiscoveryError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BootDiscoveryError {
    fn from(error: serde_json::Error) -> Self {
        Self::Parse(error)
    }
}

pub fn discover_boot_artifacts(
    project_dir: &Path,
) -> Result<BootArtifactDiscovery, BootDiscoveryError> {
    if !project_dir.is_dir() {
        return Err(BootDiscoveryError::MissingProject(
            project_dir.to_path_buf(),
        ));
    }

    let mut artifacts = Vec::new();
    let mut bootloader_images = Vec::new();
    let mut rejection_reasons = Vec::new();

    let bootloader_json = project_dir.join("analysis").join("bootloader.json");
    let bootloader_snapshot = if bootloader_json.is_file() {
        Some(load_bootloader_snapshot(&bootloader_json)?)
    } else {
        None
    };
    let extraction_manifest = load_extraction_manifest(project_dir)?;
    seed_artifacts_from_manifest(
        &mut artifacts,
        extraction_manifest.as_ref(),
        bootloader_snapshot.as_ref(),
    );

    let evidence_roots = discovery_roots(project_dir);
    for root in evidence_roots {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if is_rootfs_tree(path) {
                    artifacts.push(BootArtifact {
                        kind: "rootfs".into(),
                        path: path.display().to_string(),
                        source_path: path.display().to_string(),
                        format: "rootfs-tree".into(),
                        provenance: "extracted".into(),
                        confidence: 0.9,
                        ..Default::default()
                    });
                }
                continue;
            }

            if !entry.file_type().is_file() {
                continue;
            }

            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            if let Some(image) = detect_bootloader_image(path, &bytes, bootloader_snapshot.as_ref())
            {
                bootloader_images.push(image);
            }
            if let Some(kind) = detect_kind(path, &bytes) {
                let format = detect_format(path, &bytes, &kind);
                let carve_embedded_dtbs = kind == "kernel" || kind == "fit";
                artifacts.push(BootArtifact {
                    kind,
                    path: path.display().to_string(),
                    source_path: path.display().to_string(),
                    format,
                    arch: String::new(),
                    load_addr: bootloader_value(bootloader_snapshot.as_ref(), "loadaddr"),
                    provenance: "extracted".into(),
                    confidence: confidence_for(path),
                    ..Default::default()
                });

                if carve_embedded_dtbs {
                    artifacts.extend(carve_embedded_dtb_artifacts(project_dir, path, &bytes)?);
                }
            }
        }
    }

    dedup_artifacts(&mut artifacts);
    dedup_bootloader_images(&mut bootloader_images);

    let primary = build_primary_set(&artifacts, bootloader_snapshot.as_ref());
    let alternates = build_alternates(&artifacts);

    if bootloader_images.is_empty()
        && primary.is_some()
        && bootloader_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.family.as_ref())
            .is_some_and(|family| family.eq_ignore_ascii_case("u-boot"))
    {
        rejection_reasons.push(
            "bootloader evidence was found, but no vendor bootloader artifact was extracted; this looks like an upgrade package or partial firmware image rather than a full flash dump"
                .into(),
        );
    }

    if primary.is_none() {
        rejection_reasons.push("no viable strict-real boot artifact set found".into());
    }

    Ok(BootArtifactDiscovery {
        artifacts,
        bootloader_images,
        primary,
        alternates,
        rejection_reasons,
    })
}

fn load_bootloader_snapshot(path: &Path) -> Result<BootloaderSnapshot, BootDiscoveryError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_extraction_manifest(
    project_dir: &Path,
) -> Result<Option<ExtractionManifest>, BootDiscoveryError> {
    let path = project_dir.join("work").join("extraction-manifest.json");
    if !path.is_file() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn seed_artifacts_from_manifest(
    artifacts: &mut Vec<BootArtifact>,
    manifest: Option<&ExtractionManifest>,
    snapshot: Option<&BootloaderSnapshot>,
) {
    let Some(manifest) = manifest else {
        return;
    };

    if let Some(rootfs_path) = &manifest.rootfs_path {
        let rootfs_path = rootfs_path.display().to_string();
        artifacts.push(BootArtifact {
            kind: "rootfs".into(),
            path: rootfs_path.clone(),
            source_path: rootfs_path,
            format: "rootfs-tree".into(),
            provenance: "manifest".into(),
            confidence: 0.95,
            ..Default::default()
        });
    }

    for kernel_path in &manifest.kernel_paths {
        let path = kernel_path.as_path();
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let format = manifest_kernel_format(path, &bytes);
        let path = path.display().to_string();
        artifacts.push(BootArtifact {
            kind: "kernel".into(),
            path: path.clone(),
            source_path: path,
            format,
            arch: String::new(),
            load_addr: bootloader_value(snapshot, "loadaddr"),
            provenance: "manifest".into(),
            confidence: 0.95,
            ..Default::default()
        });
    }
}

fn detect_kind(path: &Path, bytes: &[u8]) -> Option<String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if bytes.starts_with(&[0x27, 0x05, 0x19, 0x56]) || file_name == "uimage" {
        return Some("kernel".into());
    }

    if file_name.ends_with(".itb") || is_fit_magic(bytes) {
        return Some("fit".into());
    }

    if file_name.ends_with(".dtb") || is_dtb_magic(bytes) {
        return Some("dtb".into());
    }

    if file_name.contains("rootfs") || file_name.ends_with(".img") {
        return Some("rootfs".into());
    }

    None
}

fn detect_format(path: &Path, bytes: &[u8], kind: &str) -> String {
    match kind {
        "kernel" if bytes.starts_with(&[0x27, 0x05, 0x19, 0x56]) => "uImage".into(),
        "fit" => "FIT".into(),
        "dtb" => "dtb".into(),
        "rootfs" if path.extension().and_then(|value| value.to_str()) == Some("img") => {
            "rootfs-image".into()
        }
        "rootfs" => "rootfs-tree".into(),
        _ => "unknown".into(),
    }
}

fn manifest_kernel_format(path: &Path, bytes: &[u8]) -> String {
    if bytes.starts_with(&[0x27, 0x05, 0x19, 0x56]) {
        return "uImage".into();
    }

    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name == "zimage" {
        return "zImage".into();
    }
    if name == "image" {
        return "Image".into();
    }

    "kernel-raw".into()
}

fn is_rootfs_tree(path: &Path) -> bool {
    path.join("sbin").join("init").is_file() || path.join("etc").join("inittab").is_file()
}

fn bootloader_value(snapshot: Option<&BootloaderSnapshot>, key: &str) -> Option<String> {
    snapshot.and_then(|snapshot| {
        snapshot
            .env_variables
            .iter()
            .find(|variable| variable.key.eq_ignore_ascii_case(key))
            .map(|variable| variable.value.clone())
    })
}

fn confidence_for(path: &Path) -> f32 {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if name == "uimage" || name.ends_with(".itb") || name.ends_with(".dtb") {
        0.95
    } else if name.contains("rootfs") {
        0.9
    } else {
        0.6
    }
}

fn detect_bootloader_image(
    path: &Path,
    bytes: &[u8],
    snapshot: Option<&BootloaderSnapshot>,
) -> Option<BootloaderImage> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let snapshot_is_u_boot = snapshot
        .and_then(|data| data.family.as_ref())
        .is_some_and(|family| family.eq_ignore_ascii_case("u-boot"));
    let binary_like =
        extension.is_empty() || matches!(extension.as_str(), "bin" | "img" | "rom" | "elf");
    let metadata_like = matches!(
        extension.as_str(),
        "sh" | "control"
            | "list"
            | "txt"
            | "conf"
            | "cfg"
            | "json"
            | "yaml"
            | "yml"
            | "md"
            | "lua"
            | "py"
            | "pl"
            | "ini"
            | "service"
    );
    let userspace_boot_tool = matches!(file_name.as_str(), "fw_printenv" | "fw_setenv");
    let userspace_path = path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|segment| matches!(segment, "bin" | "sbin" | "usr" | "lib" | "etc"))
    });
    let bootloader_like_name =
        (file_name.contains("u-boot") || file_name == "uboot" || file_name.contains("bootloader"))
            && binary_like
            || file_name == "spl"
            || file_name.starts_with("spl.")
            || file_name == "tpl"
            || file_name.starts_with("tpl.");
    let content_looks_like_binary_bootloader = text.contains("u-boot ")
        && binary_like
        && bootloader_like_name
        && !metadata_like
        && !userspace_boot_tool
        && !userspace_path
        && !bytes.starts_with(b"#!");

    let is_u_boot = (file_name.contains("u-boot") && binary_like)
        || content_looks_like_binary_bootloader
        || (snapshot_is_u_boot && bootloader_like_name);
    if !is_u_boot {
        return None;
    }

    Some(BootloaderImage {
        family: "u-boot".into(),
        path: path.display().to_string(),
        source_path: path.display().to_string(),
        format: bootloader_image_format(path),
        architecture: bootloader_architecture(bytes, snapshot),
        provenance: "extracted".into(),
        confidence: 0.9,
        ..Default::default()
    })
}

fn bootloader_image_format(path: &Path) -> String {
    match path.extension().and_then(|value| value.to_str()) {
        Some("bin") => "raw".into(),
        Some(extension) => extension.to_string(),
        None => "unknown".into(),
    }
}

fn bootloader_architecture(bytes: &[u8], snapshot: Option<&BootloaderSnapshot>) -> String {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if text.contains("arm") {
        "arm".into()
    } else if text.contains("mips") {
        "mips".into()
    } else if text.contains("aarch64") || text.contains("arm64") {
        "arm64".into()
    } else {
        snapshot
            .and_then(|data| data.version_hint.as_ref())
            .and_then(|hint| {
                let hint = hint.to_ascii_lowercase();
                if hint.contains("arm") {
                    Some("arm".to_string())
                } else if hint.contains("mips") {
                    Some("mips".to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }
}

fn build_primary_set(
    artifacts: &[BootArtifact],
    snapshot: Option<&BootloaderSnapshot>,
) -> Option<BootArtifactSet> {
    if let Some(kernel) = artifacts.iter().find(|artifact| artifact.kind == "kernel") {
        let mut rationale = vec!["selected kernel artifact candidate".to_string()];
        if snapshot.is_some() {
            rationale.push("bootloader evidence was available".to_string());
        }

        let mut alternates = Vec::new();
        if let Some(rootfs) = artifacts.iter().find(|artifact| artifact.kind == "rootfs") {
            alternates.push(rootfs.clone());
            rationale.push("paired with rootfs candidate".to_string());
        }
        if let Some(dtb) = artifacts.iter().find(|artifact| artifact.kind == "dtb") {
            alternates.push(dtb.clone());
            rationale.push("paired with dtb candidate".to_string());
        }

        return Some(BootArtifactSet {
            primary: Some(kernel.clone()),
            alternates,
            missing_requirements: Vec::new(),
            selection_rationale: rationale,
        });
    }

    artifacts
        .iter()
        .find(|artifact| artifact.kind == "fit")
        .map(|fit| BootArtifactSet {
            primary: Some(fit.clone()),
            alternates: Vec::new(),
            missing_requirements: Vec::new(),
            selection_rationale: vec!["selected fit image candidate".to_string()],
        })
}

fn build_alternates(artifacts: &[BootArtifact]) -> Vec<BootArtifactSet> {
    artifacts
        .iter()
        .filter(|artifact| artifact.kind == "fit")
        .map(|artifact| BootArtifactSet {
            primary: Some(artifact.clone()),
            alternates: Vec::new(),
            missing_requirements: Vec::new(),
            selection_rationale: vec!["fit image candidate".to_string()],
        })
        .collect()
}

fn discovery_roots(project_dir: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for candidate in [
        project_dir.join("work").join("extractions"),
        project_dir.join("extracted"),
    ] {
        if candidate.is_dir() {
            roots.push(candidate);
        }
    }

    if roots.is_empty() {
        roots.push(project_dir.to_path_buf());
    }

    roots
}

fn dedup_artifacts(artifacts: &mut Vec<BootArtifact>) {
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    artifacts.dedup_by(|left, right| left.path == right.path && left.kind == right.kind);
}

fn dedup_bootloader_images(images: &mut Vec<BootloaderImage>) {
    images.sort_by(|left, right| left.path.cmp(&right.path));
    images.dedup_by(|left, right| left.path == right.path && left.family == right.family);
}

fn is_fit_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0x0d, 0xfe, 0xed])
        && bytes
            .windows(3)
            .any(|window| window.eq_ignore_ascii_case(b"fit"))
}

fn is_dtb_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0x0d, 0xfe, 0xed])
}

fn carve_embedded_dtb_artifacts(
    project_dir: &Path,
    source_path: &Path,
    bytes: &[u8],
) -> Result<Vec<BootArtifact>, BootDiscoveryError> {
    let mut artifacts = Vec::new();
    for (offset, total_size) in valid_embedded_dtb_ranges(bytes) {
        let carve_dir = project_dir
            .join("work")
            .join("discovery-carve")
            .join("embedded-dtb");
        fs::create_dir_all(&carve_dir)?;
        let leaf = source_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("kernel");
        let carved = carve_dir.join(format!("{leaf}-{offset:x}.dtb"));
        fs::write(&carved, &bytes[offset..offset + total_size])?;
        artifacts.push(BootArtifact {
            kind: "dtb".into(),
            path: carved.display().to_string(),
            source_path: source_path.display().to_string(),
            format: "dtb".into(),
            provenance: "embedded-carve".into(),
            confidence: 0.85,
            ..Default::default()
        });
    }

    Ok(artifacts)
}

fn valid_embedded_dtb_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let magic = [0xd0, 0x0d, 0xfe, 0xed];
    let mut offset = 0usize;

    while let Some(relative) = bytes[offset..]
        .windows(4)
        .position(|window| window == magic)
    {
        let start = offset + relative;
        if let Some(total_size) = valid_dtb_total_size(&bytes[start..]) {
            ranges.push((start, total_size));
            offset = start + total_size;
        } else {
            offset = start + 1;
        }
    }

    ranges
}

fn valid_dtb_total_size(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 40 || !bytes.starts_with(&[0xd0, 0x0d, 0xfe, 0xed]) {
        return None;
    }

    let total_size = u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize;
    let off_dt_struct = u32::from_be_bytes(bytes[8..12].try_into().ok()?) as usize;
    let off_dt_strings = u32::from_be_bytes(bytes[12..16].try_into().ok()?) as usize;
    let off_mem_rsvmap = u32::from_be_bytes(bytes[16..20].try_into().ok()?) as usize;
    let version = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    let last_comp_version = u32::from_be_bytes(bytes[24..28].try_into().ok()?);
    let size_dt_strings = u32::from_be_bytes(bytes[32..36].try_into().ok()?) as usize;
    let size_dt_struct = u32::from_be_bytes(bytes[36..40].try_into().ok()?) as usize;

    if total_size < 40 || total_size > bytes.len() {
        return None;
    }
    if off_mem_rsvmap < 40 || off_dt_struct < 40 || off_dt_strings < 40 {
        return None;
    }
    if off_dt_struct > total_size || off_dt_strings > total_size || off_mem_rsvmap > total_size {
        return None;
    }
    if off_dt_struct + size_dt_struct > total_size || off_dt_strings + size_dt_strings > total_size
    {
        return None;
    }
    if !(16..=17).contains(&version) || last_comp_version > version {
        return None;
    }

    Some(total_size)
}
