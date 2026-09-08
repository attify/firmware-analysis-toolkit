use crate::{elf_inspect, envelope_cmd, schema_versions};
use fat_analyze::bootloader::{
    analyze_firmware_bytes, build_layout_report, build_layout_report_with_bytes,
};
use fat_analyze::mcu::detect_cortex_m_ivt;
use fat_analyze::mcu_inspect::{inspect_file, McuInspectRequest};
use fat_core::inspection::ContainerHeader;
use fat_core::inspection::FilesystemHeader;
use fat_core::layout::LayoutReport;
use fat_core::mcu_inspection::McuInspectionReport;
use fat_extract::ExtractionManifest;
use fat_query::target_detection::{self, TargetKind};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

type DynResult<T> = Result<T, Box<dyn Error>>;

const DIRECTORY_COLLECTION_SCAN_LIMIT: usize = 64;
const DIRECTORY_COLLECTION_SAMPLE_LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct IdentifyReport {
    pub schema_version: &'static str,
    pub input_path: String,
    pub path_kind: String,
    pub likely_class: String,
    pub confidence: String,
    pub summary: Vec<String>,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_label: Option<String>,
    pub envelope: Option<envelope_cmd::EnvelopeReport>,
    pub structure: Option<StructureSummary>,
    pub mcu: Option<McuSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructureSummary {
    pub regions: Vec<ObjectHit>,
    pub container_headers: Vec<ObjectHit>,
    pub image_headers: Vec<ObjectHit>,
    pub compression_members: Vec<ObjectHit>,
    pub filesystem_headers: Vec<ObjectHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partitioning: Option<PartitioningSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inferences: Vec<StructureInference>,
    pub dominant_boot_image: Option<String>,
    pub dominant_rootfs: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectHit {
    pub kind: String,
    pub format: String,
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompressed_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_offset: Option<u64>,
    pub span_is_exact: bool,
    pub fills_to_eof: bool,
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<PartitionRoleSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endianness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_offset: Option<u64>,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PartitionRoleSummary {
    pub mtdblock: u32,
    pub name: String,
    pub mount_point: Option<String>,
    pub mount_confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PartitioningSummary {
    pub source: String,
    pub device: String,
    pub partition_count: usize,
    pub flash_size_bytes: u64,
    pub root_device: Option<String>,
    pub root_fstype: Option<String>,
    pub firmware_offset_delta: Option<i64>,
    pub root: Option<String>,
    pub app_system: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_data: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructureInference {
    pub id: String,
    pub label: String,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McuSummary {
    pub architecture: String,
    pub family: String,
    pub family_confidence: u8,
    pub reset_vector: String,
    pub base_hypothesis: Option<String>,
}

pub fn run(path: Option<&Path>, file: Option<&Path>, json: bool) -> DynResult<()> {
    let input = match (path, file) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(
                "exactly one input source is required: either <path> or --file <path>".into(),
            );
        }
        (Some(path), None) | (None, Some(path)) => path,
    };

    let report = collect_report(input)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_report(&report);
    }
    Ok(())
}

fn collect_report(path: &Path) -> DynResult<IdentifyReport> {
    if path.is_dir() {
        if path.join(".fat.db").is_file() {
            return Ok(fat_project_report(path));
        }
        return match target_detection::detect_path(path) {
            Ok(target) => {
                let path_kind = format!("{:?}", target.kind);
                match target.kind {
                    TargetKind::Rootfs => Ok(rootfs_directory_report(path, path_kind)),
                    TargetKind::SourceTree => Ok(directory_report(
                        path,
                        path_kind,
                        "source-tree",
                        "high",
                        vec!["Directory target detected from source-tree shape.".to_string()],
                    )),
                    TargetKind::CodeQlDatabase => Ok(directory_report(
                        path,
                        path_kind,
                        "codeql-database",
                        "high",
                        vec!["Directory target detected as a CodeQL database.".to_string()],
                    )),
                    _ => Ok(directory_report(
                        path,
                        path_kind,
                        "unknown",
                        "low",
                        vec!["Directory target detected, but the shape is not specific enough for a stronger class.".to_string()],
                    )),
                }
            }
            Err(err) if is_unrecognized_directory_error(&err) => {
                let path_kind = "Directory".to_string();
                Ok(firmware_blob_collection_report(path, path_kind.clone()).unwrap_or_else(
                    || {
                        directory_report(
                            path,
                            path_kind,
                            "unknown",
                            "low",
                            vec!["Directory target detected, but the shape is not specific enough for a stronger class.".to_string()],
                        )
                    },
                ))
            }
            Err(err) => {
                Err(format!("target detection failed for {}: {err}", path.display()).into())
            }
        };
    }

    let target = target_detection::detect_path(path)
        .map_err(|err| format!("target detection failed for {}: {err}", path.display()))?;
    let path_kind = format!("{:?}", target.kind);

    match target.kind {
        TargetKind::RawBlob => collect_raw_blob_report(path, path_kind),
        TargetKind::ElfBinary | TargetKind::MachOBinary => Ok(executable_report(path, path_kind)),
        TargetKind::Rootfs => Ok(rootfs_directory_report(path, path_kind)),
        TargetKind::SourceTree => Ok(directory_report(
            path,
            path_kind,
            "source-tree",
            "high",
            vec!["Directory target detected from source-tree shape.".to_string()],
        )),
        TargetKind::CodeQlDatabase => Ok(directory_report(
            path,
            path_kind,
            "codeql-database",
            "high",
            vec!["Directory target detected as a CodeQL database.".to_string()],
        )),
        _ => Ok(directory_report(
            path,
            path_kind,
            "unknown",
            "low",
            vec!["Directory target detected, but the shape is not specific enough for a stronger class.".to_string()],
        )),
    }
}

fn fat_project_report(path: &Path) -> IdentifyReport {
    let manifest_path = path.join("work/extraction-manifest.json");
    let manifest = fs::read(&manifest_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ExtractionManifest>(&bytes).ok());
    let reusable_rootfs = manifest
        .as_ref()
        .and_then(|manifest| manifest.rootfs_path.as_deref())
        .map(|rootfs| {
            if rootfs.is_absolute() {
                rootfs.to_path_buf()
            } else {
                path.join(rootfs)
            }
        })
        .filter(|rootfs| reusable_project_rootfs(path, rootfs));

    let mut summary = vec!["FAT project workspace detected from .fat.db.".to_string()];
    if let Some(rootfs) = reusable_rootfs {
        summary.push(format!("Reusable extracted rootfs: {}", rootfs.display()));
    } else {
        summary.push("No reusable extracted rootfs is recorded yet.".to_string());
    }
    directory_report(
        path,
        "FatProject".to_string(),
        "fat-project",
        "high",
        summary,
    )
}

fn reusable_project_rootfs(project: &Path, rootfs: &Path) -> bool {
    let Ok(extraction_root) = project.join("work/extractions").canonicalize() else {
        return false;
    };
    let Ok(rootfs) = rootfs.canonicalize() else {
        return false;
    };
    rootfs.starts_with(extraction_root)
        && rootfs.is_dir()
        && !summarize_rootfs_markers(&rootfs).is_empty()
}

fn collect_raw_blob_report(path: &Path, path_kind: String) -> DynResult<IdentifyReport> {
    let bytes = fs::read(path)?;
    let snapshot = analyze_firmware_bytes(&bytes)?;
    let layout = build_layout_report_with_bytes(&snapshot, &bytes)?;
    let structure = summarize_structure(
        &layout,
        &snapshot.container_headers,
        &snapshot.filesystem_headers,
    );
    if snapshot
        .container_headers
        .iter()
        .any(|header| header.magic == "UTPK")
    {
        let likely_class = "vendor-update-package".to_string();
        let summary = synthesize_raw_blob_summary(&bytes, &layout, &snapshot.container_headers);
        return Ok(IdentifyReport {
            schema_version: schema_versions::IDENTIFY_REPORT_V1,
            input_path: render_input_path(path),
            path_kind,
            likely_class,
            confidence: "high".to_string(),
            summary,
            evidence: Vec::new(),
            envelope_label: None,
            envelope: None,
            structure: Some(structure),
            mcu: None,
        });
    }

    let envelope = envelope_cmd::analyze_envelope(&bytes, None);
    let mcu_report = if should_attempt_mcu_inspection(&envelope.classification, &layout) {
        maybe_inspect_mcu(path, &bytes, &layout)
    } else {
        None
    };
    let mcu = mcu_report.as_ref().and_then(summarize_mcu);
    let likely_class = synthesize_likely_class(
        &envelope.classification,
        &layout,
        &snapshot.container_headers,
        mcu.as_ref(),
    );
    let confidence = synthesize_confidence(
        &envelope.classification,
        &layout,
        &snapshot.container_headers,
        mcu.as_ref(),
    );
    let envelope_label = synthesize_identify_envelope_label(&envelope, &layout);
    let mut summary = synthesize_raw_blob_summary(&bytes, &layout, &snapshot.container_headers);
    summary.extend(synthesize_envelope_interpretation(&envelope, &layout));

    Ok(IdentifyReport {
        schema_version: schema_versions::IDENTIFY_REPORT_V1,
        input_path: render_input_path(path),
        path_kind,
        likely_class,
        confidence,
        summary,
        evidence: envelope.evidence.iter().take(4).cloned().collect(),
        envelope_label,
        envelope: Some(envelope),
        structure: Some(structure),
        mcu,
    })
}

fn executable_report(path: &Path, path_kind: String) -> IdentifyReport {
    let summary = match elf_inspect::parse_elf_file(path) {
        Ok(report) => summarize_elf_executable(&report),
        Err(_) => vec!["Executable binary detected from file magic.".to_string()],
    };

    IdentifyReport {
        schema_version: schema_versions::IDENTIFY_REPORT_V1,
        input_path: render_input_path(path),
        path_kind,
        likely_class: "executable-binary".to_string(),
        confidence: "high".to_string(),
        summary,
        evidence: Vec::new(),
        envelope_label: None,
        envelope: None,
        structure: None,
        mcu: None,
    }
}

fn summarize_elf_executable(report: &elf_inspect::ElfInspectReport) -> Vec<String> {
    let mut summary = vec![
        format!(
            "{} {} {}",
            report.header.class, report.header.endianness, report.header.file_type
        ),
        format!("Machine: {}", report.header.machine),
        format!("Entry point: 0x{:016X}", report.header.entry_point),
    ];

    if let Some(dynamic) = &report.dynamic {
        summary.push("Linking: dynamic".to_string());
        if !dynamic.needed.is_empty() {
            summary.push(format!("Needed libraries: {}", dynamic.needed.join(", ")));
        }
    } else {
        summary.push("Linking: static or no dynamic table found".to_string());
    }

    summary.push(format!("Sections: {}", report.sections.len()));
    summary.push(format!(
        "Stripped: {}",
        if report
            .sections
            .iter()
            .any(|section| section.name == ".symtab")
        {
            "no"
        } else {
            "yes"
        }
    ));

    summary
}

fn directory_report(
    path: &Path,
    path_kind: String,
    likely_class: &str,
    confidence: &str,
    summary: Vec<String>,
) -> IdentifyReport {
    IdentifyReport {
        schema_version: schema_versions::IDENTIFY_REPORT_V1,
        input_path: render_input_path(path),
        path_kind,
        likely_class: likely_class.to_string(),
        confidence: confidence.to_string(),
        summary,
        evidence: Vec::new(),
        envelope_label: None,
        envelope: None,
        structure: None,
        mcu: None,
    }
}

fn rootfs_directory_report(path: &Path, path_kind: String) -> IdentifyReport {
    let mut summary = vec!["Directory target detected from filesystem shape.".to_string()];
    let markers = summarize_rootfs_markers(path);
    if !markers.is_empty() {
        summary.push(format!("Rootfs markers: {}", markers.join(", ")));
    }

    directory_report(path, path_kind, "rootfs-directory", "high", summary)
}

struct FirmwareCollectionCandidate {
    path: PathBuf,
    size: u64,
}

fn firmware_blob_collection_report(path: &Path, path_kind: String) -> Option<IdentifyReport> {
    let mut entries = fs::read_dir(path)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().map(|ty| ty.is_file()).unwrap_or(false))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();
    entries.truncate(DIRECTORY_COLLECTION_SCAN_LIMIT);

    let mut candidates = entries
        .iter()
        .filter_map(|entry_path| firmware_blob_collection_candidate(entry_path))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by(|left, right| {
        right
            .size
            .cmp(&left.size)
            .then_with(|| left.path.cmp(&right.path))
    });
    let names = candidates
        .iter()
        .take(3)
        .filter_map(|candidate| {
            candidate
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>()
        .join(", ");

    Some(directory_report(
        path,
        path_kind,
        "firmware-blob-collection",
        "medium",
        vec![
            format!("Candidate firmware blobs: {}", candidates.len()),
            format!("Top candidates: {names}"),
            format!(
                "Shallow directory scan: sampled up to {DIRECTORY_COLLECTION_SCAN_LIMIT} files and {} per file",
                render_byte_size(DIRECTORY_COLLECTION_SAMPLE_LIMIT)
            ),
        ],
    ))
}

fn firmware_blob_collection_candidate(path: &Path) -> Option<FirmwareCollectionCandidate> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }

    let bytes = read_file_prefix(path, DIRECTORY_COLLECTION_SAMPLE_LIMIT).ok()?;
    if looks_like_firmware_blob_sample(&bytes) {
        Some(FirmwareCollectionCandidate {
            path: path.to_path_buf(),
            size: metadata.len(),
        })
    } else {
        None
    }
}

fn read_file_prefix(path: &Path, limit: u64) -> DynResult<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut reader = file.take(limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn looks_like_firmware_blob_sample(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if known_top_level_header(bytes).is_some()
        || bytes.starts_with(&0x2705_1956u32.to_be_bytes())
        || bytes.starts_with(b"HDR0")
        || bytes.starts_with(&[0x1f, 0x8b])
        || bytes.starts_with(b"hsqs")
        || bytes.starts_with(b"sqsh")
    {
        return true;
    }

    analyze_firmware_bytes(bytes)
        .ok()
        .and_then(|snapshot| build_layout_report(&snapshot).ok())
        .map(|layout| !layout.regions.is_empty())
        .unwrap_or(false)
}

fn summarize_rootfs_markers(path: &Path) -> Vec<&'static str> {
    [
        ("bin", "/bin"),
        ("etc", "/etc"),
        ("etc/init.d", "/etc/init.d"),
        ("lib", "/lib"),
        ("sbin", "/sbin"),
        ("usr", "/usr"),
        ("www", "/www"),
    ]
    .into_iter()
    .filter_map(|(relative, label)| path.join(relative).exists().then_some(label))
    .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn render_input_path_preserves_non_utf8_bytes() {
        let path = PathBuf::from(OsStr::from_bytes(b"/tmp/opaque-\xFF.bin"));
        let rendered = render_input_path(&path);

        assert!(
            rendered.starts_with("$'"),
            "non-UTF8 input path should use byte-preserving rendering: {rendered}"
        );
        assert!(
            rendered.contains("\\xFF"),
            "non-UTF8 byte should be preserved: {rendered}"
        );
        assert!(
            !rendered.contains('\u{FFFD}'),
            "non-UTF8 input path should not use lossy replacement: {rendered}"
        );
    }

    #[test]
    fn render_byte_size_uses_iec_units_and_exact_bytes() {
        assert_eq!(render_byte_size(512), "512 bytes");
        assert_eq!(render_byte_size(1_024), "1.00 KiB (1,024 bytes)");
        assert_eq!(render_byte_size(8_128_512), "7.75 MiB (8,128,512 bytes)");
        assert_eq!(
            render_byte_size(16 * 1_024 * 1_024),
            "16.00 MiB (16,777,216 bytes)"
        );
        assert_eq!(
            render_byte_size(3 * 1_024_u64.pow(3)),
            "3.00 GiB (3,221,225,472 bytes)"
        );
    }
}

fn is_unrecognized_directory_error(err: &str) -> bool {
    err.starts_with("could not determine target kind for directory ")
}

fn maybe_inspect_mcu(
    path: &Path,
    bytes: &[u8],
    _layout: &LayoutReport,
) -> Option<McuInspectionReport> {
    detect_cortex_m_ivt(bytes)?;
    inspect_file(&McuInspectRequest {
        file: path.to_path_buf(),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .ok()
}

fn should_attempt_mcu_inspection(envelope_classification: &str, layout: &LayoutReport) -> bool {
    if envelope_classification == "opaque-wrapper-likely" {
        return false;
    }
    if layout.summary.dominant_boot_image_offset.is_some()
        || layout.summary.dominant_rootfs_offset.is_some()
    {
        return false;
    }
    !layout
        .regions
        .iter()
        .any(|region| region.kind.as_str() == "filesystem")
}

fn summarize_mcu(report: &McuInspectionReport) -> Option<McuSummary> {
    let profile = report.fast_profile.as_ref()?;
    let base_hypothesis = report
        .address_hypotheses
        .as_ref()
        .and_then(|hypotheses| hypotheses.iter().find(|hypothesis| hypothesis.is_primary))
        .map(|hypothesis| format!("0x{:08X}", hypothesis.base))
        .or_else(|| Some(format!("0x{:08X}", profile.flash_base)));

    Some(McuSummary {
        architecture: profile.architecture.clone(),
        family: profile.chip_family.clone(),
        family_confidence: profile.chip_family_confidence,
        reset_vector: format!("0x{:08X}", profile.reset_vector),
        base_hypothesis,
    })
}

fn summarize_structure(
    layout: &LayoutReport,
    container_headers: &[ContainerHeader],
    filesystem_headers: &[FilesystemHeader],
) -> StructureSummary {
    let filesystem_hits = summarize_hits(layout, "filesystem");
    let filesystem_objects = enrich_filesystem_hits(filesystem_headers, filesystem_hits);
    let container_hits =
        enrich_container_hits(container_headers, summarize_hits(layout, "container"));
    let regions = enrich_container_hits(
        container_headers,
        enrich_filesystem_hits(filesystem_headers, summarize_all_regions(layout)),
    );
    StructureSummary {
        regions,
        container_headers: container_hits,
        image_headers: summarize_hits(layout, "boot-image"),
        compression_members: summarize_hits(layout, "compression"),
        partitioning: summarize_partitioning(layout, &filesystem_objects),
        inferences: summarize_structure_inferences(layout, &filesystem_objects),
        filesystem_headers: filesystem_objects,
        dominant_boot_image: render_layout_offset(
            layout,
            layout.summary.dominant_boot_image_offset,
        ),
        dominant_rootfs: render_layout_offset(layout, layout.summary.dominant_rootfs_offset),
    }
}

fn enrich_container_hits(
    container_headers: &[ContainerHeader],
    mut hits: Vec<ObjectHit>,
) -> Vec<ObjectHit> {
    for hit in &mut hits {
        if let Some(header) = container_headers
            .iter()
            .find(|header| header.offset == hit.offset && header.format == hit.format)
        {
            hit.name = header.package_name.clone();
            hit.role = Some(
                match header.format.as_str() {
                    "moxa-rom-map" => "vendor partition map",
                    "fit" => "boot image tree",
                    "fdt" => "device tree blob",
                    "trx" => "partitioned firmware container",
                    _ => "vendor update package",
                }
                .to_string(),
            );
        }
    }
    hits
}

fn enrich_filesystem_hits(
    filesystem_headers: &[FilesystemHeader],
    mut hits: Vec<ObjectHit>,
) -> Vec<ObjectHit> {
    for hit in &mut hits {
        if let Some(header) = filesystem_headers
            .iter()
            .find(|header| header.offset == hit.offset && header.format == hit.format)
        {
            hit.endianness = header.endianness.clone();
            hit.inode_count = header.inode_count.map(|count| count as u64);
            hit.block_size = header.block_size.map(|size| size as u64);
            hit.image_size = header.image_size;
        }
    }
    hits
}

fn summarize_hits(layout: &LayoutReport, kind: &str) -> Vec<ObjectHit> {
    layout
        .regions
        .iter()
        .filter(|region| region.kind.as_str() == kind)
        .map(summarize_region)
        .collect()
}

fn summarize_all_regions(layout: &LayoutReport) -> Vec<ObjectHit> {
    layout.regions.iter().map(summarize_region).collect()
}

fn summarize_region(region: &fat_core::layout::LayoutRegion) -> ObjectHit {
    ObjectHit {
        kind: region.kind.as_str().to_string(),
        format: region.format.clone(),
        offset: region.offset,
        size: region.size,
        uncompressed_size: region.uncompressed_size,
        end_offset: region.end_offset,
        span_is_exact: region.span_is_exact,
        fills_to_eof: region.fills_to_eof,
        role: Some(region.role.as_str().to_string()),
        name: region.original_name.clone(),
        original_name: region.original_name.clone(),
        architecture: region.architecture.clone(),
        kernel_format: region.kernel_format.clone(),
        partition: region.partition.as_ref().map(|partition| {
            let (mount_point, mount_confidence) =
                summarize_mount_for_partition(&partition.name, partition.mount_point.as_deref());
            PartitionRoleSummary {
                mtdblock: partition.mtdblock,
                name: partition.name.clone(),
                mount_point,
                mount_confidence,
            }
        }),
        endianness: None,
        inode_count: None,
        block_size: None,
        image_size: None,
        scope: Some(region.scope.as_str().to_string()),
        parent_offset: region.parent_offset,
        depth: region.depth,
    }
}

fn summarize_mount_for_partition(
    partition_name: &str,
    mount_point: Option<&str>,
) -> (Option<String>, String) {
    if let Some(mount_point) = mount_point {
        return (Some(mount_point.to_string()), "confirmed".to_string());
    }

    if is_app_system_partition_name(partition_name) {
        return (Some("/system".to_string()), "inferred".to_string());
    }

    (None, "unknown".to_string())
}

fn summarize_partitioning(
    layout: &LayoutReport,
    filesystems: &[ObjectHit],
) -> Option<PartitioningSummary> {
    let map = layout.partition_map.as_ref()?;
    let flash_size_bytes = map
        .partitions
        .iter()
        .map(|partition| partition.size_bytes)
        .sum();
    let firmware_offset_delta = layout.regions.iter().find_map(|region| {
        region
            .partition
            .as_ref()
            .map(|partition| partition.firmware_offset_delta)
    });
    let root_mtdblock = map.root_device.as_deref().and_then(parse_mtdblock_number);
    let root = root_mtdblock.and_then(|mtdblock| {
        filesystems.iter().find_map(|hit| {
            let partition = hit.partition.as_ref()?;
            (partition.mtdblock == mtdblock).then(|| {
                format!(
                    "mtdblock{}/{}, {}, mounted as /",
                    partition.mtdblock, partition.name, hit.format
                )
            })
        })
    });
    let app_system = filesystems.iter().find_map(|hit| {
        let partition = hit.partition.as_ref()?;
        is_app_system_partition_name(&partition.name).then(|| {
            let mount = partition
                .mount_point
                .as_deref()
                .map(|mount| {
                    if partition.mount_confidence == "confirmed" {
                        format!("mounted as {mount}")
                    } else {
                        format!("likely mounted as {mount}")
                    }
                })
                .unwrap_or_else(|| "mount point unknown".to_string());
            format!(
                "mtdblock{}/{}, {}, {mount}",
                partition.mtdblock, partition.name, hit.format
            )
        })
    });

    Some(PartitioningSummary {
        source: render_partition_source(&map.source),
        device: map.device.clone(),
        partition_count: map.partitions.len(),
        flash_size_bytes,
        root_device: map.root_device.clone(),
        root_fstype: map.root_fstype.clone(),
        firmware_offset_delta,
        root,
        app_system,
        backups: map
            .partitions
            .iter()
            .filter(|partition| is_backup_partition_name(&partition.name))
            .map(|partition| format!("mtdblock{}/{}", partition.index, partition.name))
            .collect(),
        config_data: map
            .partitions
            .iter()
            .filter(|partition| is_config_partition_name(&partition.name))
            .map(|partition| format!("mtdblock{}/{}", partition.index, partition.name))
            .collect(),
    })
}

fn summarize_structure_inferences(
    layout: &LayoutReport,
    filesystems: &[ObjectHit],
) -> Vec<StructureInference> {
    let has_root = filesystems.iter().any(|hit| {
        hit.partition.as_ref().is_some_and(|partition| {
            partition.mount_point.as_deref() == Some("/")
                || partition.name.eq_ignore_ascii_case("rootfs")
        })
    });
    let has_app_system = filesystems.iter().any(|hit| {
        hit.partition
            .as_ref()
            .is_some_and(|partition| is_app_system_partition_name(&partition.name))
    });

    if !has_root || !has_app_system || layout.partition_map.is_none() {
        return Vec::new();
    }

    let evidence = filesystems
        .iter()
        .filter_map(|hit| {
            let partition = hit.partition.as_ref()?;
            Some(format!(
                "{} @ 0x{:08X} maps to mtdblock{}/{}",
                hit.format, hit.offset, partition.mtdblock, partition.name
            ))
        })
        .collect();

    vec![StructureInference {
        id: "layout.split-root".to_string(),
        label: "split-root embedded Linux firmware".to_string(),
        confidence: "high".to_string(),
        evidence,
        confirmation: Some(
            "inspect extracted init scripts for non-root filesystem mount points".to_string(),
        ),
    }]
}

fn render_partition_source(source: &str) -> String {
    if source.starts_with("lzma @") {
        format!("kernel cmdline ({source})")
    } else {
        source.to_string()
    }
}

fn parse_mtdblock_number(value: &str) -> Option<u32> {
    value
        .rsplit_once("mtdblock")
        .and_then(|(_, number)| number.parse::<u32>().ok())
}

fn is_app_system_partition_name(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "app" | "system")
}

fn is_backup_partition_name(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "kback" | "aback")
        || name.to_ascii_lowercase().contains("backup")
}

fn is_config_partition_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cfg" | "config" | "para" | "factory" | "nvram"
    )
}

fn render_layout_offset(layout: &LayoutReport, offset: Option<u64>) -> Option<String> {
    let offset = offset?;
    layout
        .regions
        .iter()
        .find(|region| region.offset == offset)
        .map(|region| format!("{} @ 0x{:08X}", region.format, region.offset))
}

fn render_input_path(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }
    shell_quote_non_utf8_path(path)
}

#[cfg(unix)]
fn shell_quote_non_utf8_path(path: &Path) -> String {
    let mut quoted = String::from("$'");
    for byte in path.as_os_str().as_bytes() {
        quoted.push_str(&format!("\\x{byte:02X}"));
    }
    quoted.push('\'');
    quoted
}

#[cfg(not(unix))]
fn shell_quote_non_utf8_path(_path: &Path) -> String {
    "<non-UTF8 path>".to_string()
}

fn synthesize_likely_class(
    envelope_classification: &str,
    layout: &LayoutReport,
    container_headers: &[ContainerHeader],
    mcu: Option<&McuSummary>,
) -> String {
    if container_headers
        .iter()
        .any(|header| header.magic == "UTPK")
    {
        "vendor-update-package".to_string()
    } else if envelope_classification == "opaque-wrapper-likely" {
        "opaque-wrapper-likely".to_string()
    } else if mcu.is_some()
        && layout.summary.dominant_boot_image_offset.is_none()
        && layout.summary.dominant_rootfs_offset.is_none()
    {
        "mcu-firmware-likely".to_string()
    } else if layout.summary.dominant_boot_image_offset.is_some()
        || layout.summary.dominant_rootfs_offset.is_some()
        || container_headers
            .iter()
            .any(|header| matches!(header.format.as_str(), "fit" | "fdt" | "trx"))
        || layout
            .regions
            .iter()
            .any(|region| region.kind.as_str() == "filesystem")
    {
        "structured-firmware-container".to_string()
    } else if !layout.regions.is_empty() {
        "raw-firmware-blob".to_string()
    } else {
        "unknown".to_string()
    }
}

fn synthesize_raw_blob_summary(
    bytes: &[u8],
    layout: &LayoutReport,
    container_headers: &[ContainerHeader],
) -> Vec<String> {
    let mut summary = vec![format!("{} analyzed", render_byte_size(bytes.len() as u64))];

    if let Some(header) = container_headers
        .iter()
        .find(|header| header.magic == "UTPK")
    {
        summary.push(format!(
            "Known top-level header: {} (Unitree UPK firmware package; parsed)",
            header.magic
        ));
        if let Some(package_name) = header.package_name.as_deref() {
            summary.push(format!("Package name: {package_name}"));
        }
        if let Some(status) = header.integrity_status.as_deref() {
            summary.push(format!("Static integrity: {status}"));
        }
        if let Some(marker) = header.payload_marker.as_deref() {
            summary.push(format!("Payload marker: {marker}"));
        }
    } else if let Some(header) = container_headers
        .iter()
        .find(|header| header.format == "moxa-rom-map")
    {
        summary.push(
            "Known top-level header: Moxa ROM map (kernel slot + CramFS; parsed)".to_string(),
        );
        if let Some(package_name) = header.package_name.as_deref() {
            summary.push(format!("Firmware version: {package_name}"));
        }
        if let Some(marker) = header.payload_marker.as_deref() {
            summary.push(format!("Map: {marker}"));
        }
    } else if let Some(header) = container_headers
        .iter()
        .find(|header| matches!(header.format.as_str(), "fit" | "fdt"))
    {
        summary.push(format!(
            "Validated {} at 0x{:08X}",
            header
                .payload_type
                .as_deref()
                .unwrap_or("flattened device tree"),
            header.offset
        ));
    } else if let Some(header) = container_headers
        .iter()
        .find(|header| header.format == "trx")
    {
        summary.push(format!(
            "Validated TRX partition container at 0x{:08X}",
            header.offset
        ));
        if let Some(marker) = header.payload_marker.as_deref() {
            summary.push(format!("Map: {marker}"));
        }
    } else if has_compression_only_firmware_indicator(layout) {
        let members = layout
            .regions
            .iter()
            .filter(|region| region.kind.as_str() == "compression")
            .take(4)
            .map(|region| format!("{} @ 0x{:08X}", region.format, region.offset))
            .collect::<Vec<_>>()
            .join(", ");
        summary.push(format!(
            "Firmware indicators: embedded compression member(s) ({members}); no dominant boot image or rootfs identified"
        ));

        if let Some(header_summary) = top_level_header_summary(bytes) {
            summary.push(header_summary);
        }
    }

    summary
}

fn synthesize_identify_envelope_label(
    envelope: &envelope_cmd::EnvelopeReport,
    layout: &LayoutReport,
) -> Option<String> {
    if is_high_entropy_structured_blob(envelope, layout) {
        return Some("High-entropy structured blob".to_string());
    }
    None
}

fn synthesize_envelope_interpretation(
    envelope: &envelope_cmd::EnvelopeReport,
    layout: &LayoutReport,
) -> Vec<String> {
    if is_high_entropy_structured_blob(envelope, layout) {
        return vec![
            "Interpretation: compression or encryption is likely; low duplicate-block count does not suggest ECB-like repetition".to_string(),
        ];
    }
    Vec::new()
}

fn is_high_entropy_structured_blob(
    envelope: &envelope_cmd::EnvelopeReport,
    layout: &LayoutReport,
) -> bool {
    envelope.classification == "structured-or-plaintext-like"
        && envelope.entropy >= 7.5
        && envelope.unique_byte_count >= 200
        && has_compression_only_firmware_indicator(layout)
}

struct KnownHeader {
    magic: &'static str,
    label: &'static str,
    support: &'static str,
}

fn known_top_level_header(bytes: &[u8]) -> Option<KnownHeader> {
    match bytes.get(..4)? {
        b"SHRS" => Some(KnownHeader {
            magic: "SHRS",
            label: "SGE/T&W factory firmware envelope",
            support: "detection only",
        }),
        _ => None,
    }
}

fn top_level_header_summary(bytes: &[u8]) -> Option<String> {
    if let Some(header) = known_top_level_header(bytes) {
        return Some(format!(
            "Known top-level header: {} ({}; {})",
            header.magic, header.label, header.support
        ));
    }

    printable_unknown_top_level_header(bytes).map(|header| {
        format!("Unknown top-level header: {header} (no supported container parser matched)")
    })
}

fn has_compression_only_firmware_indicator(layout: &LayoutReport) -> bool {
    layout.summary.dominant_boot_image_offset.is_none()
        && layout.summary.dominant_rootfs_offset.is_none()
        && layout
            .regions
            .iter()
            .any(|region| region.kind.as_str() == "compression")
        && !layout
            .regions
            .iter()
            .any(|region| region.kind.as_str() == "filesystem")
}

fn printable_unknown_top_level_header(bytes: &[u8]) -> Option<String> {
    let header = bytes.get(..4)?;
    if header
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Some(String::from_utf8_lossy(header).into_owned())
    } else {
        None
    }
}

fn synthesize_confidence(
    envelope_classification: &str,
    layout: &LayoutReport,
    container_headers: &[ContainerHeader],
    mcu: Option<&McuSummary>,
) -> String {
    if container_headers
        .iter()
        .any(|header| header.magic == "UTPK")
        || envelope_classification == "opaque-wrapper-likely"
        || (mcu.is_some()
            && layout.summary.dominant_boot_image_offset.is_none()
            && layout.summary.dominant_rootfs_offset.is_none())
        || layout.summary.dominant_boot_image_offset.is_some()
        || layout.summary.dominant_rootfs_offset.is_some()
        || container_headers
            .iter()
            .any(|header| matches!(header.format.as_str(), "fit" | "fdt" | "trx"))
    {
        "high".to_string()
    } else if !layout.regions.is_empty() {
        "medium".to_string()
    } else {
        "low".to_string()
    }
}

/// A confidence word as a fraction for the confidence bar.
fn confidence_fraction(confidence: &str) -> Option<f32> {
    match confidence.to_ascii_lowercase().as_str() {
        "very high" => Some(0.9),
        "high" => Some(0.75),
        "medium" => Some(0.5),
        "low" => Some(0.25),
        "very low" => Some(0.1),
        _ => None,
    }
}

/// The workflow hand-off after an identify run: name the next command that
/// consumes this input, keyed off the likely class.
fn identify_next_hint(report: &IdentifyReport) -> String {
    match report.likely_class.as_str() {
        "rootfs-directory" => "fat new <firmware> — or extract a container image above it".into(),
        "mcu-firmware-likely" => "fat inspect-mcu <path>".into(),
        "executable-binary" => "fat inspect-elf <path>".into(),
        _ => "fat extract <path>".into(),
    }
}

/// Panel-mode identify report: identity block, summary, envelope with an
/// entropy bar, structure entries with dimmed metadata, and the MCU signal.
fn identify_panel_lines(report: &IdentifyReport, p: &crate::style::Palette) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push(p.kv("Input", &report.input_path));
    lines.push(p.kv("Path kind", &report.path_kind));
    lines.push(format!(
        "{} {}",
        p.dot_ok(),
        p.good(format!("likely class: {}", report.likely_class))
    ));
    let confidence_word = match report.confidence.to_ascii_lowercase().as_str() {
        "high" | "very high" => p.good(&report.confidence),
        "medium" => p.warn(&report.confidence),
        "low" | "very low" => p.bad(&report.confidence),
        _ => report.confidence.clone(),
    };
    let confidence_line = match confidence_fraction(&report.confidence) {
        Some(frac) => format!("confidence: {confidence_word}  {}", p.bar(frac, 10)),
        None => format!("confidence: {confidence_word}"),
    };
    lines.push(format!("{} {}", p.dot_ok(), confidence_line));

    if !report.summary.is_empty() {
        lines.push(String::new());
        lines.push(p.heading("Summary"));
        for line in &report.summary {
            lines.push(format!("{} {}", p.dot_muted(), p.muted(line)));
        }
    }

    if let Some(envelope) = report.envelope.as_ref() {
        lines.push(String::new());
        lines.push(p.heading("Envelope"));
        lines.push(format!(
            "{} {}",
            p.dot_ok(),
            report
                .envelope_label
                .as_deref()
                .unwrap_or_else(|| envelope_cmd::render_classification(&envelope.classification))
        ));
        lines.push(format!(
            "  entropy  {}  {ent:.2}/8.0",
            p.bar((envelope.entropy / 8.0) as f32, 10),
            ent = envelope.entropy,
        ));
        for line in envelope.evidence.iter().skip(1).take(2) {
            lines.push(format!("{} {}", p.dot_muted(), p.muted(line)));
        }
    }

    if let Some(structure) = report.structure.as_ref() {
        let visible_hits: Vec<&ObjectHit> = structure
            .regions
            .iter()
            .filter(|hit| {
                if hit.kind != "compression" || hit.scope.as_deref() != Some("nested") {
                    return true;
                }
                let parent_is_filesystem = hit.parent_offset.is_some_and(|parent_offset| {
                    structure
                        .regions
                        .iter()
                        .any(|parent| parent.offset == parent_offset && parent.kind == "filesystem")
                });
                !parent_is_filesystem || hit.role.as_deref() == Some("likely kernel payload")
            })
            .collect();
        if !visible_hits.is_empty() {
            lines.push(String::new());
            lines.push(p.heading("Structure"));
            for hit in visible_hits {
                let (head, metas) = structure_hit_parts(hit);
                let meta = if metas.is_empty() {
                    String::new()
                } else {
                    format!("  {}", p.muted(format!("({})", metas.join("; "))))
                };
                lines.push(format!("{} {head}{meta}", p.dot_ok()));
            }
            if let Some(dominant) = structure.dominant_boot_image.as_deref() {
                lines.push(p.kv("Dominant boot image", dominant));
            }
            if let Some(dominant) = structure.dominant_rootfs.as_deref() {
                lines.push(p.kv("Dominant rootfs", dominant));
            }
        }

        if let Some(partitioning) = structure.partitioning.as_ref() {
            lines.push(String::new());
            lines.push(p.heading("Partitioning"));
            lines.push(p.kv("Source", &partitioning.source));
            lines.push(p.kv("Device", &partitioning.device));
            lines.push(p.kv(
                "Flash map",
                format!(
                    "{} MTD partitions, {} total",
                    partitioning.partition_count,
                    render_byte_size(partitioning.flash_size_bytes)
                ),
            ));
            if let Some(root) = partitioning.root.as_deref() {
                lines.push(p.kv("Root", root));
            }
            if let Some(app_system) = partitioning.app_system.as_deref() {
                lines.push(p.kv("App/system", app_system));
            }
            if !partitioning.backups.is_empty() {
                lines.push(p.kv("Backups", partitioning.backups.join(", ")));
            }
            if !partitioning.config_data.is_empty() {
                lines.push(p.kv("Config/data", partitioning.config_data.join(", ")));
            }
        }

        if !structure.inferences.is_empty() {
            lines.push(String::new());
            lines.push(p.heading("Inferences"));
            for inference in &structure.inferences {
                let label = if inference.id == "layout.split-root" {
                    format!("Layout pattern: {}", inference.label)
                } else {
                    format!("{}: {}", inference.id, inference.label)
                };
                lines.push(format!("{} {}", p.dot_ok(), label));
            }
        }
    }

    lines.push(String::new());
    lines.push(p.heading("MCU signal"));
    if report.likely_class == "mcu-firmware-likely" {
        if let Some(mcu) = report.mcu.as_ref() {
            lines.push(p.kv("Architecture", &mcu.architecture));
            lines.push(p.kv(
                "Family",
                format!(
                    "{} [{}%]  {}",
                    mcu.family,
                    mcu.family_confidence,
                    p.bar(mcu.family_confidence as f32 / 100.0, 10)
                ),
            ));
            lines.push(p.kv("Reset vector", &mcu.reset_vector));
            if let Some(base) = mcu.base_hypothesis.as_deref() {
                lines.push(p.kv("Base hypothesis", base));
            }
        } else {
            lines.push(p.muted("not indicated"));
        }
    } else {
        lines.push(p.muted("not indicated"));
    }
    lines
}

fn render_structure_hit(hit: &ObjectHit) -> String {
    let (head, metas) = structure_hit_parts(hit);
    let mut rendered = head;
    for meta in metas {
        rendered.push_str(&format!(" ({meta})"));
    }
    rendered
}

/// Split one structure hit into its `kind @ offset` head and the parenthesised
/// metadata groups the plain renderer appends. The panel shows the head with a
/// status dot and the metadata dimmed; the plain renderer joins them back into
/// the historical `head (meta)` shape.
fn structure_hit_parts(hit: &ObjectHit) -> (String, Vec<String>) {
    if hit.kind == "padding" {
        let inclusive_end = hit.end_offset.and_then(|end| end.checked_sub(1));
        return match (inclusive_end, hit.size) {
            (Some(end), Some(size)) => (
                format!("pad @ 0x{:08X} .. 0x{end:08X}", hit.offset),
                vec![format!(
                    "{}, {}",
                    render_byte_size(size),
                    if hit.format == "zero-padding" {
                        "zero-filled"
                    } else {
                        "erased-fill"
                    }
                )],
            ),
            _ => (
                format!("pad @ 0x{:08X}", hit.offset),
                vec!["span unknown".to_string()],
            ),
        };
    }
    let mut head = format!("{} @ 0x{:08X}", hit.format, hit.offset);
    if let Some(name) = hit.original_name.as_deref().or(hit.name.as_deref()) {
        head.push_str(&format!(" ({name})"));
    }
    let mut metas: Vec<String> = Vec::new();
    if hit.kind == "compression" {
        if let (Some(compressed), Some(uncompressed)) = (hit.size, hit.uncompressed_size) {
            metas.push(format!(
                "{} -> {}",
                render_byte_size(compressed),
                render_byte_size(uncompressed)
            ));
        }
        if hit.kernel_format.is_some() || hit.architecture.is_some() {
            metas.push(
                [hit.kernel_format.as_deref(), hit.architecture.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    }
    if let Some(partition) = hit.partition.as_ref() {
        head.push_str(&format!(
            " -> mtdblock{}/{}",
            partition.mtdblock, partition.name
        ));
        if let Some(mount_point) = partition.mount_point.as_deref() {
            if partition.mount_confidence == "confirmed" {
                head.push_str(&format!(" -> {mount_point}"));
            } else {
                head.push_str(&format!(" -> likely {mount_point}"));
            }
        }
    }
    if let (Some(endianness), Some(inode_count), Some(image_size)) =
        (&hit.endianness, hit.inode_count, hit.image_size)
    {
        metas.push(format!(
            "{endianness} endian, {inode_count} inodes, {}",
            render_byte_size(image_size)
        ));
    }
    if hit.fills_to_eof {
        metas.push("fills to EOF".to_string());
    }
    (head, metas)
}

fn render_byte_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    let (unit, divisor) = if bytes >= TIB {
        ("TiB", TIB)
    } else if bytes >= GIB {
        ("GiB", GIB)
    } else if bytes >= MIB {
        ("MiB", MIB)
    } else if bytes >= KIB {
        ("KiB", KIB)
    } else {
        return format!("{} bytes", render_grouped_integer(bytes));
    };

    format!(
        "{:.2} {unit} ({} bytes)",
        bytes as f64 / divisor as f64,
        render_grouped_integer(bytes)
    )
}

fn render_grouped_integer(value: u64) -> String {
    let digits = value.to_string();
    let mut rendered = String::with_capacity(digits.len() + digits.len().saturating_sub(1) / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            rendered.push(',');
        }
        rendered.push(digit);
    }
    rendered
}

fn render_report(report: &IdentifyReport) {
    let p = crate::style::Palette::stdout();
    if p.enabled() {
        println!(
            "{}",
            p.panel("fat identify", &identify_panel_lines(report, &p))
        );
        println!("{}", p.next_hint(&identify_next_hint(report)));
        return;
    }
    // Width of the widest key in the identity block so the colons line up.
    const KW: usize = 12;
    let bullet = |line: &str| format!("  {} {line}", p.muted("-"));

    let confidence = match report.confidence.to_ascii_lowercase().as_str() {
        "high" | "very high" => p.good(&report.confidence),
        "medium" => p.warn(&report.confidence),
        "low" | "very low" => p.bad(&report.confidence),
        _ => report.confidence.clone(),
    };

    println!("{}", p.heading("Identification"));
    println!("  {}", p.kv_aligned("Input", KW, &report.input_path));
    println!("  {}", p.kv_aligned("Path kind", KW, &report.path_kind));
    println!(
        "  {}",
        p.kv_aligned("Likely class", KW, &report.likely_class)
    );
    println!("  {}", p.kv_aligned("Confidence", KW, confidence));

    if !report.summary.is_empty() {
        println!();
        println!("{}", p.heading("Summary"));
        for line in &report.summary {
            println!("{}", bullet(line));
        }
    }

    if let Some(envelope) = report.envelope.as_ref() {
        println!();
        println!("{}", p.heading("Envelope"));
        println!(
            "  {}",
            report
                .envelope_label
                .as_deref()
                .unwrap_or_else(|| envelope_cmd::render_classification(&envelope.classification))
        );
        for line in envelope.evidence.iter().take(3) {
            println!("{}", bullet(line));
        }
    }

    if let Some(structure) = report.structure.as_ref() {
        println!();
        println!("{}", p.heading("Structure"));
        for hit in structure.regions.iter().filter(|hit| {
            if hit.kind != "compression" || hit.scope.as_deref() != Some("nested") {
                return true;
            }
            let parent_is_filesystem = hit.parent_offset.is_some_and(|parent_offset| {
                structure
                    .regions
                    .iter()
                    .any(|parent| parent.offset == parent_offset && parent.kind == "filesystem")
            });
            !parent_is_filesystem || hit.role.as_deref() == Some("likely kernel payload")
        }) {
            println!("  {}", render_structure_hit(hit));
        }
        if let Some(dominant) = structure.dominant_boot_image.as_deref() {
            println!("  {}", p.kv("Dominant boot image", dominant));
        }
        if let Some(dominant) = structure.dominant_rootfs.as_deref() {
            println!("  {}", p.kv("Dominant rootfs", dominant));
        }
    }

    if let Some(partitioning) = report
        .structure
        .as_ref()
        .and_then(|structure| structure.partitioning.as_ref())
    {
        println!();
        println!("{}", p.heading("Partitioning"));
        println!("  {}", p.kv("Source", &partitioning.source));
        println!("  {}", p.kv("Device", &partitioning.device));
        println!(
            "  {}",
            p.kv(
                "Flash map",
                format!(
                    "{} MTD partitions, {} total",
                    partitioning.partition_count,
                    render_byte_size(partitioning.flash_size_bytes)
                )
            )
        );
        if let Some(root) = partitioning.root.as_deref() {
            println!("  {}", p.kv("Root", root));
        }
        if let Some(app_system) = partitioning.app_system.as_deref() {
            println!("  {}", p.kv("App/system", app_system));
        }
        if !partitioning.backups.is_empty() {
            println!("  {}", p.kv("Backups", partitioning.backups.join(", ")));
        }
        if !partitioning.config_data.is_empty() {
            println!(
                "  {}",
                p.kv("Config/data", partitioning.config_data.join(", "))
            );
        }
    }

    if let Some(structure) = report.structure.as_ref() {
        if !structure.inferences.is_empty() {
            println!();
            println!("{}", p.heading("Inferences"));
            for inference in &structure.inferences {
                if inference.id == "layout.split-root" {
                    println!("  {}", p.kv("Layout pattern", &inference.label));
                } else {
                    println!("  {}", p.kv(&inference.id, &inference.label));
                }
            }
        }
    }

    println!();
    println!("{}", p.heading("MCU signal"));
    if report.likely_class == "mcu-firmware-likely" {
        if let Some(mcu) = report.mcu.as_ref() {
            println!("  {}", p.kv("Architecture", &mcu.architecture));
            println!(
                "  {}",
                p.kv(
                    "Family",
                    format!("{} [{}%]", mcu.family, mcu.family_confidence)
                )
            );
            println!("  {}", p.kv("Reset vector", &mcu.reset_vector));
            if let Some(base) = mcu.base_hypothesis.as_deref() {
                println!("  {}", p.kv("Base hypothesis", base));
            }
        } else {
            println!("  {}", p.muted("not indicated"));
        }
    } else {
        println!("  {}", p.muted("not indicated"));
    }
}
