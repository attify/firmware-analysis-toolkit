use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto_census_cmd::{self, CryptoCensusSummary};
use crate::crypto_cmd::{self, CryptoReport};
use crate::elf_inspect;
use crate::envelope_cmd;
use crate::schema_versions;
use crate::trust_boundary_cmd::{self, TrustMapJsonReport};
use fat_analyze::bootloader::{analyze_firmware_path, analyze_layout_path, build_layout_report};
use fat_analyze::svd_rank::{rank_svd_corpus, SvdRankReport, SvdRankRequest};
use fat_core::bootloader::{BootImageHeader, BootloaderSnapshot};
use fat_core::inspection::{
    CompressionMember, ContainerHeader, FilesystemHeader, InspectionReport,
};
use fat_core::layout::{LayoutRegion, LayoutReport};
use fat_core::mcu_inspection::{
    CacheEffectKind, ClockEffectKind, CompressorVariant, ExecutionModelKind, FpuStatus,
    InitHandlerKind, InitTableFormat, InitTableReport, InspectionDegradation, InterruptHandlerKind,
    LinkerCapBasis, McuInspectionReport, PeripheralMapReport, PeripheralSurfaceReport,
    SharedStateRiskReport, SramPartitionReport, SystemInitEffectsReport, ThreatModelHint,
};
use fat_taint::recon::trust_boundary::{analyze_rootfs, check_rabin2, TrustBoundaryReport};
use serde::Serialize;
use walkdir::WalkDir;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
pub struct UpdateWorkflowReport {
    pub schema_version: &'static str,
    pub firmware_file: String,
    pub rootfs_path: String,
    pub reference_file: Option<String>,
    pub confidence: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub envelope: envelope_cmd::EnvelopeReport,
    pub trust_path: TrustMapJsonReport,
    pub crypto_census: Option<CryptoCensusSummary>,
    pub governing_binary_crypto: Option<CryptoReport>,
}

#[derive(Debug, Serialize)]
pub struct PeripheralSurfaceCliReport {
    pub schema_version: &'static str,
    pub artifact_path: String,
    pub family: Option<String>,
    pub degradations: Option<Vec<InspectionDegradation>>,
    pub peripheral_map: Option<PeripheralMapReport>,
    pub peripheral_surface: Option<PeripheralSurfaceReport>,
}

#[derive(Debug, Serialize)]
pub struct IsrStateCliReport {
    pub schema_version: &'static str,
    pub artifact_path: String,
    pub family: Option<String>,
    pub degradations: Option<Vec<InspectionDegradation>>,
    pub shared_state_risk: Option<SharedStateRiskReport>,
}

pub fn run_headers(
    project_dir: Option<&Path>,
    firmware_path: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    if let (None, Some(firmware_path)) = (project_dir, firmware_path) {
        if matches!(
            fat_query::target_detection::detect_path(firmware_path)
                .ok()
                .map(|target| target.kind),
            Some(fat_query::target_detection::TargetKind::ElfBinary)
        ) {
            let report = elf_inspect::parse_elf_file(firmware_path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", elf_inspect::render_headers(&report));
            }
            return Ok(());
        }
    }

    let report =
        match (project_dir, firmware_path) {
            (Some(project_dir), None) => load_project_report(project_dir)?,
            (None, Some(firmware_path)) => load_file_report(firmware_path)?,
            _ => return Err(
                "exactly one input source is required: either <project> or --file <firmware.bin>"
                    .into(),
            ),
        };
    if report.image_headers.is_empty()
        && report.container_headers.is_empty()
        && report.compression_members.is_empty()
        && report.filesystem_headers.is_empty()
    {
        return Err("no image headers found for the selected input source".into());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let report = render_report(&report);
        print!(
            "{}",
            crate::style::render_doc(&report, &crate::style::Palette::stdout())
        );
    }
    Ok(())
}

pub fn run_layout(
    project_dir: Option<&Path>,
    firmware_path: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    if let Some(firmware_path) = firmware_path {
        match fat_query::target_detection::detect_path(firmware_path)
            .ok()
            .map(|target| target.kind)
        {
            Some(fat_query::target_detection::TargetKind::MachOBinary) => {
                return Err(
                    "Mach-O executables are not firmware layout inputs. Use `fat identify-launcher`, `fat inspect-handoff`, or `fat r2-triage` instead."
                        .into(),
                );
            }
            Some(fat_query::target_detection::TargetKind::ElfBinary) => {
                let report = elf_inspect::parse_elf_file(firmware_path)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", elf_inspect::render_layout(&report));
                }
                return Ok(());
            }
            _ => {}
        }
    }

    let mut report =
        match (project_dir, firmware_path) {
            (Some(project_dir), None) => load_project_layout(project_dir)?,
            (None, Some(firmware_path)) => load_file_layout(firmware_path)?,
            _ => return Err(
                "exactly one input source is required: either <project> or --file <firmware.bin>"
                    .into(),
            ),
        };

    if report.regions.is_empty() {
        if let Some(firmware_path) = firmware_path {
            let bytes = fs::read(firmware_path)?;
            let envelope = envelope_cmd::analyze_envelope(&bytes, None);
            if envelope.classification == "opaque-wrapper-likely" {
                let mut message =
                    "no recognized plaintext layout regions found; opaque wrapper likely\n"
                        .to_string();
                for line in &envelope.evidence {
                    message.push_str("- ");
                    message.push_str(line);
                    message.push('\n');
                }
                return Err(message.into());
            }
        }
        return Err("no layout regions found for the selected input source".into());
    }

    if let Some(project_dir) = project_dir {
        enrich_runtime_mount_points(&mut report, &normalize_project_dir(project_dir)?);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let palette = crate::style::Palette::stdout();
        print!(
            "{}",
            crate::style::render_doc(&render_layout_report(&report), &palette)
        );
    }
    Ok(())
}

pub fn run_envelope(file: &Path, reference: Option<&Path>, json: bool) -> DynResult<()> {
    envelope_cmd::run(file, reference, json)
}

pub fn run_update(
    file: &Path,
    rootfs: &Path,
    reference: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }

    check_rabin2().map_err(|e| -> Box<dyn Error> { e.into() })?;

    let firmware_bytes = fs::read(file)?;
    let reference_bytes = match reference {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    let envelope = envelope_cmd::analyze_envelope(&firmware_bytes, reference_bytes.as_deref());

    let trust_report = analyze_rootfs(rootfs).map_err(|e| -> Box<dyn Error> { e.into() })?;
    let trust_path = trust_boundary_cmd::build_trust_map_json_report(&trust_report);
    let crypto_census_summary = build_crypto_census_summary(rootfs, &trust_report);

    let governing_binary_crypto = match trust_path
        .governing_update_path
        .as_ref()
        .map(|candidate| &candidate.path)
    {
        Some(governing_path) => {
            let governing_file = rootfs.join(governing_path.trim_start_matches('/'));
            if governing_file.is_file() {
                Some(crypto_cmd::analyze_crypto(&governing_file)?)
            } else {
                None
            }
        }
        None => None,
    };

    let (confidence, reason, evidence) =
        summarize_update_contract(&envelope, &trust_path, crypto_census_summary.as_ref());

    let report = UpdateWorkflowReport {
        schema_version: schema_versions::INSPECT_UPDATE_REPORT_V1,
        firmware_file: file.display().to_string(),
        rootfs_path: rootfs.display().to_string(),
        reference_file: reference.map(|path| path.display().to_string()),
        confidence,
        reason,
        evidence,
        envelope,
        trust_path,
        crypto_census: crypto_census_summary,
        governing_binary_crypto,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_update_report(&report);
    }

    Ok(())
}

fn build_crypto_census_summary(
    rootfs: &Path,
    trust_report: &TrustBoundaryReport,
) -> Option<CryptoCensusSummary> {
    build_crypto_census_summary_with(rootfs, trust_report, |rootfs, trust_report| {
        crypto_census_cmd::build_report_from_trust_report(
            rootfs,
            trust_report,
            Vec::new(),
            "fingerprint",
        )
    })
}

fn build_crypto_census_summary_with<F>(
    rootfs: &Path,
    trust_report: &TrustBoundaryReport,
    builder: F,
) -> Option<CryptoCensusSummary>
where
    F: FnOnce(
        &Path,
        &TrustBoundaryReport,
    ) -> Result<crypto_census_cmd::CryptoCensusReport, Box<dyn Error>>,
{
    builder(rootfs, trust_report)
        .ok()
        .map(|report| crypto_census_cmd::summarize(&report))
}

fn summarize_update_contract(
    envelope: &envelope_cmd::EnvelopeReport,
    trust_path: &TrustMapJsonReport,
    crypto_census: Option<&CryptoCensusSummary>,
) -> (String, String, Vec<String>) {
    let opaque_signal = envelope_has_opaque_signal(envelope);
    let confidence = if trust_path.governing_update_path.is_some() && opaque_signal {
        "high"
    } else if trust_path.governing_update_path.is_some() || opaque_signal {
        "medium"
    } else {
        "low"
    };
    let reason = if trust_path.governing_update_path.is_some() {
        format!("{}; {}", envelope.reason, trust_path.reason)
    } else {
        envelope.reason.clone()
    };
    let mut evidence = envelope
        .evidence
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    evidence.extend(trust_path.evidence.iter().take(2).cloned());
    if let Some(census) = crypto_census {
        evidence.push(census.summary.clone());
    }
    (confidence.into(), reason, evidence)
}

fn envelope_has_opaque_signal(envelope: &envelope_cmd::EnvelopeReport) -> bool {
    envelope.classification == "opaque-wrapper-likely" || envelope.ecb_assessment == "ecb-plausible"
}

pub fn run_mcu(file: &Path, base: Option<&str>, family: Option<&str>, json: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    let user_base = parse_base_address(base)?;
    let mut report =
        fat_analyze::mcu_inspect::inspect_file(&fat_analyze::mcu_inspect::McuInspectRequest {
            file: file.to_path_buf(),
            user_base,
            user_family: family.map(|value| value.to_string()),
            bundle_root: None,
            backend_preference: None,
        })
        .map_err(|err| -> Box<dyn Error> { err.into() })?;
    report.schema_version = schema_versions::MCU_INSPECTION_REPORT_V1.to_string();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_mcu_report(&report);
    }
    Ok(())
}

pub fn run_peripheral_map(
    file: &Path,
    base: Option<&str>,
    family: Option<&str>,
    json: bool,
) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    let user_base = parse_base_address(base)?;
    let report =
        fat_analyze::mcu_inspect::inspect_file(&fat_analyze::mcu_inspect::McuInspectRequest {
            file: file.to_path_buf(),
            user_base,
            user_family: family.map(|value| value.to_string()),
            bundle_root: None,
            backend_preference: None,
        })
        .map_err(|err| -> Box<dyn Error> { err.into() })?;
    let response = PeripheralSurfaceCliReport {
        schema_version: schema_versions::MCU_PERIPHERAL_SURFACE_REPORT_V1,
        artifact_path: report.artifact_path.clone(),
        family: report
            .fast_profile
            .as_ref()
            .map(|profile| profile.chip_family.clone()),
        degradations: report.degradations.clone(),
        peripheral_map: report.peripheral_map.clone(),
        peripheral_surface: report.peripheral_surface.clone(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        render_peripheral_surface_report(&response);
    }
    Ok(())
}

pub fn run_isr_state(
    file: &Path,
    base: Option<&str>,
    family: Option<&str>,
    json: bool,
) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    let user_base = parse_base_address(base)?;
    let report =
        fat_analyze::mcu_inspect::inspect_file(&fat_analyze::mcu_inspect::McuInspectRequest {
            file: file.to_path_buf(),
            user_base,
            user_family: family.map(|value| value.to_string()),
            bundle_root: None,
            backend_preference: None,
        })
        .map_err(|err| -> Box<dyn Error> { err.into() })?;
    let response = IsrStateCliReport {
        schema_version: schema_versions::MCU_ISR_STATE_REPORT_V1,
        artifact_path: report.artifact_path.clone(),
        family: report
            .fast_profile
            .as_ref()
            .map(|profile| profile.chip_family.clone()),
        degradations: report.degradations.clone(),
        shared_state_risk: report.shared_state_risk.clone(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        render_isr_state_report(&response);
    }
    Ok(())
}

pub fn run_svd_rank(
    file: &Path,
    svd_corpus: &Path,
    max_results: usize,
    json: bool,
) -> DynResult<()> {
    let report = rank_svd_corpus(&SvdRankRequest {
        firmware: file.to_path_buf(),
        svd_corpus: svd_corpus.to_path_buf(),
        max_results,
    })
    .map_err(|err| -> Box<dyn Error> { err.into() })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_svd_rank_report(&report);
    }
    Ok(())
}

fn render_update_report(report: &UpdateWorkflowReport) {
    println!("Update workflow: {}\n", report.firmware_file);

    println!("Envelope");
    println!(
        "  classification: {}",
        envelope_cmd::render_classification(&report.envelope.classification)
    );
    println!("  confidence: {:.2}", report.envelope.confidence);
    for line in report.envelope.evidence.iter().take(4) {
        println!("  - {line}");
    }
    println!();

    println!("Trust path");
    if let Some(governing) = &report.trust_path.governing_update_path {
        println!("  Governing updater: {}", governing.path);
        println!("  Candidate role: {}", governing.candidate_role);
        println!("  Score: {:.2}", governing.update_path_score);
        println!("  Path confidence: {}", governing.path_confidence);
        for reason in governing.why.iter().take(3) {
            println!("  - {reason}");
        }
    } else {
        println!("  Governing updater: (none identified)");
    }
    println!();

    println!("Crypto census");
    if let Some(census) = &report.crypto_census {
        println!("  cluster count: {}", census.cluster_count);
        if census.governing_path_hit_clusters.is_empty() {
            println!("  governing-path hit clusters: none");
        } else {
            println!(
                "  governing-path hit clusters: {}",
                census.governing_path_hit_clusters.join(", ")
            );
        }
        if census.candidate_classifications.is_empty() {
            println!("  candidate classifications: none");
        } else {
            println!(
                "  candidate classifications: {}",
                census.candidate_classifications.join(", ")
            );
        }
        println!("  {}", census.summary);
    } else {
        println!("  no census summary available");
    }
    println!();

    println!("Governing binary crypto");
    if let Some(crypto) = &report.governing_binary_crypto {
        if let Some(context) = &crypto.trust_context {
            println!("  Binary: {}", context.binary_path);
        } else {
            println!("  Binary: {}", crypto.binary);
        }
        println!("  Classification: {}", crypto.classification.role);
        println!("  Weaknesses: {}", crypto.weaknesses.len());
        println!("  Embedded key material: {}", crypto.embedded_keys.len());
        if let Some(context) = &crypto.trust_context {
            println!("  Relevance: {}", context.trust_path_relevance);
        }
    } else {
        println!("  No governing binary was available for crypto profiling.");
    }
}

fn load_project_report(project_dir: &Path) -> DynResult<InspectionReport> {
    let project_dir = normalize_project_dir(project_dir)?;
    let bootloader_path = project_dir.join("analysis").join("bootloader.json");
    if bootloader_path.is_file() {
        let snapshot: BootloaderSnapshot = serde_json::from_slice(&fs::read(&bootloader_path)?)?;
        return Ok(InspectionReport {
            container_headers: snapshot.container_headers,
            image_headers: snapshot.image_headers,
            compression_members: snapshot.compression_members,
            filesystem_headers: snapshot.filesystem_headers,
        });
    }

    let headers_path = project_dir.join("analysis").join("image-headers.json");
    let image_headers: Vec<BootImageHeader> = serde_json::from_slice(&fs::read(&headers_path)?)?;
    Ok(InspectionReport {
        container_headers: Vec::new(),
        image_headers,
        compression_members: Vec::new(),
        filesystem_headers: Vec::new(),
    })
}

fn load_file_report(firmware_path: &Path) -> DynResult<InspectionReport> {
    if !firmware_path.is_file() {
        return Err(format!(
            "firmware path does not exist or is not a file: {}",
            firmware_path.display()
        )
        .into());
    }
    let snapshot = analyze_firmware_path(firmware_path)?;
    Ok(InspectionReport {
        container_headers: snapshot.container_headers,
        image_headers: snapshot.image_headers,
        compression_members: snapshot.compression_members,
        filesystem_headers: snapshot.filesystem_headers,
    })
}

fn load_project_layout(project_dir: &Path) -> DynResult<LayoutReport> {
    let snapshot = load_project_snapshot(project_dir)?;
    Ok(build_layout_report(&snapshot)?)
}

fn load_file_layout(firmware_path: &Path) -> DynResult<LayoutReport> {
    if !firmware_path.is_file() {
        return Err(format!(
            "firmware path does not exist or is not a file: {}",
            firmware_path.display()
        )
        .into());
    }
    Ok(analyze_layout_path(firmware_path)?)
}

fn enrich_runtime_mount_points(report: &mut LayoutReport, project: &Path) {
    let mounts = discover_runtime_mount_points(project);
    if mounts.is_empty() {
        return;
    }

    for region in &mut report.regions {
        let Some(partition) = region.partition.as_mut() else {
            continue;
        };
        if partition.mount_point.as_deref() == Some("/") {
            continue;
        }
        if let Some(mount_point) = mounts.get(&partition.mtdblock) {
            partition.mount_point = Some(mount_point.clone());
        }
    }
}

fn discover_runtime_mount_points(project: &Path) -> BTreeMap<u32, String> {
    let mut mounts = BTreeMap::new();
    for root in candidate_mount_scan_roots(project) {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
        {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.len() > 1024 * 1024 {
                continue;
            }
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines() {
                if let Some((mtdblock, mount_point)) = parse_mount_line(line) {
                    mounts.entry(mtdblock).or_insert(mount_point);
                }
            }
        }
    }
    mounts
}

fn candidate_mount_scan_roots(project: &Path) -> Vec<PathBuf> {
    vec![
        project.join("extracted"),
        project.join("rootfs"),
        project.join("work").join("extractions"),
    ]
}

fn parse_mount_line(line: &str) -> Option<(u32, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || !line.contains("/dev/mtdblock") {
        return None;
    }
    let tokens: Vec<_> = line
        .split_whitespace()
        .map(|token| token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ';')))
        .collect();
    for (index, token) in tokens.iter().enumerate() {
        let Some(mtdblock) = parse_mtdblock_token(token) else {
            continue;
        };
        let mount_point = tokens
            .iter()
            .skip(index + 1)
            .find(|candidate| candidate.starts_with('/') && !candidate.starts_with("/dev/"))?;
        return Some((mtdblock, (*mount_point).to_string()));
    }
    None
}

fn parse_mtdblock_token(token: &str) -> Option<u32> {
    let (_, number) = token.rsplit_once("mtdblock")?;
    let digits: String = number
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse::<u32>().ok()
}

fn load_project_snapshot(project_dir: &Path) -> DynResult<BootloaderSnapshot> {
    let project_dir = normalize_project_dir(project_dir)?;
    let bootloader_path = project_dir.join("analysis").join("bootloader.json");
    if bootloader_path.is_file() {
        return Ok(serde_json::from_slice(&fs::read(&bootloader_path)?)?);
    }

    let headers_path = project_dir.join("analysis").join("image-headers.json");
    let image_headers: Vec<BootImageHeader> = serde_json::from_slice(&fs::read(&headers_path)?)?;
    Ok(BootloaderSnapshot {
        image_headers,
        ..BootloaderSnapshot::default()
    })
}

fn render_report(report: &InspectionReport) -> String {
    let mut output = String::new();
    if !report.container_headers.is_empty() {
        output.push_str(&render_container_headers(&report.container_headers));
    }
    if !report.image_headers.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&render_headers(&report.image_headers));
    }
    if !report.compression_members.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&render_compression_members(&report.compression_members));
    }
    if !report.filesystem_headers.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&render_filesystem_headers(&report.filesystem_headers));
    }
    output
}

fn render_layout_report(report: &LayoutReport) -> String {
    let mut output = String::new();
    output.push_str("Firmware layout summary\n");
    output.push_str(&format!(
        "- Top-level regions: {}\n",
        report.summary.top_level_region_count
    ));
    output.push_str(&format!(
        "- Nested regions: {}\n",
        report.summary.nested_region_count
    ));
    output.push_str(&format!(
        "- Dominant boot image: {}\n",
        render_summary_region(&report.regions, report.summary.dominant_boot_image_offset)
    ));
    output.push_str(&format!(
        "- Dominant rootfs: {}\n\n",
        render_summary_region(&report.regions, report.summary.dominant_rootfs_offset)
    ));
    output.push_str(&render_partition_map(report));
    output.push_str(&render_partial_overlaps(report));
    output.push_str(&render_resolved_filesystems(report));
    output.push_str("Firmware layout\n");
    output.push_str(
        "| Offset | Kind | Format | Size/Span | Role | Scope | Parent | Notes | Name | Architecture | Exact span |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for region in &report.regions {
        output.push_str(&render_layout_region(region));
    }
    output
}

fn render_partial_overlaps(report: &LayoutReport) -> String {
    if report.overlaps.is_empty() {
        return String::new();
    }

    let mut output = String::from("Partial overlaps\n");
    for overlap in &report.overlaps {
        output.push_str(&format!(
            "- Regions at 0x{:08X} and 0x{:08X} overlap from 0x{:08X} to 0x{:08X}; neither contains the other.\n",
            overlap.left_offset,
            overlap.right_offset,
            overlap.start_offset,
            overlap.end_offset.saturating_sub(1)
        ));
    }
    output.push('\n');
    output
}

fn render_partition_map(report: &LayoutReport) -> String {
    let Some(map) = report.partition_map.as_ref() else {
        return String::new();
    };

    let mut output = String::new();
    output.push_str("Partition map\n");
    output.push_str(&format!("- Source: kernel cmdline ({})\n", map.source));
    output.push_str(&format!("- Device: {}\n", map.device));
    if let Some(root) = map.root_device.as_deref() {
        match map.root_fstype.as_deref() {
            Some(root_fstype) => {
                output.push_str(&format!("- Root: {root} ({root_fstype})\n"));
            }
            None => output.push_str(&format!("- Root: {root}\n")),
        }
    }
    output.push_str("| MTD block | Name | Size | Flash offset |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for partition in &map.partitions {
        output.push_str(&format!(
            "| mtdblock{} | {} | {} | 0x{:08X} |\n",
            partition.index,
            partition.name,
            render_partition_size(partition.size_bytes),
            partition.flash_offset
        ));
    }
    output.push('\n');
    output
}

fn render_resolved_filesystems(report: &LayoutReport) -> String {
    let resolved: Vec<_> = report
        .regions
        .iter()
        .filter(|region| region.kind.as_str() == "filesystem")
        .filter_map(|region| {
            region
                .partition
                .as_ref()
                .map(|partition| (region, partition))
        })
        .collect();
    if resolved.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    output.push_str("Resolved filesystems\n");
    for (region, partition) in resolved {
        output.push_str(&format!(
            "- {} @ 0x{:08X} -> mtdblock{}/{}",
            region.format, region.offset, partition.mtdblock, partition.name
        ));
        if let Some(mount_point) = partition.mount_point.as_deref() {
            output.push_str(&format!(" -> {mount_point}"));
        }
        output.push('\n');
    }
    output.push('\n');
    output
}

fn render_partition_size(size: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    if size.is_multiple_of(MIB) {
        format!("{}M", size / MIB)
    } else if size.is_multiple_of(KIB) {
        format!("{}K", size / KIB)
    } else {
        format!("{size} bytes")
    }
}

pub fn render_headers(headers: &[BootImageHeader]) -> String {
    let mut output = String::new();

    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&format!(
            "Header {}: {} @ 0x{:08X}\n",
            index + 1,
            header.format,
            header.offset
        ));
        output.push_str("| Offset | Size | Value | Field |\n");
        output.push_str("| --- | --- | --- | --- |\n");
        push_row(
            &mut output,
            "0x00",
            "4",
            &header.magic_hex,
            "uImage magic number",
        );
        push_row(
            &mut output,
            "0x04",
            "4",
            &header.header_crc32_hex,
            "Header CRC-32",
        );
        push_row(
            &mut output,
            "0x08",
            "4",
            &format!("0x{:08X}", header.timestamp_unix),
            "Timestamp (Unix)",
        );
        push_row(
            &mut output,
            "0x0C",
            "4",
            &format!("0x{:08X}", header.data_size),
            &format!("Data size ({} bytes)", header.data_size),
        );
        push_row(
            &mut output,
            "0x10",
            "4",
            &header.load_address_hex,
            "Load address",
        );
        push_row(
            &mut output,
            "0x14",
            "4",
            &header.entry_point_hex,
            "Entry point",
        );
        push_row(
            &mut output,
            "0x18",
            "4",
            &header.data_crc32_hex,
            "Data CRC-32",
        );
        push_row(
            &mut output,
            "0x1C",
            "1",
            header.os_code_hex.as_deref().unwrap_or("unknown"),
            &format!(
                "OS type ({})",
                header.operating_system.as_deref().unwrap_or("unknown")
            ),
        );
        push_row(
            &mut output,
            "0x1D",
            "1",
            header.architecture_code_hex.as_deref().unwrap_or("unknown"),
            &format!(
                "Architecture ({})",
                header.architecture.as_deref().unwrap_or("unknown")
            ),
        );
        push_row(
            &mut output,
            "0x1E",
            "1",
            header.image_type_code_hex.as_deref().unwrap_or("unknown"),
            &format!(
                "Image type ({})",
                header.image_type.as_deref().unwrap_or("unknown")
            ),
        );
        push_row(
            &mut output,
            "0x1F",
            "1",
            header.compression_code_hex.as_deref().unwrap_or("unknown"),
            &format!(
                "Compression ({})",
                header.compression.as_deref().unwrap_or("unknown")
            ),
        );
        push_row(
            &mut output,
            "0x20",
            "32",
            &format!("\"{}\"", header.name.as_deref().unwrap_or("")),
            "Image name",
        );
    }

    output
}

fn render_container_headers(headers: &[ContainerHeader]) -> String {
    let mut output = String::new();

    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&format!(
            "Header {}: {} @ 0x{:08X}\n",
            index + 1,
            header.format,
            header.offset
        ));
        output.push_str("| Offset | Size | Value | Field |\n");
        output.push_str("| --- | --- | --- | --- |\n");
        push_row(&mut output, "0x00", "4", &header.magic, "Container magic");
        if let Some(timestamp) = header.timestamp_unix {
            push_row(
                &mut output,
                "0x08",
                "8",
                &timestamp.to_string(),
                "Timestamp (Unix)",
            );
        }
        if let Some(size) = header.declared_payload_size {
            push_row(
                &mut output,
                "0x10",
                "8",
                &size.to_string(),
                "Declared payload size",
            );
        }
        if let Some(payload_type) = header.payload_type.as_deref() {
            push_row(&mut output, "0x18", "1", payload_type, "Payload type");
        }
        if let Some(seed) = header.seed_hex.as_deref() {
            push_row(&mut output, "0x1C", "4", seed, "Seed");
        }
        if let Some(digest) = header.stored_digest_hex.as_deref() {
            push_row(
                &mut output,
                "0x20",
                "16",
                digest,
                header.integrity_algorithm.as_deref().unwrap_or("Digest"),
            );
        }
        push_row(
            &mut output,
            "0x30",
            "64",
            &format!("\"{}\"", header.package_name.as_deref().unwrap_or("")),
            "Package name",
        );
        if let Some(marker) = header.payload_marker.as_deref() {
            push_row(&mut output, "0x70", "4", marker, "Payload marker");
        }
        if let Some(status) = header.integrity_status.as_deref() {
            push_row(&mut output, "-", "-", status, "Static integrity status");
        }
    }

    output
}

fn render_compression_members(members: &[CompressionMember]) -> String {
    let mut output = String::new();
    output.push_str("Compressed and embedded objects\n");
    output.push_str("| Offset | Format | Field 1 | Field 2 | Field 3 |\n");
    output.push_str("| --- | --- | --- | --- | --- |\n");
    for member in members {
        let (field_1, field_2, field_3) = match member.format.as_str() {
            "lzma" => (
                member
                    .properties_hex
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string(),
                member
                    .dictionary_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                member
                    .uncompressed_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            "gzip" => (
                member
                    .operating_system
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string(),
                member
                    .timestamp_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                member
                    .uncompressed_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            _ => (
                member
                    .properties_hex
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string(),
                member
                    .dictionary_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                member
                    .uncompressed_size
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
        };
        output.push_str(&format!(
            "| 0x{:08X} | {} | {} | {} | {} |\n",
            member.offset, member.format, field_1, field_2, field_3
        ));
    }
    output
}

fn render_filesystem_headers(headers: &[FilesystemHeader]) -> String {
    let mut output = String::new();
    output.push_str("Filesystem objects\n");
    output.push_str("| Offset | Format | Endianness | Version | Compression | Inodes | Block Size | Image Size |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for header in headers {
        output.push_str(&format!(
            "| 0x{:08X} | {} | {} | {} | {} | {} | {} | {} |\n",
            header.offset,
            header.format,
            header.endianness.as_deref().unwrap_or("unknown"),
            header.version.as_deref().unwrap_or("unknown"),
            header.compression.as_deref().unwrap_or("unknown"),
            header
                .inode_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            header
                .block_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            header
                .image_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }
    output
}

fn render_layout_region(region: &LayoutRegion) -> String {
    format!(
        "| 0x{:08X} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        region.offset,
        region.kind.as_str(),
        region.format,
        region
            .size
            .map(|value| format!("{value} bytes"))
            .unwrap_or_else(|| "span unknown".to_string()),
        region.role.as_str(),
        region.scope.as_str(),
        region
            .parent_offset
            .map(|offset| format!("0x{offset:08X}"))
            .unwrap_or_else(|| "-".to_string()),
        if region.notes.is_empty() {
            "none".to_string()
        } else {
            region.notes.join(", ")
        },
        region.original_name.as_deref().unwrap_or("-"),
        region.architecture.as_deref().unwrap_or("-"),
        if region.span_is_exact {
            region
                .end_offset
                .map(|end| {
                    format!(
                        "ends 0x{end:08X} (exclusive{})",
                        if region.fills_to_eof {
                            ", fills to EOF"
                        } else {
                            ""
                        }
                    )
                })
                .unwrap_or_else(|| "invalid exact span".to_string())
        } else {
            "unknown".to_string()
        },
    )
}

fn render_summary_region(regions: &[LayoutRegion], offset: Option<u64>) -> String {
    let Some(offset) = offset else {
        return "none".to_string();
    };

    regions
        .iter()
        .find(|region| region.offset == offset)
        .map(|region| format!("{} @ 0x{:08X}", region.format, region.offset))
        .unwrap_or_else(|| format!("unknown @ 0x{offset:08X}"))
}

fn push_row(output: &mut String, offset: &str, size: &str, value: &str, field: &str) {
    output.push_str(&format!("| {offset} | {size} | {value} | {field} |\n"));
}

fn normalize_project_dir(project_dir: &Path) -> DynResult<std::path::PathBuf> {
    if project_dir.is_dir() {
        Ok(project_dir.to_path_buf())
    } else {
        Err(format!("project path does not exist: {}", project_dir.display()).into())
    }
}

// ------------------------------------------------------------------
// MCU / bare-metal firmware inspection
// ------------------------------------------------------------------

fn init_table_format_label(format: InitTableFormat) -> &'static str {
    match format {
        InitTableFormat::CmsisCopyTable => "cmsis-copy-table",
        InitTableFormat::CmsisZeroTable => "cmsis-zero-table",
        InitTableFormat::ScatterLoad => "scatter-load",
        InitTableFormat::Unknown => "unknown",
    }
}

fn init_handler_kind_label(kind: InitHandlerKind) -> &'static str {
    match kind {
        InitHandlerKind::WordCopy => "word-copy",
        InitHandlerKind::ZeroInit => "zero-init",
        InitHandlerKind::Decompress => "decompress",
        InitHandlerKind::Custom => "custom",
        InitHandlerKind::Unknown => "unknown",
    }
}

fn compressor_variant_label(variant: CompressorVariant) -> String {
    match variant {
        CompressorVariant::Lzss {
            literal_bits,
            match_bits,
        } => format!("lzss (control byte split {literal_bits}/{match_bits})"),
        CompressorVariant::UnclassifiedLz => "lz (control byte split unrecovered)".to_string(),
    }
}

fn render_init_handlers(table: &InitTableReport) {
    let classified: Vec<_> = table
        .records
        .iter()
        .filter_map(|record| {
            let classification = record.handler_classification.as_ref()?;
            let handler = record.handler?;
            Some((record.index, handler, classification))
        })
        .collect();
    if classified.is_empty() {
        return;
    }

    println!();
    println!("Runtime init handlers");
    for (index, handler, classification) in classified {
        let variant = classification
            .compressor
            .map(|variant| format!(", variant: {}", compressor_variant_label(variant)))
            .unwrap_or_default();
        println!(
            "  Record {index} handler @ 0x{handler:08X}: {}{variant} (conf {:.2})",
            init_handler_kind_label(classification.kind),
            classification.confidence
        );
        for evidence in &classification.evidence {
            println!(
                "    - {} @ 0x{:08X}",
                evidence.description, evidence.instruction_addr
            );
        }
    }

    let Some(fingerprint) = table.toolchain_fingerprint.as_ref() else {
        return;
    };
    println!();
    println!("Toolchain fingerprint");
    match fingerprint.data_compression {
        Some(variant) => println!(
            "  .data compression:  {} (conf {:.2})",
            compressor_variant_label(variant),
            fingerprint.confidence
        ),
        None => println!("  .data compression:  none"),
    }
    if fingerprint.consistent_with.is_empty() {
        println!("  consistent with:    no known packed-copy runtime");
    } else {
        println!(
            "  consistent with:    {}",
            fingerprint.consistent_with.join(", ")
        );
    }
    for note in &fingerprint.notes {
        println!("    note: {note}");
    }
}

fn linker_cap_basis_label(basis: LinkerCapBasis) -> &'static str {
    match basis {
        LinkerCapBasis::InitTableAndStackPointer => {
            ".data + .bss + stack reserve, anchored at initial SP"
        }
        LinkerCapBasis::InitTable => ".data + .bss from the init descriptor table",
        LinkerCapBasis::StackPointer => "stack reserve below the initial SP",
        LinkerCapBasis::NoEvidence => "nothing static claims this region",
    }
}

fn render_sram_partitions(report: &SramPartitionReport) {
    for partition in &report.sram_regions {
        let label = partition.region.label.as_deref().unwrap_or("sram");
        let end = partition.region.end.unwrap_or(partition.region.start);
        let total = end.saturating_sub(partition.region.start);
        let header = format!(
            "  {label} (0x{:08X} - 0x{:08X}, {})",
            partition.region.start,
            end,
            render_partition_size(total)
        );

        // A region nothing static claims and nothing points into is one line;
        // spelling out a 100%-runtime split for each of them buries the
        // region that actually carries the program.
        if partition.linker_cap_basis == LinkerCapBasis::NoEvidence
            && partition.runtime_literal_references.is_empty()
        {
            println!("{header}  entirely runtime-managed, no static references");
            continue;
        }

        println!("{header}");
        let percent = |bytes: u64| -> f64 {
            if total == 0 {
                0.0
            } else {
                (bytes as f64) * 100.0 / (total as f64)
            }
        };
        println!(
            "    Linker-managed   0x{:08X} - 0x{:08X}  ({} B / {:.2}%)",
            partition.linker_managed.start,
            partition.linker_managed.end,
            partition.linker_bytes,
            percent(partition.linker_bytes)
        );
        println!(
            "      from {}",
            linker_cap_basis_label(partition.linker_cap_basis)
        );
        println!(
            "    Runtime-managed  0x{:08X} - 0x{:08X}  ({} B / {:.2}%)",
            partition.runtime_managed.start,
            partition.runtime_managed.end,
            partition.runtime_bytes,
            percent(partition.runtime_bytes)
        );
        if !partition.runtime_literal_references.is_empty() {
            println!(
                "    Static pointer literals into runtime-managed region: {}",
                partition.runtime_literal_total
            );
            for reference in &partition.runtime_literal_references {
                let sites = reference
                    .referenced_from
                    .iter()
                    .map(|site| format!("0x{site:08X}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "      0x{:08X}  {}-byte aligned, referenced from {} site{} [{sites}]",
                    reference.target,
                    reference.alignment,
                    reference.referenced_from.len(),
                    if reference.referenced_from.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
            println!("      -> candidate DMA descriptor / pool base addresses");
        }
        match partition.threat_model_hint.as_ref() {
            Some(ThreatModelHint::DmaReachable { masters }) if !masters.is_empty() => println!(
                "    Threat-model note: DMA-capable masters detected ({}); untrusted payloads may land here",
                masters.join(", ")
            ),
            Some(ThreatModelHint::CpuOnly) => {
                println!("    Threat-model note: no DMA-capable master detected (CPU-only)")
            }
            _ => println!("    Threat-model note: DMA reachability unknown"),
        }
    }
}

fn clock_effect_label(kind: ClockEffectKind) -> &'static str {
    match kind {
        ClockEffectKind::HsiEnable => "HSI enable",
        ClockEffectKind::HsiDisable => "HSI disable",
        ClockEffectKind::HseEnable => "HSE enable",
        ClockEffectKind::HseBypassClear => "HSE bypass clear",
        ClockEffectKind::PllConfigure => "PLL configure",
        ClockEffectKind::PllEnable => "PLL enable",
        ClockEffectKind::SysclkSwitch => "sysclk switch",
        ClockEffectKind::Other => "unclassified clock write",
    }
}

fn cache_effect_label(kind: CacheEffectKind) -> &'static str {
    match kind {
        CacheEffectKind::ICacheEnable => "I-cache enable",
        CacheEffectKind::DCacheEnable => "D-cache enable",
        CacheEffectKind::CacheMaintenance => "cache maintenance",
        CacheEffectKind::Other => "unclassified cache write",
    }
}

fn render_system_init_effects(report: &SystemInitEffectsReport) {
    println!(
        "  SystemInit @ 0x{:08X} ({} bytes decoded, conf {:.2})",
        report.function_address, report.function_size, report.confidence
    );
    println!(
        "    FPU:            {}",
        match report.fpu {
            FpuStatus::Enabled => "enabled (CPACR.CP10/CP11 full access)",
            FpuStatus::Disabled => "disabled (CPACR.CP10/CP11 cleared)",
            FpuStatus::Unknown => "unknown",
        }
    );
    match report.flash_latency {
        Some(latency) => println!(
            "    Flash latency:  {latency} wait state{}",
            if latency == 1 { "" } else { "s" }
        ),
        None => println!("    Flash latency:  unknown"),
    }
    if report.clock_effects.is_empty() {
        println!("    Clock tree:     no classified write");
    } else {
        let effects = report
            .clock_effects
            .iter()
            .map(|effect| clock_effect_label(effect.kind))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    Clock tree:     {effects}");
    }
    if !report.cache_effects.is_empty() {
        let effects = report
            .cache_effects
            .iter()
            .map(|effect| cache_effect_label(effect.kind))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    Cache:          {effects}");
    }
    if report.mpu_configured {
        println!("    MPU:            configured");
    }
    if let Some(enabled) = report.art_accel {
        println!(
            "    ART accel:      {}",
            if enabled { "enabled" } else { "written" }
        );
    }
    if let Some(check) = report.vtor_relocation_check.as_ref() {
        println!(
            "    VTOR check:     present (compare against 0x{:08X} at 0x{:08X})",
            check.sentinel_value, check.instruction_addr
        );
    }
    if let Some(write) = report.vtor_write.as_ref() {
        match write.value {
            Some(value) => println!("    VTOR write:     0x{value:08X}"),
            None => println!("    VTOR write:     value unresolved"),
        }
    }
    if !report.unclassified_writes.is_empty() {
        println!("    Unclassified peripheral writes:");
        for write in &report.unclassified_writes {
            match write.value {
                Some(value) => println!(
                    "      0x{:08X} <- 0x{value:08X}  (at 0x{:08X})",
                    write.target, write.at
                ),
                None => println!(
                    "      0x{:08X} <- unresolved   (at 0x{:08X})",
                    write.target, write.at
                ),
            }
        }
    }
    if !report.evidence.is_empty() {
        println!("    Evidence:");
        for item in &report.evidence {
            println!(
                "      {} @ 0x{:08X}: {}",
                item.label, item.instruction_addr, item.detail
            );
        }
    }
    if !report.not_observed.is_empty() {
        println!("    Not observed:   {}", report.not_observed.join(", "));
    }
}

fn render_mcu_report(report: &McuInspectionReport) {
    println!("MCU inspection");
    if let Some(profile) = report.fast_profile.as_ref() {
        println!("  Architecture:       {}", profile.architecture);
        println!(
            "  Family:             {} [{}%]",
            profile.chip_family, profile.chip_family_confidence
        );
        println!("  Initial SP:         0x{:08X}", profile.initial_sp);
        println!("  Reset vector:       0x{:08X}", profile.reset_vector);
    } else {
        println!("  Architecture:       unknown");
        println!("  Family:             unknown");
    }

    println!();
    println!("Address hypotheses");
    if let Some(hypotheses) = report.address_hypotheses.as_ref() {
        for hypothesis in hypotheses.iter().take(3) {
            let marker = if hypothesis.is_primary { "*" } else { "-" };
            println!(
                "  {marker} 0x{:08X} [confidence: {:.2}]",
                hypothesis.base, hypothesis.confidence
            );
        }
    } else {
        println!("  none recovered");
    }

    println!();
    println!("Vector table");
    if let Some(vector_table) = report.vector_table.as_ref() {
        if vector_table.scan_boundary.is_empty() {
            println!("  Entries scanned:     {}", vector_table.entry_count);
        } else {
            println!(
                "  Entries scanned:     {} ({})",
                vector_table.entry_count, vector_table.scan_boundary
            );
        }

        let interrupt_count = vector_table
            .entries
            .iter()
            .filter(|entry| entry.handler_kind == InterruptHandlerKind::Interrupt)
            .count();
        let active_core_exceptions = vector_table
            .entries
            .iter()
            .filter(|entry| {
                entry.index < 16 && entry.handler_kind == InterruptHandlerKind::Interrupt
            })
            .count();
        let active_external_irqs = vector_table
            .entries
            .iter()
            .filter(|entry| {
                entry.index >= 16 && entry.handler_kind == InterruptHandlerKind::Interrupt
            })
            .collect::<Vec<_>>();
        let reserved_count = vector_table
            .entries
            .iter()
            .filter(|entry| entry.handler_kind == InterruptHandlerKind::Reserved)
            .count();

        println!(
            "  Active handlers:     {} (reset + {interrupt_count} interrupts)",
            vector_table.active_count
        );
        println!("  Active core exceptions: {active_core_exceptions}");
        println!("  Active external IRQs: {}", active_external_irqs.len());
        println!(
            "  Default-handler positions: {}",
            vector_table.default_handler_count
        );
        println!("  Reserved positions:  {reserved_count}");

        if let Some(default_entry) = vector_table
            .entries
            .iter()
            .find(|entry| entry.handler_kind == InterruptHandlerKind::DefaultHandler)
        {
            println!(
                "  Default target:      0x{:08X} ({} positions)",
                default_entry.address & !1,
                vector_table.default_handler_count
            );
        }

        if active_external_irqs.is_empty() {
            println!("  no active external IRQ handlers recovered");
        } else {
            println!("  Active external handlers:");
            for entry in active_external_irqs {
                let irq = entry.index - 16;
                let label = entry.family_label.as_deref().unwrap_or("unlabeled");
                println!(
                    "    IRQ {irq} (vector {}) {label} @ 0x{:08X}",
                    entry.index, entry.address
                );
            }
        }
    } else {
        println!("  no vector table recovered");
    }

    println!();
    println!("Startup chain");
    if let Some(chain) = report.startup_chain.as_ref() {
        for step in &chain.steps {
            println!(
                "  {}: {:?} @ 0x{:08X}",
                step.ordinal, step.role, step.address
            );
        }
    } else {
        println!("  no startup chain recovered");
    }

    println!();
    println!("Init descriptor table");
    if let Some(table) = report.init_table.as_ref() {
        println!(
            "  Bounds:             0x{:08X} - 0x{:08X}",
            table.base_address, table.end_address
        );
        if table.segments.len() > 1 {
            println!(
                "  Format:             mixed ({} records across {} tables)",
                table.records.len(),
                table.segments.len()
            );
            for segment in &table.segments {
                println!(
                    "    segment {}: {} @ 0x{:08X} - 0x{:08X} ({} record{})",
                    segment.index,
                    init_table_format_label(segment.format),
                    segment.base_address,
                    segment.end_address,
                    segment.record_count,
                    if segment.record_count == 1 { "" } else { "s" }
                );
            }
        } else {
            println!(
                "  Format:             {} ({} record{}, stride {} B)",
                init_table_format_label(table.format),
                table.records.len(),
                if table.records.len() == 1 { "" } else { "s" },
                table.record_stride
            );
        }
        for record in &table.records {
            let source = match record.src {
                Some(src) => format!("0x{src:08X}"),
                None => "zero-fill".to_string(),
            };
            let handler = match record.handler {
                Some(handler) => format!("0x{handler:08X}"),
                None => "-".to_string(),
            };
            println!(
                "  [{}] 0x{:08X} - 0x{:08X} ({:>9} B)  source {source:<10}  handler {handler:<10} {}",
                record.index,
                record.dst,
                record.dst.saturating_add(record.size),
                record.size,
                init_handler_kind_label(record.handler_kind)
            );
        }
        println!(
            "  Total dst coverage: 0x{:X} bytes ({})",
            table.total_dst_coverage, table.total_dst_coverage
        );
        match table.initial_sp {
            Some(sp) => println!(
                "  Stack top (SP):     0x{sp:08X} [{}]",
                if table.matches_initial_sp {
                    format!("matches dst end 0x{:08X}", table.max_dst_end)
                } else {
                    format!("differs from dst end 0x{:08X}", table.max_dst_end)
                }
            ),
            None => println!("  Stack top (SP):     unavailable"),
        }
        println!("  Confidence:         {:.2}", table.confidence);
        render_init_handlers(table);
    } else {
        println!("  no init descriptor table recovered");
    }

    println!();
    println!("SystemInit effects");
    match report.system_init_effects.as_ref() {
        Some(effects) => render_system_init_effects(effects),
        None => println!("  no SystemInit step located in the startup chain"),
    }

    println!();
    println!("SRAM partition");
    match report.sram_partitions.as_ref() {
        Some(partitions) if !partitions.sram_regions.is_empty() => {
            render_sram_partitions(partitions)
        }
        _ => println!("  no SRAM partition recovered"),
    }

    println!();
    println!("Execution model");
    if let Some(model) = report.execution_model.as_ref() {
        let name = match model.model.value {
            ExecutionModelKind::Superloop => "superloop",
            ExecutionModelKind::Rtos => "rtos",
            ExecutionModelKind::IsrDriven => "isr-driven",
            ExecutionModelKind::Mixed => "mixed",
            ExecutionModelKind::Unknown => "unknown",
        };
        println!("  Model:              {name}");
        if !model.loop_heads.is_empty() {
            println!("  Loop heads:         {}", model.loop_heads.len());
        }
        if !model.supporting_evidence.is_empty() {
            println!("  Supporting evidence:");
            for item in model.supporting_evidence.iter().take(4) {
                println!("  [+] {}", item.description);
            }
        }
        if !model.anti_evidence.is_empty() {
            println!("  Anti-evidence:");
            for item in model.anti_evidence.iter().take(4) {
                println!("  [-] {}", item.description);
            }
        }
        println!(
            "  Metrics:            loop heads: {}, non-default IRQ handlers: {}, vector entries: {}",
            model.metrics.loop_heads_total,
            model.metrics.non_default_irq_handlers,
            model.metrics.vector_table_entries
        );
    } else {
        println!("  Model:              unknown");
    }

    println!();
    println!("Peripheral map");
    if let Some(map) = report.peripheral_map.as_ref() {
        if map.uses.is_empty() {
            println!("  no peripheral candidates recovered");
        } else {
            for peripheral in &map.uses {
                println!(
                    "  {} @ 0x{:08X} [{:.2}]",
                    peripheral.peripheral_name, peripheral.base, peripheral.confidence
                );
            }
        }
    } else {
        println!("  no peripheral candidates recovered");
    }

    if let Some(surface) = report.peripheral_surface.as_ref() {
        println!();
        println!("Peripheral surface");
        if surface.register_blocks.is_empty() {
            println!("  no register-block observations recovered");
        } else {
            for block in surface.register_blocks.iter().take(4) {
                println!(
                    "  {} @ 0x{:08X} registers: {}",
                    block.peripheral_name,
                    block.base,
                    block.observed_registers.join(", ")
                );
            }
        }
        for config in surface.recovered_configs.iter().take(3) {
            println!("  Config:             {}", config.summary);
        }
    }

    println!();
    println!("Security controls");
    if let Some(integrity_checks) = report.integrity_checks.as_ref() {
        for check in integrity_checks.iter().take(3) {
            println!("  Integrity:          {}", check.description);
        }
    }
    if let Some(write_authority) = report.write_authority.as_ref() {
        for entry in write_authority.iter().take(2) {
            println!("  Write authority:    {}", entry.description);
        }
    }
    if let Some(surface) = report.security_surface.as_ref() {
        if let Some(item) = surface.update_surface.first() {
            println!("  Update surface:     {item}");
        }
        if let Some(item) = surface.flash_surface.first() {
            println!("  Flash surface:      {item}");
        }
        if let Some(item) = surface.comms_surface.first() {
            println!("  Comms surface:      {item}");
        }
    }

    if let Some(risk) = report.shared_state_risk.as_ref() {
        println!();
        println!("ISR / shared state");
        for finding in risk.ranked_findings.iter().take(3) {
            println!("  Risk:               {}", finding.title);
        }
    }

    if let Some(degradations) = report.degradations.as_ref() {
        println!();
        println!("Degradations");
        for degradation in degradations {
            println!("  - {degradation:?}");
        }
    }
}

fn render_peripheral_surface_report(report: &PeripheralSurfaceCliReport) {
    println!("MCU peripheral surface");
    if let Some(family) = report.family.as_deref() {
        println!("  Family:             {family}");
    }
    println!("  Artifact:           {}", report.artifact_path);
    println!();
    println!("Peripheral map");
    if let Some(map) = report.peripheral_map.as_ref() {
        for peripheral in map.uses.iter().take(8) {
            println!(
                "  {} @ 0x{:08X} [{:.2}]",
                peripheral.peripheral_name, peripheral.base, peripheral.confidence
            );
        }
    } else {
        println!("  no peripheral candidates recovered");
    }
    println!();
    println!("Register blocks");
    if let Some(surface) = report.peripheral_surface.as_ref() {
        if surface.register_blocks.is_empty() {
            println!("  no register blocks recovered");
        } else {
            for block in surface.register_blocks.iter().take(8) {
                println!(
                    "  {} @ 0x{:08X}: {}",
                    block.peripheral_name,
                    block.base,
                    block.observed_registers.join(", ")
                );
            }
        }
        if !surface.recovered_configs.is_empty() {
            println!();
            println!("Recovered config");
            for config in surface.recovered_configs.iter().take(8) {
                println!("  {}", config.summary);
                for field in config.fields.iter().take(4) {
                    println!("    {} = {}", field.name, field.value);
                }
            }
        }
    } else {
        println!("  no register blocks recovered");
    }
}

fn render_isr_state_report(report: &IsrStateCliReport) {
    println!("MCU ISR / shared-state surface");
    if let Some(family) = report.family.as_deref() {
        println!("  Family:             {family}");
    }
    println!("  Artifact:           {}", report.artifact_path);
    println!();
    println!("Ranked findings");
    if let Some(risk) = report.shared_state_risk.as_ref() {
        if risk.ranked_findings.is_empty() {
            println!("  no shared-state findings recovered");
        } else {
            for finding in risk.ranked_findings.iter().take(8) {
                println!("  {} [{:.2}]", finding.title, finding.confidence);
            }
        }
        if !risk.edges.is_empty() {
            println!();
            println!("Edges");
            for edge in risk.edges.iter().take(8) {
                println!(
                    "  {} -> 0x{:08X} ({:?})",
                    edge.producer_label.as_deref().unwrap_or("unlabeled"),
                    edge.consumer,
                    edge.access_pattern
                );
            }
        }
    } else {
        println!("  no shared-state findings recovered");
    }
}

fn render_svd_rank_report(report: &SvdRankReport) {
    println!("SVD ranking");
    println!("  Artifact:              {}", report.artifact_path);
    println!("  Corpus:                {}", report.corpus_path);
    println!(
        "  Observed MMIO literals: {}",
        report.observed_mmio_literals
    );
    println!("  Candidate SVDs:         {}", report.candidate_count);
    println!();
    println!("Ranked candidates");
    if report.candidates.is_empty() {
        println!("  no SVD candidates parsed");
    } else {
        for (index, candidate) in report.candidates.iter().enumerate() {
            println!(
                "  {}. {} score {:.2} (mmio {:.0}, strings {:.2}, vectors {:.2}; {} registers, {} peripherals, coverage {:.2})",
                index + 1,
                candidate.device,
                candidate.score,
                candidate.mmio_score,
                candidate.string_hint_score,
                candidate.vector_hint_score,
                candidate.matched_register_count,
                candidate.matched_peripheral_count,
                candidate.coverage
            );
            println!("     {}", candidate.source_path);
            for matched in candidate.matched_registers.iter().take(5) {
                println!(
                    "     0x{:08X} {}.{}",
                    matched.address, matched.peripheral, matched.register
                );
            }
        }
    }
    if !report.diagnostics.is_empty() {
        println!();
        println!("Diagnostics");
        for diagnostic in report.diagnostics.iter().take(8) {
            println!("  - {diagnostic}");
        }
    }
}

fn parse_base_address(base: Option<&str>) -> DynResult<Option<u32>> {
    let Some(base) = base else {
        return Ok(None);
    };
    if let Some(hex) = base.strip_prefix("0x").or_else(|| base.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    } else {
        base.parse::<u32>()
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    }
}

fn invalid_base_error(base: &str) -> Box<dyn Error> {
    format!("invalid --base value '{base}' (expected decimal or 0x-prefixed hex)").into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_census_cmd::CryptoCensusReport;

    #[test]
    fn census_summary_failure_is_non_fatal() {
        let trust_report = TrustBoundaryReport {
            rootfs_path: "/tmp/rootfs".into(),
            binaries_scanned: 0,
            update_binaries: Vec::new(),
            auth_binaries: Vec::new(),
            crypto_binaries: Vec::new(),
            dependency_chains: Vec::new(),
        };

        let summary = build_crypto_census_summary_with(
            Path::new("/tmp/rootfs"),
            &trust_report,
            |_rootfs, _trust_report| -> Result<CryptoCensusReport, Box<dyn Error>> {
                Err("census failed".into())
            },
        );

        assert!(summary.is_none(), "expected census failure to be non-fatal");
    }
}
