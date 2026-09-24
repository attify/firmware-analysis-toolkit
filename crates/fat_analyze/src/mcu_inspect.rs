use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use fat_core::mcu_inspection::{
    AddressHypothesis, AnalysisProvenance, AuthenticityMechanismReport, EvidenceHeuristicKind,
    EvidenceKind, EvidenceLocation, EvidenceRecord, ExecutionModelEvidence, ExecutionModelKind,
    ExecutionModelMetrics, ExecutionModelReport, ImageLayoutKind, ImageLayoutReport,
    ImageMeasurements, InspectionDegradation, IntegrityCheckReport, Interpretation,
    InterruptHandlerKind, InterruptVectorReport, MainEntryReport, McuInspectionReport,
    PeripheralEvidenceSource, PeripheralMapReport, PeripheralSurfaceReport, PeripheralUse,
    RegisterBlockObservation, SectionProvenance, SecuritySurfaceSummary, SharedAccessPattern,
    SharedStateEdge, SharedStateFinding, SharedStateRiskReport, SharedStateRiskTag,
    StartupChainReport, StartupRole, StartupStep, WriteAuthorityReport,
    MCU_INSPECTION_SCHEMA_VERSION,
};

use crate::image_measurements::measure_image;
use crate::mcu::{
    detect_cortex_m_ivt, detect_cortex_m_ivt_with_base, identify_mcu_with_base, vector_candidates,
};
use crate::mcu_family::{
    convert_role, enrich_peripheral_map, enrich_security_roles, enrich_vector_table,
    resolve_family_resolution, FamilyResolution, FamilyResolutionMode,
};
use crate::mcu_init_table::{
    extract_runtime_init_table, function_walks_init_table, scan_frame, ImageAddressing,
};
use crate::mcu_sram::extract_sram_partition;
use crate::mcu_system_init::extract_system_init_effects;

#[derive(Debug, Clone)]
pub struct McuInspectRequest {
    pub file: PathBuf,
    pub user_base: Option<u32>,
    pub user_family: Option<String>,
    pub bundle_root: Option<PathBuf>,
    pub backend_preference: Option<String>,
}

pub fn inspect_file(request: &McuInspectRequest) -> Result<McuInspectionReport, String> {
    let bytes = fs::read(&request.file)
        .map_err(|err| format!("failed to read {}: {err}", request.file.display()))?;
    let measurements = measure_image(request.file.display().to_string(), &bytes);

    let identification = identify_mcu_with_base(&bytes, request.user_base);
    let vector_offset = identification
        .vector_candidates
        .iter()
        .find(|c| c.accepted)
        .map(|c| c.offset as usize);
    let mut fast_profile = vector_offset
        .and_then(|offset| detect_cortex_m_ivt_with_base(&bytes[offset..], request.user_base));
    if let (Some(profile), Some(family)) = (fast_profile.as_mut(), identification.family.as_ref()) {
        profile.chip_family = family.clone();
        if identification.family_confidence == "corroborated" {
            profile.chip_family_confidence = 85;
        }
    }
    let family_resolution = resolve_family_resolution(
        request.user_family.as_deref(),
        fast_profile
            .as_ref()
            .map(|profile| profile.chip_family.as_str()),
    );

    let selected_backend = select_backend(request.backend_preference.as_deref());
    let family_selection_mode = match family_resolution.mode {
        FamilyResolutionMode::UserExact => "user-family",
        FamilyResolutionMode::FastProfileExact => "fast-profile",
        FamilyResolutionMode::Fallback => "fallback",
    };

    let mut degradations = Vec::new();
    if identification.architecture.is_none() {
        degradations.push(InspectionDegradation::WeakSignal);
    }

    let mut provenance = AnalysisProvenance {
        backend: selected_backend.execution_backend.clone(),
        backend_version: None,
        user_base: request.user_base,
        user_family: request.user_family.clone(),
        family_selection_mode: family_selection_mode.to_string(),
        notes: Vec::new(),
    };
    provenance.notes.push(format!(
        "backend_execution={}",
        selected_backend.execution_backend
    ));
    if let Some(requested) = selected_backend.requested {
        provenance
            .notes
            .push(format!("backend_preference={requested}"));
    } else {
        provenance
            .notes
            .push("backend_preference=absent".to_string());
    }
    if let Some(alias) = selected_backend.alias {
        provenance.notes.push(format!("backend_alias={alias}"));
    }
    if !selected_backend.accepted {
        provenance.notes.push(format!(
            "backend_preference_rejected={}",
            selected_backend.rejected.unwrap_or_default()
        ));
    }
    provenance.notes.push(match request.bundle_root.as_ref() {
        Some(path) => format!("bundle_root=present:{}", path.display()),
        None => "bundle_root=absent".to_string(),
    });
    provenance.notes.push(match family_resolution.mode {
        FamilyResolutionMode::UserExact | FamilyResolutionMode::FastProfileExact => {
            format!("family_pack={}", family_resolution.pack.family_id)
        }
        FamilyResolutionMode::Fallback => "family_pack=fallback".to_string(),
    });
    if let Some(user_family) = request.user_family.as_deref() {
        match family_resolution.mode {
            FamilyResolutionMode::UserExact => provenance
                .notes
                .push(format!("user_family_exact={user_family}")),
            _ => provenance
                .notes
                .push(format!("user_family_unresolved={user_family}")),
        }
    }

    let mut address_hypotheses = build_address_hypotheses(&bytes);
    if let Some(user_base) = request.user_base {
        address_hypotheses.retain(|hyp| hyp.base != user_base);
        {
            address_hypotheses.insert(
                0,
                AddressHypothesis {
                    base: user_base,
                    confidence: 0.99,
                    rationale: vec!["user-specified base".to_string()],
                    evidence_ids: Vec::new(),
                    is_primary: true,
                },
            );
            for hypothesis in address_hypotheses.iter_mut().skip(1) {
                hypothesis.is_primary = false;
            }
        }
    }

    if identification.architecture.is_some() && address_hypotheses.is_empty() {
        degradations.push(InspectionDegradation::BaseAddressAmbiguous);
    }

    let image_layout = if address_hypotheses.is_empty() {
        None
    } else {
        Some(classify_layout_candidates(
            identification
                .vector_candidates
                .iter()
                .filter(|c| c.accepted)
                .map(|c| c.offset as u32)
                .collect(),
            &address_hypotheses,
        ))
    };
    let vector_table = image_layout.as_ref().and_then(|layout| {
        extract_vector_table_with_resolution(
            &bytes,
            layout,
            &address_hypotheses,
            Some(&family_resolution),
        )
    });
    let vector_table = vector_table.map(|report| enrich_vector_table(report, &family_resolution));
    if let (Some(profile), Some(table)) = (fast_profile.as_mut(), vector_table.as_ref()) {
        profile.active_interrupt_count = table.active_count;
        profile.total_interrupt_slots = table.entry_count;
    }
    let startup_chain = image_layout.as_ref().and_then(|layout| {
        extract_startup_chain(&bytes, vector_table.as_ref(), layout, &address_hypotheses)
    });
    let execution_model = image_layout.as_ref().and_then(|layout| {
        extract_execution_model(
            &bytes,
            startup_chain.as_ref(),
            vector_table.as_ref(),
            layout,
        )
    });
    let initial_sp = vector_table
        .as_ref()
        .and_then(|table| table.entries.first().map(|entry| entry.address))
        .or_else(|| fast_profile.as_ref().map(|profile| profile.initial_sp));
    let init_table = image_layout.as_ref().and_then(|layout| {
        extract_runtime_init_table(
            &bytes,
            startup_chain.as_ref(),
            layout,
            &address_hypotheses,
            initial_sp,
        )
    });
    let code_analysis = image_layout.as_ref().and_then(|layout| {
        let table = vector_table.as_ref()?;
        let reset = table.entries.get(1)?.address & !1;
        let mut addressing = ImageAddressing::from_layout(reset, layout, bytes.len())?;
        // Clip only against a selected, corroborated (or explicitly supplied)
        // profile. Identical file copies alone do not establish address aliases.
        if identification.family_confidence == "corroborated"
            || family_resolution.mode == FamilyResolutionMode::UserExact {
            if let Some(region) = family_resolution.pack.executable_regions.iter()
                .find(|region| region.contains(addressing.flash_base)) {
                let mapped_end = u64::from(addressing.vector_offset)
                    + u64::from(region.end - addressing.flash_base);
                addressing.image_len = addressing.image_len.min(mapped_end as usize);
            }
        }
        let seeds = table.entries.iter()
            .filter(|entry| matches!(entry.handler_kind,
                InterruptHandlerKind::ResetHandler | InterruptHandlerKind::Interrupt))
            .map(|entry| crate::mcu_code::CodeSeed {
                address: entry.address & !1,
                reason: format!("vector-entry-{}", entry.index),
            }).collect::<Vec<_>>();
        let mut code = crate::mcu_code::analyze_code(&bytes, &addressing, &seeds, init_table.as_ref());
        code.notes.push(format!(
            "Selected mapping: vector file offset 0x{:X} maps to 0x{:08X}; mapped input ends at file offset 0x{:X}.",
            addressing.vector_offset, addressing.flash_base, addressing.image_len
        ));
        Some(code)
    });
    let register_annotations = code_analysis
        .as_ref()
        .map(|code| crate::mcu_registers::annotate_registers(code, &family_resolution));
    provenance.notes.push(match (&init_table, &startup_chain) {
        (Some(table), _) => format!(
            "init_table=present segments={} records={}",
            table.segments.len(),
            table.records.len()
        ),
        (None, Some(_)) => {
            "init_table=absent: no startup literal pool yielded validating descriptor bounds"
                .to_string()
        }
        (None, None) => "init_table=absent: no startup chain to anchor the search".to_string(),
    });
    let system_init_effects = image_layout.as_ref().and_then(|layout| {
        extract_system_init_effects(&bytes, startup_chain.as_ref(), &family_resolution, layout)
    });
    provenance
        .notes
        .push(match (&system_init_effects, &startup_chain) {
            (Some(report), _) => format!(
                "system_init_effects=present at=0x{:08x} observations={}",
                report.function_address,
                report.evidence.len()
            ),
            (None, Some(_)) => {
                "system_init_effects=absent: the startup walk named no SystemInit step".to_string()
            }
            (None, None) => {
                "system_init_effects=absent: no startup chain to locate SystemInit in".to_string()
            }
        });

    let main_entry = startup_chain.as_ref().and_then(build_main_entry);
    let peripheral_map = extract_peripheral_map(&bytes, &family_resolution);
    let peripheral_surface =
        extract_peripheral_surface(&bytes, &peripheral_map, &family_resolution);
    let sram_partitions = image_layout.as_ref().and_then(|layout| {
        extract_sram_partition(
            &bytes,
            init_table.as_ref(),
            initial_sp,
            startup_chain
                .as_ref()
                .and_then(|chain| chain.steps.first().map(|step| step.address)),
            &family_resolution,
            Some(&peripheral_map),
            layout,
        )
    });
    provenance.notes.push(match sram_partitions.as_ref() {
        Some(report) => format!(
            "sram_partitions=present regions={}",
            report.sram_regions.len()
        ),
        None => {
            "sram_partitions=absent: no addressable image or no family SRAM windows".to_string()
        }
    });

    let main_address = main_entry.as_ref().map(|entry| entry.entrypoint.value);
    let shared_state_edges = extract_shared_state_edges(
        &bytes,
        vector_table.as_ref(),
        main_address,
        Some(&peripheral_map),
        Some(&peripheral_surface),
    );
    let shared_state_risk = extract_shared_state_risk(
        &bytes,
        vector_table.as_ref(),
        main_entry.as_ref(),
        execution_model.as_ref(),
        Some(&peripheral_map),
        Some(&peripheral_surface),
    );
    let integrity_controls = extract_integrity_controls(&bytes, Some(&peripheral_map));
    let (integrity_checks, authenticity_checks) = integrity_controls.clone();
    let write_authority = extract_write_authority(&bytes, Some(&peripheral_map));
    let security_surface = summarize_security_surface(
        &bytes,
        &peripheral_map,
        &integrity_controls,
        &write_authority,
    );
    let security_surface =
        enrich_security_roles(security_surface, &peripheral_map, &family_resolution);

    let execution_model = execution_model.map(|mut report| {
        report.isr_shared_state_edges = shared_state_edges.clone();
        report
    });

    let vector_table_file_offset = image_layout
        .as_ref()
        .and_then(|layout| layout.candidate_offsets.first())
        .copied()
        .map(u64::from);
    let evidence = build_measurement_evidence(
        &measurements,
        vector_table.as_ref(),
        vector_table_file_offset,
    );

    let report = McuInspectionReport {
        schema_version: MCU_INSPECTION_SCHEMA_VERSION.to_string(),
        artifact_path: request.file.display().to_string(),
        artifact_identity: Some(measurements.identity),
        byte_measurements: Some(measurements.bytes),
        analysis_provenance: provenance,
        fast_profile,
        identification: Some(identification),
        degradations: if degradations.is_empty() {
            None
        } else {
            Some(degradations)
        },
        image_layout,
        address_hypotheses: if address_hypotheses.is_empty() {
            None
        } else {
            Some(address_hypotheses)
        },
        vector_table,
        startup_chain,
        code_analysis,
        register_annotations,
        init_table,
        sram_partitions,
        system_init_effects,
        main_entry,
        execution_model,
        peripheral_map: if peripheral_map.uses.is_empty() {
            None
        } else {
            Some(peripheral_map)
        },
        peripheral_surface: if peripheral_surface.register_blocks.is_empty()
            && peripheral_surface.recovered_configs.is_empty()
        {
            None
        } else {
            Some(peripheral_surface)
        },
        security_surface: if security_surface.update_surface.is_empty()
            && security_surface.flash_surface.is_empty()
            && security_surface.actuation_surface.is_empty()
            && security_surface.comms_surface.is_empty()
            && security_surface.debug_surface.is_empty()
            && security_surface.crypto_surface.is_empty()
        {
            None
        } else {
            Some(security_surface)
        },
        integrity_checks: if integrity_checks.is_empty() {
            None
        } else {
            Some(integrity_checks)
        },
        authenticity_checks: if authenticity_checks.is_empty() {
            None
        } else {
            Some(authenticity_checks)
        },
        write_authority: if write_authority.is_empty() {
            None
        } else {
            Some(write_authority)
        },
        shared_state_risk,
        evidence: Some(evidence),
        ..McuInspectionReport::default()
    };

    Ok(report)
}

fn build_measurement_evidence(
    measurements: &ImageMeasurements,
    vector_table: Option<&InterruptVectorReport>,
    vector_table_file_offset: Option<u64>,
) -> Vec<EvidenceRecord> {
    let mut evidence = vec![
        EvidenceRecord {
            evidence_id: "artifact-identity".to_string(),
            kind: EvidenceKind::ToolOutput,
            summary: format!(
                "SHA-256 {} over {} bytes",
                measurements.identity.sha256, measurements.identity.total_bytes
            ),
            location: None,
            raw: Some(format!(
                "sha256={} bytes={}",
                measurements.identity.sha256, measurements.identity.total_bytes
            )),
        },
        EvidenceRecord {
            evidence_id: "content-prefix".to_string(),
            kind: EvidenceKind::RawBytes,
            summary: format!(
                "Content prefix spans byte offsets [0, {})",
                measurements.bytes.content_prefix_bytes
            ),
            location: Some(EvidenceLocation {
                offset: Some(0),
                note: Some(format!(
                    "length={}",
                    measurements.bytes.content_prefix_bytes
                )),
                ..EvidenceLocation::default()
            }),
            raw: None,
        },
    ];

    if let (Some(byte), Some(offset)) = (
        measurements.bytes.trailing_uniform_byte,
        measurements.bytes.trailing_uniform_offset,
    ) {
        evidence.push(EvidenceRecord {
            evidence_id: "trailing-uniform-run".to_string(),
            kind: EvidenceKind::RawBytes,
            summary: format!(
                "Uniform trailing run of 0x{byte:02x} spans byte offsets [{offset}, {})",
                measurements.bytes.total_bytes
            ),
            location: Some(EvidenceLocation {
                offset: Some(offset),
                note: Some(format!(
                    "length={}",
                    measurements.bytes.trailing_uniform_bytes
                )),
                ..EvidenceLocation::default()
            }),
            raw: Some(format!("byte=0x{byte:02x}")),
        });
    }

    if let Some(vector_table) = vector_table {
        evidence.extend(
            vector_table
                .entries
                .iter()
                .take(8)
                .map(|entry| EvidenceRecord {
                    evidence_id: format!("vector-word-{}", entry.index),
                    kind: EvidenceKind::VectorWord,
                    summary: format!("Vector word {} is 0x{:08x}", entry.index, entry.address),
                    location: Some(EvidenceLocation {
                        offset: Some(
                            vector_table_file_offset.unwrap_or(0) + u64::from(entry.index) * 4,
                        ),
                        note: Some("little-endian 32-bit vector word".to_string()),
                        ..EvidenceLocation::default()
                    }),
                    raw: Some(format!("0x{:08x}", entry.address)),
                }),
        );
    }

    evidence
}

pub fn build_address_hypotheses(bytes: &[u8]) -> Vec<AddressHypothesis> {
    let candidates = find_vector_candidates(bytes);
    let mut hypotheses = Vec::new();

    for (index, candidate) in candidates.into_iter().enumerate() {
        let reset_addr = candidate.profile.reset_vector & !1;
        let region_base =
            crate::mcu::infer_code_base(reset_addr).expect("profile requires known mapping");
        let remaining = bytes.len().saturating_sub(candidate.offset);
        let aligned_base = if (reset_addr - region_base) as usize >= remaining {
            align_down(reset_addr, 0x2000)
        } else {
            region_base
        };
        let mut rationale = vec![
            format!("vector_offset=0x{:x}", candidate.offset),
            format!("reset=0x{reset_addr:08x}"),
            if aligned_base == region_base {
                "known executable region base; reset maps inside the supplied bytes".into()
            } else {
                "8 KiB-aligned relocation hypothesis; original region base places reset outside the supplied bytes".into()
            },
        ];
        if candidate.offset == 0 {
            rationale.push("vector table found at image start".to_string());
        } else {
            rationale.push("vector table found after non-vector prefix".to_string());
        }

        hypotheses.push(AddressHypothesis {
            base: aligned_base,
            confidence: if aligned_base != region_base {
                0.6
            } else if candidate.offset == 0 {
                0.85
            } else {
                0.7
            },
            rationale,
            evidence_ids: Vec::new(),
            is_primary: index == 0,
        });
    }

    hypotheses
}

pub fn classify_image_layout(bytes: &[u8], hypotheses: &[AddressHypothesis]) -> ImageLayoutReport {
    classify_layout_candidates(vector_candidate_offsets(bytes), hypotheses)
}

// Preserve candidate selection from identification. An inferred mapping must
// not feed back into discovery and silently select a different vector table.
fn classify_layout_candidates(
    candidate_offsets: Vec<u32>,
    hypotheses: &[AddressHypothesis],
) -> ImageLayoutReport {
    let (kind, confidence, rationale) = if let Some(offset) = candidate_offsets.first().copied() {
        if offset > 0 {
            (
                ImageLayoutKind::BootloaderPlusAppConcat,
                0.82,
                vec![format!(
                    "vector table starts at non-zero offset 0x{offset:x}"
                )],
            )
        } else {
            let primary_base = hypotheses.first().map(|hyp| hyp.base).unwrap_or_default();
            if fat_family::mcu_packs::executable_region(primary_base)
                .is_some_and(|region| region.kind == "boot-rom")
            {
                (
                    ImageLayoutKind::BootloaderOnlyImage,
                    0.8,
                    vec!["vector mapping lies in a documented boot ROM region".into()],
                )
            } else if primary_base == 0x0800_0000 {
                (
                    ImageLayoutKind::FullFlashDump,
                    0.78,
                    vec!["primary base aligns with canonical flash base".to_string()],
                )
            } else {
                (
                    ImageLayoutKind::AppOnlyImage,
                    0.72,
                    vec![format!("primary base starts at 0x{primary_base:08x}")],
                )
            }
        }
    } else {
        (
            ImageLayoutKind::Unknown,
            0.0,
            vec!["no Cortex-M vector table candidate recovered".to_string()],
        )
    };

    ImageLayoutReport {
        kind: Interpretation {
            value: kind,
            confidence,
            rationale: rationale.clone(),
            evidence_ids: Vec::new(),
        },
        candidate_offsets,
        vector_address: hypotheses.iter().find(|h| h.is_primary).map(|h| h.base),
        rationale,
        evidence_ids: Vec::new(),
    }
}

pub fn extract_vector_table(
    bytes: &[u8],
    layout: &ImageLayoutReport,
    hypotheses: &[AddressHypothesis],
) -> Option<InterruptVectorReport> {
    extract_vector_table_with_resolution(bytes, layout, hypotheses, None)
}

fn extract_vector_table_with_resolution(
    bytes: &[u8],
    layout: &ImageLayoutReport,
    hypotheses: &[AddressHypothesis],
    requested_resolution: Option<&FamilyResolution>,
) -> Option<InterruptVectorReport> {
    let offset = usize::try_from(*layout.candidate_offsets.first()?).ok()?;
    let vector_address = layout
        .vector_address
        .or_else(|| hypotheses.iter().find(|h| h.is_primary).map(|h| h.base));
    let profile = detect_cortex_m_ivt_with_base(bytes.get(offset..)?, vector_address)?;
    let detected_resolution = resolve_family_resolution(None, Some(profile.chip_family.as_str()));
    let family_resolution = requested_resolution
        .filter(|resolution| resolution.is_enriching_match())
        .or_else(|| {
            detected_resolution
                .is_enriching_match()
                .then_some(&detected_resolution)
        });
    let mut table = crate::mcu::scan_vector_table(
        bytes.get(offset..)?,
        vector_address,
        family_resolution.map(|resolution| resolution.pack),
    )?;
    table.provenance = Some(section_provenance("vector-table-extractor", vector_address));
    Some(table)
}

/// Startup functions decoded while walking the chain. Bounded so a mis-decode
/// cannot walk the whole image; the last frame's targets are still recorded as
/// steps, they are just not descended into.
const MAX_STARTUP_FRAMES: usize = 2;
/// Upper bound on recovered startup steps, including the reset stub.
const MAX_STARTUP_STEPS: usize = 6;

pub fn extract_startup_chain(
    bytes: &[u8],
    vector_table: Option<&InterruptVectorReport>,
    layout: &ImageLayoutReport,
    hypotheses: &[AddressHypothesis],
) -> Option<StartupChainReport> {
    let vector_table = vector_table?;
    let reset_entry = vector_table.entries.get(1)?;
    let reset_addr = reset_entry.address & !1;
    let addressing = ImageAddressing::from_layout(reset_addr, layout, bytes.len())?;

    let mut addresses = vec![reset_addr];
    // Parallel to `addresses[1..]`: whether the step was reached by an
    // indirect `bx rN` trampoline rather than a call or a direct branch.
    let mut via_trampoline = vec![false];
    let mut frame = reset_addr;
    let mut frames = 0usize;

    while frames < MAX_STARTUP_FRAMES && addresses.len() < MAX_STARTUP_STEPS {
        let Some(scan) = scan_frame(bytes, frame, &addressing) else {
            break;
        };
        frames += 1;
        for call in scan.calls {
            if addresses.len() >= MAX_STARTUP_STEPS {
                break;
            }
            if addresses.contains(&call) {
                continue;
            }
            addresses.push(call);
            via_trampoline.push(false);
        }
        let Some(tail) = scan.tail else {
            break;
        };
        if addresses.contains(&tail) || addresses.len() >= MAX_STARTUP_STEPS {
            break;
        }
        addresses.push(tail);
        via_trampoline.push(scan.tail_indirect);
        frame = tail;
    }

    let roles = assign_startup_roles(bytes, &addresses, &via_trampoline, &addressing);
    let steps = addresses
        .iter()
        .zip(roles)
        .enumerate()
        .map(|(ordinal, (address, role))| StartupStep {
            ordinal: ordinal as u8,
            address: *address,
            role,
            evidence_ids: Vec::new(),
        })
        .collect::<Vec<_>>();

    Some(StartupChainReport {
        confidence: if steps.len() <= 1 { 0.45 } else { 0.7 },
        steps,
        provenance: Some(section_provenance(
            "startup-chain-extractor",
            hypotheses.first().map(|hyp| hyp.base),
        )),
    })
}

/// Assign startup roles from evidence first, falling back to ordinal position.
///
/// The strong signal is the init-descriptor table: the step whose body walks
/// one is `RuntimeInit`, and once a table has been located anywhere in the
/// chain (including inlined into the reset stub, which is what CMSIS
/// `startup_ARMCMx.c` produces) the final step is `main`. Without that anchor
/// the extractor keeps its historical ordinal-based labelling.
fn assign_startup_roles(
    bytes: &[u8],
    addresses: &[u32],
    via_trampoline: &[bool],
    addressing: &ImageAddressing,
) -> Vec<StartupRole> {
    let mut roles = vec![StartupRole::Unknown; addresses.len()];
    if addresses.is_empty() {
        return roles;
    }
    roles[0] = StartupRole::ResetStub;

    let reset_walks_table = function_walks_init_table(bytes, addresses[0], addressing);
    let runtime_index = (1..addresses.len())
        .find(|index| function_walks_init_table(bytes, addresses[*index], addressing));
    if let Some(index) = runtime_index {
        roles[index] = StartupRole::RuntimeInit;
    }

    let last = addresses.len() - 1;
    if (reset_walks_table || runtime_index.is_some()) && last > 0 && Some(last) != runtime_index {
        roles[last] = StartupRole::Main;
    }

    for (index, role) in roles.iter_mut().enumerate().skip(1) {
        if *role != StartupRole::Unknown {
            continue;
        }
        if via_trampoline.get(index).copied().unwrap_or(false) {
            *role = StartupRole::StartupStub;
            continue;
        }
        *role = match index {
            1 => StartupRole::SystemInit,
            2 => StartupRole::RuntimeInit,
            3 => StartupRole::Main,
            _ => StartupRole::Unknown,
        };
    }

    roles
}

/// RTOS kernel marker families scanned over the raw image bytes, in scan
/// order. The first family with a symbol hit wins the marker evidence.
const RTOS_MARKER_FAMILIES: &[(&str, &[&str])] = &[
    (
        "freertos",
        &[
            "pxCurrentTCB",
            "vTaskDelay",
            "vTaskStartScheduler",
            "xTaskCreate",
            "xQueueSend",
            "osKernelStart",
        ],
    ),
    ("zephyr", &["z_thread_entry", "k_sleep", "_kernel"]),
    ("cmsis-rtos", &["osThreadNew", "osKernelStart"]),
    ("threadx", &["_tx_thread_schedule", "tx_thread_create"]),
];

fn find_marker_offset(bytes: &[u8], symbol: &str) -> Option<usize> {
    let needle = symbol.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return None;
    }
    (0..=bytes.len() - needle.len()).find(|&offset| &bytes[offset..offset + needle.len()] == needle)
}

/// Relative confidence contribution of each heuristic toward the classified
/// model. The degradation marker carries no weight.
fn evidence_weight(evidence: &ExecutionModelEvidence) -> f32 {
    match evidence.kind {
        EvidenceHeuristicKind::RtosMarkerAbsent { .. } => 0.04,
        EvidenceHeuristicKind::RtosMarkerPresent { .. } => 0.25,
        EvidenceHeuristicKind::SysTickHandlerDefault => 0.12,
        EvidenceHeuristicKind::SysTickHandlerCustom => 0.2,
        EvidenceHeuristicKind::NonDefaultVectorDensity { .. } => 0.04,
        EvidenceHeuristicKind::MainDominatingLoopUnknown => 0.0,
    }
}

pub fn extract_execution_model(
    bytes: &[u8],
    startup_chain: Option<&StartupChainReport>,
    vector_table: Option<&InterruptVectorReport>,
    layout: &ImageLayoutReport,
) -> Option<ExecutionModelReport> {
    let mut supporting_evidence = Vec::new();
    let mut anti_evidence = Vec::new();

    // Explicit degradation entry when the Main step is unavailable: the
    // Main-CFG dominating-loop heuristic cannot be evaluated.
    let main_step_present = startup_chain
        .map(|chain| {
            chain
                .steps
                .iter()
                .any(|step| step.role == StartupRole::Main)
        })
        .unwrap_or(false);
    if !main_step_present {
        anti_evidence.push(ExecutionModelEvidence {
            kind: EvidenceHeuristicKind::MainDominatingLoopUnknown,
            description:
                "startup chain has no Main step; main dominating-loop heuristic not evaluated"
                    .to_string(),
            artifact_ref: None,
        });
    }

    let unknown_interpretation = Interpretation {
        value: ExecutionModelKind::Unknown,
        confidence: if startup_chain.is_some() { 0.35 } else { 0.0 },
        rationale: vec!["no stable loop or scheduler signal recovered".to_string()],
        evidence_ids: Vec::new(),
    };

    let finish = |model: Interpretation<ExecutionModelKind>,
                  loop_heads: Vec<u32>,
                  supporting_evidence: Vec<ExecutionModelEvidence>,
                  anti_evidence: Vec<ExecutionModelEvidence>,
                  metrics: ExecutionModelMetrics| {
        Some(ExecutionModelReport {
            model,
            loop_heads,
            scheduler_candidates: Vec::new(),
            task_spawn_sites: Vec::new(),
            isr_shared_state_edges: Vec::new(),
            evidence_ids: Vec::new(),
            supporting_evidence,
            anti_evidence,
            metrics,
            provenance: Some(SectionProvenance {
                extractor: "execution-model-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: Vec::new(),
            }),
        })
    };

    let degraded = |loop_heads: Vec<u32>, anti_evidence: Vec<ExecutionModelEvidence>| {
        finish(
            unknown_interpretation.clone(),
            loop_heads,
            Vec::new(),
            anti_evidence,
            ExecutionModelMetrics::default(),
        )
    };
    let Some(base_address) = startup_chain
        .and_then(|chain| chain.steps.first().map(|step| step.address))
        .or_else(|| {
            vector_table.and_then(|table| table.entries.get(1).map(|entry| entry.address & !1))
        })
    else {
        return degraded(Vec::new(), anti_evidence);
    };
    let Some(flash_base) = layout
        .vector_address
        .or_else(|| infer_flash_base(base_address))
    else {
        return degraded(Vec::new(), anti_evidence);
    };
    let Some(vector_offset) = usize::try_from(*layout.candidate_offsets.first().unwrap_or(&0)).ok()
    else {
        return degraded(Vec::new(), anti_evidence);
    };
    let Some(scan_start) = map_address_to_offset(base_address, flash_base, vector_offset as u32)
    else {
        return degraded(Vec::new(), anti_evidence);
    };
    let scan_end = bytes.len().min(scan_start.saturating_add(0x800));
    let mut loop_heads = Vec::new();
    for offset in (scan_start..scan_end.saturating_sub(2)).step_by(2) {
        let Some(relative) = offset.checked_sub(vector_offset) else {
            continue;
        };
        let address = flash_base.wrapping_add(relative as u32);
        if let Some(target) = direct_branch_target(bytes, address, offset) {
            if target <= address {
                loop_heads.push(address);
            }
        }
    }

    // RTOS kernel marker scan over the raw image bytes, per family.
    let mut rtos_marker: Option<(&str, &str, usize)> = None;
    for (family, symbols) in RTOS_MARKER_FAMILIES {
        if let Some((symbol, offset)) = symbols
            .iter()
            .filter_map(|symbol| find_marker_offset(bytes, symbol).map(|offset| (*symbol, offset)))
            .next()
        {
            rtos_marker = Some((*family, symbol, offset));
            break;
        }
        supporting_evidence.push(ExecutionModelEvidence {
            kind: EvidenceHeuristicKind::RtosMarkerAbsent {
                family: (*family).to_string(),
            },
            description: format!("no {family} kernel symbols found in image bytes"),
            artifact_ref: None,
        });
    }
    if let Some((family, symbol, offset)) = rtos_marker {
        anti_evidence.push(ExecutionModelEvidence {
            kind: EvidenceHeuristicKind::RtosMarkerPresent {
                family: family.to_string(),
                symbol: symbol.to_string(),
            },
            description: format!("{family} kernel symbol \"{symbol}\" found in image bytes"),
            artifact_ref: Some(offset as u32),
        });
    }

    // Vector targets measure populated entries and aliases. Neither a shared
    // target nor a dedicated pointer proves default/custom code or whether an
    // interrupt is enabled. Leave the legacy non-default count unresolved.
    let mut metrics = ExecutionModelMetrics::default();
    if let Some(table) = vector_table {
        metrics.vector_table_entries = table.entries.len() as u32;
    }
    metrics.loop_heads_total = loop_heads.len() as u32;

    // Classification: RTOS markers dominate; otherwise keep the established
    // loop-head superloop classification. Populated SysTick vectors alone
    // cannot establish an ISR-driven kernel.
    let model_value = if rtos_marker.is_some() {
        ExecutionModelKind::Rtos
    } else if !loop_heads.is_empty() {
        ExecutionModelKind::Superloop
    } else {
        ExecutionModelKind::Unknown
    };
    let rationale = match model_value {
        ExecutionModelKind::Rtos => {
            let (family, symbol, _) = rtos_marker.expect("marker recorded");
            format!("{family} kernel symbol \"{symbol}\" found in image bytes")
        }
        ExecutionModelKind::Superloop => "backward Thumb branch(s) detected".to_string(),
        ExecutionModelKind::IsrDriven => {
            "custom systick handler without RTOS kernel markers".to_string()
        }
        _ => "no stable loop or scheduler signal recovered".to_string(),
    };

    // Confidence derived from the balance of supporting vs anti evidence.
    let support_weight: f32 = supporting_evidence.iter().map(evidence_weight).sum();
    let anti_weight: f32 = anti_evidence.iter().map(evidence_weight).sum();
    let confidence = match model_value {
        ExecutionModelKind::Rtos => {
            (0.55 + anti_weight * 0.6 + support_weight * 0.3).clamp(0.55, 0.9)
        }
        ExecutionModelKind::IsrDriven => {
            (0.4 + support_weight * 0.5 + anti_weight * 0.8).clamp(0.3, 0.85)
        }
        ExecutionModelKind::Superloop => (0.4 + support_weight - anti_weight).clamp(0.3, 0.85),
        _ => {
            if startup_chain.is_some() {
                0.35
            } else {
                0.0
            }
        }
    };

    finish(
        Interpretation {
            value: model_value,
            confidence,
            rationale: vec![rationale,
                "vector targets alone do not establish default/custom handler roles or enabled interrupts; non-default handler metric is unresolved".into()],
            evidence_ids: Vec::new(),
        },
        loop_heads,
        supporting_evidence,
        anti_evidence,
        metrics,
    )
}

pub fn extract_mmio_clusters(bytes: &[u8]) -> PeripheralMapReport {
    let mmio_hits: Vec<(usize, u32)> = (0..bytes.len().saturating_sub(4))
        .step_by(4)
        .filter_map(|offset| {
            let word = read_u32_at(bytes, offset)?;
            is_probable_mmio(word).then_some((offset, word))
        })
        .collect();

    let mut seen = HashMap::<u32, PeripheralUse>::new();
    for window in mmio_hits.windows(2) {
        let [(first_offset, first_word), (second_offset, second_word)] = window else {
            continue;
        };
        if second_offset - first_offset != 4 {
            continue;
        }
        if !forms_mmio_cluster(*first_word, *second_word) {
            continue;
        }

        for word in [*first_word, *second_word] {
            seen.entry(word).or_insert_with(|| PeripheralUse {
                family: None,
                peripheral_name: format!("mmio-cluster@0x{word:08x}"),
                base: word as u64,
                roles: Vec::new(),
                source: PeripheralEvidenceSource::Mmio,
                confidence: 0.42,
                evidence_ids: Vec::new(),
            });
        }
    }

    let mut uses: Vec<_> = seen.into_values().collect();
    uses.sort_by_key(|use_| use_.base);
    PeripheralMapReport {
        uses,
        provenance: Some(SectionProvenance {
            extractor: "mmio-cluster-extractor".to_string(),
            backend: Some("native-mcu-inspect".to_string()),
            family_pack: None,
            notes: Vec::new(),
        }),
    }
}

pub fn extract_peripheral_map(bytes: &[u8], resolution: &FamilyResolution) -> PeripheralMapReport {
    let mut peripheral_map = extract_mmio_clusters(bytes);
    let family_hits = extract_family_mmio_literals(bytes, resolution);
    peripheral_map.uses.extend(family_hits.uses);
    peripheral_map = enrich_peripheral_map(peripheral_map, resolution);
    peripheral_map = dedupe_peripheral_map(peripheral_map);

    if resolution.is_enriching_match()
        && peripheral_map
            .uses
            .iter()
            .any(|use_| use_.family.is_some() || !use_.roles.is_empty())
    {
        peripheral_map.uses.retain(|use_| {
            use_.family.is_some()
                || !use_.roles.is_empty()
                || use_.source != PeripheralEvidenceSource::Mmio
        });
    }

    peripheral_map
}

pub fn extract_peripheral_surface(
    bytes: &[u8],
    peripheral_map: &PeripheralMapReport,
    resolution: &FamilyResolution,
) -> PeripheralSurfaceReport {
    let mut block_map = HashMap::<(Option<String>, String, u64), RegisterBlockObservation>::new();

    if !resolution.is_enriching_match() {
        return PeripheralSurfaceReport {
            provenance: Some(SectionProvenance {
                extractor: "peripheral-surface-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: vec!["family-pack unavailable".to_string()],
            }),
            ..PeripheralSurfaceReport::default()
        };
    }

    for offset in (0..bytes.len().saturating_sub(4)).step_by(4) {
        let Some(word) = read_u32_at(bytes, offset) else {
            continue;
        };
        let Some(spec) = resolution.pack.lookup_register(word) else {
            continue;
        };

        let key = (
            Some(resolution.pack.family_id.to_string()),
            spec.peripheral_name.to_string(),
            spec.base as u64,
        );
        let entry = block_map
            .entry(key)
            .or_insert_with(|| RegisterBlockObservation {
                family: Some(resolution.pack.family_id.to_string()),
                peripheral_name: spec.peripheral_name.to_string(),
                base: spec.base as u64,
                observed_registers: Vec::new(),
                sample_offsets: Vec::new(),
                confidence: 0.64,
                evidence_ids: Vec::new(),
            });
        if !entry
            .observed_registers
            .iter()
            .any(|name| name == spec.register_name)
        {
            entry
                .observed_registers
                .push(spec.register_name.to_string());
        }
        if entry.sample_offsets.len() < 4 {
            entry.sample_offsets.push(offset as u64);
        }
        entry.confidence = entry.confidence.max(0.68);
    }

    for use_ in &peripheral_map.uses {
        let key = (use_.family.clone(), use_.peripheral_name.clone(), use_.base);
        if let Some(block) = block_map.get_mut(&key) {
            block.confidence = block.confidence.max(use_.confidence);
        }
    }

    let mut register_blocks: Vec<_> = block_map.into_values().collect();
    register_blocks.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.base.cmp(&right.base))
    });

    PeripheralSurfaceReport {
        register_blocks,
        recovered_configs: Vec::new(),
        provenance: Some(SectionProvenance {
            extractor: "peripheral-surface-extractor".to_string(),
            backend: Some("native-mcu-inspect".to_string()),
            family_pack: Some(resolution.pack.family_id.to_string()),
            notes: vec![
                "register-block observations built from family-backed register literals"
                    .to_string(),
                "address literals do not prove register writes; configuration values require instruction-backed evidence"
                    .to_string(),
            ],
        }),
    }
}

pub fn extract_shared_state_edges(
    bytes: &[u8],
    vector_table: Option<&InterruptVectorReport>,
    main_consumer: Option<u32>,
    peripheral_map: Option<&PeripheralMapReport>,
    peripheral_surface: Option<&PeripheralSurfaceReport>,
) -> Vec<SharedStateEdge> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let async_keywords = [
        text.contains("irq"),
        text.contains("main"),
        text.contains("flag"),
        text.contains("buffer"),
        text.contains("queue"),
        text.contains("dma"),
        text.contains("uart"),
        text.contains("update"),
        text.contains("watchdog"),
        text.contains("motor"),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if async_keywords < 3 {
        return Vec::new();
    }

    let Some(vector_table) = vector_table else {
        return Vec::new();
    };
    let Some(consumer) = main_consumer else {
        return Vec::new();
    };
    let variable = if text.contains("queue") {
        Some("shared_queue_candidate".to_string())
    } else if text.contains("buffer") {
        Some("shared_buffer_candidate".to_string())
    } else if text.contains("flag") || text.contains("status") {
        Some("shared_flag_candidate".to_string())
    } else {
        None
    };
    let access_pattern = if text.contains("queue") || text.contains("rx") {
        SharedAccessPattern::RingBuffer
    } else if text.contains("buffer") || text.contains("dma") {
        SharedAccessPattern::SharedBuffer
    } else if text.contains("count") {
        SharedAccessPattern::SharedCounter
    } else {
        SharedAccessPattern::PollingFlag
    };

    let handlers: Vec<_> = vector_table
        .entries
        .iter()
        .skip(2)
        .filter(|entry| {
            entry.address != 0
                && entry.address != 0xffff_ffff
                && entry.handler_kind != InterruptHandlerKind::Reserved
                && entry.handler_kind != InterruptHandlerKind::DefaultHandler
        })
        .take(4)
        .collect();
    if handlers.is_empty() {
        return Vec::new();
    }

    let mut edges = Vec::new();
    for entry in handlers {
        let producer_label = entry.family_label.clone();
        let producer_text = producer_label
            .as_deref()
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        let mut rationale = Vec::new();
        let mut confidence: f32 = 0.38;
        if !producer_text.is_empty() {
            rationale.push(format!("family-labeled IRQ: {producer_text}"));
            confidence += 0.08;
        }
        if producer_text.contains("dma") || text.contains("dma") {
            confidence += 0.08;
        }
        if producer_text.contains("uart")
            || producer_text.contains("usart")
            || producer_text.contains("eth")
            || producer_text.contains("i2c")
            || text.contains("uart")
        {
            confidence += 0.06;
        }

        let touches_flash_or_update = text.contains("update")
            || text.contains("ota")
            || producer_has_role(
                producer_label.as_deref(),
                peripheral_map,
                peripheral_surface,
                fat_core::mcu_inspection::PeripheralRole::UpdateTransport,
            )
            || producer_has_role(
                producer_label.as_deref(),
                peripheral_map,
                peripheral_surface,
                fat_core::mcu_inspection::PeripheralRole::FlashWritePath,
            );
        let touches_actuation = text.contains("motor")
            || text.contains("actuat")
            || producer_has_role(
                producer_label.as_deref(),
                peripheral_map,
                peripheral_surface,
                fat_core::mcu_inspection::PeripheralRole::Actuation,
            );
        let touches_comms = text.contains("uart")
            || text.contains("comms")
            || producer_has_role(
                producer_label.as_deref(),
                peripheral_map,
                peripheral_surface,
                fat_core::mcu_inspection::PeripheralRole::CommsBridge,
            )
            || producer_has_role(
                producer_label.as_deref(),
                peripheral_map,
                peripheral_surface,
                fat_core::mcu_inspection::PeripheralRole::HostSidecarLink,
            );
        let touches_watchdog = text.contains("watchdog");
        let touches_dma = text.contains("dma") || producer_text.contains("dma");
        let touches_safety = text.contains("safe") || text.contains("fault");

        if touches_flash_or_update {
            rationale.push("update/flash signal present".to_string());
            confidence += 0.08;
        }
        if touches_actuation {
            rationale.push("actuation signal present".to_string());
            confidence += 0.08;
        }
        if touches_comms {
            rationale.push("comms signal present".to_string());
            confidence += 0.06;
        }

        edges.push(SharedStateEdge {
            irq_handler: entry.address & !1,
            consumer,
            variable: variable.clone(),
            producer_label: producer_label.clone(),
            consumer_label: Some("main_loop_candidate".to_string()),
            access_pattern,
            touches_flash_or_update,
            touches_actuation,
            touches_comms,
            touches_watchdog,
            touches_dma,
            touches_safety,
            confidence: confidence.min(0.86),
            rationale,
            evidence_ids: Vec::new(),
        });
    }

    edges
}

pub fn extract_shared_state_risk(
    bytes: &[u8],
    vector_table: Option<&InterruptVectorReport>,
    main_entry: Option<&MainEntryReport>,
    execution_model: Option<&ExecutionModelReport>,
    peripheral_map: Option<&PeripheralMapReport>,
    peripheral_surface: Option<&PeripheralSurfaceReport>,
) -> Option<SharedStateRiskReport> {
    let consumer = main_entry
        .map(|entry| entry.entrypoint.value)
        .or_else(|| execution_model.and_then(|model| model.loop_heads.first().copied()));

    // When main-entry detection falls back to the reset stub, the consumer is
    // the reset handler itself. An "IRQ shares state with main" claim that
    // reaches the reset stub is unfounded — suppress the report rather than emit
    // findings that point at the reset stub.
    let reset_stub = vector_table
        .and_then(|table| table.entries.get(1))
        .map(|entry| entry.address & !1);
    if let (Some(consumer_addr), Some(reset_addr)) = (consumer, reset_stub) {
        if consumer_addr == reset_addr {
            return None;
        }
    }

    let edges = extract_shared_state_edges(
        bytes,
        vector_table,
        consumer,
        peripheral_map,
        peripheral_surface,
    );
    if edges.is_empty() {
        return None;
    }

    let mut ranked_findings = Vec::new();
    for edge in &edges {
        let mut tags = Vec::new();
        if edge.touches_flash_or_update {
            tags.push(SharedStateRiskTag::Update);
        }
        if edge.touches_flash_or_update {
            tags.push(SharedStateRiskTag::FlashWrite);
        }
        if edge.touches_actuation {
            tags.push(SharedStateRiskTag::Actuation);
        }
        if edge.touches_watchdog {
            tags.push(SharedStateRiskTag::Watchdog);
        }
        if edge.touches_dma {
            tags.push(SharedStateRiskTag::Dma);
        }
        if edge.touches_safety {
            tags.push(SharedStateRiskTag::Safety);
        }
        if edge.touches_comms {
            tags.push(SharedStateRiskTag::HostComms);
        }
        if edge
            .producer_label
            .as_deref()
            .map(|label| label.to_ascii_lowercase().contains("eth"))
            .unwrap_or(false)
        {
            tags.push(SharedStateRiskTag::NetworkIngress);
        }
        ranked_findings.push(SharedStateFinding {
            title: format!(
                "{} IRQ shared state reaches 0x{:08x}",
                edge.producer_label.as_deref().unwrap_or("unlabeled"),
                edge.consumer
            ),
            tags,
            confidence: edge.confidence,
            rationale: edge.rationale.clone(),
            evidence_ids: edge.evidence_ids.clone(),
        });
    }
    ranked_findings.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Collapse identical findings: several unlabeled IRQ handlers reaching the
    // same consumer otherwise produce byte-for-byte duplicate messages.
    let mut seen_titles = std::collections::HashSet::new();
    ranked_findings.retain(|finding| seen_titles.insert(finding.title.clone()));

    Some(SharedStateRiskReport {
        edges,
        ranked_findings,
        degradation_notes: Vec::new(),
        provenance: Some(SectionProvenance {
            extractor: "shared-state-risk-extractor".to_string(),
            backend: Some("native-mcu-inspect".to_string()),
            family_pack: None,
            notes: vec!["bounded async shared-state ranking".to_string()],
        }),
    })
}

pub fn summarize_security_surface(
    bytes: &[u8],
    peripheral_map: &PeripheralMapReport,
    integrity: &(Vec<IntegrityCheckReport>, Vec<AuthenticityMechanismReport>),
    write_authority: &[WriteAuthorityReport],
) -> SecuritySurfaceSummary {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut update_surface = Vec::new();
    let mut flash_surface = Vec::new();
    let mut actuation_surface = Vec::new();
    let mut comms_surface = Vec::new();
    let mut debug_surface = Vec::new();
    let mut crypto_surface = Vec::new();

    if text.contains("update") || text.contains("ota") {
        update_surface.push("update/ota candidate string surface present".to_string());
    }
    if text.contains("flash") || text.contains("erase") || text.contains("program") {
        flash_surface.push("flash erase/program candidate string surface present".to_string());
    }
    if text.contains("uart") || text.contains("comms") {
        comms_surface.push("uart/comms candidate string surface present".to_string());
    }
    if text.contains("motor") || text.contains("actuat") {
        actuation_surface.push("actuation candidate string surface present".to_string());
    }
    if text.contains("swd") || text.contains("jtag") || text.contains("debug") {
        debug_surface.push("debug-oriented string surface present".to_string());
    }
    if integrity
        .0
        .iter()
        .any(|check| check.description.to_ascii_lowercase().contains("crc"))
    {
        crypto_surface.push("error-detection primitive candidate present".to_string());
    }
    let _ = peripheral_map;
    if !write_authority.is_empty() {
        flash_surface.push("flash write candidate present with supporting evidence".to_string());
    }

    let populated_groups = [
        !update_surface.is_empty(),
        !flash_surface.is_empty(),
        !actuation_surface.is_empty(),
        !comms_surface.is_empty(),
        !debug_surface.is_empty(),
        !crypto_surface.is_empty(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count() as f32;

    SecuritySurfaceSummary {
        update_surface,
        flash_surface,
        actuation_surface,
        comms_surface,
        debug_surface,
        crypto_surface,
        confidence: (populated_groups / 6.0) * 0.5,
        evidence_ids: Vec::new(),
    }
}

pub fn extract_integrity_controls(
    bytes: &[u8],
    _peripheral_map: Option<&PeripheralMapReport>,
) -> (Vec<IntegrityCheckReport>, Vec<AuthenticityMechanismReport>) {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut integrity_checks = Vec::new();

    if text.contains("crc") || text.contains("crc32") {
        integrity_checks.push(IntegrityCheckReport {
            description: "CRC-based integrity signal present".to_string(),
            confidence: 0.84,
            evidence_ids: Vec::new(),
            provenance: Some(SectionProvenance {
                extractor: "integrity-control-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: vec!["derived from string evidence".to_string()],
            }),
        });
    }
    if text.contains("checksum") {
        integrity_checks.push(IntegrityCheckReport {
            description: "checksum integrity signal present".to_string(),
            confidence: 0.72,
            evidence_ids: Vec::new(),
            provenance: Some(SectionProvenance {
                extractor: "integrity-control-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: vec!["derived from string evidence".to_string()],
            }),
        });
    }

    (integrity_checks, Vec::new())
}

pub fn extract_write_authority(
    bytes: &[u8],
    peripheral_map: Option<&PeripheralMapReport>,
) -> Vec<WriteAuthorityReport> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut reports = Vec::new();
    let has_flash_text =
        text.contains("flash") && text.contains("erase") && text.contains("program");
    let has_mmio_cluster = peripheral_map.is_some_and(|map| {
        map.uses.iter().any(|use_| {
            use_.base == 0x5200_2000
                || use_
                    .roles
                    .contains(&fat_core::mcu_inspection::PeripheralRole::FlashWritePath)
        })
    });

    if has_flash_text && has_mmio_cluster {
        reports.push(WriteAuthorityReport {
            description: "flash erase/program candidate supported by clustered MMIO and strings"
                .to_string(),
            confidence: 0.46,
            evidence_ids: Vec::new(),
            provenance: Some(SectionProvenance {
                extractor: "write-authority-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: vec![
                    "derived from conservative string evidence".to_string(),
                    "supported by clustered MMIO candidate".to_string(),
                ],
            }),
        });
    }

    reports
}

fn build_main_entry(startup_chain: &StartupChainReport) -> Option<MainEntryReport> {
    let (main, confidence, rationale) = if let Some(main) = startup_chain
        .steps
        .iter()
        .find(|step| step.role == StartupRole::Main)
    {
        (
            main,
            startup_chain.confidence,
            "last recovered startup edge treated as likely main".to_string(),
        )
    } else {
        let candidate = startup_chain.steps.last()?;
        (
            candidate,
            (startup_chain.confidence * 0.8).max(0.3),
            "last recovered startup step retained as likely main candidate".to_string(),
        )
    };
    Some(MainEntryReport {
        entrypoint: Interpretation {
            value: main.address,
            confidence,
            rationale: vec![rationale,
                "vector targets alone do not establish default/custom handler roles or enabled interrupts; non-default handler metric is unresolved".into()],
            evidence_ids: Vec::new(),
        },
        provenance: startup_chain.provenance.clone(),
    })
}

struct BackendSelection {
    execution_backend: String,
    requested: Option<String>,
    alias: Option<String>,
    accepted: bool,
    rejected: Option<String>,
}

fn select_backend(requested: Option<&str>) -> BackendSelection {
    const ALLOWLIST: &[&str] = &["fat-analyze", "native-mcu-inspect"];
    match requested {
        Some(value) if ALLOWLIST.iter().any(|allowed| allowed == &value) => BackendSelection {
            execution_backend: "native-mcu-inspect".to_string(),
            requested: Some(value.to_string()),
            alias: Some(value.to_string()),
            accepted: true,
            rejected: None,
        },
        Some(value) => BackendSelection {
            execution_backend: "native-mcu-inspect".to_string(),
            requested: Some(value.to_string()),
            alias: None,
            accepted: false,
            rejected: Some(value.to_string()),
        },
        None => BackendSelection {
            execution_backend: "native-mcu-inspect".to_string(),
            requested: None,
            alias: None,
            accepted: true,
            rejected: None,
        },
    }
}

#[derive(Debug, Clone)]
struct VectorCandidate {
    offset: usize,
    profile: fat_core::mcu_inspection::McuProfile,
}

fn find_vector_candidates(bytes: &[u8]) -> Vec<VectorCandidate> {
    vector_candidates(bytes)
        .into_iter()
        .filter(|candidate| candidate.accepted)
        // Mapping belongs to the selected table. Keep other structural
        // candidates in identification, never borrow their base for this one.
        .take(1)
        .filter_map(|candidate| {
            let offset = candidate.offset as usize;
            detect_cortex_m_ivt(&bytes[offset..]).map(|profile| VectorCandidate { offset, profile })
        })
        .collect()
}

fn vector_candidate_offsets(bytes: &[u8]) -> Vec<u32> {
    vector_candidates(bytes)
        .into_iter()
        .filter(|candidate| candidate.accepted)
        .map(|candidate| candidate.offset as u32)
        .collect()
}

pub(crate) fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    let array: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn align_down(value: u32, alignment: u32) -> u32 {
    value & !(alignment - 1)
}

pub(crate) fn infer_flash_base(address: u32) -> Option<u32> {
    crate::mcu::infer_code_base(address)
}

fn extract_family_mmio_literals(
    bytes: &[u8],
    resolution: &FamilyResolution,
) -> PeripheralMapReport {
    let mut hits = HashMap::<u32, usize>::new();
    if !resolution.is_enriching_match() {
        return PeripheralMapReport {
            uses: Vec::new(),
            provenance: Some(SectionProvenance {
                extractor: "family-mmio-literal-extractor".to_string(),
                backend: Some("native-mcu-inspect".to_string()),
                family_pack: None,
                notes: vec!["family-pack unavailable".to_string()],
            }),
        };
    }

    for offset in (0..bytes.len().saturating_sub(4)).step_by(4) {
        let Some(word) = read_u32_at(bytes, offset) else {
            continue;
        };
        let Some(range) = resolution.pack.lookup_mmio(word) else {
            continue;
        };
        *hits.entry(range.start).or_insert(0) += 1;
    }

    let uses = resolution
        .pack
        .mmio_ranges
        .iter()
        .filter_map(|range| {
            let count = hits.get(&range.start).copied()?;
            let mut roles = Vec::new();
            for role in range.roles {
                let converted = convert_role(*role);
                if !roles.contains(&converted) {
                    roles.push(converted);
                }
            }
            Some(PeripheralUse {
                family: Some(resolution.pack.family_id.to_string()),
                peripheral_name: range.peripheral_name.to_string(),
                base: range.start as u64,
                roles,
                source: PeripheralEvidenceSource::Mixed,
                confidence: (0.72 + (count as f32 * 0.04)).min(0.96),
                evidence_ids: Vec::new(),
            })
        })
        .collect();

    PeripheralMapReport {
        uses,
        provenance: Some(SectionProvenance {
            extractor: "family-mmio-literal-extractor".to_string(),
            backend: Some("native-mcu-inspect".to_string()),
            family_pack: Some(resolution.pack.family_id.to_string()),
            notes: vec!["derived from exact MMIO literals in the binary".to_string()],
        }),
    }
}

fn dedupe_peripheral_map(mut peripheral_map: PeripheralMapReport) -> PeripheralMapReport {
    let mut merged = HashMap::<(Option<String>, String, u64), PeripheralUse>::new();
    for use_ in peripheral_map.uses.drain(..) {
        let key = (use_.family.clone(), use_.peripheral_name.clone(), use_.base);
        if let Some(existing) = merged.get_mut(&key) {
            existing.confidence = existing.confidence.max(use_.confidence);
            if existing.source != use_.source {
                existing.source = PeripheralEvidenceSource::Mixed;
            }
            for role in use_.roles {
                if !existing.roles.contains(&role) {
                    existing.roles.push(role);
                }
            }
            for evidence in use_.evidence_ids {
                if !existing.evidence_ids.contains(&evidence) {
                    existing.evidence_ids.push(evidence);
                }
            }
        } else {
            merged.insert(key, use_);
        }
    }
    let mut uses: Vec<_> = merged.into_values().collect();
    uses.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.base.cmp(&right.base))
    });
    peripheral_map.uses = uses;
    peripheral_map
}

fn producer_has_role(
    producer_label: Option<&str>,
    peripheral_map: Option<&PeripheralMapReport>,
    peripheral_surface: Option<&PeripheralSurfaceReport>,
    role: fat_core::mcu_inspection::PeripheralRole,
) -> bool {
    let Some(producer_label) = producer_label else {
        return false;
    };
    let normalized = producer_label.to_ascii_lowercase();
    let label_matches = |name: &str| {
        let candidate = name.to_ascii_lowercase();
        normalized.contains(&candidate)
            || candidate.contains(normalized.split('_').next().unwrap_or_default())
    };

    if peripheral_map.is_some_and(|map| {
        map.uses
            .iter()
            .any(|use_| label_matches(&use_.peripheral_name) && use_.roles.contains(&role))
    }) {
        return true;
    }

    peripheral_surface.is_some_and(|surface| {
        surface
            .register_blocks
            .iter()
            .any(|block| label_matches(&block.peripheral_name))
    })
}

fn is_probable_mmio(word: u32) -> bool {
    matches!(word & 0xf000_0000, 0x4000_0000 | 0x5000_0000)
}

fn forms_mmio_cluster(first_word: u32, second_word: u32) -> bool {
    if (first_word & 0x3) != 0 || (second_word & 0x3) != 0 {
        return false;
    }

    let delta = first_word.abs_diff(second_word);
    delta != 0
        && delta <= 0x100
        && delta.is_multiple_of(4)
        && align_down(first_word, 0x1000) == align_down(second_word, 0x1000)
}

pub(crate) fn map_address_to_offset(
    address: u32,
    flash_base: u32,
    vector_offset: u32,
) -> Option<usize> {
    let relative = address.checked_sub(flash_base)?;
    let offset = vector_offset.checked_add(relative)?;
    usize::try_from(offset).ok()
}

pub(crate) fn direct_branch_target(bytes: &[u8], address: u32, offset: usize) -> Option<u32> {
    let opcode = bytes.get(offset..offset + 2)?;
    let halfword = u16::from_le_bytes(opcode.try_into().ok()?);
    if (halfword & 0xf800) != 0xe000 {
        return None;
    }
    let imm11 = (halfword & 0x07ff) as i32;
    let signed = if (imm11 & 0x0400) != 0 {
        imm11 | !0x07ff
    } else {
        imm11
    };
    let delta = signed << 1;
    Some(address.wrapping_add(4).wrapping_add_signed(delta))
}

pub(crate) fn direct_call_target(bytes: &[u8], address: u32, offset: usize) -> Option<u32> {
    let first = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
    let second = u16::from_le_bytes(bytes.get(offset + 2..offset + 4)?.try_into().ok()?);
    if (first & 0xf800) != 0xf000 || (second & 0xd000) != 0xd000 {
        return None;
    }

    let s = ((first >> 10) & 1) as u32;
    let imm10 = (first & 0x03ff) as u32;
    let j1 = ((second >> 13) & 1) as u32;
    let j2 = ((second >> 11) & 1) as u32;
    let imm11 = (second & 0x07ff) as u32;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    let signed = if (imm25 & (1 << 24)) != 0 {
        (imm25 | 0xfe00_0000) as i32
    } else {
        imm25 as i32
    };
    Some(address.wrapping_add(4).wrapping_add_signed(signed))
}

pub(crate) fn section_provenance(extractor: &str, base: Option<u32>) -> SectionProvenance {
    let mut notes = Vec::new();
    if let Some(base) = base {
        notes.push(format!("primary_base=0x{base:08x}"));
    }
    SectionProvenance {
        extractor: extractor.to_string(),
        backend: Some("native-mcu-inspect".to_string()),
        family_pack: None,
        notes,
    }
}
