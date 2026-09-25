//! Presentation only: the inspection report remains the source of every value.
use std::collections::BTreeMap;

use fat_core::mcu_inspection::*;

use crate::report::Report;
use crate::style::Palette;

fn status(p: Palette, value: &str) -> String {
    let badge = format!("[{value}]");
    match value {
        "high" | "corroborated" => p.good(badge),
        "tentative" | "low" | "unknown" | "unresolved" => p.warn(badge),
        _ => p.info(badge),
    }
}

fn addr(p: Palette, address: impl Into<u64>) -> String {
    let address = address.into();
    p.info(format!("0x{address:08X}"))
}

fn matched_execution_observation(item: &ExecutionModelEvidence) -> bool {
    !matches!(
        item.kind,
        EvidenceHeuristicKind::RtosMarkerAbsent { .. }
            | EvidenceHeuristicKind::MainDominatingLoopUnknown
    )
}

pub(crate) fn render(report: &McuInspectionReport, details: bool) -> String {
    let filename = std::path::Path::new(&report.artifact_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty());
    let title = filename
        .map(|name| format!("MCU inspection · {name}"))
        .unwrap_or_else(|| "MCU inspection".into());
    let mut view = Report::new(&title);
    render_identity(report, &mut view);
    render_image(report, details, &mut view);
    render_startup(report, details, &mut view);
    render_interrupts(report, details, &mut view);
    render_hardware(report, details, &mut view);
    view.finish()
}

fn subheading(view: &mut Report, title: &str) {
    view.text(view.palette().key(title));
}

fn remaining(view: &mut Report, count: usize, shown: usize, noun: &str) {
    if count > shown {
        view.text(format!("{} more {noun}; --details", count - shown));
    }
}

fn render_identity(report: &McuInspectionReport, view: &mut Report) {
    let p = view.palette();
    let mut identity = Vec::new();
    if let Some(id) = &report.identification {
        if let Some(family) = &id.family {
            identity.push(format!(
                "{}{}",
                p.good(family),
                if matches!(id.family_confidence.as_str(), "high" | "corroborated") {
                    String::new()
                } else {
                    format!(" {}", status(p, &id.family_confidence))
                }
            ));
        }
        if let Some(core) = report
            .register_annotations
            .as_ref()
            .and_then(|r| r.core_name.as_ref())
        {
            let origin = if let Some(registers) = report
                .register_annotations
                .as_ref()
                .filter(|r| r.profile_selection == "user-assumption")
            {
                let selected = registers
                    .family_profile
                    .as_deref()
                    .or(report.analysis_provenance.user_family.as_deref());
                selected
                    .map(|name| format!("supplied profile: {name}"))
                    .unwrap_or_else(|| "supplied profile".into())
            } else {
                "profile".into()
            };
            identity.push(format!("{core} ({origin})"));
        } else if let Some(architecture) = &id.architecture {
            identity.push(if id.architecture_confidence == "high" {
                architecture.clone()
            } else {
                format!("{architecture} {}", status(p, &id.architecture_confidence))
            });
        }
        if let Some(role) = &id.image_role {
            identity.push(match role.as_str() {
                "boot-rom-likely" => "Likely boot ROM".into(),
                _ => role.replace('-', " "),
            });
        }
    } else if let Some(profile) = &report.fast_profile {
        identity.push(format!("{} (heuristic)", profile.chip_family));
        identity.push(profile.architecture.clone());
    }
    if !identity.is_empty() {
        view.text(identity.join(" · "));
    }
}

fn size_label(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    }
}

fn render_image(report: &McuInspectionReport, details: bool, view: &mut Report) {
    let p = view.palette();
    view.section("Image");
    if details && !report.artifact_path.is_empty() {
        view.kv("Path", &report.artifact_path);
    }
    if let Some(m) = &report.byte_measurements {
        let repeated = m
            .repetition
            .repeated_unit_bytes
            .map(|unit| {
                format!(
                    "; {} identical copies of {}",
                    m.repetition.copies,
                    size_label(unit)
                )
            })
            .unwrap_or_default();
        view.kv("Size", format!("{}{repeated}", size_label(m.total_bytes)));
        if details {
            view.kv("Raw size", format!("{} bytes", m.total_bytes));
            let rows = [
                (
                    "From exact copies",
                    m.repetition.duplicate_blocks_from_copies,
                ),
                ("From uniform fill", m.repetition.duplicate_uniform_blocks),
                ("Unexplained", m.repetition.unexplained_duplicate_blocks),
            ]
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(label, count)| vec![label.into(), count.to_string()])
            .collect::<Vec<_>>();
            if !rows.is_empty() {
                view.table(&["Duplicate blocks", "Count"], &rows);
            }
        }
    }
    if let Some(hypotheses) = &report.address_hypotheses {
        if let Some(base) = hypotheses.iter().find(|h| h.is_primary) {
            view.kv(
                if report.analysis_provenance.user_base.is_some() {
                    "Base (supplied)"
                } else {
                    "Base candidate"
                },
                addr(p, base.base),
            );
        }
        if details && !hypotheses.is_empty() {
            subheading(view, "Address hypotheses");
            view.table(
                &["Base", "Selection", "Confidence score"],
                &hypotheses
                    .iter()
                    .map(|h| {
                        vec![
                            addr(p, h.base),
                            if h.is_primary {
                                "selected".into()
                            } else {
                                "alternative".into()
                            },
                            format!("{:.2}", h.confidence),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
    }
    let entry = report
        .identification
        .as_ref()
        .and_then(|id| {
            id.vector_candidates
                .iter()
                .find(|v| v.accepted)
                .map(|v| (v.initial_sp, v.reset_vector))
        })
        .or_else(|| {
            report
                .fast_profile
                .as_ref()
                .map(|p| (p.initial_sp, p.reset_vector))
        });
    if let Some((sp, reset)) = entry {
        view.kv("Initial SP", addr(p, sp));
        view.kv("Reset handler", addr(p, reset & !1));
        if details {
            view.kv("Reset Thumb pointer", addr(p, reset));
        }
    }
    if let Some(id) = &report.identification {
        for candidate in id.vector_candidates.iter().filter(|c| c.accepted) {
            for conflict in &candidate.contradictions {
                view.kv(
                    &format!("Vector +0x{:X} conflict", candidate.offset),
                    p.warn(conflict),
                );
            }
        }
        if details && !id.identity_strings.is_empty() {
            let mut identities: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
            for hit in &id.identity_strings {
                identities
                    .entry((&hit.encoding, &hit.value))
                    .or_default()
                    .push(format!("+0x{:X}", hit.offset));
            }
            subheading(view, "Identity strings");
            view.table(
                &["File offsets", "Encoding", "Identity text"],
                &identities
                    .into_iter()
                    .map(|((encoding, value), offsets)| {
                        vec![offsets.join(", "), encoding.into(), value.into()]
                    })
                    .collect::<Vec<_>>(),
            );
        }
    }
    if details {
        if let Some(partitions) = &report.sram_partitions {
            render_sram_partitions(partitions, view);
        }
    }
}

fn startup_role(role: StartupRole) -> &'static str {
    match role {
        StartupRole::ResetStub => "Reset",
        StartupRole::StartupStub => "startup stub",
        StartupRole::SystemInit => "SystemInit",
        StartupRole::RuntimeInit => "runtime init",
        StartupRole::Main => "main",
        StartupRole::Unknown => "unknown step",
    }
}

fn render_startup(report: &McuInspectionReport, details: bool, view: &mut Report) {
    let p = view.palette();
    let chain = report
        .startup_chain
        .as_ref()
        .filter(|c| !c.steps.is_empty());
    let code = report
        .code_analysis
        .as_ref()
        .filter(|c| c.instruction_count > 0);
    let table = report.init_table.as_ref().filter(|t| !t.records.is_empty());
    let effects = report
        .system_init_effects
        .as_ref()
        .filter(|e| has_system_init_effects(e));
    let model = report
        .execution_model
        .as_ref()
        .filter(|m| m.model.value != ExecutionModelKind::Unknown);
    if chain.is_none()
        && table.is_none()
        && effects.is_none()
        && model.is_none()
        && !(details && code.is_some())
    {
        return;
    }
    view.section("Startup");
    if let Some(chain) = chain {
        if details {
            subheading(view, "Startup chain");
            view.table(
                &["Candidate step", "Handler"],
                &chain
                    .steps
                    .iter()
                    .map(|step| {
                        vec![
                            format!("{}: {}", step.ordinal, startup_role(step.role)),
                            addr(p, step.address & !1),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        } else {
            view.kv(
                "Candidate path",
                chain
                    .steps
                    .iter()
                    .take(5)
                    .enumerate()
                    .map(|(index, step)| {
                        if index == 0 {
                            format!("{} {}", startup_role(step.role), addr(p, step.address & !1))
                        } else {
                            addr(p, step.address & !1)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" → "),
            );
            remaining(view, chain.steps.len(), 5, "startup steps");
        }
    }
    if let Some(table) = table {
        if details {
            render_initialization(report, view);
        } else {
            let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
            for record in &table.records {
                *kinds
                    .entry(init_handler_kind_label(record.handler_kind))
                    .or_default() += 1;
            }
            view.kv(
                "Init descriptors",
                format!(
                    "{}; {} bytes destination coverage",
                    kinds
                        .into_iter()
                        .map(|(kind, count)| format!("{count} {kind}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    table.total_dst_coverage
                ),
            );
        }
    }
    if let Some(effects) = effects {
        if details {
            render_system_init_effects(effects, view);
        } else {
            let mut summary = Vec::new();
            if effects.fpu != FpuStatus::Unknown {
                summary.push(format!(
                    "FPU {}",
                    if effects.fpu == FpuStatus::Enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ));
            }
            if let Some(latency) = effects.flash_latency {
                summary.push(format!("flash latency {latency}"));
            }
            summary.extend(
                effects
                    .clock_effects
                    .iter()
                    .map(|e| clock_effect_label(e.kind))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(str::to_owned),
            );
            summary.extend(
                effects
                    .cache_effects
                    .iter()
                    .map(|e| cache_effect_label(e.kind))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(str::to_owned),
            );
            if effects.mpu_configured {
                summary.push("MPU configured".into());
            }
            if let Some(enabled) = effects.art_accel {
                summary.push(if enabled {
                    "ART enabled".into()
                } else {
                    "ART written".into()
                });
            }
            if let Some(write) = &effects.vtor_write {
                summary.push(format!(
                    "VTOR {}",
                    write
                        .value
                        .map(|v| format!("0x{v:08X}"))
                        .unwrap_or_else(|| "unresolved write".into())
                ));
            }
            if effects.vtor_relocation_check.is_some() {
                summary.push("VTOR relocation check".into());
            }
            if !effects.unclassified_writes.is_empty() {
                summary.push(format!(
                    "{} unclassified writes",
                    effects.unclassified_writes.len()
                ));
            }
            view.kv("SystemInit effects", summary.join(", "));
        }
    }
    if let Some(model) = model {
        let name = match model.model.value {
            ExecutionModelKind::Superloop => "superloop",
            ExecutionModelKind::Rtos => "RTOS",
            ExecutionModelKind::IsrDriven => "ISR-driven",
            ExecutionModelKind::Mixed => "mixed",
            ExecutionModelKind::Unknown => "unknown",
        };
        view.kv("Execution model", format!("{name} (heuristic)"));
        if details {
            if !model.loop_heads.is_empty() {
                view.kv(
                    "Loop heads",
                    model
                        .loop_heads
                        .iter()
                        .map(|a| addr(p, *a))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            for item in model
                .supporting_evidence
                .iter()
                .filter(|item| matched_execution_observation(item))
            {
                view.kv("Supporting observation", &item.description);
            }
        }
        for item in model
            .anti_evidence
            .iter()
            .filter(|item| matched_execution_observation(item))
        {
            view.kv("Conflicting observation", &item.description);
        }
    }
    if let Some(code) = code.filter(|_| details) {
        subheading(view, "Code analysis");
        view.kv(
            "Decoded instructions",
            format!(
                "{} across {} blocks{}",
                code.instruction_count,
                code.block_count,
                if code.budget_exhausted {
                    " (partial; budget reached)"
                } else {
                    ""
                }
            ),
        );
        if !code.literal_references.is_empty() {
            view.kv(
                "Literal references",
                code.literal_references.len().to_string(),
            );
        }
        if !code.initialization.is_empty() {
            view.kv(
                "Initialization descriptors",
                code.initialization.len().to_string(),
            );
        }
        if !code.function_candidates.is_empty() {
            view.table(
                &["Function candidate", "File offset", "Evidence"],
                &code
                    .function_candidates
                    .iter()
                    .map(|f| {
                        vec![
                            addr(p, f.address),
                            format!("+0x{:X}", f.file_offset),
                            f.reasons.join(", "),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if !code.string_references.is_empty() {
            view.table(
                &["String offset", "Encoding", "Referenced by", "Text"],
                &code
                    .string_references
                    .iter()
                    .map(|s| {
                        vec![
                            format!("+0x{:X}", s.file_offset),
                            s.encoding.clone(),
                            addr(p, s.instruction_address),
                            format!("{:?}", s.value),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
    }
}

fn vector_label(entry: &InterruptVectorEntry) -> String {
    if entry.index >= 16 {
        let irq = format!("IRQ {}", entry.index - 16);
        entry
            .family_label
            .as_ref()
            .map(|label| format!("{irq} {label}"))
            .unwrap_or(irq)
    } else {
        entry
            .core_exception
            .clone()
            .unwrap_or_else(|| format!("vector {}", entry.index))
    }
}

fn populated(entry: &InterruptVectorEntry) -> bool {
    matches!(
        entry.handler_kind,
        InterruptHandlerKind::ResetHandler
            | InterruptHandlerKind::Interrupt
            | InterruptHandlerKind::DefaultHandler
    )
}

fn render_interrupts(report: &McuInspectionReport, details: bool, view: &mut Report) {
    let Some(table) = report.vector_table.as_ref().filter(|t| t.active_count > 0) else {
        if details
            && report
                .shared_state_risk
                .as_ref()
                .is_some_and(|r| !r.ranked_findings.is_empty())
        {
            view.section("Interrupts");
            render_shared_state(report, view);
        }
        return;
    };
    let p = view.palette();
    view.section("Interrupts");
    view.kv(
        "Populated vectors",
        format!(
            "{} core (including Reset), {} external IRQs",
            table.core_exception_count, table.external_irq_count
        ),
    );
    if details {
        subheading(view, "Vector table");
        view.kv("Entries scanned", table.scanned_word_count.to_string());
        if table.entry_count != table.scanned_word_count {
            view.kv("Entries retained", table.entry_count.to_string());
        }
        for (label, count) in [
            ("Reserved positions", table.reserved_entry_count),
            ("Unpopulated positions", table.unpopulated_entry_count),
        ] {
            if count > 0 {
                view.kv(label, count.to_string());
            }
        }
        view.table(
            &["Vector / label", "Aligned handler", "Thumb pointer"],
            &table
                .entries
                .iter()
                .filter(|e| populated(e))
                .map(|e| {
                    vec![
                        format!("{}: {}", e.index, vector_label(e)),
                        addr(p, e.address & !1),
                        addr(p, e.address),
                    ]
                })
                .collect::<Vec<_>>(),
        );
    } else {
        let mut targets: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for entry in table
            .entries
            .iter()
            .filter(|e| e.index >= 16 && populated(e))
        {
            targets
                .entry(entry.address & !1)
                .or_default()
                .push(vector_label(entry));
        }
        for (target, labels) in targets.iter().take(6) {
            let mut summary = labels
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if labels.len() > 6 {
                summary.push_str(&format!(", {} more; --details", labels.len() - 6));
            }
            view.kv(&format!("0x{target:08X}"), summary);
        }
        remaining(view, targets.len(), 6, "IRQ targets");
    }
    if details {
        render_shared_state(report, view);
    }
}

fn render_shared_state(report: &McuInspectionReport, view: &mut Report) {
    if let Some(risk) = report
        .shared_state_risk
        .as_ref()
        .filter(|r| !r.ranked_findings.is_empty())
    {
        subheading(view, "ISR / shared state");
        for finding in &risk.ranked_findings {
            view.kv("Shared-state candidate", &finding.title);
        }
    }
}

fn register_names(items: &[fat_core::mcu_registers::RegisterName]) -> String {
    if items.is_empty() {
        return "unnamed".into();
    }
    items
        .iter()
        .map(|n| match &n.condition {
            Some(condition) => format!("{}.{} ({condition})", n.peripheral, n.register),
            None => format!("{}.{}", n.peripheral, n.register),
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn render_hardware(report: &McuInspectionReport, details: bool, view: &mut Report) {
    let registers = report
        .register_annotations
        .as_ref()
        .filter(|r| !r.accesses.is_empty() || (details && !r.address_references.is_empty()));
    let map = report
        .peripheral_map
        .as_ref()
        .filter(|m| !m.uses.is_empty());
    let surface = report
        .peripheral_surface
        .as_ref()
        .filter(|s| !s.register_blocks.is_empty() || !s.recovered_configs.is_empty());
    if registers.is_none() && !(details && (map.is_some() || surface.is_some())) {
        return;
    }
    let p = view.palette();
    view.section("Hardware");
    if let Some(registers) = registers {
        if details {
            if let Some(profile) = &registers.family_profile {
                view.kv(
                    "Register profile",
                    format!("{profile} ({})", registers.profile_selection),
                );
            }
        }
        if !registers.accesses.is_empty() {
            subheading(view, "Hardware registers accessed");
            if details {
                view.table(
                    &[
                        "Operation",
                        "Register address",
                        "Instruction / file",
                        "Register",
                    ],
                    &registers
                        .accesses
                        .iter()
                        .map(|a| {
                            vec![
                                format!("{} {} B", a.access, a.width_bytes),
                                addr(p, a.target),
                                format!(
                                    "{} / +0x{:X}",
                                    addr(p, a.instruction_address),
                                    a.instruction_offset
                                ),
                                register_names(&a.names),
                            ]
                        })
                        .collect::<Vec<_>>(),
                );
            } else {
                let mut grouped: BTreeMap<(u32, &str, u8, String), usize> = BTreeMap::new();
                for access in &registers.accesses {
                    *grouped
                        .entry((
                            access.target,
                            &access.access,
                            access.width_bytes,
                            register_names(&access.names),
                        ))
                        .or_default() += 1;
                }
                view.table(
                    &["Register address", "Operation", "Register"],
                    &grouped
                        .iter()
                        .take(8)
                        .map(|((target, access, width, names), count)| {
                            vec![
                                addr(p, *target),
                                format!(
                                    "{access} {width} B{}",
                                    if *count > 1 {
                                        format!(" ({count} sites)")
                                    } else {
                                        String::new()
                                    }
                                ),
                                names.clone(),
                            ]
                        })
                        .collect::<Vec<_>>(),
                );
                remaining(view, grouped.len(), 8, "MMIO access groups");
            }
        }
        if details && !registers.address_references.is_empty() {
            subheading(view, "Address constants");
            view.table(
                &[
                    "Constant",
                    "Literal offset",
                    "Instruction",
                    "Register candidate",
                ],
                &registers
                    .address_references
                    .iter()
                    .map(|a| {
                        vec![
                            addr(p, a.value),
                            format!("+0x{:X}", a.pool_offset),
                            addr(p, a.instruction_address),
                            register_names(&a.names),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
    }

    if details {
        if let Some(map) = map {
            subheading(view, "Peripheral candidates");
            view.table(
                &["Peripheral candidate", "Base", "Evidence source"],
                &map.uses
                    .iter()
                    .map(|x| {
                        vec![
                            x.peripheral_name.clone(),
                            addr(p, x.base),
                            format!("{:?}", x.source).to_lowercase(),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if let Some(surface) = surface {
            if !surface.register_blocks.is_empty() {
                subheading(view, "Peripheral surface");
                view.table(
                    &["Peripheral", "Base", "Observed registers"],
                    &surface
                        .register_blocks
                        .iter()
                        .map(|x| {
                            vec![
                                x.peripheral_name.clone(),
                                addr(p, x.base),
                                x.observed_registers.join(", "),
                            ]
                        })
                        .collect::<Vec<_>>(),
                );
            }
            for config in &surface.recovered_configs {
                view.kv("Config candidate", &config.summary);
            }
        }
    }
}

fn render_initialization(report: &McuInspectionReport, view: &mut Report) {
    let p = view.palette();
    let Some(table) = report.init_table.as_ref().filter(|t| !t.records.is_empty()) else {
        return;
    };
    subheading(view, "Init descriptor table");
    view.kv(
        "Bounds",
        format!(
            "{} - {}",
            addr(p, table.base_address),
            addr(p, table.end_address)
        ),
    );
    if table.segments.len() > 1 {
        view.kv(
            "Format",
            format!(
                "mixed ({} records across {} tables)",
                table.records.len(),
                table.segments.len()
            ),
        );
        view.table(
            &["Segment", "Format", "Range", "Records"],
            &table
                .segments
                .iter()
                .map(|s| {
                    vec![
                        s.index.to_string(),
                        init_table_format_label(s.format).into(),
                        format!("0x{:08X} - 0x{:08X}", s.base_address, s.end_address),
                        s.record_count.to_string(),
                    ]
                })
                .collect::<Vec<_>>(),
        );
    } else {
        view.kv(
            "Format",
            format!(
                "{} ({} records, stride {} B)",
                init_table_format_label(table.format),
                table.records.len(),
                table.record_stride
            ),
        );
    }
    view.table(
        &[
            "Record",
            "Destination range",
            "Size",
            "Source",
            "Handler / kind",
        ],
        &table
            .records
            .iter()
            .map(|r| {
                vec![
                    r.index.to_string(),
                    format!("0x{:08X} - 0x{:08X}", r.dst, r.dst.saturating_add(r.size)),
                    format!("{} B", r.size),
                    r.src
                        .map(|s| format!("0x{s:08X}"))
                        .unwrap_or_else(|| "zero-fill".into()),
                    format!(
                        "{} / {}",
                        r.handler
                            .map(|s| format!("0x{s:08X}"))
                            .unwrap_or_else(|| "-".into()),
                        init_handler_kind_label(r.handler_kind)
                    ),
                ]
            })
            .collect::<Vec<_>>(),
    );
    view.kv(
        "Total dst coverage",
        format!(
            "0x{:X} bytes ({})",
            table.total_dst_coverage, table.total_dst_coverage
        ),
    );
    if let Some(sp) = table.initial_sp {
        view.kv(
            "Stack top (SP)",
            format!(
                "0x{sp:08X} [{} dst end 0x{:08X}]",
                if table.matches_initial_sp {
                    "matches"
                } else {
                    "differs from"
                },
                table.max_dst_end
            ),
        );
    }
    view.kv("Confidence score", format!("{:.2}", table.confidence));
    render_init_handlers(table, view);
}

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

fn render_init_handlers(table: &InitTableReport, view: &mut Report) {
    let classified: Vec<_> = table
        .records
        .iter()
        .filter_map(|record| {
            let classification = record.handler_classification.as_ref()?;
            if classification.kind == InitHandlerKind::Unknown {
                return None;
            }
            let handler = record.handler?;
            Some((record.index, handler, classification))
        })
        .collect();
    if classified.is_empty() {
        return;
    }

    view.text("");
    subheading(view, "Runtime init handlers");
    for (index, handler, classification) in classified {
        let variant = classification
            .compressor
            .map(|variant| format!(", variant: {}", compressor_variant_label(variant)))
            .unwrap_or_default();
        view.text(format!(
            "  Record {index} handler @ 0x{handler:08X}: {}{variant} (conf {:.2})",
            init_handler_kind_label(classification.kind),
            classification.confidence
        ));
    }

    let Some(fingerprint) = table
        .toolchain_fingerprint
        .as_ref()
        .filter(|f| f.data_compression.is_some() || !f.consistent_with.is_empty())
    else {
        return;
    };
    view.text("");
    subheading(view, "Toolchain fingerprint");
    if let Some(variant) = fingerprint.data_compression {
        view.text(format!(
            "  .data compression:  {} (conf {:.2})",
            compressor_variant_label(variant),
            fingerprint.confidence
        ));
    }
    if !fingerprint.consistent_with.is_empty() {
        view.text(format!(
            "  consistent with:    {}",
            fingerprint.consistent_with.join(", ")
        ));
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

fn render_sram_partitions(report: &SramPartitionReport, view: &mut Report) {
    let matched = report
        .sram_regions
        .iter()
        .filter(|partition| {
            partition.linker_cap_basis != LinkerCapBasis::NoEvidence
                || !partition.runtime_literal_references.is_empty()
        })
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }
    subheading(view, "SRAM partition estimates");
    for partition in matched {
        let label = partition.region.label.as_deref().unwrap_or("sram");
        let end = partition.region.end.unwrap_or(partition.region.start);
        let total = end.saturating_sub(partition.region.start);
        let header = format!(
            "  {label} (0x{:08X} - 0x{end:08X}, {total} B)",
            partition.region.start
        );

        view.text(header);
        let percent = |bytes: u64| -> f64 {
            if total == 0 {
                0.0
            } else {
                (bytes as f64) * 100.0 / (total as f64)
            }
        };
        if partition.linker_bytes > 0 {
            view.text(format!(
                "    Linker-managed estimate   0x{:08X} - 0x{:08X}  ({} B / {:.2}%)",
                partition.linker_managed.start,
                partition.linker_managed.end,
                partition.linker_bytes,
                percent(partition.linker_bytes)
            ));
            view.text(format!(
                "      from {}",
                linker_cap_basis_label(partition.linker_cap_basis)
            ));
        }
        if partition.runtime_bytes > 0 {
            view.text(format!(
                "    Remaining region estimate  0x{:08X} - 0x{:08X}  ({} B / {:.2}%)",
                partition.runtime_managed.start,
                partition.runtime_managed.end,
                partition.runtime_bytes,
                percent(partition.runtime_bytes)
            ));
        }
        if !partition.runtime_literal_references.is_empty() {
            view.text(format!(
                "    Static pointer literals into remaining region: {}",
                partition.runtime_literal_total
            ));
            for reference in &partition.runtime_literal_references {
                let sites = reference
                    .referenced_from
                    .iter()
                    .map(|site| format!("0x{site:08X}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                view.text(format!(
                    "      0x{:08X}  {}-byte aligned, referenced from {} site{} [{sites}]",
                    reference.target,
                    reference.alignment,
                    reference.referenced_from.len(),
                    if reference.referenced_from.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                ));
            }
        }
        if let Some(ThreatModelHint::DmaReachable { masters }) = &partition.threat_model_hint {
            if !masters.is_empty() {
                view.kv(
                    "DMA master candidates",
                    format!("{} (peripheral heuristic)", masters.join(", ")),
                );
            }
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

fn has_system_init_effects(report: &SystemInitEffectsReport) -> bool {
    !(report.fpu == FpuStatus::Unknown
        && report.flash_latency.is_none()
        && report.clock_effects.is_empty()
        && report.cache_effects.is_empty()
        && !report.mpu_configured
        && report.art_accel.is_none()
        && report.vtor_relocation_check.is_none()
        && report.vtor_write.is_none()
        && report.unclassified_writes.is_empty())
}

fn render_system_init_effects(report: &SystemInitEffectsReport, view: &mut Report) {
    subheading(view, "SystemInit effects");
    view.text(format!(
        "  SystemInit @ 0x{:08X} ({} bytes decoded, conf {:.2})",
        report.function_address, report.function_size, report.confidence
    ));
    if report.fpu != FpuStatus::Unknown {
        view.text(format!(
            "    FPU:            {}",
            match report.fpu {
                FpuStatus::Enabled => "enabled (CPACR.CP10/CP11 full access)",
                FpuStatus::Disabled => "disabled (CPACR.CP10/CP11 cleared)",
                FpuStatus::Unknown => "unknown",
            }
        ));
    }
    if let Some(latency) = report.flash_latency {
        view.text(format!(
            "    Flash latency:  {latency} wait state{}",
            if latency == 1 { "" } else { "s" }
        ));
    }
    if !report.clock_effects.is_empty() {
        let effects = report
            .clock_effects
            .iter()
            .map(|effect| clock_effect_label(effect.kind))
            .collect::<Vec<_>>()
            .join(", ");
        view.text(format!("    Clock tree:     {effects}"));
    }
    if !report.cache_effects.is_empty() {
        let effects = report
            .cache_effects
            .iter()
            .map(|effect| cache_effect_label(effect.kind))
            .collect::<Vec<_>>()
            .join(", ");
        view.text(format!("    Cache:          {effects}"));
    }
    if report.mpu_configured {
        view.text("    MPU:            configured");
    }
    if let Some(enabled) = report.art_accel {
        view.text(format!(
            "    ART accel:      {}",
            if enabled { "enabled" } else { "written" }
        ));
    }
    if let Some(check) = report.vtor_relocation_check.as_ref() {
        view.text(format!(
            "    VTOR check:     present (compare against 0x{:08X} at 0x{:08X})",
            check.sentinel_value, check.instruction_addr
        ));
    }
    if let Some(write) = report.vtor_write.as_ref() {
        match write.value {
            Some(value) => view.text(format!("    VTOR write:     0x{value:08X}")),
            None => view.text("    VTOR write:     value unresolved"),
        }
    }
    if !report.unclassified_writes.is_empty() {
        view.text("    Unclassified peripheral writes:");
        for write in &report.unclassified_writes {
            match write.value {
                Some(value) => view.text(format!(
                    "      0x{:08X} <- 0x{value:08X}  (at 0x{:08X})",
                    write.target, write.at
                )),
                None => view.text(format!(
                    "      0x{:08X} <- unresolved   (at 0x{:08X})",
                    write.target, write.at
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_report_keeps_present_markers_without_absent_marker_prose() {
        let report = McuInspectionReport {
            execution_model: Some(ExecutionModelReport {
                model: Interpretation {
                    value: ExecutionModelKind::Rtos,
                    ..Default::default()
                },
                supporting_evidence: vec![
                    ExecutionModelEvidence {
                        kind: EvidenceHeuristicKind::RtosMarkerPresent {
                            family: "freertos".into(),
                            symbol: "vTaskStartScheduler".into(),
                        },
                        description: "vTaskStartScheduler marker".into(),
                        artifact_ref: None,
                    },
                    ExecutionModelEvidence {
                        kind: EvidenceHeuristicKind::RtosMarkerAbsent {
                            family: "zephyr".into(),
                        },
                        description: "no zephyr kernel symbols found".into(),
                        artifact_ref: None,
                    },
                ],
                anti_evidence: vec![ExecutionModelEvidence {
                    kind: EvidenceHeuristicKind::MainDominatingLoopUnknown,
                    description: "startup chain has no Main step".into(),
                    artifact_ref: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let output = render(&report, true);
        assert!(output.contains("Execution model"));
        assert!(output.contains("vTaskStartScheduler marker"));
        assert!(!output.contains("no zephyr"));
        assert!(!output.contains("no Main step"));
    }

    #[test]
    fn unknown_init_handler_omits_classification_but_keeps_descriptor() {
        let mut report = McuInspectionReport {
            init_table: Some(InitTableReport {
                records: vec![InitRecord {
                    handler: Some(0x08000100),
                    dst: 0x20000000,
                    size: 32,
                    handler_classification: Some(InitHandlerClassification::default()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let unknown = render(&report, true);
        assert!(unknown.contains("Init descriptor table"));
        assert!(unknown.contains("0x20000000"));
        assert!(!unknown.contains("Runtime init handlers"));
        report.init_table.as_mut().unwrap().records[0].handler_classification =
            Some(InitHandlerClassification {
                kind: InitHandlerKind::WordCopy,
                confidence: 0.9,
                ..Default::default()
            });
        let matched = render(&report, true);
        assert!(matched.contains("Runtime init handlers"));
        assert!(matched.contains("word-copy"));
    }

    #[test]
    fn overview_uses_basename_and_aligned_entry_details_keep_thumb_pointer() {
        let report = McuInspectionReport {
            artifact_path: "/some/long/location/firmware.bin".into(),
            identification: Some(McuIdentification {
                family: Some("Example family".into()),
                family_confidence: "high".into(),
                image_role: Some("boot-rom-likely".into()),
                vector_candidates: vec![McuVectorCandidate {
                    initial_sp: 0x20001000,
                    reset_vector: 0x08000105,
                    accepted: true,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            analysis_provenance: AnalysisProvenance {
                user_family: Some("different".into()),
                ..Default::default()
            },
            register_annotations: Some(fat_core::mcu_registers::RegisterAnnotationReport {
                core_name: Some("ARM Cortex-M3".into()),
                family_profile: Some("different".into()),
                profile_selection: "user-assumption".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let overview = render(&report, false);
        assert!(overview.contains("firmware.bin"));
        assert!(!overview.contains("/some/long/location"));
        assert!(overview.contains("0x08000104"));
        assert!(!overview.contains("0x08000105"));
        assert!(overview.contains("Example family"));
        assert!(!overview.contains("supplied family"));
        assert!(overview.contains("supplied profile: different"));
        assert!(overview.contains("Likely boot ROM"));
        let details = render(&report, true);
        assert!(details.contains("/some/long/location/firmware.bin"));
        assert!(details.contains("Reset Thumb pointer"));
        assert!(details.contains("0x08000105"));
    }

    #[test]
    fn hardware_groups_static_sites_without_merging_direction_width_or_conditions() {
        use fat_core::mcu_registers::*;
        let name = RegisterName {
            peripheral: "SERIAL".into(),
            register: "DATA".into(),
            condition: Some("mode A".into()),
            ..Default::default()
        };
        let read = RegisterAccessAnnotation {
            target: 0x40000000,
            access: "read".into(),
            width_bytes: 4,
            names: vec![name],
            ..Default::default()
        };
        let report = McuInspectionReport {
            register_annotations: Some(RegisterAnnotationReport {
                accesses: vec![
                    read.clone(),
                    RegisterAccessAnnotation {
                        instruction_address: 0x08000102,
                        ..read.clone()
                    },
                    RegisterAccessAnnotation {
                        access: "write".into(),
                        ..read.clone()
                    },
                    RegisterAccessAnnotation {
                        width_bytes: 1,
                        ..read
                    },
                ],
                address_references: vec![RegisterAddressReference {
                    value: 0xE000E010,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let overview = render(&report, false);
        assert!(overview.contains("read 4 B (2 sites)"));
        assert!(overview.contains("write 4 B"));
        assert!(overview.contains("read 1 B"));
        assert!(overview.contains("mode A"));
        assert!(!overview.contains("Address constants"));
        assert!(!overview.contains("0xE000E010"));
        let details = render(&report, true);
        assert!(details.contains("Address constants"));
        assert!(details.contains("0xE000E010"));
        assert!(!details.contains("2 sites"));
    }

    #[test]
    fn overview_caps_startup_steps_while_details_preserves_each_step() {
        let report = McuInspectionReport {
            startup_chain: Some(StartupChainReport {
                steps: (0..7)
                    .map(|ordinal| StartupStep {
                        ordinal,
                        address: 0x08001000 + u32::from(ordinal) * 16,
                        role: StartupRole::StartupStub,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let overview = render(&report, false);
        assert!(overview.contains("2 more startup steps; --details"));
        assert!(!overview.contains("0x08001060"));
        let details = render(&report, true);
        assert!(details.contains("0x08001060"));
        assert!(!details.contains("more startup steps"));
    }

    #[test]
    fn details_keep_descriptor_counts_and_independent_shared_state_findings() {
        let report = McuInspectionReport {
            code_analysis: Some(fat_core::mcu_code::McuCodeReport {
                instruction_count: 1,
                literal_references: vec![fat_core::mcu_code::CodeLiteralReference {
                    instruction_address: 0x08000100,
                    instruction_offset: 0x100,
                    pool_address: 0x08000104,
                    pool_offset: 0x104,
                    value: 0x20000000,
                }],
                initialization: vec![fat_core::mcu_code::CodeInitialization {
                    record_address: 0x08000200,
                    kind: "zero-init".into(),
                    source: None,
                    destination: 0x20000000,
                    length: 32,
                }],
                ..Default::default()
            }),
            shared_state_risk: Some(SharedStateRiskReport {
                ranked_findings: vec![SharedStateFinding {
                    title: "Shared state observed".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let details = render(&report, true);
        assert!(details.contains("Literal references"));
        assert!(details.contains("Initialization descriptors"));
        assert!(details.contains("Shared state observed"));
        let overview = render(&report, false);
        assert!(!overview.contains("Literal references"));
        assert!(!overview.contains("Shared state observed"));
    }
}
