//! Attach profile register names to bounded static code evidence. This module
//! never scans arbitrary words or converts literal addresses into accesses.
use fat_core::mcu_code::{McuCodeReport, MemoryAccessKind};
use fat_core::mcu_registers::{
    RegisterAccessAnnotation, RegisterAddressReference, RegisterAnnotationReport, RegisterName,
    RegisterSource,
};
use fat_family::mcu_packs::{DocumentedRegisterSpec, ProfileSource, RegisterAccess};

use crate::mcu_family::{FamilyResolution, FamilyResolutionMode};

pub fn annotate_registers(
    code: &McuCodeReport,
    family: &FamilyResolution,
) -> RegisterAnnotationReport {
    let selected = family.is_enriching_match();
    let mut report = RegisterAnnotationReport {
        family_profile: selected.then(|| family.pack.family_id.to_string()),
        profile_selection: match family.mode {
            FamilyResolutionMode::UserExact => "user-assumption",
            FamilyResolutionMode::FastProfileExact => "inferred-family-profile",
            FamilyResolutionMode::Fallback => "unresolved",
        }
        .into(),
        notes: vec![
            "Memory accesses: statically decoded instructions with resolved addresses.".into(),
            "Address references: constants loaded by instructions.".into(),
            "Register names: documented entries in the selected profile.".into(),
        ],
        ..Default::default()
    };
    let specs: Vec<&DocumentedRegisterSpec> = if selected {
        if let Some(core) = family.pack.core {
            report.core_name = Some(core.name.into());
            report.core_source = Some(source(core.source));
            report
                .notes
                .push("Core name from the selected family profile.".into());
        }
        report
            .notes
            .extend(family.pack.memory_notes.iter().map(|note| note.to_string()));
        family
            .pack
            .documented_registers
            .iter()
            .chain(family.pack.core_registers)
            .collect()
    } else {
        report.notes.push("Family profile: unresolved.".into());
        Vec::new()
    };

    for access in &code.memory_accesses {
        if !mmio_address(access.target) {
            continue;
        }
        let candidates = names_at(
            &specs,
            access.target,
            Some((access.access, access.width_bytes)),
        );
        let mut notes = Vec::new();
        if candidates.len() > 1 {
            notes.push("Register aliases share this address.".into());
        }
        if candidates.is_empty() {
            if names_at(&specs, access.target, None).is_empty() {
                notes.push("Address absent from the selected register profile.".into());
            } else {
                notes.push(
                    "Register definition conflicts with access direction, width, or alignment."
                        .into(),
                );
            }
        }
        report.accesses.push(RegisterAccessAnnotation {
            instruction_address: access.instruction_address,
            instruction_offset: access.instruction_offset,
            target: access.target,
            access: match access.access {
                MemoryAccessKind::Read => "read",
                MemoryAccessKind::Write => "write",
            }
            .into(),
            width_bytes: access.width_bytes,
            names: candidates,
            notes,
        });
    }
    for reference in &code.literal_references {
        if !mmio_address(reference.value) {
            continue;
        }
        report.address_references.push(RegisterAddressReference {
            instruction_address: reference.instruction_address,
            instruction_offset: reference.instruction_offset,
            pool_address: reference.pool_address,
            pool_offset: reference.pool_offset,
            value: reference.value,
            names: names_at(&specs, reference.value, None),
        });
    }
    report
}

fn mmio_address(address: u32) -> bool {
    (0x4000_0000..0x6000_0000).contains(&address) || (0xe000_0000..0xe010_0000).contains(&address)
}

fn names_at(
    specs: &[&DocumentedRegisterSpec],
    address: u32,
    access: Option<(MemoryAccessKind, u8)>,
) -> Vec<RegisterName> {
    specs
        .iter()
        .filter_map(|spec| {
            let index = spec.index_at(address)?;
            let mut last_index = index;
            if let Some((direction, width)) = access {
                if width > spec.width_bytes
                    && spec.width_bytes == spec.stride
                    && spec.width_bytes > 0
                {
                    last_index =
                        index.checked_add(u16::from(width / spec.width_bytes).saturating_sub(1))?;
                }
                if !matches!(width, 1 | 2 | 4)
                    || !address.is_multiple_of(u32::from(width.max(1)))
                    || (width > spec.width_bytes
                        && (last_index == index || last_index >= spec.count))
                    || !matches!(
                        (direction, spec.access),
                        (
                            MemoryAccessKind::Read,
                            RegisterAccess::ReadOnly | RegisterAccess::ReadWrite
                        ) | (
                            MemoryAccessKind::Write,
                            RegisterAccess::WriteOnly | RegisterAccess::ReadWrite
                        )
                    )
                {
                    return None;
                }
            }
            Some(RegisterName {
                peripheral: spec.peripheral_name.into(),
                register: if spec.count > 1 {
                    if last_index > index {
                        format!("{}[{index}..{last_index}]", spec.register_name)
                    } else {
                        format!("{}[{index}]", spec.register_name)
                    }
                } else {
                    spec.register_name.into()
                },
                documented_access: match spec.access {
                    RegisterAccess::ReadOnly => "read-only",
                    RegisterAccess::WriteOnly => "write-only",
                    RegisterAccess::ReadWrite => "read-write",
                }
                .into(),
                condition: spec.condition.map(str::to_string),
                source: source(spec.source),
            })
        })
        .collect()
}

fn source(source: ProfileSource) -> RegisterSource {
    RegisterSource {
        title: source.title.into(),
        url: source.url.into(),
        location: source.location.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcu_family::resolve_family_resolution;
    use fat_core::mcu_code::{CodeLiteralReference, CodeMemoryAccess};

    fn access(target: u32, kind: MemoryAccessKind) -> CodeMemoryAccess {
        CodeMemoryAccess {
            instruction_address: 0x1fff_0108,
            instruction_offset: 0x108,
            target,
            access: kind,
            width_bytes: 4,
        }
    }
    fn names(report: &RegisterAnnotationReport) -> Vec<&str> {
        report.accesses[0]
            .names
            .iter()
            .map(|name| name.register.as_str())
            .collect()
    }

    #[test]
    fn literal_only_reference_is_never_a_read_or_write() {
        let code = McuCodeReport {
            literal_references: vec![CodeLiteralReference {
                instruction_address: 0x1fff_0104,
                instruction_offset: 0x104,
                pool_address: 0x1fff_0120,
                pool_offset: 0x120,
                value: 0x4000_8000,
            }],
            ..Default::default()
        };
        let report =
            annotate_registers(&code, &resolve_family_resolution(None, Some("NXP LPC134x")));
        assert!(report.accesses.is_empty());
        assert_eq!(report.address_references.len(), 1);
        assert_eq!(report.address_references[0].names.len(), 3);
        assert_eq!(report.profile_selection, "inferred-family-profile");
    }

    #[test]
    fn alias_names_respect_read_write_direction_without_guessing_dlab() {
        let family = resolve_family_resolution(None, Some("NXP LPC134x"));
        let mut code = McuCodeReport {
            memory_accesses: vec![access(0x4000_8000, MemoryAccessKind::Read)],
            ..Default::default()
        };
        let read = annotate_registers(&code, &family);
        assert_eq!(names(&read), ["RBR", "DLL"]);
        assert!(read.accesses[0]
            .names
            .iter()
            .all(|name| name.condition.is_some()));
        code.memory_accesses[0].access = MemoryAccessKind::Write;
        assert_eq!(names(&annotate_registers(&code, &family)), ["THR", "DLL"]);
        code.memory_accesses[0].target = 0x4000_8008;
        assert_eq!(names(&annotate_registers(&code, &family)), ["FCR"]);
        code.memory_accesses[0].access = MemoryAccessKind::Read;
        assert_eq!(names(&annotate_registers(&code, &family)), ["IIR"]);
    }

    #[test]
    fn unknown_family_preserves_raw_access_without_vendor_or_core_assertions() {
        let code = McuCodeReport {
            memory_accesses: vec![
                access(0x4000_8008, MemoryAccessKind::Read),
                access(0xe000_ed08, MemoryAccessKind::Write),
            ],
            ..Default::default()
        };
        let report = annotate_registers(&code, &resolve_family_resolution(None, None));
        assert!(report.family_profile.is_none());
        assert!(report.core_name.is_none());
        assert!(report.accesses.iter().all(|item| item.names.is_empty()));
        assert_eq!(report.accesses.len(), 2);
    }

    #[test]
    fn explicit_profile_is_labeled_an_assumption_and_has_source_provenance() {
        let code = McuCodeReport {
            memory_accesses: vec![access(0xe000_ed08, MemoryAccessKind::Write)],
            ..Default::default()
        };
        let report = annotate_registers(&code, &resolve_family_resolution(Some("lpc13xx"), None));
        assert_eq!(report.profile_selection, "user-assumption");
        assert_eq!(report.core_name.as_deref(), Some("ARM Cortex-M3"));
        assert!(report.core_source.as_ref().unwrap().url.contains("nxp.com"));
        assert_eq!(names(&report), ["VTOR"]);
        assert!(report.accesses[0].names[0]
            .source
            .url
            .contains("ARM-software/CMSIS_5/5.9.0"));
    }

    #[test]
    fn incompatible_direction_width_and_address_are_not_named() {
        let family = resolve_family_resolution(None, Some("NXP LPC134x"));
        let mut code = McuCodeReport {
            memory_accesses: vec![access(0x4000_8014, MemoryAccessKind::Write)],
            ..Default::default()
        };
        assert!(names(&annotate_registers(&code, &family)).is_empty()); // LSR is read only.
        code.memory_accesses[0] = access(0xe000_e400, MemoryAccessKind::Read);
        assert_eq!(names(&annotate_registers(&code, &family)), ["IP[0..3]"]); // Word access spans four byte priorities.
        code.memory_accesses[0].width_bytes = 3;
        assert!(names(&annotate_registers(&code, &family)).is_empty());
        code.memory_accesses[0].width_bytes = 1;
        assert_eq!(names(&annotate_registers(&code, &family)), ["IP[0]"]);
        code.memory_accesses[0].target = 0x4000_8001;
        assert!(names(&annotate_registers(&code, &family)).is_empty());
    }

    #[test]
    fn unaligned_halfword_and_word_accesses_remain_unresolved() {
        let family = resolve_family_resolution(None, Some("lpc13xx"));
        let mut code = McuCodeReport {
            memory_accesses: vec![access(0xe000_e401, MemoryAccessKind::Write)],
            ..Default::default()
        };
        for width in [2, 4] {
            code.memory_accesses[0].width_bytes = width;
            let report = annotate_registers(&code, &family);
            assert_eq!(report.accesses[0].target, 0xe000_e401);
            assert!(names(&report).is_empty());
        }
    }

    #[test]
    fn documented_usb_names_include_variant_presence_caveat() {
        let code = McuCodeReport {
            memory_accesses: vec![access(0x4002_0008, MemoryAccessKind::Write)],
            ..Default::default()
        };
        let report = annotate_registers(&code, &resolve_family_resolution(None, Some("lpc13xx")));
        assert_eq!(names(&report), ["DEVINTCLR"]);
        assert!(report.accesses[0].names[0]
            .condition
            .as_ref()
            .unwrap()
            .contains("LPC1342/43 only"));
    }
}
