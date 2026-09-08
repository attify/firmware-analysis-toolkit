use fat_core::mcu_inspection::{
    InterruptVectorReport, PeripheralMapReport, PeripheralRole as CorePeripheralRole,
    SecuritySurfaceSummary,
};
use fat_family::mcu_packs::{McuFamilyPack, PeripheralRole as PackPeripheralRole};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyResolutionMode {
    UserExact,
    FastProfileExact,
    Fallback,
}

#[derive(Debug, Clone, Copy)]
pub struct FamilyResolution {
    pub pack: &'static McuFamilyPack,
    pub mode: FamilyResolutionMode,
}

impl FamilyResolution {
    pub fn is_enriching_match(&self) -> bool {
        self.mode != FamilyResolutionMode::Fallback
    }
}

/// Resolve an MCU family pack for inspection.
///
/// The first argument is the preferred family hint; the second is a fallback.
pub fn resolve_family_pack(
    preferred_family: Option<&str>,
    fallback_family: Option<&str>,
) -> FamilyResolution {
    resolve_family_resolution(preferred_family, fallback_family)
}

pub fn resolve_family_resolution(
    preferred_family: Option<&str>,
    fallback_family: Option<&str>,
) -> FamilyResolution {
    if let Some(preferred_family) = preferred_family {
        if let Some(pack) = fat_family::resolve_mcu_pack(Some(preferred_family), None) {
            if exact_pack_match(pack, preferred_family) {
                return FamilyResolution {
                    pack,
                    mode: FamilyResolutionMode::UserExact,
                };
            }
        }
    }

    if let Some(fallback_family) = fallback_family {
        if let Some(pack) = fat_family::resolve_mcu_pack(None, Some(fallback_family)) {
            if exact_pack_match(pack, fallback_family) {
                return FamilyResolution {
                    pack,
                    mode: FamilyResolutionMode::FastProfileExact,
                };
            }
        }
    }

    let pack = fat_family::resolve_mcu_pack(None, None)
        .unwrap_or_else(|| fat_family::resolve_mcu_pack(Some("cortex-m"), None).unwrap());
    FamilyResolution {
        pack,
        mode: FamilyResolutionMode::Fallback,
    }
}

pub fn enrich_vector_table(
    mut vector_table: InterruptVectorReport,
    resolution: &FamilyResolution,
) -> InterruptVectorReport {
    if !resolution.is_enriching_match() {
        return vector_table;
    }

    if let Some(provenance) = vector_table.provenance.as_mut() {
        provenance.family_pack = Some(resolution.pack.family_id.to_string());
        provenance
            .notes
            .push("family-pack selected for vector enrichment".to_string());
    }

    let mut labeled = false;
    for entry in &mut vector_table.entries {
        if let Some(label) = resolution.pack.lookup_irq(entry.index) {
            entry.family_label = Some(label.name.to_string());
            labeled = true;
        }
    }

    if labeled {
        if let Some(provenance) = vector_table.provenance.as_mut() {
            provenance
                .notes
                .push("family-pack vector enrichment applied".to_string());
        }
    }

    vector_table
}

pub fn enrich_peripheral_map(
    mut peripheral_map: PeripheralMapReport,
    resolution: &FamilyResolution,
) -> PeripheralMapReport {
    if !resolution.is_enriching_match() {
        return peripheral_map;
    }

    if let Some(provenance) = peripheral_map.provenance.as_mut() {
        provenance.family_pack = Some(resolution.pack.family_id.to_string());
        provenance
            .notes
            .push("family-pack selected for MMIO enrichment".to_string());
    }

    let original_uses = peripheral_map.uses.clone();
    let mut enriched_uses = Vec::new();
    let mut enriched = false;
    for use_ in &original_uses {
        let Some(base) = u32::try_from(use_.base).ok() else {
            continue;
        };
        let Some(hit) = resolution.pack.lookup_mmio(base) else {
            continue;
        };

        let mut enriched_use = use_.clone();
        enriched_use.family = Some(resolution.pack.family_id.to_string());
        enriched_use.peripheral_name = hit.peripheral_name.to_string();
        for role in hit.roles {
            let converted = convert_role(*role);
            if !enriched_use.roles.contains(&converted) {
                enriched_use.roles.push(converted);
            }
        }
        if let Some(hint) = resolution
            .pack
            .role_hint_for_peripheral(hit.peripheral_name)
        {
            for role in hint.roles {
                let converted = convert_role(*role);
                if !enriched_use.roles.contains(&converted) {
                    enriched_use.roles.push(converted);
                }
            }
            enriched_use.confidence = enriched_use.confidence.max(hint.confidence);
        } else {
            enriched_use.confidence = enriched_use.confidence.max(0.72);
        }
        enriched_uses.push(enriched_use);
        enriched = true;
    }

    if enriched {
        if let Some(provenance) = peripheral_map.provenance.as_mut() {
            provenance
                .notes
                .push("family-pack MMIO enrichment applied".to_string());
        }
        peripheral_map.uses.extend(enriched_uses);
    }

    peripheral_map
}

pub fn enrich_security_roles(
    mut surface: SecuritySurfaceSummary,
    peripheral_map: &PeripheralMapReport,
    resolution: &FamilyResolution,
) -> SecuritySurfaceSummary {
    if !resolution.is_enriching_match() {
        return surface;
    }

    for use_ in &peripheral_map.uses {
        if use_.roles.contains(&CorePeripheralRole::UpdateTransport)
            && !surface
                .update_surface
                .iter()
                .any(|item| item.contains(&use_.peripheral_name))
        {
            surface.update_surface.push(format!(
                "{} candidate update transport surface",
                use_.peripheral_name
            ));
        }
        if (use_.roles.contains(&CorePeripheralRole::CommsBridge)
            || use_.roles.contains(&CorePeripheralRole::HostSidecarLink))
            && !surface
                .comms_surface
                .iter()
                .any(|item| item.contains(&use_.peripheral_name))
        {
            surface
                .comms_surface
                .push(format!("{} candidate comms surface", use_.peripheral_name));
        }
        if use_.roles.contains(&CorePeripheralRole::FlashWritePath)
            && !surface
                .flash_surface
                .iter()
                .any(|item| item.contains(&use_.peripheral_name))
        {
            surface.flash_surface.push(format!(
                "{} candidate flash-write surface",
                use_.peripheral_name
            ));
        }
    }

    surface.confidence = surface.confidence.max(0.35);
    surface
}

fn exact_pack_match(pack: &McuFamilyPack, hint: &str) -> bool {
    let normalized_hint = normalize_name(hint);
    normalize_name(pack.family_id) == normalized_hint
        || pack
            .aliases
            .iter()
            .any(|alias| normalize_name(alias) == normalized_hint)
}

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

pub(crate) fn convert_role(role: PackPeripheralRole) -> CorePeripheralRole {
    match role {
        PackPeripheralRole::UpdateTransport => CorePeripheralRole::UpdateTransport,
        PackPeripheralRole::FlashWritePath => CorePeripheralRole::FlashWritePath,
        PackPeripheralRole::CommsBridge => CorePeripheralRole::CommsBridge,
        PackPeripheralRole::HostSidecarLink => CorePeripheralRole::HostSidecarLink,
        PackPeripheralRole::Actuation => CorePeripheralRole::Actuation,
        PackPeripheralRole::Debug => CorePeripheralRole::Unknown,
        PackPeripheralRole::Identity => CorePeripheralRole::Identity,
        PackPeripheralRole::Crypto => CorePeripheralRole::Cryptography,
        PackPeripheralRole::ErrorDetection => CorePeripheralRole::Unknown,
    }
}
