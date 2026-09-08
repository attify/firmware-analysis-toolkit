//! SRAM partitioning for bare-metal Cortex-M images.
//!
//! `fat inspect mcu` already reports the initial stack pointer, but a bare
//! number does not answer the question an analyst actually has: *which* bytes
//! of SRAM hold static program state, and which are left for the runtime to
//! hand out. Those two halves have completely different security properties.
//! Everything below the cap is `.data`, `.bss` and the stack reserve, all
//! placed by the linker and visible statically. Everything above it is only
//! ever claimed at runtime, which on a DMA-capable part is where descriptor
//! rings and packet pools live — the memory attacker-supplied bytes land in.
//!
//! The cap comes from two independent anchors and takes the higher of them:
//!
//! * the init-descriptor table recovered by [`crate::mcu_init_table`], whose
//!   record destinations cover `.data` and `.bss`, and
//! * the initial stack pointer from vector word 0, which sits at the top of
//!   the stack reserve.
//!
//! Neither is guessed at: when a region has neither anchor it is reported as
//! entirely runtime-managed with [`LinkerCapBasis::NoEvidence`] rather than
//! being given an invented boundary.

use std::collections::HashMap;

use fat_core::mcu_inspection::{
    AddressRange, ImageLayoutReport, InitTableReport, LinkerCapBasis, MemoryRegion,
    MemoryRegionKind, PeripheralMapReport, RuntimeLiteralRef, SramPartitionReport,
    SramRegionPartition, ThreatModelHint,
};

use crate::mcu_family::FamilyResolution;
use crate::mcu_init_table::ImageAddressing;
use crate::mcu_inspect::{read_u32_at, section_provenance};

/// How many distinct literal targets are reported per region. The scan itself
/// is unbounded; only the report is capped, and the pre-cap count is kept in
/// [`SramRegionPartition::runtime_literal_total`].
const MAX_REPORTED_LITERALS: usize = 32;
/// How many source sites are listed per literal target.
const MAX_SITES_PER_LITERAL: usize = 8;

/// Peripheral-name fragments that identify a bus master capable of writing
/// RAM without the CPU. Matching is on the family-pack peripheral name, so a
/// generic `mmio-cluster@0x...` entry never matches.
const DMA_MASTER_FRAGMENTS: &[&str] = &[
    "ETH", "OTG", "USB", "DMA", "MDMA", "BDMA", "SDMMC", "DMA2D", "LTDC", "CRYP", "HASH",
];

/// Split every SRAM window the family pack knows about into a linker-managed
/// and a runtime-managed range.
///
/// Returns `None` when the family pack declares no SRAM windows or the image
/// cannot be addressed (no reset vector to anchor the flash base on).
pub fn extract_sram_partition(
    bytes: &[u8],
    init_table: Option<&InitTableReport>,
    initial_sp: Option<u32>,
    reset_address: Option<u32>,
    family: &FamilyResolution,
    peripheral_map: Option<&PeripheralMapReport>,
    layout: &ImageLayoutReport,
) -> Option<SramPartitionReport> {
    if family.pack.sram_ranges.is_empty() {
        return None;
    }
    let addressing = ImageAddressing::from_layout(reset_address?, layout, bytes.len())?;

    let masters = dma_masters(peripheral_map);
    let threat_model_hint = match (peripheral_map, masters.is_empty()) {
        (None, _) => ThreatModelHint::Unknown,
        (Some(_), true) => ThreatModelHint::CpuOnly,
        (Some(_), false) => ThreatModelHint::DmaReachable { masters },
    };

    let mut partitions = Vec::with_capacity(family.pack.sram_ranges.len());
    for range in family.pack.sram_ranges {
        let region = MemoryRegion {
            start: u64::from(range.start),
            end: Some(u64::from(range.end)),
            kind: MemoryRegionKind::Ram,
            label: Some(range.label.to_string()),
            confidence: 0.9,
            evidence_ids: Vec::new(),
        };

        let table_cap = init_table.and_then(|table| {
            table
                .records
                .iter()
                .filter(|record| (range.start..range.end).contains(&record.dst))
                .filter_map(|record| record.dst.checked_add(record.size))
                .map(|end| end.min(range.end))
                .max()
        });
        let sp_cap = initial_sp.filter(|sp| (range.start..=range.end).contains(sp));
        let (cap, linker_cap_basis) = match (table_cap, sp_cap) {
            (Some(table), Some(sp)) => (table.max(sp), LinkerCapBasis::InitTableAndStackPointer),
            (Some(table), None) => (table, LinkerCapBasis::InitTable),
            (None, Some(sp)) => (sp, LinkerCapBasis::StackPointer),
            (None, None) => (range.start, LinkerCapBasis::NoEvidence),
        };

        let linker_managed = AddressRange::new(range.start, cap);
        let runtime_managed = AddressRange::new(cap, range.end);
        let (references, total) =
            scan_runtime_literals(bytes, &addressing, runtime_managed, initial_sp);

        partitions.push(SramRegionPartition {
            region,
            linker_managed,
            runtime_managed,
            linker_bytes: linker_managed.len(),
            runtime_bytes: runtime_managed.len(),
            linker_cap_basis,
            runtime_literal_references: references,
            runtime_literal_total: total,
            threat_model_hint: Some(threat_model_hint.clone()),
        });
    }

    let mut provenance =
        section_provenance("sram-partition-extractor", Some(addressing.flash_base));
    provenance.family_pack = Some(family.pack.family_id.to_string());
    provenance.notes.push(format!(
        "regions={} source=family-pack:{}",
        partitions.len(),
        family.pack.family_id
    ));
    provenance.notes.push(match (init_table, initial_sp) {
        (Some(_), Some(sp)) => {
            format!("cap_anchors=init-table+initial-sp initial_sp=0x{sp:08x}")
        }
        (Some(_), None) => "cap_anchors=init-table".to_string(),
        (None, Some(sp)) => format!("cap_anchors=initial-sp initial_sp=0x{sp:08x}"),
        (None, None) => "cap_anchors=none: every region reported as runtime-managed".to_string(),
    });
    provenance.notes.push(
        "dma reachability is derived from detected peripheral names, not from a bus-matrix model"
            .to_string(),
    );

    Some(SramPartitionReport {
        sram_regions: partitions,
        provenance: Some(provenance),
    })
}

/// Collect 32-bit words in the image whose value lands inside `range`.
///
/// Only word-aligned offsets are read. A halfword-stepped scan looks more
/// thorough but is not: on a Cortex-M image it straddles adjacent 16-bit
/// Thumb instructions and manufactures pointers out of them (`bx lr` followed
/// by `movs r0, #0` reads back as `0x2000_4770`, which sits squarely inside a
/// DTCM window). ARM literal pools and descriptor tables are word arrays at
/// word-aligned addresses, so nothing real is lost by requiring alignment.
///
/// The initial stack pointer is excluded as well: it is by construction the
/// exclusive top of the stack and equals the partition boundary, so reporting
/// it as a pool base would be a guaranteed false positive.
fn scan_runtime_literals(
    bytes: &[u8],
    addressing: &ImageAddressing,
    range: AddressRange,
    initial_sp: Option<u32>,
) -> (Vec<RuntimeLiteralRef>, usize) {
    if range.is_empty() {
        return (Vec::new(), 0);
    }

    let mut hits: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        if let Some(word) = read_u32_at(bytes, offset) {
            if range.contains(word) && word.is_multiple_of(4) && Some(word) != initial_sp {
                if let Some(site) = addressing.address_of(offset) {
                    let sites = hits.entry(word).or_default();
                    if sites.len() < MAX_SITES_PER_LITERAL {
                        sites.push(site);
                    }
                }
            }
        }
        offset += 4;
    }

    let total = hits.len();
    let mut references: Vec<RuntimeLiteralRef> = hits
        .into_iter()
        .map(|(target, referenced_from)| RuntimeLiteralRef {
            alignment: alignment_of(target),
            target,
            referenced_from,
        })
        .collect();
    // Most strongly aligned candidates first (a descriptor ring or DMA pool
    // base is cache-line aligned), then most-referenced, then by address so
    // the order is stable.
    references.sort_by(|left, right| {
        right
            .alignment
            .cmp(&left.alignment)
            .then_with(|| right.referenced_from.len().cmp(&left.referenced_from.len()))
            .then_with(|| left.target.cmp(&right.target))
    });
    references.truncate(MAX_REPORTED_LITERALS);
    (references, total)
}

/// Largest power-of-two `address` is aligned to, capped at 32 (a cache line
/// on the Cortex-M7 parts where DMA alignment matters most).
fn alignment_of(address: u32) -> u32 {
    if address == 0 {
        return 32;
    }
    (1u32 << address.trailing_zeros().min(5)).max(4)
}

/// Names of detected peripherals that can write RAM without the CPU.
fn dma_masters(peripheral_map: Option<&PeripheralMapReport>) -> Vec<String> {
    let Some(map) = peripheral_map else {
        return Vec::new();
    };
    let mut masters: Vec<String> = map
        .uses
        .iter()
        .filter(|use_| is_dma_master(&use_.peripheral_name))
        .map(|use_| use_.peripheral_name.clone())
        .collect();
    masters.sort();
    masters.dedup();
    masters
}

fn is_dma_master(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    // `mmio-cluster@0x...` placeholders carry no peripheral identity.
    if upper.starts_with("MMIO-CLUSTER") {
        return false;
    }
    DMA_MASTER_FRAGMENTS
        .iter()
        .any(|fragment| upper.contains(fragment))
}
