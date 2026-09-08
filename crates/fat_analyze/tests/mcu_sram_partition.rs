//! SRAM partitioning into linker-managed and runtime-managed windows.
//!
//! Fixtures are real `arm-none-eabi-gcc` output — see
//! `tests/fixtures/mcu/init-table/Makefile`. `scatter-load-dma.bin` is the
//! same startup and linker script as `scatter-load.bin` with an application
//! that parks two DMA pools above the linker cap and drives the Ethernet MAC,
//! which is the shape that makes the partition worth reporting at all.

use std::fs;
use std::path::PathBuf;

use fat_analyze::mcu_inspect::{inspect_file, McuInspectRequest};
use fat_core::mcu_inspection::{
    LinkerCapBasis, McuInspectionReport, SramPartitionReport, SramRegionPartition, ThreatModelHint,
};

const SCATTER: &str = "scatter-load.bin";
const SCATTER_DMA: &str = "scatter-load-dma.bin";
const CMSIS: &str = "cmsis-copy-zero-os.bin";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mcu/init-table")
        .join(name)
}

fn inspect(name: &str) -> McuInspectionReport {
    inspect_file(&McuInspectRequest {
        file: fixture_path(name),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .expect("mcu inspection report")
}

fn partitions(name: &str) -> SramPartitionReport {
    inspect(name)
        .sram_partitions
        .expect("sram partition report")
}

fn region<'a>(report: &'a SramPartitionReport, label: &str) -> &'a SramRegionPartition {
    report
        .sram_regions
        .iter()
        .find(|partition| partition.region.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no {label} partition in {report:#?}"))
}

#[test]
fn every_stm32h7_sram_window_is_enumerated_from_the_family_pack() {
    let report = partitions(SCATTER);
    let windows: Vec<(&str, u64, u64)> = report
        .sram_regions
        .iter()
        .map(|partition| {
            (
                partition.region.label.as_deref().unwrap_or_default(),
                partition.region.start,
                partition.region.end.expect("bounded sram window"),
            )
        })
        .collect();

    assert_eq!(
        windows,
        vec![
            ("dtcm-sram", 0x2000_0000, 0x2002_0000),
            ("axi-sram", 0x2400_0000, 0x2408_0000),
            ("d2-sram", 0x3000_0000, 0x3004_8000),
            ("d3-sram", 0x3800_0000, 0x3801_0000),
            ("backup-sram", 0x3880_0000, 0x3880_1000),
        ]
    );
}

#[test]
fn axi_sram_splits_at_the_cap_the_init_table_and_initial_sp_agree_on() {
    // `.data` (4 B at 0x24000000) + `.bss` (0x100 at 0x24000004) end exactly
    // at __StackTop, so both anchors give the same cap. That is the same
    // arithmetic that holds on the motivating STM32H743 image.
    let report = partitions(SCATTER);
    let axi = region(&report, "axi-sram");

    assert_eq!(axi.linker_managed.start, 0x2400_0000);
    assert_eq!(axi.linker_managed.end, 0x2400_0104);
    assert_eq!(axi.runtime_managed.start, 0x2400_0104);
    assert_eq!(axi.runtime_managed.end, 0x2408_0000);
    assert_eq!(axi.linker_bytes, 0x104);
    assert_eq!(axi.runtime_bytes, 0x0008_0000 - 0x104);
    assert_eq!(
        axi.linker_cap_basis,
        LinkerCapBasis::InitTableAndStackPointer
    );
    assert_eq!(
        axi.linker_bytes + axi.runtime_bytes,
        axi.region.end.expect("bounded window") - axi.region.start
    );
}

#[test]
fn the_cap_includes_the_stack_reserve_when_the_stack_sits_above_bss() {
    // The CMSIS fixture puts __StackTop at the top of a 64 KiB SRAM, far above
    // .bss. Capping at the descriptor coverage alone would hand 65 KiB of
    // stack reserve to the "runtime-managed" side, which is wrong: the linker
    // placed it.
    let report = partitions(CMSIS);
    let sram = region(&report, "generic-sram");

    assert_eq!(sram.linker_managed.end, 0x2001_0000, "initial SP wins");
    assert_eq!(sram.linker_bytes, 0x0001_0000);
    assert_eq!(
        sram.linker_cap_basis,
        LinkerCapBasis::InitTableAndStackPointer
    );
}

#[test]
fn a_window_nothing_static_claims_is_reported_as_entirely_runtime_managed() {
    let report = partitions(SCATTER);
    for label in ["dtcm-sram", "d2-sram", "d3-sram", "backup-sram"] {
        let partition = region(&report, label);
        assert_eq!(
            partition.linker_cap_basis,
            LinkerCapBasis::NoEvidence,
            "{label} should carry no cap anchor"
        );
        assert_eq!(partition.linker_bytes, 0, "{label}");
        assert_eq!(
            u64::from(partition.runtime_managed.start),
            partition.region.start
        );
        assert_eq!(
            partition.runtime_bytes,
            partition.region.end.expect("bounded window") - partition.region.start,
            "{label}"
        );
    }
}

#[test]
fn static_pool_pointers_into_the_runtime_region_are_reported_as_candidates() {
    let report = partitions(SCATTER_DMA);
    let axi = region(&report, "axi-sram");

    let targets: Vec<u32> = axi
        .runtime_literal_references
        .iter()
        .map(|reference| reference.target)
        .collect();
    assert_eq!(targets, vec![0x2402_0000, 0x2404_0000], "{axi:#?}");
    assert_eq!(axi.runtime_literal_total, 2);

    for reference in &axi.runtime_literal_references {
        assert!(
            axi.runtime_managed.contains(reference.target),
            "0x{:08X} is outside the runtime-managed window",
            reference.target
        );
        // Both pools are 128 KiB apart from the region base, so both are
        // cache-line aligned; that is what ranks them above a stray word.
        assert_eq!(reference.alignment, 32);
        assert!(!reference.referenced_from.is_empty());
        for site in &reference.referenced_from {
            assert!(
                (0x0800_0000..0x0800_1000).contains(site),
                "reference site 0x{site:08X} is not inside the image"
            );
        }
    }
}

#[test]
fn the_initial_stack_pointer_is_never_reported_as_a_pool_candidate() {
    // Vector word 0 holds the initial SP, which by construction equals the
    // partition boundary. Reporting it would be a guaranteed false positive.
    for fixture in [SCATTER, SCATTER_DMA] {
        let report = partitions(fixture);
        let initial_sp = inspect(fixture)
            .fast_profile
            .expect("fast profile")
            .initial_sp;
        for partition in &report.sram_regions {
            assert!(
                partition
                    .runtime_literal_references
                    .iter()
                    .all(|reference| reference.target != initial_sp),
                "{fixture}: initial SP 0x{initial_sp:08X} reported as a pool candidate"
            );
        }
    }
}

#[test]
fn adjacent_thumb_instructions_are_not_read_back_as_pool_pointers() {
    // A halfword-stepped scan reads `bx lr` + `movs r0, #0` back as
    // 0x2000_4770 and reports it as a DTCM pool base. Every candidate must be
    // word-aligned and read from a word-aligned offset, which rules that out.
    for fixture in [SCATTER, SCATTER_DMA, CMSIS] {
        let report = partitions(fixture);
        for partition in &report.sram_regions {
            for reference in &partition.runtime_literal_references {
                assert_eq!(
                    reference.target % 4,
                    0,
                    "{fixture}: 0x{:08X} is not word-aligned",
                    reference.target
                );
                assert!(reference.alignment >= 4);
            }
        }
        let dtcm = report
            .sram_regions
            .iter()
            .find(|partition| partition.region.label.as_deref() == Some("dtcm-sram"));
        if let Some(dtcm) = dtcm {
            assert!(
                dtcm.runtime_literal_references.is_empty(),
                "{fixture}: DTCM picked up {:?}",
                dtcm.runtime_literal_references
            );
        }
    }
}

#[test]
fn a_detected_ethernet_mac_marks_the_runtime_region_dma_reachable() {
    let report = partitions(SCATTER_DMA);
    let axi = region(&report, "axi-sram");
    match axi.threat_model_hint.as_ref().expect("threat model hint") {
        ThreatModelHint::DmaReachable { masters } => {
            assert!(
                masters.iter().any(|master| master == "ETH_MAC"),
                "{masters:?}"
            );
        }
        other => panic!("expected DmaReachable, got {other:?}"),
    }

    // The plain scatter-load fixture touches no DMA-capable peripheral, so the
    // hint must not be manufactured for it.
    let plain = partitions(SCATTER);
    assert_eq!(
        region(&plain, "axi-sram").threat_model_hint,
        Some(ThreatModelHint::CpuOnly)
    );
}

#[test]
fn the_partition_is_explained_in_provenance_and_analysis_notes() {
    let report = inspect(SCATTER_DMA);
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note.starts_with("sram_partitions=present regions=5")));

    let provenance = report
        .sram_partitions
        .expect("partitions")
        .provenance
        .expect("provenance");
    assert_eq!(provenance.extractor, "sram-partition-extractor");
    assert_eq!(provenance.family_pack.as_deref(), Some("stm32h7"));
    assert!(provenance
        .notes
        .iter()
        .any(|note| note.contains("cap_anchors=init-table+initial-sp")));
    // DMA reachability is name-derived; the report must say so rather than
    // implying a bus-matrix model exists.
    assert!(provenance
        .notes
        .iter()
        .any(|note| note.contains("not from a bus-matrix model")));
}

#[test]
fn an_image_without_a_startup_chain_reports_no_partition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("no-chain.bin");
    // Vector word 1 points outside any plausible flash image, so no reset
    // address is recovered and nothing can be addressed.
    let bytes = vec![0u8; 0x400];
    fs::write(&blob, &bytes).expect("write blob");

    let report = inspect_file(&McuInspectRequest {
        file: blob,
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .expect("report");
    assert!(report.sram_partitions.is_none());
    assert!(report
        .analysis_provenance
        .notes
        .iter()
        .any(|note| note.starts_with("sram_partitions=absent")));
}

#[test]
fn the_partition_report_survives_a_json_round_trip() {
    let report = partitions(SCATTER_DMA);
    let serialized = serde_json::to_string(&report).expect("serialize");
    assert!(serialized.contains("dma-reachable"));
    assert!(serialized.contains("init-table-and-stack-pointer"));
    assert!(serialized.contains("no-evidence"));
    let restored: SramPartitionReport = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(restored, report);
}
