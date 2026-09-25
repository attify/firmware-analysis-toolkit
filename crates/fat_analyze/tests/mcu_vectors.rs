use fat_analyze::mcu::detect_cortex_m_ivt_with_base;
use fat_analyze::mcu_inspect::extract_vector_table;
use fat_core::mcu_inspection::{
    AddressHypothesis, ImageLayoutReport, InterruptHandlerKind, InterruptVectorReport,
};

fn put(bytes: &mut [u8], index: usize, value: u32) {
    bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
}

fn table(base: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x200];
    put(&mut bytes, 0, 0x2000_2000);
    for index in [1, 2, 3, 4, 5, 6, 11, 12, 14, 15, 16, 20, 31] {
        put(&mut bytes, index, base + 0x81);
    }
    // Nonzero reserved fields must not terminate the table or become handlers.
    put(&mut bytes, 7, 0xdead_beef);
    put(&mut bytes, 8, base + 0x81);
    for word in bytes[0x80..].chunks_exact_mut(4) {
        word.copy_from_slice(&(base + 0x101).to_le_bytes());
    }
    bytes
}

fn report(bytes: &[u8], offset: u32, base: u32) -> InterruptVectorReport {
    let layout = ImageLayoutReport {
        candidate_offsets: vec![offset],
        vector_address: Some(base),
        ..Default::default()
    };
    let hypotheses = [AddressHypothesis {
        base,
        is_primary: true,
        ..Default::default()
    }];
    extract_vector_table(bytes, &layout, &hypotheses).expect("vector table")
}

#[test]
fn generic_vectors_share_accounting_with_prefixed_and_relocated_reports() {
    for base in [0x6000_0000, 0x0804_0000] {
        let data = table(base);
        let fast = detect_cortex_m_ivt_with_base(&data, Some(base)).unwrap();
        for offset in [0, 0x200] {
            let mut container = vec![0xaa; offset as usize];
            container.extend_from_slice(&data);
            let details = report(&container, offset, base);
            assert_eq!(fast.active_interrupt_count, details.active_count);
            assert_eq!(fast.total_interrupt_slots, details.entry_count);
            assert_eq!(details.core_exception_count, 10);
            assert_eq!(details.external_irq_count, 3);
            assert_eq!(details.reserved_entry_count, 5);
            assert_eq!(details.unpopulated_entry_count, 13);
            assert_eq!(details.entry_count, 32);
            assert_eq!(details.scan_boundary, "mapped-handler");
            assert_eq!(details.entries[16].external_irq_number, Some(0));
            assert_eq!(
                details.entries[15].core_exception.as_deref(),
                Some("SysTick")
            );
            assert_eq!(
                details.entries[7].handler_kind,
                InterruptHandlerKind::Reserved
            );
            assert_eq!(
                details.entries[8].handler_kind,
                InterruptHandlerKind::Reserved
            );
            assert_eq!(details.unique_aligned_target_count, 1);
            assert_eq!(details.repeated_targets[0].reference_count, 13);
            assert_eq!(details.default_handler_count, 0);
        }
    }
}

#[test]
fn partial_table_preserves_available_evidence_without_claiming_irq_capacity() {
    let base = 0x6000_0000;
    let mut bytes = table(base);
    bytes.truncate(18 * 4 + 2);
    let details = report(&bytes, 0, base);
    let fast = detect_cortex_m_ivt_with_base(&bytes, Some(base)).unwrap();
    assert_eq!(details.scan_boundary, "available-bytes");
    assert_eq!(details.scanned_word_count, 18);
    assert_eq!(details.entry_count, 17); // trailing zero is ambiguous padding
    assert_eq!(details.external_irq_count, 1);
    assert_eq!(fast.total_interrupt_slots, details.entry_count);
    assert!(details
        .scan_boundary_rationale
        .iter()
        .any(|why| why.contains("partial table")));
}

#[test]
fn mapped_short_core_table_is_not_extended_into_instructions() {
    let base = 0x6000_0000;
    let mut bytes = vec![0u8; 64];
    put(&mut bytes, 0, 0x2000_2000);
    for index in 1..4 {
        put(&mut bytes, index, base + 0x11);
    }
    bytes[16..].fill(0xa5);
    let details = report(&bytes, 0, base);
    assert_eq!(details.entry_count, 4);
    assert_eq!(details.core_exception_count, 3);
    assert_eq!(details.external_irq_count, 0);
    assert_eq!(details.scan_boundary, "mapped-handler");
}

#[test]
fn a_handler_pointer_into_already_scanned_vectors_is_a_mapping_conflict() {
    let base = 0x6000_0000;
    let mut bytes = table(base);
    put(&mut bytes, 20, base + 0x41); // target at table offset64, before slot20
    let details = report(&bytes, 0, base);
    assert_eq!(details.scan_boundary, "overlapping-handler-target");
    assert!(!details.entries.iter().any(|entry| entry.index == 20));
    assert!(details
        .scan_boundary_rationale
        .iter()
        .any(|why| why.contains("overlaps")));
}
