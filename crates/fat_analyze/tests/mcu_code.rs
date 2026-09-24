use fat_analyze::mcu_code::{analyze_code, CodeSeed};
use fat_analyze::mcu_init_table::ImageAddressing;
use fat_core::mcu_code::MemoryAccessKind;

const BASE: u32 = 0x0800_0000;
fn analyze(bytes: &[u8]) -> fat_core::mcu_code::McuCodeReport {
    analyze_code(
        bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: bytes.len(),
        },
        &[CodeSeed {
            address: BASE,
            reason: "reset-vector".into(),
        }],
        None,
    )
}
fn hw(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn direct_branch_skips_literal_and_return_stops_before_data() {
    let mut bytes = vec![0xff; 32];
    hw(&mut bytes, 0, 0x4801); // ldr r0, [pc,#4] -> pool 8
    hw(&mut bytes, 2, 0xe003); // b 12
    word(&mut bytes, 8, BASE + 20);
    hw(&mut bytes, 12, 0x4770); // bx lr
    bytes[20..26].copy_from_slice(b"Hello\0");
    let report = analyze(&bytes);
    assert_eq!(report.instruction_count, 3);
    assert_eq!(report.literal_references.len(), 1);
    assert_eq!(report.literal_references[0].pool_offset, 8);
    assert_eq!(report.string_references[0].value, "Hello");
    assert!(report
        .instruction_ranges
        .iter()
        .all(|range| range.file_offset < 4 || range.file_offset == 12));
    assert!(report.memory_accesses.is_empty());
}

#[test]
fn unrelated_strings_are_not_code_references() {
    let mut bytes = vec![0xff; 24];
    hw(&mut bytes, 0, 0x4770);
    bytes[8..19].copy_from_slice(b"Peripheral\0");
    let report = analyze(&bytes);
    assert_eq!(report.instruction_count, 1);
    assert!(report.string_references.is_empty());
}

#[test]
fn unknown_indirect_branch_is_not_a_return_or_fallthrough() {
    let bytes = [0x18, 0x47, 0x00, 0x20, 0x70, 0x47]; // bx r3; movs; bx lr
    let report = analyze(&bytes);
    assert_eq!(report.instruction_count, 1);
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "unresolved-indirect-branch"));
    assert!(report.flow_edges.iter().all(|edge| edge.kind != "return"));
}

#[test]
fn partial_wide_instruction_and_out_of_mapping_stop_cleanly() {
    let report = analyze(&[0x00, 0xf0]);
    assert_eq!(report.instruction_count, 0);
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "truncated-instruction"));
    let report = analyze_code(
        &[0x70, 0x47],
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 2,
        },
        &[CodeSeed {
            address: BASE + 16,
            reason: "reset-vector".into(),
        }],
        None,
    );
    assert_eq!(report.instruction_count, 0);
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "outside-mapped-input"));
}

#[test]
fn register_access_requires_dereference_and_call_discards_constants() {
    let mut bytes = vec![0xff; 24];
    hw(&mut bytes, 0, 0x4803); // ldr r0 pool 16
    hw(&mut bytes, 2, 0x6801); // ldr r1 [r0]
    hw(&mut bytes, 4, 0x4798); // blx r3
    hw(&mut bytes, 6, 0x6802); // ldr r2 [r0] -> unknown after call
    hw(&mut bytes, 8, 0x4770);
    word(&mut bytes, 16, 0xe000_ed00);
    let report = analyze(&bytes);
    assert_eq!(report.memory_accesses.len(), 1);
    assert_eq!(report.memory_accesses[0].access, MemoryAccessKind::Read);
    assert_eq!(report.memory_accesses[0].target, 0xe000_ed00);
    assert_eq!(report.memory_accesses[0].instruction_offset, 2);
}

#[test]
fn direct_calls_create_candidates_and_do_not_decode_entire_gap() {
    let mut bytes = vec![0xff; 32];
    hw(&mut bytes, 0, 0xf000);
    hw(&mut bytes, 2, 0xf806); // bl 16
    hw(&mut bytes, 4, 0x4770);
    hw(&mut bytes, 16, 0x4770);
    let report = analyze(&bytes);
    assert_eq!(report.instruction_count, 3);
    assert!(report
        .function_candidates
        .iter()
        .any(|candidate| candidate.address == BASE + 16
            && candidate.reasons.contains(&"direct-call-target".into())));
}

#[test]
fn utf16_literal_reference_preserves_encoding_and_offsets() {
    let mut bytes = vec![0xff; 48];
    hw(&mut bytes, 0, 0x4801);
    hw(&mut bytes, 2, 0x4770);
    word(&mut bytes, 8, BASE + 24);
    for (index, value) in "Boot ROM\0".encode_utf16().enumerate() {
        hw(&mut bytes, 24 + index * 2, value);
    }
    let report = analyze(&bytes);
    assert_eq!(report.string_references[0].encoding, "utf-16le");
    assert_eq!(report.string_references[0].file_offset, 24);
}

#[test]
fn branch_join_and_unsupported_encoding_do_not_keep_register_constants() {
    let mut bytes = vec![0xff; 24];
    hw(&mut bytes, 0, 0x4803); // literal into r0
    hw(&mut bytes, 2, 0xe000); // branch to 6
    hw(&mut bytes, 6, 0x6801); // no constant imported into new block
    hw(&mut bytes, 8, 0x4770);
    word(&mut bytes, 16, 0xe000_ed00);
    assert!(analyze(&bytes).memory_accesses.is_empty());
    hw(&mut bytes, 2, 0x0000); // unsupported LSL: stop, do not trust r0 afterward
    let report = analyze(&bytes);
    assert!(report.memory_accesses.is_empty());
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "unsupported-instruction"));
}

#[test]
fn wide_pop_with_pc_does_not_fall_through_into_data() {
    let bytes = [0xbd, 0xe8, 0x00, 0x80, 0x00, 0x20, 0x70, 0x47];
    let report = analyze(&bytes);
    assert_eq!(report.instruction_count, 1);
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "unresolved-multiple-pc-load"));
}

#[test]
fn mapping_length_limits_literals_and_partial_halfwords() {
    let bytes = [0x00, 0x48, 0x70, 0x47, 0x00, 0xed, 0x00, 0xe0];
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 6,
        },
        &[CodeSeed {
            address: BASE,
            reason: "reset-vector".into(),
        }],
        None,
    );
    assert!(report.literal_references.is_empty());
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 1,
        },
        &[CodeSeed {
            address: BASE,
            reason: "reset-vector".into(),
        }],
        None,
    );
    assert_eq!(report.instruction_count, 0);
}

#[test]
fn observed_literal_pool_is_never_an_instruction_range_even_with_a_conflicting_seed() {
    let mut bytes = vec![0xff; 16];
    hw(&mut bytes, 0, 0x4801);
    hw(&mut bytes, 2, 0x4770);
    word(&mut bytes, 8, 0x4770_2000); // plausible instructions but a referenced literal word
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: bytes.len(),
        },
        &[
            CodeSeed {
                address: BASE + 8,
                reason: "vector-handler".into(),
            },
            CodeSeed {
                address: BASE,
                reason: "reset-vector".into(),
            },
        ],
        None,
    );
    assert!(report
        .instruction_ranges
        .iter()
        .all(|range| range.file_offset < 8));
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "code-literal-overlap"));
}

#[test]
fn initialization_only_summarizes_known_recovered_descriptor_semantics() {
    use fat_core::mcu_inspection::{InitHandlerKind, InitRecord, InitTableReport};
    let tables = InitTableReport {
        records: vec![
            InitRecord {
                record_address: BASE + 0x100,
                src: Some(BASE + 0x200),
                dst: 0x2000_0000,
                size: 16,
                handler_kind: InitHandlerKind::WordCopy,
                ..Default::default()
            },
            InitRecord {
                record_address: BASE + 0x110,
                dst: 0x2000_0010,
                size: 32,
                handler_kind: InitHandlerKind::ZeroInit,
                ..Default::default()
            },
            InitRecord {
                record_address: BASE + 0x120,
                dst: 0x2000_0030,
                size: 32,
                handler_kind: InitHandlerKind::Unknown,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let report = analyze_code(
        &[0x70, 0x47],
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 2,
        },
        &[CodeSeed {
            address: BASE,
            reason: "reset-vector".into(),
        }],
        Some(&tables),
    );
    assert_eq!(report.initialization.len(), 2);
    assert_eq!(report.initialization[0].kind, "copy-descriptor");
    assert_eq!(report.initialization[1].kind, "zero-descriptor");
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("do not prove")));
}

#[test]
fn loops_and_long_fallthrough_are_bounded() {
    let report = analyze(&[0xfe, 0xe7]); // b .
    assert_eq!(report.instruction_count, 1);
    let report = analyze(&[0x00, 0xbf].repeat(5000));
    assert!(report.budget_exhausted);
    assert_eq!(report.instruction_count, report.instruction_budget);
}

#[test]
fn contradictory_halfword_seeds_do_not_produce_overlapping_instruction_ranges() {
    let bytes = [0x40, 0xf2, 0x00, 0x00, 0x70, 0x47]; // movw r0, #0; bx lr
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: bytes.len(),
        },
        &[
            CodeSeed {
                address: BASE + 2,
                reason: "handler-vector".into(),
            },
            CodeSeed {
                address: BASE,
                reason: "reset-vector".into(),
            },
        ],
        None,
    );
    assert!(
        report
            .instruction_ranges
            .windows(2)
            .all(|ranges| ranges[0].file_offset + u64::from(ranges[0].length)
                <= ranges[1].file_offset)
    );
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "overlapping-instruction-boundary"));
}

#[test]
fn literal_pool_seed_does_not_survive_as_a_function_candidate() {
    let mut bytes = vec![0xff; 16];
    hw(&mut bytes, 0, 0x4801);
    hw(&mut bytes, 2, 0x4770);
    word(&mut bytes, 8, 0x4770_2000);
    for entries in [[BASE, BASE + 8], [BASE + 8, BASE]] {
        let seeds = entries.map(|address| CodeSeed {
            address,
            reason: "vector-handler".into(),
        });
        let report = analyze_code(
            &bytes,
            &ImageAddressing {
                flash_base: BASE,
                vector_offset: 0,
                image_len: bytes.len(),
            },
            &seeds,
            None,
        );
        assert!(report
            .function_candidates
            .iter()
            .all(|candidate| candidate.address != BASE + 8));
    }
}

#[test]
fn nop_does_not_discard_a_known_literal_constant() {
    let mut bytes = vec![0xff; 24];
    hw(&mut bytes, 0, 0x4803);
    hw(&mut bytes, 2, 0xbf00); // ldr r0 pool16; nop
    hw(&mut bytes, 4, 0x6801);
    hw(&mut bytes, 6, 0x4770); // ldr r1 [r0]; return
    word(&mut bytes, 16, 0xe000_ed00);
    let report = analyze(&bytes);
    assert_eq!(report.memory_accesses.len(), 1);
    assert_eq!(report.memory_accesses[0].instruction_offset, 4);
}

#[test]
fn wide_conditional_branch_offsets_follow_t3_encoding() {
    use fat_analyze::mcu_thumb::{decode_instruction, ThumbOp};
    // Assembled with arm-none-eabi-as .arch armv7-m, then checked with objdump:
    // bne.w .-2; bne.w .+0x40004; bne.w .+0x80004
    for (first, second, delta) in [
        (0xf47fu16, 0xaffdu16, -2i32),
        (0xf040, 0xa000, 0x40004),
        (0xf040, 0x8800, 0x80004),
    ] {
        let mut bytes = [0u8; 4];
        hw(&mut bytes, 0, first);
        hw(&mut bytes, 2, second);
        let addressing = ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 4,
        };
        assert_eq!(
            decode_instruction(&bytes, BASE, &addressing).unwrap().op,
            ThumbOp::Branch {
                target: BASE.wrapping_add_signed(delta),
                conditional: true
            }
        );
    }
}

#[test]
fn thumb_barriers_are_never_decoded_as_conditional_branches() {
    use fat_analyze::mcu_thumb::{decode_instruction, ThumbOp};
    // arm-none-eabi-as: dmb sy; dsb sy; isb sy.
    for second in [0x8f5f, 0x8f4f, 0x8f6f] {
        let mut bytes = [0u8; 4];
        hw(&mut bytes, 0, 0xf3bf);
        hw(&mut bytes, 2, second);
        let addressing = ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: 4,
        };
        assert!(!matches!(
            decode_instruction(&bytes, BASE, &addressing).unwrap().op,
            ThumbOp::Branch { .. } | ThumbOp::Call { .. }
        ));
    }
}

#[test]
fn repeated_vector_targets_do_not_consume_the_unique_function_budget() {
    let mut seeds = (0..150)
        .map(|index| CodeSeed {
            address: BASE,
            reason: format!("vector-entry-{index}"),
        })
        .collect::<Vec<_>>();
    seeds.push(CodeSeed {
        address: BASE + 2,
        reason: "vector-entry-150".into(),
    });
    let bytes = [0x70, 0x47, 0x70, 0x47];
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: bytes.len(),
        },
        &seeds,
        None,
    );
    assert_eq!(report.function_candidates.len(), 2);
    assert_eq!(report.instruction_count, 2);
    assert!(!report.budget_exhausted);
}

#[test]
fn startup_descriptor_scanner_does_not_follow_barriers_past_return() {
    use fat_analyze::mcu_init_table::scan_frame;
    // dmb sy; bx lr; data that resembles ldr r0,[r0]
    let bytes = [0xbf, 0xf3, 0x5f, 0x8f, 0x70, 0x47, 0x00, 0x68];
    let addressing = ImageAddressing {
        flash_base: BASE,
        vector_offset: 0,
        image_len: bytes.len(),
    };
    let frame = scan_frame(&bytes, BASE, &addressing).unwrap();
    assert_eq!(frame.memory.word_loads, 0);
    assert_eq!(frame.memory.loop_backedges, 0);
}

#[test]
fn local_literal_thumb_trampoline_is_followed_without_target_state() {
    for base in [0x0800_0000, 0x1fff_0000, 0x2000_0000] {
        let mut bytes = vec![0xff; 24];
        hw(&mut bytes, 0, 0x4a00); // ldr r2 [pc,#0] -> pool4
        hw(&mut bytes, 2, 0x4710); // bx r2
        word(&mut bytes, 4, base + 9);
        hw(&mut bytes, 8, 0x6811); // ldr r1 [r2]; constant must not cross transfer
        hw(&mut bytes, 10, 0x4770);
        let report = analyze_code(
            &bytes,
            &ImageAddressing {
                flash_base: base,
                vector_offset: 0,
                image_len: bytes.len(),
            },
            &[CodeSeed {
                address: base,
                reason: "reset-vector".into(),
            }],
            None,
        );
        assert_eq!(report.instruction_count, 4);
        assert!(report
            .flow_edges
            .iter()
            .any(|edge| edge.kind == "resolved-indirect-branch" && edge.target == Some(base + 8)));
        assert!(report
            .function_candidates
            .iter()
            .any(|entry| entry.address == base + 8
                && entry
                    .reasons
                    .contains(&"local-constant-indirect-branch-target".into())));
        assert!(report.memory_accesses.is_empty());
    }
}

#[test]
fn local_even_and_unmapped_indirect_targets_are_not_followed() {
    for (value, expected_stop) in [
        (BASE + 8, "non-thumb-indirect-target"),
        (BASE + 0x101, "outside-mapped-indirect-target"),
    ] {
        let mut bytes = vec![0xff; 16];
        hw(&mut bytes, 0, 0x4a00);
        hw(&mut bytes, 2, 0x4710);
        word(&mut bytes, 4, value);
        hw(&mut bytes, 8, 0x4770);
        let report = analyze(&bytes);
        assert_eq!(report.instruction_count, 2);
        assert_eq!(report.function_candidates.len(), 1);
        assert!(report.stops.iter().any(|stop| stop.reason == expected_stop));
    }
}

#[test]
fn late_literal_conflict_omits_descendants_of_the_contradicted_seed() {
    let mut bytes = vec![0xff; 24];
    hw(&mut bytes, 0, 0x4801);
    hw(&mut bytes, 2, 0x4770); // valid source references pool8
    hw(&mut bytes, 8, 0x2000);
    hw(&mut bytes, 10, 0xbf00); // literal value resembles instructions
    hw(&mut bytes, 12, 0x2100);
    hw(&mut bytes, 14, 0x4770); // descendants beyond pool
    let report = analyze_code(
        &bytes,
        &ImageAddressing {
            flash_base: BASE,
            vector_offset: 0,
            image_len: bytes.len(),
        },
        &[
            CodeSeed {
                address: BASE + 8,
                reason: "vector-handler".into(),
            },
            CodeSeed {
                address: BASE,
                reason: "reset-vector".into(),
            },
        ],
        None,
    );
    assert!(report.instruction_ranges.is_empty());
    assert!(report.function_candidates.is_empty());
    assert!(report.flow_edges.is_empty());
    assert!(report.literal_references.is_empty());
    assert!(report
        .stops
        .iter()
        .any(|stop| stop.reason == "code-literal-overlap"));
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("candidate graph") && note.contains("omitted")));
}
