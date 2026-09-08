//! Classification of startup init-descriptor record handlers.
//!
//! A scatter-load descriptor names the function that services its record, so
//! copy / zero / decompress is decided per record by that function's shape.
//! Table recovery alone does not distinguish a handler
//! that *decompresses* `.data` out of flash rather than copying it. That is
//! worth surfacing on its own, for three reasons:
//!
//! * It is a toolchain fingerprint. GCC and Clang emit straight copies; a
//!   packed `.data` image means a vendor runtime with a packed-copy variant.
//! * It is an unusual-firmware signal. A build compressing `.data` is
//!   flash-constrained and is likely doing other unusual things.
//! * It breaks naive loaders. Anything that assumes the flash image of `.data`
//!   is a byte-identical copy of its RAM contents will mis-populate RAM.
//!
//! Detection is structural. An LZ77/LZSS control-byte codec reads a byte,
//! splits it into a literal count and a match count with a byte-extend
//! fallback when a field reads zero, copies that many literal bytes, then
//! copies a run from earlier output through a back-reference. Those four
//! observations are reported individually so a reader can see what the
//! classification rests on rather than being handed a bare label.

use fat_core::mcu_inspection::{
    CompressorVariant, HandlerEvidence, HandlerEvidenceKind, InitHandlerClassification,
    InitHandlerKind, InitRecord, ToolchainFingerprint,
};

use crate::mcu_init_table::ImageAddressing;
use crate::mcu_thumb::{decode_function, AccessWidth, DecodedFunction, ThumbOp};

/// Confidence reported when every part of the codec shape is present.
const FULL_DECOMPRESS_CONFIDENCE: f32 = 0.85;
/// Confidence reported when the control split plus two of the three loops are
/// present but the fourth observation is missing.
const PARTIAL_DECOMPRESS_CONFIDENCE: f32 = 0.7;
/// Confidence for the plain word-copy and zero-fill templates, which are
/// unambiguous.
const TEMPLATE_CONFIDENCE: f32 = 0.95;
/// Confidence for a load/store loop that matches no template.
const CUSTOM_CONFIDENCE: f32 = 0.3;

/// Classify the handler function at `handler`.
pub fn classify_handler(
    bytes: &[u8],
    handler: u32,
    addressing: &ImageAddressing,
) -> InitHandlerClassification {
    let Some(decoded) = decode_function(bytes, handler, addressing) else {
        return unknown();
    };
    classify_decoded(&decoded)
}

fn unknown() -> InitHandlerClassification {
    InitHandlerClassification {
        kind: InitHandlerKind::Unknown,
        compressor: None,
        evidence: Vec::new(),
        confidence: 0.0,
    }
}

fn classify_decoded(decoded: &DecodedFunction) -> InitHandlerClassification {
    if let Some(classification) = classify_decompressor(decoded) {
        return classification;
    }
    classify_copy_or_fill(decoded)
}

/// A byte-granular copy loop: a backward branch whose body both loads and
/// stores a byte.
#[derive(Debug, Clone, Copy)]
struct ByteCopyLoop {
    head: u32,
    back_edge: u32,
}

fn classify_decompressor(decoded: &DecodedFunction) -> Option<InitHandlerClassification> {
    let split = control_byte_split(decoded)?;
    let loops = byte_copy_loops(decoded);
    let extended = extended_count_fallback(decoded);
    let back_reference = back_reference_loop(decoded, &loops);

    let mut evidence = vec![HandlerEvidence {
        kind: HandlerEvidenceKind::ControlByteSplit {
            literal_bits: split.literal_bits,
            match_bits: split.match_bits,
        },
        description: format!(
            "control byte split {}/{}: mask #{:#x} and right shift #{}",
            split.literal_bits, split.match_bits, split.mask, split.shift
        ),
        instruction_addr: split.address,
    }];
    if let Some(address) = extended {
        evidence.push(HandlerEvidence {
            kind: HandlerEvidenceKind::ExtendedCountFallback,
            description: "conditional byte load re-reads a count field that read zero".to_string(),
            instruction_addr: address,
        });
    }
    if let Some(literal) = loops.first() {
        evidence.push(HandlerEvidence {
            kind: HandlerEvidenceKind::LiteralCopyLoop,
            description: "byte load/store loop copying a literal run".to_string(),
            instruction_addr: literal.head,
        });
    }
    if let Some(address) = back_reference {
        evidence.push(HandlerEvidence {
            kind: HandlerEvidenceKind::BackReferenceLoop,
            description: "second byte copy loop fed by a subtracted output pointer".to_string(),
            instruction_addr: address,
        });
    }

    // The split alone is not enough: an ordinary bitfield unpacker would show
    // it too. Require the copy machinery that makes it a codec.
    let supporting = evidence.len() - 1;
    if supporting < 2 {
        return None;
    }

    Some(InitHandlerClassification {
        kind: InitHandlerKind::Decompress,
        compressor: Some(CompressorVariant::Lzss {
            literal_bits: split.literal_bits,
            match_bits: split.match_bits,
        }),
        confidence: if supporting >= 3 {
            FULL_DECOMPRESS_CONFIDENCE
        } else {
            PARTIAL_DECOMPRESS_CONFIDENCE
        },
        evidence,
    })
}

#[derive(Debug, Clone, Copy)]
struct ControlSplit {
    literal_bits: u8,
    match_bits: u8,
    mask: u32,
    shift: u8,
    address: u32,
}

/// A byte loaded into a register that is then both masked with a low-bit mask
/// and right-shifted: the control byte of a control-byte codec.
fn control_byte_split(decoded: &DecodedFunction) -> Option<ControlSplit> {
    let byte_loaded = decoded.byte_loaded_registers();

    for insn in &decoded.instructions {
        let ThumbOp::AndImm { rn, imm, .. } = insn.op else {
            continue;
        };
        if !byte_loaded.get(rn as usize).copied().unwrap_or(false) {
            continue;
        }
        // A literal count occupies the low bits, so the mask is 2^k - 1 and
        // must leave room for a match field in the same byte.
        let literal_bits = match imm {
            0x1 | 0x3 | 0x7 | 0xf | 0x1f | 0x3f => imm.count_ones() as u8,
            _ => continue,
        };
        for other in &decoded.instructions {
            let ThumbOp::ShiftRightImm {
                rn: shift_rn,
                amount,
                ..
            } = other.op
            else {
                continue;
            };
            if shift_rn != rn || !(1..8).contains(&amount) {
                continue;
            }
            // Both fields must fit inside the same eight bits.
            if u32::from(amount) < literal_bits.into() {
                continue;
            }
            return Some(ControlSplit {
                literal_bits,
                match_bits: 8 - amount,
                mask: imm,
                shift: amount,
                address: insn.address,
            });
        }
    }
    None
}

/// A conditionally executed byte load: the re-read of a count field whose
/// in-band encoding was the escape value.
///
/// Both forms compilers produce count: a load inside an `it` block, and a load
/// jumped over by a conditional branch.
fn extended_count_fallback(decoded: &DecodedFunction) -> Option<u32> {
    for (index, insn) in decoded.instructions.iter().enumerate() {
        if !matches!(
            insn.op,
            ThumbOp::Load {
                width: AccessWidth::Byte,
                ..
            }
        ) {
            continue;
        }
        if insn.predicated {
            return Some(insn.address);
        }
        let skipped_by_branch = decoded.instructions[..index]
            .iter()
            .rev()
            .take(2)
            .any(|prior| {
                matches!(
                    prior.op,
                    ThumbOp::Branch {
                        target,
                        conditional: true,
                    } if target > insn.address
                )
            });
        if skipped_by_branch {
            return Some(insn.address);
        }
    }
    None
}

/// Backward branches whose loop body both loads and stores a byte.
fn byte_copy_loops(decoded: &DecodedFunction) -> Vec<ByteCopyLoop> {
    let mut loops: Vec<ByteCopyLoop> = Vec::new();
    for insn in &decoded.instructions {
        let ThumbOp::Branch { target, .. } = insn.op else {
            continue;
        };
        if target >= insn.address {
            continue;
        }
        let body = decoded
            .instructions
            .iter()
            .filter(|candidate| (target..=insn.address).contains(&candidate.address));
        let mut loads = false;
        let mut stores = false;
        for candidate in body {
            match candidate.op {
                ThumbOp::Load {
                    width: AccessWidth::Byte,
                    ..
                } => loads = true,
                ThumbOp::Store {
                    width: AccessWidth::Byte,
                    ..
                } => stores = true,
                _ => {}
            }
        }
        if loads && stores && !loops.iter().any(|existing| existing.head == target) {
            loops.push(ByteCopyLoop {
                head: target,
                back_edge: insn.address,
            });
        }
    }
    loops
}

/// The back-reference copy: a second byte copy loop, whose source pointer is
/// produced by subtracting an offset from the output pointer.
fn back_reference_loop(decoded: &DecodedFunction, loops: &[ByteCopyLoop]) -> Option<u32> {
    if loops.len() < 2 {
        return None;
    }
    let subtracts = decoded
        .instructions
        .iter()
        .any(|insn| matches!(insn.op, ThumbOp::SubReg { .. } | ThumbOp::NegReg { .. }));
    subtracts.then(|| loops[1].back_edge)
}

/// The word-copy / zero-fill / byte-loop classification, kept behaviourally
/// identical to what the init-table extractor did before handler shapes were
/// modelled: it is what every non-decompressing handler still falls back to.
fn classify_copy_or_fill(decoded: &DecodedFunction) -> InitHandlerClassification {
    let mut word_loads = 0u32;
    let mut word_stores = 0u32;
    let mut narrow_loads = 0u32;
    let mut narrow_stores = 0u32;
    let mut zero_constant = false;
    let mut first_store = None;

    for insn in &decoded.instructions {
        match insn.op {
            ThumbOp::MovImm { imm: 0, .. } => zero_constant = true,
            ThumbOp::Load { width, .. } => match width {
                AccessWidth::Word | AccessWidth::Multiple => word_loads += 1,
                AccessWidth::Byte | AccessWidth::Halfword => narrow_loads += 1,
            },
            ThumbOp::Store { width, .. } => {
                first_store.get_or_insert(insn.address);
                match width {
                    AccessWidth::Word | AccessWidth::Multiple => word_stores += 1,
                    AccessWidth::Byte | AccessWidth::Halfword => narrow_stores += 1,
                }
            }
            _ => {}
        }
    }

    let loads = word_loads + narrow_loads;
    let stores = word_stores + narrow_stores;
    let store_address = first_store.unwrap_or(decoded.start);

    if stores == 0 {
        return unknown();
    }
    if loads == 0 {
        return if zero_constant {
            InitHandlerClassification {
                kind: InitHandlerKind::ZeroInit,
                compressor: None,
                evidence: vec![HandlerEvidence {
                    kind: HandlerEvidenceKind::ZeroInitLoop,
                    description: "store loop with no load and a zero constant in scope".to_string(),
                    instruction_addr: store_address,
                }],
                confidence: TEMPLATE_CONFIDENCE,
            }
        } else {
            unknown()
        };
    }
    if narrow_loads > 0 || narrow_stores > 0 {
        // Byte or halfword granularity that is not a recognised codec: a
        // byte-wise memcpy, or a codec this classifier does not model. Say so
        // rather than guessing, and carry no evidence for a guess.
        return InitHandlerClassification {
            kind: InitHandlerKind::Custom,
            compressor: None,
            evidence: Vec::new(),
            confidence: CUSTOM_CONFIDENCE,
        };
    }
    if word_loads > 0 && word_stores > 0 {
        return InitHandlerClassification {
            kind: InitHandlerKind::WordCopy,
            compressor: None,
            evidence: vec![HandlerEvidence {
                kind: HandlerEvidenceKind::WordCopyLoop,
                description: "word load feeding a word store".to_string(),
                instruction_addr: store_address,
            }],
            confidence: TEMPLATE_CONFIDENCE,
        };
    }
    unknown()
}

/// Derive a toolchain hint from how the recovered records initialise memory.
///
/// Returns `None` when nothing is compressed, which is the common case and
/// carries no signal worth reporting.
pub fn toolchain_fingerprint(records: &[InitRecord]) -> Option<ToolchainFingerprint> {
    let compressor = records
        .iter()
        .filter(|record| record.handler_kind == InitHandlerKind::Decompress)
        .find_map(|record| {
            record
                .handler_classification
                .as_ref()
                .and_then(|classification| classification.compressor)
        })?;

    let mut notes = vec![
        "GCC and Clang runtimes copy .data verbatim; a packed .data image implies a vendor \
         packed-copy runtime"
            .to_string(),
    ];
    let consistent_with = match compressor {
        CompressorVariant::Lzss {
            literal_bits: 3,
            match_bits: 4,
        } => {
            notes.push(
                "control-byte split 3/4 matches IAR's packed-copy runtime; the split alone does \
                 not identify the vendor"
                    .to_string(),
            );
            vec!["iar-ewarm".to_string()]
        }
        CompressorVariant::Lzss { .. } => {
            notes.push(
                "control-byte split does not match a packed-copy runtime this build knows about"
                    .to_string(),
            );
            Vec::new()
        }
        CompressorVariant::UnclassifiedLz => Vec::new(),
    };

    Some(ToolchainFingerprint {
        data_compression: Some(compressor),
        confidence: if consistent_with.is_empty() { 0.2 } else { 0.4 },
        consistent_with,
        notes,
    })
}
