//! A small Thumb-2 decoder for the startup-code analyses.
//!
//! [`crate::mcu_init_table`] already walks startup functions, but it only
//! accumulates *counts* (how many word loads, how many byte stores) because
//! that is all table recovery needs. Recognising a decompressor by its shape,
//! or reading back which peripheral register `SystemInit` wrote, needs the
//! individual instructions: which register a mask was applied to, what value a
//! store carried, where a conditional branch jumped.
//!
//! This decoder covers the encodings those two analyses depend on and maps
//! everything else to [`ThumbOp::Other`]. It is deliberately not a general
//! disassembler: an unrecognised encoding degrades an analysis to "not
//! observed", which is the honest outcome, whereas a wrong decode would put a
//! fabricated fact in a report.

use crate::mcu_init_table::ImageAddressing;

/// Upper bound on how far a single function body is decoded.
const DEFAULT_WINDOW_BYTES: u32 = 0x400;

/// Access width of a load or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessWidth {
    Byte,
    Halfword,
    Word,
    /// `ldm`/`stm`/`ldrd`/`strd`: multiple words, base register only.
    Multiple,
}

/// Indexing mode of a load or store with an immediate offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexMode {
    /// `[rn, #imm]`
    Offset,
    /// `[rn, #imm]!`
    PreIndexed,
    /// `[rn], #imm`
    PostIndexed,
    /// Register offset or writeback list; the effective address is not a
    /// simple base-plus-immediate.
    Computed,
}

/// The subset of Thumb-2 semantics these analyses read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThumbOp {
    /// `ldr rt, [pc, #imm]` with the pool word already resolved.
    LoadLiteral {
        rt: u8,
        value: u32,
    },
    /// `mov`/`movs`/`mov.w`/`movw` with an immediate.
    MovImm {
        rd: u8,
        imm: u32,
    },
    /// `movt rd, #imm16`: replaces the top halfword of `rd`.
    MovTop {
        rd: u8,
        imm: u32,
    },
    MovReg {
        rd: u8,
        rm: u8,
    },
    AndImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    OrrImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    BicImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    EorImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    AddImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    SubImm {
        rd: u8,
        rn: u8,
        imm: u32,
    },
    /// `lsr`/`asr` by an immediate.
    ShiftRightImm {
        rd: u8,
        rn: u8,
        amount: u8,
    },
    SubReg {
        rd: u8,
        rn: u8,
        rm: u8,
    },
    /// `rsbs rd, rn, #0` — the 16-bit `negs`.
    NegReg {
        rd: u8,
        rn: u8,
    },
    Load {
        rt: u8,
        rn: u8,
        offset: u32,
        width: AccessWidth,
        index: IndexMode,
    },
    Store {
        rt: u8,
        rn: u8,
        offset: u32,
        width: AccessWidth,
        index: IndexMode,
    },
    CmpImm {
        rn: u8,
        imm: u32,
    },
    CmpReg {
        rn: u8,
        rm: u8,
    },
    Branch {
        target: u32,
        conditional: bool,
    },
    /// `bl` / `blx` — a call, whose target is known only for the direct form.
    Call {
        target: Option<u32>,
    },
    /// `bx` or `pop {.., pc}`.
    Return,
    /// An `it` block header; the covered instructions carry `predicated`.
    ItBlock,
    /// An encoding this decoder does not model. Deliberately opaque: no
    /// analysis may infer anything from it.
    Other,
}

/// One decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThumbInsn {
    pub address: u32,
    pub width: u32,
    pub op: ThumbOp,
    /// Whether an enclosing `it` block makes this instruction conditional.
    pub predicated: bool,
}

/// A decoded function body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedFunction {
    pub start: u32,
    /// One past the last decoded instruction.
    pub end: u32,
    pub instructions: Vec<ThumbInsn>,
    /// Whether decoding stopped at a terminator rather than at the window cap.
    pub terminated: bool,
}

impl DecodedFunction {
    /// Size in bytes of the decoded body.
    pub fn size(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Registers written by a byte-granular load anywhere in the body.
    pub fn byte_loaded_registers(&self) -> [bool; 16] {
        let mut registers = [false; 16];
        for insn in &self.instructions {
            if let ThumbOp::Load {
                rt,
                width: AccessWidth::Byte,
                ..
            } = insn.op
            {
                if let Some(slot) = registers.get_mut(rt as usize) {
                    *slot = true;
                }
            }
        }
        registers
    }
}

/// Decode one complete instruction at a mapped address. No subsequent bytes are
/// interpreted as instructions and no execution or predicate state is inferred.
pub fn decode_instruction(
    bytes: &[u8],
    address: u32,
    addressing: &ImageAddressing,
) -> Option<ThumbInsn> {
    if address & 1 != 0 {
        return None;
    }
    let offset = addressing.offset_of(address)?;
    if offset.checked_add(2)? > addressing.image_len.min(bytes.len()) {
        return None;
    }
    let first = read_u16(bytes, addressing, address)?;
    let wide = matches!(first & 0xf800, 0xe800 | 0xf000 | 0xf800);
    if wide && offset.checked_add(4)? > addressing.image_len.min(bytes.len()) {
        return None;
    }
    let mut op = if wide {
        let second = read_u16(bytes, addressing, address.checked_add(2)?)?;
        decode_wide(bytes, addressing, first, second, address)
    } else {
        decode_narrow(bytes, addressing, first, address)
    };
    if matches!(op, ThumbOp::LoadLiteral { .. }) {
        // Only a supported word literal wholly inside the selected mapping can
        // establish a constant. The legacy shape decoder has broader semantics.
        let pool = if wide {
            let second = read_u16(bytes, addressing, address.checked_add(2)?)?;
            (first == 0xf8df)
                .then(|| (address.wrapping_add(4) & !3).wrapping_add(u32::from(second & 0xfff)))
        } else {
            Some((address.wrapping_add(4) & !3).wrapping_add(u32::from(first & 0xff) * 4))
        };
        if pool
            .and_then(|pool| addressing.offset_of(pool))
            .and_then(|pool| pool.checked_add(4))
            .is_none_or(|end| end > addressing.image_len.min(bytes.len()))
        {
            op = ThumbOp::Other;
        }
    }
    Some(ThumbInsn {
        address,
        width: if wide { 4 } else { 2 },
        op,
        predicated: false,
    })
}

/// Decode the function body at `start`.
///
/// Decoding stops at the first terminator that sits at or past every forward
/// branch target seen so far — GCC routinely parks loop bodies after the
/// return path, so stopping at the first `bx lr` would truncate the shape the
/// callers are looking for.
pub fn decode_function(
    bytes: &[u8],
    start: u32,
    addressing: &ImageAddressing,
) -> Option<DecodedFunction> {
    decode_function_within(bytes, start, addressing, DEFAULT_WINDOW_BYTES)
}

/// [`decode_function`] with an explicit window size.
pub fn decode_function_within(
    bytes: &[u8],
    start: u32,
    addressing: &ImageAddressing,
    window_bytes: u32,
) -> Option<DecodedFunction> {
    addressing.offset_of(start)?;

    let mut decoded = DecodedFunction {
        start,
        end: start,
        instructions: Vec::new(),
        terminated: false,
    };
    let mut address = start;
    let mut max_forward = start;
    let mut it_remaining = 0u8;
    let limit = start.saturating_add(window_bytes);

    while address < limit {
        let Some(first) = read_u16(bytes, addressing, address) else {
            break;
        };
        let wide = matches!(first & 0xf800, 0xe800 | 0xf000 | 0xf800);
        let width = if wide { 4 } else { 2 };
        let op = if wide {
            let Some(second) = read_u16(bytes, addressing, address.wrapping_add(2)) else {
                break;
            };
            decode_wide(bytes, addressing, first, second, address)
        } else {
            decode_narrow(bytes, addressing, first, address)
        };

        let predicated = it_remaining > 0;
        it_remaining = it_remaining.saturating_sub(1);
        if matches!(op, ThumbOp::ItBlock) {
            it_remaining = it_block_length(first);
        }

        if let ThumbOp::Branch { target, .. } = op {
            if target > address {
                max_forward = max_forward.max(target);
            }
        }

        decoded.instructions.push(ThumbInsn {
            address,
            width,
            op,
            predicated,
        });
        address = address.wrapping_add(width);
        decoded.end = address;

        let terminator = matches!(op, ThumbOp::Return)
            || matches!(
                op,
                ThumbOp::Branch {
                    conditional: false,
                    ..
                }
            );
        if terminator && address > max_forward {
            decoded.terminated = true;
            break;
        }
    }

    Some(decoded)
}

fn read_u16(bytes: &[u8], addressing: &ImageAddressing, address: u32) -> Option<u16> {
    let offset = addressing.offset_of(address)?;
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

/// Number of instructions an `it` block makes conditional (1 plus one per
/// then/else slot).
fn it_block_length(halfword: u16) -> u8 {
    let mask = (halfword & 0xf) as u8;
    match mask {
        0 => 0,
        m if m & 0x1 != 0 => 4,
        m if m & 0x2 != 0 => 3,
        m if m & 0x4 != 0 => 2,
        _ => 1,
    }
}

fn decode_narrow(
    bytes: &[u8],
    addressing: &ImageAddressing,
    halfword: u16,
    address: u32,
) -> ThumbOp {
    let low3 = |shift: u16| ((halfword >> shift) & 0x7) as u8;
    match halfword {
        // LSR/ASR (immediate) T1: the control-byte split of an LZ decoder.
        hw if (0x0800..0x1800).contains(&hw) => {
            let amount = ((hw >> 6) & 0x1f) as u8;
            ThumbOp::ShiftRightImm {
                rd: low3(0),
                rn: low3(3),
                // A zero shift immediate encodes 32.
                amount: if amount == 0 { 32 } else { amount },
            }
        }
        hw if (0x1a00..0x1c00).contains(&hw) => ThumbOp::SubReg {
            rd: low3(0),
            rn: low3(3),
            rm: low3(6),
        },
        hw if (0x1c00..0x1e00).contains(&hw) => ThumbOp::AddImm {
            rd: low3(0),
            rn: low3(3),
            imm: u32::from((hw >> 6) & 0x7),
        },
        hw if (0x1e00..0x2000).contains(&hw) => ThumbOp::SubImm {
            rd: low3(0),
            rn: low3(3),
            imm: u32::from((hw >> 6) & 0x7),
        },
        hw if (0x2000..0x2800).contains(&hw) => ThumbOp::MovImm {
            rd: ((hw >> 8) & 0x7) as u8,
            imm: u32::from(hw & 0xff),
        },
        hw if (0x2800..0x3000).contains(&hw) => ThumbOp::CmpImm {
            rn: ((hw >> 8) & 0x7) as u8,
            imm: u32::from(hw & 0xff),
        },
        hw if (0x3000..0x3800).contains(&hw) => {
            let rd = ((hw >> 8) & 0x7) as u8;
            ThumbOp::AddImm {
                rd,
                rn: rd,
                imm: u32::from(hw & 0xff),
            }
        }
        hw if (0x3800..0x4000).contains(&hw) => {
            let rd = ((hw >> 8) & 0x7) as u8;
            ThumbOp::SubImm {
                rd,
                rn: rd,
                imm: u32::from(hw & 0xff),
            }
        }
        // RSBS Rd, Rn, #0 (`negs`)
        hw if hw & 0xffc0 == 0x4240 => ThumbOp::NegReg {
            rd: low3(0),
            rn: low3(3),
        },
        // CMP (register) T1
        hw if hw & 0xffc0 == 0x4280 => ThumbOp::CmpReg {
            rn: low3(0),
            rm: low3(3),
        },
        // CMP (register) T2, high registers
        hw if hw & 0xff00 == 0x4500 => ThumbOp::CmpReg {
            rn: (hw & 0x7) as u8 | (((hw >> 7) & 0x1) as u8) << 3,
            rm: ((hw >> 3) & 0xf) as u8,
        },
        // MOV (register) T1
        hw if hw & 0xff00 == 0x4600 => ThumbOp::MovReg {
            rd: (hw & 0x7) as u8 | (((hw >> 7) & 0x1) as u8) << 3,
            rm: ((hw >> 3) & 0xf) as u8,
        },
        // BLX Rm
        hw if hw & 0xff87 == 0x4780 => ThumbOp::Call { target: None },
        // BX Rm
        hw if hw & 0xff87 == 0x4700 => ThumbOp::Return,
        // LDR (literal) T1
        hw if (0x4800..0x5000).contains(&hw) => {
            let literal = (address.wrapping_add(4) & !3).wrapping_add(u32::from(hw & 0xff) * 4);
            match read_u32(bytes, addressing, literal) {
                Some(value) => ThumbOp::LoadLiteral {
                    rt: ((hw >> 8) & 0x7) as u8,
                    value,
                },
                None => ThumbOp::Other,
            }
        }
        // Load/store register offset: 0101 op(3) Rm Rn Rt
        hw if (0x5000..0x6000).contains(&hw) => {
            let rt = low3(0);
            let rn = low3(3);
            let (store, width) = match (hw >> 9) & 0x7 {
                0 => (true, AccessWidth::Word),
                1 => (true, AccessWidth::Halfword),
                2 => (true, AccessWidth::Byte),
                3 => (false, AccessWidth::Byte),
                4 => (false, AccessWidth::Word),
                5 => (false, AccessWidth::Halfword),
                6 => (false, AccessWidth::Byte),
                _ => (false, AccessWidth::Halfword),
            };
            build_access(store, rt, rn, 0, width, IndexMode::Computed)
        }
        hw if (0x6000..0x6800).contains(&hw) => build_access(
            true,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f) * 4,
            AccessWidth::Word,
            IndexMode::Offset,
        ),
        hw if (0x6800..0x7000).contains(&hw) => build_access(
            false,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f) * 4,
            AccessWidth::Word,
            IndexMode::Offset,
        ),
        hw if (0x7000..0x7800).contains(&hw) => build_access(
            true,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f),
            AccessWidth::Byte,
            IndexMode::Offset,
        ),
        hw if (0x7800..0x8000).contains(&hw) => build_access(
            false,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f),
            AccessWidth::Byte,
            IndexMode::Offset,
        ),
        hw if (0x8000..0x8800).contains(&hw) => build_access(
            true,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f) * 2,
            AccessWidth::Halfword,
            IndexMode::Offset,
        ),
        hw if (0x8800..0x9000).contains(&hw) => build_access(
            false,
            low3(0),
            low3(3),
            u32::from((hw >> 6) & 0x1f) * 2,
            AccessWidth::Halfword,
            IndexMode::Offset,
        ),
        // CBZ / CBNZ
        hw if hw & 0xf500 == 0xb100 => {
            let imm = u32::from(((hw >> 3) & 0x1f) | ((hw >> 4) & 0x20));
            ThumbOp::Branch {
                target: address.wrapping_add(4).wrapping_add(imm * 2),
                conditional: true,
            }
        }
        // POP {.., pc}
        hw if hw & 0xff00 == 0xbd00 => ThumbOp::Return,
        // IT (a hint has a zero mask and is not an IT block)
        hw if hw & 0xff00 == 0xbf00 && hw & 0x000f != 0 => ThumbOp::ItBlock,
        hw if (0xc000..0xc800).contains(&hw) => build_access(
            true,
            0,
            low3(8),
            0,
            AccessWidth::Multiple,
            IndexMode::Computed,
        ),
        hw if (0xc800..0xd000).contains(&hw) => build_access(
            false,
            0,
            low3(8),
            0,
            AccessWidth::Multiple,
            IndexMode::Computed,
        ),
        // B<cond> T1 (0b1110 is UDF, 0b1111 is SVC)
        hw if hw & 0xf000 == 0xd000 && (hw & 0x0f00) <= 0x0d00 => {
            let imm8 = (hw & 0x00ff) as i32;
            let signed = if imm8 & 0x80 != 0 { imm8 | !0xff } else { imm8 };
            ThumbOp::Branch {
                target: address.wrapping_add(4).wrapping_add_signed(signed << 1),
                conditional: true,
            }
        }
        // B T2 (unconditional)
        hw if (0xe000..0xe800).contains(&hw) => {
            let imm11 = (hw & 0x07ff) as i32;
            let signed = if imm11 & 0x400 != 0 {
                imm11 | !0x07ff
            } else {
                imm11
            };
            ThumbOp::Branch {
                target: address.wrapping_add(4).wrapping_add_signed(signed << 1),
                conditional: false,
            }
        }
        _ => ThumbOp::Other,
    }
}

fn build_access(
    store: bool,
    rt: u8,
    rn: u8,
    offset: u32,
    width: AccessWidth,
    index: IndexMode,
) -> ThumbOp {
    if store {
        ThumbOp::Store {
            rt,
            rn,
            offset,
            width,
            index,
        }
    } else {
        ThumbOp::Load {
            rt,
            rn,
            offset,
            width,
            index,
        }
    }
}

fn read_u32(bytes: &[u8], addressing: &ImageAddressing, address: u32) -> Option<u32> {
    let offset = addressing.offset_of(address)?;
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn decode_wide(
    bytes: &[u8],
    addressing: &ImageAddressing,
    first: u16,
    second: u16,
    address: u32,
) -> ThumbOp {
    // Branches and calls: bit 15 of the second halfword is set.
    if first & 0xf800 == 0xf000 && second & 0x8000 != 0 {
        return match second & 0xd000 {
            0xd000 => ThumbOp::Call {
                target: wide_branch_target(first, second, address, true),
            },
            0x9000 => match wide_branch_target(first, second, address, true) {
                Some(target) => ThumbOp::Branch {
                    target,
                    conditional: false,
                },
                None => ThumbOp::Other,
            },
            0x8000 if (first >> 6) & 0xf < 0xe => {
                match wide_branch_target(first, second, address, false) {
                    Some(target) => ThumbOp::Branch {
                        target,
                        conditional: true,
                    },
                    None => ThumbOp::Other,
                }
            }
            _ => ThumbOp::Other,
        };
    }

    // MOVW / MOVT: 16-bit immediate, no ThumbExpandImm.
    if first & 0xfbf0 == 0xf240 || first & 0xfbf0 == 0xf2c0 {
        let imm4 = u32::from(first & 0xf);
        let i = u32::from((first >> 10) & 1);
        let imm3 = u32::from((second >> 12) & 0x7);
        let imm8 = u32::from(second & 0xff);
        let imm = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
        let rd = ((second >> 8) & 0xf) as u8;
        return if first & 0xfbf0 == 0xf240 {
            ThumbOp::MovImm { rd, imm }
        } else {
            ThumbOp::MovTop { rd, imm }
        };
    }

    // ADDW / SUBW: plain 12-bit immediate.
    if first & 0xfbf0 == 0xf200 || first & 0xfbf0 == 0xf2a0 {
        let i = u32::from((first >> 10) & 1);
        let imm3 = u32::from((second >> 12) & 0x7);
        let imm8 = u32::from(second & 0xff);
        let imm = (i << 11) | (imm3 << 8) | imm8;
        let rd = ((second >> 8) & 0xf) as u8;
        let rn = (first & 0xf) as u8;
        return if first & 0xfbf0 == 0xf200 {
            ThumbOp::AddImm { rd, rn, imm }
        } else {
            ThumbOp::SubImm { rd, rn, imm }
        };
    }

    // Data processing (modified immediate).
    if first & 0xfa00 == 0xf000 && second & 0x8000 == 0 {
        let op = (first >> 5) & 0xf;
        let rn = (first & 0xf) as u8;
        let rd = ((second >> 8) & 0xf) as u8;
        let Some(imm) = thumb_expand_imm(first, second) else {
            return ThumbOp::Other;
        };
        return match op {
            0x0 => ThumbOp::AndImm { rd, rn, imm },
            0x1 => ThumbOp::BicImm { rd, rn, imm },
            // ORR with Rn == PC encodes MOV (immediate).
            0x2 if rn == 0xf => ThumbOp::MovImm { rd, imm },
            0x2 => ThumbOp::OrrImm { rd, rn, imm },
            0x4 => ThumbOp::EorImm { rd, rn, imm },
            0x8 => ThumbOp::AddImm { rd, rn, imm },
            // SUB with Rd == PC encodes CMP (immediate).
            0xd if rd == 0xf => ThumbOp::CmpImm { rn, imm },
            0xd => ThumbOp::SubImm { rd, rn, imm },
            _ => ThumbOp::Other,
        };
    }

    // Load/store single, immediate forms.
    if first & 0xfe00 == 0xf800 {
        let rn = (first & 0xf) as u8;
        let rt = ((second >> 12) & 0xf) as u8;
        let width = match first & 0x0060 {
            0x0000 => AccessWidth::Byte,
            0x0020 => AccessWidth::Halfword,
            0x0040 => AccessWidth::Word,
            _ => return ThumbOp::Other,
        };
        let store = first & 0x0010 == 0;
        // PC-relative: resolve through the literal pool like the narrow form.
        if rn == 0xf {
            if !store && first & 0x0080 != 0 {
                let displacement = u32::from(second & 0x0fff);
                let base = address.wrapping_add(4) & !3;
                // Bit 7 of the first halfword is the U (add) bit for this form.
                let literal = if first & 0x0080 != 0 && first & 0x0100 == 0 {
                    base.wrapping_add(displacement)
                } else {
                    base.wrapping_sub(displacement)
                };
                if let Some(value) = read_u32(bytes, addressing, literal) {
                    return ThumbOp::LoadLiteral { rt, value };
                }
            }
            return ThumbOp::Other;
        }
        // T3: 12-bit positive offset.
        if first & 0x0080 != 0 {
            return build_access(
                store,
                rt,
                rn,
                u32::from(second & 0x0fff),
                width,
                IndexMode::Offset,
            );
        }
        // T4: 8-bit offset with P/U/W, or a register offset.
        if second & 0x0800 == 0 {
            return build_access(store, rt, rn, 0, width, IndexMode::Computed);
        }
        let pre = second & 0x0400 != 0;
        let add = second & 0x0200 != 0;
        let writeback = second & 0x0100 != 0;
        let offset = u32::from(second & 0xff);
        let index = match (pre, writeback) {
            (false, _) => IndexMode::PostIndexed,
            (true, true) => IndexMode::PreIndexed,
            (true, false) => IndexMode::Offset,
        };
        let offset = if add {
            offset
        } else {
            0u32.wrapping_sub(offset)
        };
        return build_access(store, rt, rn, offset, width, index);
    }

    // Load/store multiple and dual: base register only.
    if first & 0xfe40 == 0xe800 {
        let rn = (first & 0xf) as u8;
        let store = first & 0x0010 == 0;
        return build_access(store, 0, rn, 0, AccessWidth::Multiple, IndexMode::Computed);
    }

    ThumbOp::Other
}

/// `ThumbExpandImm` from the ARMv7-M ARM: `i:imm3:imm8` is either a small
/// constant replicated across bytes or an 8-bit value rotated into place.
fn thumb_expand_imm(first: u16, second: u16) -> Option<u32> {
    let i = u32::from((first >> 10) & 1);
    let imm3 = u32::from((second >> 12) & 0x7);
    let imm8 = u32::from(second & 0xff);
    let packed = (i << 11) | (imm3 << 8) | imm8;

    if packed >> 10 == 0 {
        return Some(match (packed >> 8) & 0x3 {
            0 => imm8,
            1 => (imm8 << 16) | imm8,
            2 => (imm8 << 24) | (imm8 << 8),
            _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
        });
    }
    let rotation = packed >> 7;
    let value = 0x80 | (packed & 0x7f);
    Some(value.rotate_right(rotation))
}

pub(crate) fn wide_branch_target(
    first: u16,
    second: u16,
    address: u32,
    j_encoded: bool,
) -> Option<u32> {
    if !j_encoded && (first >> 6) & 0xf >= 0xe {
        // The reserved condition values encode other instructions, including barriers.
        return None;
    }
    let s = u32::from((first >> 10) & 1);
    let j1 = u32::from((second >> 13) & 1);
    let j2 = u32::from((second >> 11) & 1);
    let imm11 = u32::from(second & 0x07ff);
    let signed = if j_encoded {
        let imm10 = u32::from(first & 0x03ff);
        let i1 = (!(j1 ^ s)) & 1;
        let i2 = (!(j2 ^ s)) & 1;
        let imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
        // BL / unconditional B.W: sign-extend S:I1:I2:imm10:imm11:0.
        ((imm25 << 7) as i32) >> 7
    } else {
        // B<cond>.W T3: S:J2:J1:imm6:imm11:0 is a 21-bit offset.
        // J1/J2 are neither inverted nor ordered as in the BL encoding.
        let imm6 = u32::from(first & 0x003f);
        let imm21 = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1);
        ((imm21 << 11) as i32) >> 11
    };
    Some(address.wrapping_add(4).wrapping_add_signed(signed))
}
