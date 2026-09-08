//! Startup init-descriptor table recovery for bare-metal Cortex-M images.
//!
//! `fat inspect mcu` used to stop its startup walk at the reset stub. This
//! module walks past it and recovers the descriptor table the C runtime uses
//! to populate `.data` and clear `.bss`, which pins down the static RAM layout
//! without running the firmware.
//!
//! Two structurally different table layouts are supported and are told apart
//! by their record stride:
//!
//! * **CMSIS** (`startup_ARMCMx.c`): a 12-byte-stride `__copy_table` of
//!   `{src, dst, size}` triples *plus a separate* 8-byte-stride `__zero_table`
//!   of `{dst, size}` pairs. Copy vs zero is decided by which table a record
//!   lives in.
//! * **Scatter-load** (armlink `__scatterload` and equivalents): a single
//!   16-byte-stride table of `{src, dst, size, handler}` records where the
//!   startup loop calls `handler(src, dst, size)` per record.
//!
//! Table bounds are always taken from the literal pool of a startup function
//! (`ldr rN, [pc, #imm]` operands), never from a bare memory scan. A bare scan
//! is not sound here: the trailing `{dst, size}` words of a copy triple read
//! back as a perfectly valid-looking zero pair, so scanning alone manufactures
//! records that do not exist. Anchoring on the reset-vector -> startup-function
//! -> literal-pool chain removes that class of false positive, and every
//! candidate is then re-validated record by record before it is reported.

use fat_core::mcu_inspection::{
    AddressHypothesis, ImageLayoutReport, InitHandlerClassification, InitHandlerKind, InitRecord,
    InitTableFormat, InitTableReport, InitTableSegment, SectionProvenance, StartupChainReport,
};

use crate::mcu_init_handler::{classify_handler, toolchain_fingerprint};
use crate::mcu_inspect::{
    direct_branch_target, direct_call_target, infer_flash_base, map_address_to_offset, read_u32_at,
};

/// Upper bound on how far a single startup function body is decoded.
const FRAME_WINDOW_BYTES: u32 = 0x400;
/// Upper bound on descriptor records per table.
const MAX_RECORDS_PER_TABLE: usize = 64;
/// Upper bound on a single record's destination size (16 MiB).
const MAX_RECORD_SIZE: u32 = 0x0100_0000;
/// How many instructions a literal-pool value stays trusted for when it is
/// used as an indirect branch target.
const LITERAL_RECENCY: usize = 4;

/// Candidate table formats, widest stride first so that a 16-byte scatter-load
/// table wins over an 8-byte reading of the same bytes when both validate.
const CANDIDATE_FORMATS: [InitTableFormat; 3] = [
    InitTableFormat::ScatterLoad,
    InitTableFormat::CmsisCopyTable,
    InitTableFormat::CmsisZeroTable,
];

/// Flash-image addressing: how MCU addresses map onto file offsets.
#[derive(Debug, Clone, Copy)]
pub struct ImageAddressing {
    pub flash_base: u32,
    pub vector_offset: u32,
    pub image_len: usize,
}

impl ImageAddressing {
    /// Derive addressing from a reset-vector address and the layout report.
    pub fn from_layout(
        reset_address: u32,
        layout: &ImageLayoutReport,
        image_len: usize,
    ) -> Option<Self> {
        Some(Self {
            flash_base: infer_flash_base(reset_address)?,
            vector_offset: *layout.candidate_offsets.first().unwrap_or(&0),
            image_len,
        })
    }

    /// File offset an MCU address maps to, or `None` when it falls outside
    /// the loaded image.
    pub fn offset_of(&self, address: u32) -> Option<usize> {
        let offset = map_address_to_offset(address, self.flash_base, self.vector_offset)?;
        (offset < self.image_len).then_some(offset)
    }

    /// Whether `address` falls inside the loaded image.
    pub fn contains(&self, address: u32) -> bool {
        self.offset_of(address).is_some()
    }

    /// Inverse of [`ImageAddressing::offset_of`]: the MCU address a file
    /// offset is loaded at, or `None` for offsets that sit below the vector
    /// table and therefore have no mapped address.
    pub fn address_of(&self, offset: usize) -> Option<u32> {
        let offset = u32::try_from(offset).ok()?;
        let relative = offset.checked_sub(self.vector_offset)?;
        self.flash_base.checked_add(relative)
    }

    fn contains_range(&self, address: u32, length: u32) -> bool {
        let Some(offset) = self.offset_of(address) else {
            return false;
        };
        offset
            .checked_add(length as usize)
            .is_some_and(|end| end <= self.image_len)
    }

    fn read_u32(&self, bytes: &[u8], address: u32) -> Option<u32> {
        let offset = self.offset_of(address)?;
        read_u32_at(bytes, offset)
    }

    fn read_u16(&self, bytes: &[u8], address: u32) -> Option<u16> {
        let offset = self.offset_of(address)?;
        let slice = bytes.get(offset..offset + 2)?;
        Some(u16::from_le_bytes(slice.try_into().ok()?))
    }
}

/// Memory-access shape of a decoded function body, used to classify handlers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryProfile {
    pub word_loads: u32,
    pub word_stores: u32,
    pub narrow_loads: u32,
    pub narrow_stores: u32,
    pub zero_constant: bool,
    pub loop_backedges: u32,
}

/// Result of decoding one startup function body.
#[derive(Debug, Clone, Default)]
pub struct FrameScan {
    /// `bl` targets plus `blx rN` targets resolved through the literal pool.
    pub calls: Vec<u32>,
    /// Tail-branch target: an unconditional branch at the function entry, or a
    /// `bx rN` resolved through the literal pool.
    pub tail: Option<u32>,
    /// Whether [`FrameScan::tail`] came from an indirect `bx rN` (a real
    /// trampoline) rather than a direct branch at the function entry.
    pub tail_indirect: bool,
    /// Values loaded by `ldr rN, [pc, #imm]` / `ldr.w rN, [pc, #imm]`.
    pub literals: Vec<u32>,
    /// Pointer-advance immediates seen in the body (`adds rN, #imm`, and
    /// post-indexed `ldr.w`/`str.w` writebacks).
    pub strides: Vec<u32>,
    pub memory: MemoryProfile,
}

/// Decode a Thumb function body starting at `start`.
///
/// The walk stops at the first terminator (`bx`, `pop {..,pc}`, unconditional
/// branch) that sits at or past every forward branch target seen so far, which
/// is the usual "end of function" approximation. GCC routinely parks loop
/// bodies *after* the return path, so stopping at the first `bx lr` would miss
/// the copy/zero loops entirely.
pub fn scan_frame(bytes: &[u8], start: u32, addressing: &ImageAddressing) -> Option<FrameScan> {
    addressing.offset_of(start)?;

    let mut scan = FrameScan::default();
    let mut registers: [Option<(u32, usize)>; 16] = [None; 16];
    let mut max_forward = start;
    let mut address = start;
    let mut index = 0usize;
    let limit = start.saturating_add(FRAME_WINDOW_BYTES);

    while address < limit {
        let Some(halfword) = addressing.read_u16(bytes, address) else {
            break;
        };
        let wide = matches!(halfword & 0xf800, 0xe800 | 0xf000 | 0xf800);
        let Some(offset) = addressing.offset_of(address) else {
            break;
        };
        let mut terminator = false;

        if wide {
            let Some(second) = addressing.read_u16(bytes, address.wrapping_add(2)) else {
                break;
            };
            decode_wide(
                bytes,
                address,
                offset,
                halfword,
                second,
                index,
                addressing,
                &mut registers,
                &mut scan,
                &mut max_forward,
                &mut terminator,
            );
        } else {
            decode_narrow(
                bytes,
                address,
                offset,
                halfword,
                index,
                addressing,
                &mut registers,
                &mut scan,
                &mut max_forward,
                &mut terminator,
                index == 0,
            );
        }

        if terminator && address >= max_forward {
            break;
        }
        address = address.wrapping_add(if wide { 4 } else { 2 });
        index += 1;
    }

    Some(scan)
}

#[allow(clippy::too_many_arguments)]
fn decode_narrow(
    bytes: &[u8],
    address: u32,
    offset: usize,
    halfword: u16,
    index: usize,
    addressing: &ImageAddressing,
    registers: &mut [Option<(u32, usize)>; 16],
    scan: &mut FrameScan,
    max_forward: &mut u32,
    terminator: &mut bool,
    is_entry: bool,
) {
    match halfword {
        // LDR (literal) T1: 0100 1 Rd imm8
        hw if hw & 0xf800 == 0x4800 => {
            let rd = ((hw >> 8) & 0x7) as usize;
            let literal = (address.wrapping_add(4) & !3).wrapping_add(u32::from(hw & 0xff) * 4);
            if let Some(value) = addressing.read_u32(bytes, literal) {
                registers[rd] = Some((value, index));
                scan.literals.push(value);
            }
        }
        // ADDS Rn, #imm8: a pointer advance in a table walk loop.
        hw if hw & 0xf800 == 0x3000 => scan.strides.push(u32::from(hw & 0xff)),
        // BLX Rm
        hw if hw & 0xff87 == 0x4780 => {
            let rm = ((hw >> 3) & 0xf) as usize;
            if let Some(target) = recent_literal(registers, rm, index) {
                scan.calls.push(target & !1);
            }
        }
        // BX Rm
        hw if hw & 0xff87 == 0x4700 => {
            let rm = ((hw >> 3) & 0xf) as usize;
            if rm != 15 {
                if let Some(target) = recent_literal(registers, rm, index) {
                    if scan.tail.is_none() {
                        scan.tail = Some(target & !1);
                        scan.tail_indirect = true;
                    }
                }
            }
            *terminator = true;
        }
        // POP {.., pc}
        hw if hw & 0xff00 == 0xbd00 => *terminator = true,
        // B T2 (unconditional)
        hw if hw & 0xf800 == 0xe000 => {
            if let Some(target) = direct_branch_target(bytes, address, offset) {
                if target > address {
                    *max_forward = (*max_forward).max(target);
                } else {
                    scan.memory.loop_backedges += 1;
                }
                // Only a branch sitting at the function entry is treated as a
                // startup-chain edge; a mid-body branch is ordinary control flow.
                if is_entry && scan.tail.is_none() {
                    scan.tail = Some(target);
                }
            }
            *terminator = true;
        }
        // B<cond> T1 (cond 0b1110/0b1111 are UDF/SVC, not branches)
        hw if hw & 0xf000 == 0xd000 && (hw & 0x0f00) <= 0x0d00 => {
            if let Some(target) = conditional_branch_target(address, hw) {
                if target > address {
                    *max_forward = (*max_forward).max(target);
                } else {
                    scan.memory.loop_backedges += 1;
                }
            }
        }
        // MOVS Rd, #0
        hw if hw & 0xf8ff == 0x2000 => scan.memory.zero_constant = true,
        // LDR/STR (immediate) T1, word
        hw if (0x6800..=0x6fff).contains(&hw) => scan.memory.word_loads += 1,
        hw if (0x6000..=0x67ff).contains(&hw) => scan.memory.word_stores += 1,
        // LDRB/STRB and LDRH/STRH (immediate) T1
        hw if (0x7800..=0x7fff).contains(&hw) || (0x8800..=0x8fff).contains(&hw) => {
            scan.memory.narrow_loads += 1
        }
        hw if (0x7000..=0x77ff).contains(&hw) || (0x8000..=0x87ff).contains(&hw) => {
            scan.memory.narrow_stores += 1
        }
        // Load/store register offset: 0101 op(3) Rm Rn Rt
        hw if hw & 0xf000 == 0x5000 => match (hw >> 9) & 0x7 {
            0 => scan.memory.word_stores += 1,
            1 | 2 => scan.memory.narrow_stores += 1,
            4 => scan.memory.word_loads += 1,
            _ => scan.memory.narrow_loads += 1,
        },
        // LDM/STM
        hw if (0xc800..=0xcfff).contains(&hw) => scan.memory.word_loads += 1,
        hw if (0xc000..=0xc7ff).contains(&hw) => scan.memory.word_stores += 1,
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_wide(
    bytes: &[u8],
    address: u32,
    offset: usize,
    first: u16,
    second: u16,
    index: usize,
    addressing: &ImageAddressing,
    registers: &mut [Option<(u32, usize)>; 16],
    scan: &mut FrameScan,
    max_forward: &mut u32,
    terminator: &mut bool,
) {
    // LDR.W Rt, [pc, #imm12]
    if first == 0xf8df {
        let rt = ((second >> 12) & 0xf) as usize;
        let literal = (address.wrapping_add(4) & !3).wrapping_add(u32::from(second & 0x0fff));
        if let Some(value) = addressing.read_u32(bytes, literal) {
            registers[rt] = Some((value, index));
            scan.literals.push(value);
        }
        return;
    }

    if first & 0xf800 == 0xf000 {
        match second & 0xd000 {
            // BL
            0xd000 => {
                if let Some(target) = direct_call_target(bytes, address, offset) {
                    scan.calls.push(target);
                }
                return;
            }
            // B.W (T4)
            0x9000 => {
                if let Some(target) = wide_branch_target(first, second, address) {
                    if target > address {
                        *max_forward = (*max_forward).max(target);
                    } else {
                        scan.memory.loop_backedges += 1;
                    }
                    if index == 0 && scan.tail.is_none() {
                        scan.tail = Some(target);
                    }
                }
                *terminator = true;
                return;
            }
            // B<cond>.W (T3)
            0x8000 => {
                if let Some(target) = wide_branch_target(first, second, address) {
                    if target > address {
                        *max_forward = (*max_forward).max(target);
                    } else {
                        scan.memory.loop_backedges += 1;
                    }
                }
                return;
            }
            _ => {}
        }
        // MOV.W Rd, #0
        if first & 0xfbef == 0xf04f && second & 0x70ff == 0 {
            scan.memory.zero_constant = true;
            return;
        }
    }

    // Post-indexed LDR.W/STR.W writeback: P=0, U=1, W=1 -> second & 0x0f00 == 0x0b00.
    let post_indexed = second & 0x0f00 == 0x0b00;
    match first & 0xfff0 {
        0xf850 | 0xf8d0 => {
            scan.memory.word_loads += 1;
            if post_indexed && first & 0xfff0 == 0xf850 {
                scan.strides.push(u32::from(second & 0xff));
            }
        }
        0xf840 | 0xf8c0 => {
            scan.memory.word_stores += 1;
            if post_indexed && first & 0xfff0 == 0xf840 {
                scan.strides.push(u32::from(second & 0xff));
            }
        }
        0xf810 | 0xf890 | 0xf830 | 0xf8b0 => scan.memory.narrow_loads += 1,
        0xf800 | 0xf880 | 0xf820 | 0xf8a0 => scan.memory.narrow_stores += 1,
        _ => match first & 0xfe50 {
            0xe850 => scan.memory.word_loads += 1,
            0xe840 => scan.memory.word_stores += 1,
            _ => {}
        },
    }
}

fn recent_literal(
    registers: &[Option<(u32, usize)>; 16],
    register: usize,
    index: usize,
) -> Option<u32> {
    let (value, loaded_at) = (*registers.get(register)?)?;
    (index.saturating_sub(loaded_at) <= LITERAL_RECENCY).then_some(value)
}

fn conditional_branch_target(address: u32, halfword: u16) -> Option<u32> {
    let imm8 = (halfword & 0x00ff) as i32;
    let signed = if imm8 & 0x80 != 0 { imm8 | !0xff } else { imm8 };
    Some(address.wrapping_add(4).wrapping_add_signed(signed << 1))
}

fn wide_branch_target(first: u16, second: u16, address: u32) -> Option<u32> {
    let s = u32::from((first >> 10) & 1);
    let imm10 = u32::from(first & 0x03ff);
    let j1 = u32::from((second >> 13) & 1);
    let j2 = u32::from((second >> 11) & 1);
    let imm11 = u32::from(second & 0x07ff);
    let (i1, i2) = if second & 0xd000 == 0x9000 {
        // B.W T4 shares BL's J-bit encoding.
        ((!(j1 ^ s)) & 1, (!(j2 ^ s)) & 1)
    } else {
        // B<cond>.W T3 uses J1/J2 directly and a 6-bit condition field.
        (j1, j2)
    };
    let imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    let signed = if imm25 & (1 << 24) != 0 {
        (imm25 | 0xfe00_0000) as i32
    } else {
        imm25 as i32
    };
    Some(address.wrapping_add(4).wrapping_add_signed(signed))
}

/// A descriptor table recovered from one startup function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTable {
    pub format: InitTableFormat,
    pub stride: u32,
    pub start: u32,
    pub end: u32,
    pub stride_observed: bool,
    pub source_function: u32,
    pub records: Vec<DetectedRecord>,
}

/// A single validated descriptor record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedRecord {
    pub record_address: u32,
    pub src: Option<u32>,
    pub dst: u32,
    pub size: u32,
    pub handler: Option<u32>,
}

/// SRAM/TCM and external-memory windows a descriptor destination may live in.
///
/// Cortex-M destinations land in SRAM (`0x2000_0000`), TCM/CCM
/// (`0x1000_0000`), the H7 AXI SRAM alias (`0x2400_0000`) or, for images that
/// initialise external RAM, the FMC/SDRAM windows above `0x6000_0000`. The
/// peripheral band `0x4000_0000..0x6000_0000` and flash itself are excluded,
/// which is what makes an accidental word pair fail validation.
fn is_ram_like(address: u32) -> bool {
    matches!(address >> 28, 0x1..=0x3 | 0x6..=0x9)
}

fn parse_records(
    bytes: &[u8],
    start: u32,
    format: InitTableFormat,
    count: usize,
    addressing: &ImageAddressing,
) -> Option<Vec<DetectedRecord>> {
    let stride = format.stride();
    let mut records = Vec::with_capacity(count);
    let mut covered: Vec<(u32, u32)> = Vec::new();

    for slot in 0..count {
        let record_address = start.checked_add((slot as u32).checked_mul(stride)?)?;
        let word = |index: u32| addressing.read_u32(bytes, record_address.checked_add(index * 4)?);
        let (src, dst, size, handler) = match format {
            InitTableFormat::CmsisZeroTable => (None, word(0)?, word(1)?, None),
            InitTableFormat::CmsisCopyTable => (Some(word(0)?), word(1)?, word(2)?, None),
            InitTableFormat::ScatterLoad => {
                (Some(word(0)?), word(1)?, word(2)?, Some(word(3)? & !1))
            }
            InitTableFormat::Unknown => return None,
        };

        if size == 0 || !size.is_multiple_of(4) || size > MAX_RECORD_SIZE {
            return None;
        }
        if !dst.is_multiple_of(4) || !is_ram_like(dst) {
            return None;
        }
        let dst_end = dst.checked_add(size)?;
        if !is_ram_like(dst_end.saturating_sub(1)) {
            return None;
        }
        // A record with src == 0 is a zero-init entry in a scatter-load table.
        let src = src.filter(|value| *value != 0);
        if let Some(src) = src {
            if !src.is_multiple_of(4) || !addressing.contains_range(src, size) {
                return None;
            }
        }
        if let Some(handler) = handler {
            if handler == 0 || !addressing.contains(handler) {
                return None;
            }
        }
        if covered
            .iter()
            .any(|(low, high)| dst < *high && *low < dst_end)
        {
            return None;
        }
        covered.push((dst, dst_end));
        records.push(DetectedRecord {
            record_address,
            src,
            dst,
            size,
            handler,
        });
    }

    (!records.is_empty()).then_some(records)
}

/// Recover every descriptor table whose bounds appear in `function`'s literal pool.
pub fn detect_init_tables(
    bytes: &[u8],
    function: u32,
    addressing: &ImageAddressing,
) -> Vec<DetectedTable> {
    let Some(scan) = scan_frame(bytes, function, addressing) else {
        return Vec::new();
    };

    let mut bounds: Vec<u32> = scan
        .literals
        .iter()
        .copied()
        .filter(|value| value.is_multiple_of(4) && addressing.contains(*value))
        .collect();
    bounds.sort_unstable();
    bounds.dedup();
    if bounds.len() < 2 {
        return Vec::new();
    }

    let mut detected: Vec<DetectedTable> = Vec::new();
    for (position, start) in bounds.iter().copied().enumerate() {
        for end in bounds.iter().copied().skip(position + 1) {
            let span = end - start;
            for format in CANDIDATE_FORMATS {
                let stride = format.stride();
                if stride == 0 || !span.is_multiple_of(stride) {
                    continue;
                }
                let count = (span / stride) as usize;
                if count == 0 || count > MAX_RECORDS_PER_TABLE {
                    continue;
                }
                let Some(records) = parse_records(bytes, start, format, count, addressing) else {
                    continue;
                };
                detected.push(DetectedTable {
                    format,
                    stride,
                    start,
                    end,
                    stride_observed: scan.strides.contains(&stride),
                    source_function: function,
                    records,
                });
            }
        }
    }

    rank_and_dedupe(detected)
}

/// Rank candidates and drop any that overlap a stronger one.
///
/// Preference order: a stride that was actually observed in the instruction
/// stream, then more records, then the wider stride.
fn rank_and_dedupe(mut detected: Vec<DetectedTable>) -> Vec<DetectedTable> {
    detected.sort_by(|left, right| {
        right
            .stride_observed
            .cmp(&left.stride_observed)
            .then_with(|| right.records.len().cmp(&left.records.len()))
            .then_with(|| right.stride.cmp(&left.stride))
            .then_with(|| left.start.cmp(&right.start))
    });

    let mut kept: Vec<DetectedTable> = Vec::new();
    for candidate in detected {
        let overlaps = kept
            .iter()
            .any(|table| candidate.start < table.end && table.start < candidate.end);
        if !overlaps {
            kept.push(candidate);
        }
    }
    kept.sort_by_key(|table| table.start);
    kept
}

/// Classify a scatter-load record handler from its instruction shape.
///
/// The full classification, including the evidence a decompressing handler is
/// recognised by, lives in [`crate::mcu_init_handler`]; this is the kind-only
/// view the table walk needs.
pub fn classify_init_handler(
    bytes: &[u8],
    handler: u32,
    addressing: &ImageAddressing,
) -> InitHandlerKind {
    classify_handler(bytes, handler, addressing).kind
}

/// Whether `function`'s literal pool yields at least one valid descriptor table.
pub fn function_walks_init_table(
    bytes: &[u8],
    function: u32,
    addressing: &ImageAddressing,
) -> bool {
    !detect_init_tables(bytes, function, addressing).is_empty()
}

/// Recover the init-descriptor table(s) reachable from a recovered startup chain.
pub fn extract_runtime_init_table(
    bytes: &[u8],
    startup_chain: Option<&StartupChainReport>,
    layout: &ImageLayoutReport,
    hypotheses: &[AddressHypothesis],
    initial_sp: Option<u32>,
) -> Option<InitTableReport> {
    let chain = startup_chain?;
    let reset = chain.steps.first()?.address;
    let addressing = ImageAddressing::from_layout(reset, layout, bytes.len())?;

    let mut functions: Vec<u32> = Vec::new();
    for step in &chain.steps {
        if !functions.contains(&step.address) {
            functions.push(step.address);
        }
    }

    let mut detected: Vec<DetectedTable> = Vec::new();
    for function in functions {
        for table in detect_init_tables(bytes, function, &addressing) {
            if !detected
                .iter()
                .any(|existing| existing.start == table.start && existing.stride == table.stride)
            {
                detected.push(table);
            }
        }
    }
    let detected = rank_and_dedupe(detected);
    if detected.is_empty() {
        return None;
    }

    let mut segments = Vec::with_capacity(detected.len());
    let mut records: Vec<InitRecord> = Vec::new();
    for (segment_index, table) in detected.iter().enumerate() {
        segments.push(InitTableSegment {
            index: segment_index,
            format: table.format,
            base_address: table.start,
            end_address: table.end,
            record_stride: table.stride,
            record_count: table.records.len(),
            source_function: table.source_function,
            stride_observed: table.stride_observed,
        });
        for record in &table.records {
            // CMSIS records take their semantics from the table they live in,
            // not from a handler body, so they carry no classification.
            let classification: Option<InitHandlerClassification> =
                match (table.format, record.handler) {
                    (InitTableFormat::ScatterLoad, Some(handler)) => {
                        Some(classify_handler(bytes, handler, &addressing))
                    }
                    _ => None,
                };
            let handler_kind = match (table.format, &classification) {
                (InitTableFormat::CmsisCopyTable, _) => InitHandlerKind::WordCopy,
                (InitTableFormat::CmsisZeroTable, _) => InitHandlerKind::ZeroInit,
                (_, Some(classification)) => classification.kind,
                _ => InitHandlerKind::Unknown,
            };
            records.push(InitRecord {
                index: 0,
                segment_index,
                record_address: record.record_address,
                src: record.src,
                dst: record.dst,
                size: record.size,
                handler: record.handler,
                handler_kind,
                handler_classification: classification,
            });
        }
    }

    records.sort_by_key(|record| (record.dst, record.record_address));
    for (index, record) in records.iter_mut().enumerate() {
        record.index = index;
    }

    let base_address = segments
        .iter()
        .map(|segment| segment.base_address)
        .min()
        .unwrap_or_default();
    let end_address = segments
        .iter()
        .map(|segment| segment.end_address)
        .max()
        .unwrap_or_default();
    let primary = segments
        .iter()
        .max_by_key(|segment| (segment.record_count, segment.record_stride))
        .cloned()
        .unwrap_or_default();
    let total_dst_coverage: u64 = records.iter().map(|record| u64::from(record.size)).sum();
    let max_dst_end = records
        .iter()
        .filter_map(|record| record.dst.checked_add(record.size))
        .max()
        .unwrap_or_default();
    let matches_initial_sp = initial_sp == Some(max_dst_end);
    let stride_observed = segments.iter().any(|segment| segment.stride_observed);

    let mut confidence = if matches_initial_sp { 0.95 } else { 0.75 };
    if !stride_observed {
        confidence -= 0.15;
    }

    let fingerprint = toolchain_fingerprint(&records);

    let mut provenance = section_provenance_for(hypotheses);
    provenance.notes.push(format!(
        "segments={} records={} stride_observed={stride_observed}",
        segments.len(),
        records.len()
    ));
    provenance.notes.push(match fingerprint.as_ref() {
        Some(_) => {
            "data_compression=present: a record handler decompresses rather than copies".to_string()
        }
        None => {
            "data_compression=absent: every record handler copies or fills verbatim".to_string()
        }
    });
    provenance.notes.push(match initial_sp {
        Some(sp) if matches_initial_sp => {
            format!("sp_consistency=match max_dst_end=0x{max_dst_end:08x} initial_sp=0x{sp:08x}")
        }
        Some(sp) => {
            format!("sp_consistency=mismatch max_dst_end=0x{max_dst_end:08x} initial_sp=0x{sp:08x}")
        }
        None => "sp_consistency=unavailable".to_string(),
    });
    provenance
        .notes
        .push("table bounds taken from startup literal pool, not a memory scan".to_string());

    Some(InitTableReport {
        base_address,
        end_address,
        record_stride: primary.record_stride,
        format: primary.format,
        segments,
        records,
        total_dst_coverage,
        max_dst_end,
        initial_sp,
        matches_initial_sp,
        toolchain_fingerprint: fingerprint,
        provenance: Some(provenance),
        confidence,
    })
}

fn section_provenance_for(hypotheses: &[AddressHypothesis]) -> SectionProvenance {
    crate::mcu_inspect::section_provenance(
        "init-table-extractor",
        hypotheses.first().map(|hypothesis| hypothesis.base),
    )
}
