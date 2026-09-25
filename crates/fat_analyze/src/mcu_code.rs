//! Conservative control-flow traversal from supplied, mapped Cortex-M seeds.
//!
//! This is deliberately a bounded metadata pass, not a whole-image disassembler.
//! Function entries and ranges remain candidates. Register constants are scoped
//! to basic blocks, and calls, predication, unsupported semantics and joins discard
//! them. Unknown indirect destinations are never guessed from nearby words.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fat_core::mcu_code::*;
use fat_core::mcu_inspection::{InitHandlerKind, InitTableReport};

use crate::mcu_init_table::ImageAddressing;
use crate::mcu_thumb::{decode_instruction, AccessWidth, IndexMode, ThumbOp};

const MAX_INSTRUCTIONS: usize = 4096;
const MAX_BLOCKS: usize = 256;
const MAX_FUNCTIONS: usize = 128;
const MAX_STRING_UNITS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSeed {
    pub address: u32,
    pub reason: String,
}

pub fn analyze_code(
    bytes: &[u8],
    addressing: &ImageAddressing,
    seeds: &[CodeSeed],
    init_tables: Option<&InitTableReport>,
) -> McuCodeReport {
    let mut walk = Walk {
        bytes,
        addressing,
        report: McuCodeReport {
            instruction_budget: MAX_INSTRUCTIONS,
            block_budget: MAX_BLOCKS,
            function_budget: MAX_FUNCTIONS,
            notes: vec![
                "At most 256 distinct seed reasons are retained per candidate entry; repeated vector targets share the function budget.".into(),
                "Static candidate reachability from supplied seeds; no execution or complete function boundaries are established.".into(),
                "Only supported Thumb encodings are followed; unresolved indirect transfers, predication and unsupported instructions bound coverage.".into(),
                "Register constants are local to a basic block and are discarded across calls, branch joins and unknown semantics.".into(),
                "Resolved indirect branches require a locally derived odd Thumb pointer mapped within input; values are not carried into the target block.".into(),
                "Strings are terminated byte sequences referenced by literal loads; their purpose is not inferred.".into(),
            ],
            ..Default::default()
        },
        pending: VecDeque::new(),
        queued: BTreeSet::new(),
        instructions: BTreeMap::new(),
        pool_bytes: BTreeSet::new(),
        functions: BTreeMap::new(),
        ambiguous_boundaries: false,
    };
    // Budget unique entries: many interrupt slots can share one default handler.
    for seed in seeds {
        walk.add_function(seed.address & !1, &seed.reason);
    }
    while let Some(start) = walk.pending.pop_front() {
        if walk.report.block_count >= MAX_BLOCKS || walk.instructions.len() >= MAX_INSTRUCTIONS {
            walk.report.budget_exhausted = true;
            walk.stop(start, "analysis-budget");
            break;
        }
        walk.block(start);
    }
    if let Some(tables) = init_tables {
        for record in &tables.records {
            let kind = match record.handler_kind {
                InitHandlerKind::WordCopy => "copy-descriptor",
                InitHandlerKind::ZeroInit => "zero-descriptor",
                _ => continue,
            };
            walk.report.initialization.push(CodeInitialization {
                record_address: record.record_address,
                kind: kind.into(),
                source: record.src,
                destination: record.dst,
                length: record.size,
            });
        }
        if !walk.report.initialization.is_empty() {
            walk.report.notes.push("Initialization entries summarize recovered startup descriptors; they do not prove these writes occurred.".into());
        }
    }
    walk.finish()
}

struct Walk<'a> {
    bytes: &'a [u8],
    addressing: &'a ImageAddressing,
    report: McuCodeReport,
    pending: VecDeque<u32>,
    queued: BTreeSet<u32>,
    instructions: BTreeMap<u32, (usize, u32)>,
    pool_bytes: BTreeSet<usize>,
    functions: BTreeMap<u32, CodeFunctionCandidate>,
    ambiguous_boundaries: bool,
}

impl Walk<'_> {
    fn stop(&mut self, address: u32, reason: &str) {
        self.report.stops.push(CodeStop {
            address,
            reason: reason.into(),
        });
    }

    fn enqueue(&mut self, address: u32) {
        if self.queued.insert(address) {
            self.pending.push_back(address);
        }
    }

    fn add_function(&mut self, address: u32, reason: &str) {
        let Some(offset) = self.addressing.offset_of(address) else {
            self.stop(address, "outside-mapped-input");
            return;
        };
        if let Some(candidate) = self.functions.get_mut(&address) {
            if candidate.reasons.len() < MAX_BLOCKS
                && !candidate.reasons.iter().any(|existing| existing == reason)
            {
                candidate.reasons.push(reason.into());
            }
            return;
        }
        if self.functions.len() >= MAX_FUNCTIONS {
            self.report.budget_exhausted = true;
            return;
        }
        self.functions.insert(
            address,
            CodeFunctionCandidate {
                address,
                file_offset: offset as u64,
                reasons: vec![reason.into()],
            },
        );
        self.enqueue(address);
    }

    fn edge(&mut self, instruction_address: u32, target: Option<u32>, kind: &str) {
        self.report.flow_edges.push(CodeFlowEdge {
            instruction_address,
            target,
            kind: kind.into(),
        });
    }

    fn block(&mut self, start: u32) {
        if self.instructions.contains_key(&start) {
            return;
        }
        self.report.block_count += 1;
        let mut address = start;
        let mut constants = [None; 16];
        loop {
            if self.instructions.len() >= MAX_INSTRUCTIONS {
                self.report.budget_exhausted = true;
                self.stop(address, "analysis-budget");
                return;
            }
            if self.instructions.contains_key(&address) {
                return;
            }
            let Some(offset) = self.addressing.offset_of(address) else {
                self.stop(address, "outside-mapped-input");
                return;
            };
            if self.pool_bytes.contains(&offset) {
                self.stop(address, "literal-pool-boundary");
                return;
            }
            let Some(insn) = decode_instruction(self.bytes, address, self.addressing) else {
                self.stop(address, "truncated-instruction");
                return;
            };
            // A target in the second halfword of an existing instruction is ambiguous.
            if self
                .instructions
                .range(..address)
                .next_back()
                .is_some_and(|(previous, (_, width))| previous.saturating_add(*width) > address)
            {
                self.ambiguous_boundaries = true;
                self.stop(address, "overlapping-instruction-boundary");
                return;
            }
            if self
                .instructions
                .range(address..)
                .next()
                .is_some_and(|(following, _)| *following < address.saturating_add(insn.width))
            {
                self.ambiguous_boundaries = true;
                self.stop(address, "overlapping-instruction-boundary");
                return;
            }
            let first = u16::from_le_bytes([self.bytes[offset], self.bytes[offset + 1]]);
            if (offset..offset + insn.width as usize).any(|at| self.pool_bytes.contains(&at)) {
                self.stop(address, "literal-pool-boundary");
                return;
            }
            self.instructions.insert(address, (offset, insn.width));
            let Some(next) = address.checked_add(insn.width) else {
                self.stop(address, "address-overflow");
                return;
            };
            // BX is a return shape only for an unresolved LR. A locally derived
            // odd Thumb pointer can establish a mapped trampoline candidate.
            if insn.width == 2 && first & 0xff87 == 0x4700 {
                let register = ((first >> 3) & 0xf) as usize;
                match constants[register] {
                    Some(value) if value & 1 != 0 && self.addressing.contains(value & !1) => {
                        let target = value & !1;
                        self.edge(address, Some(target), "resolved-indirect-branch");
                        self.add_function(target, "local-constant-indirect-branch-target");
                    }
                    Some(value) => {
                        self.edge(address, Some(value & !1), "indirect-branch");
                        self.stop(
                            address,
                            if value & 1 == 0 {
                                "non-thumb-indirect-target"
                            } else {
                                "outside-mapped-indirect-target"
                            },
                        );
                    }
                    None if register == 14 => self.edge(address, None, "return"),
                    None => {
                        self.edge(address, None, "indirect-branch");
                        self.stop(address, "unresolved-indirect-branch");
                    }
                }
                return;
            }
            if insn.width == 4 && first & 0xfe40 == 0xe800 && first & 0x0010 != 0 {
                let second = u16::from_le_bytes([self.bytes[offset + 2], self.bytes[offset + 3]]);
                if second & 0x8000 != 0 {
                    self.stop(address, "unresolved-multiple-pc-load");
                    return;
                }
            }
            if writes_pc(insn.op) {
                self.stop(address, "unresolved-pc-write");
                return;
            }
            match insn.op {
                ThumbOp::Branch {
                    target,
                    conditional,
                } => {
                    self.edge(
                        address,
                        Some(target),
                        if conditional {
                            "conditional-branch"
                        } else {
                            "direct-branch"
                        },
                    );
                    self.enqueue(target);
                    if conditional {
                        self.enqueue(next);
                    }
                    return;
                }
                ThumbOp::Call { target } => {
                    self.edge(
                        address,
                        target,
                        if target.is_some() {
                            "direct-call"
                        } else {
                            "indirect-call"
                        },
                    );
                    if let Some(target) = target {
                        self.add_function(target & !1, "direct-call-target");
                    }
                    // A continuation after a call is a candidate, never evidence that
                    // the callee returns. Do not carry values through an unknown call.
                    constants = [None; 16];
                    if target.is_none() {
                        self.stop(address, "unresolved-indirect-call-target");
                    }
                }
                ThumbOp::Return => {
                    self.edge(address, None, "return");
                    return;
                }
                ThumbOp::ItBlock => {
                    self.stop(address, "unsupported-predicated-block");
                    return;
                }
                ThumbOp::Other => {
                    if first != 0xbf00 || insn.width != 2 {
                        constants = [None; 16];
                    }
                    if !known_fallthrough(first, insn.width) {
                        self.stop(address, "unsupported-instruction");
                        return;
                    }
                }
                ThumbOp::LoadLiteral { rt, value } => {
                    if let Some(pool_address) =
                        literal_address(self.bytes, offset, address, insn.width)
                    {
                        if let Some(pool_offset) = self.addressing.offset_of(pool_address) {
                            if pool_offset.checked_add(4).is_some_and(|end| {
                                end <= self.addressing.image_len.min(self.bytes.len())
                            }) {
                                self.pool_bytes.extend(pool_offset..pool_offset + 4);
                                self.report.literal_references.push(CodeLiteralReference {
                                    instruction_address: address,
                                    instruction_offset: offset as u64,
                                    pool_address,
                                    pool_offset: pool_offset as u64,
                                    value,
                                });
                                if let Some(reference) =
                                    string_reference(self.bytes, self.addressing, address, value)
                                {
                                    self.report.string_references.push(reference);
                                }
                            }
                        }
                    }
                    constants[rt as usize] = Some(value);
                }
                op => self.observe_constants(address, offset, op, &mut constants),
            }
            address = next;
            // Stop at a previously queued join even if it has not yet been visited.
            if self.queued.contains(&address) {
                return;
            }
        }
    }

    fn observe_constants(
        &mut self,
        address: u32,
        offset: usize,
        op: ThumbOp,
        values: &mut [Option<u32>; 16],
    ) {
        match op {
            ThumbOp::MovImm { rd, imm } => values[rd as usize] = Some(imm),
            ThumbOp::MovTop { rd, imm } => {
                values[rd as usize] = values[rd as usize].map(|low| (low & 0xffff) | (imm << 16))
            }
            ThumbOp::MovReg { rd, rm } => values[rd as usize] = values[rm as usize],
            ThumbOp::AddImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].and_then(|v| v.checked_add(imm))
            }
            ThumbOp::SubImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].and_then(|v| v.checked_sub(imm))
            }
            ThumbOp::AndImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].map(|v| v & imm)
            }
            ThumbOp::OrrImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].map(|v| v | imm)
            }
            ThumbOp::BicImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].map(|v| v & !imm)
            }
            ThumbOp::EorImm { rd, rn, imm } => {
                values[rd as usize] = values[rn as usize].map(|v| v ^ imm)
            }
            ThumbOp::NegReg { rd, .. }
            | ThumbOp::ShiftRightImm { rd, .. }
            | ThumbOp::SubReg { rd, .. } => values[rd as usize] = None,
            ThumbOp::Load {
                rt,
                rn,
                offset: displacement,
                width,
                index,
            }
            | ThumbOp::Store {
                rt,
                rn,
                offset: displacement,
                width,
                index,
            } => {
                let is_load = matches!(op, ThumbOp::Load { .. });
                let width_bytes = match width {
                    AccessWidth::Byte => 1,
                    AccessWidth::Halfword => 2,
                    AccessWidth::Word => 4,
                    AccessWidth::Multiple => 0,
                };
                if width_bytes > 0 && index != IndexMode::Computed {
                    let target = values[rn as usize].and_then(|base| {
                        if index == IndexMode::PostIndexed {
                            Some(base)
                        } else {
                            base.checked_add_signed(displacement as i32)
                        }
                    });
                    if let Some(target) = target {
                        self.report.memory_accesses.push(CodeMemoryAccess {
                            instruction_address: address,
                            instruction_offset: offset as u64,
                            target,
                            access: if is_load {
                                MemoryAccessKind::Read
                            } else {
                                MemoryAccessKind::Write
                            },
                            width_bytes,
                        });
                    }
                }
                if index != IndexMode::Offset {
                    values[rn as usize] = None;
                }
                if is_load {
                    // A multi-register load can overwrite any of the tracked values.
                    if width == AccessWidth::Multiple {
                        *values = [None; 16];
                    } else {
                        values[rt as usize] = None;
                    }
                }
            }
            ThumbOp::CmpImm { .. } | ThumbOp::CmpReg { .. } => {}
            _ => *values = [None; 16],
        }
    }

    fn finish(mut self) -> McuCodeReport {
        let collisions: Vec<_> = self
            .instructions
            .iter()
            .filter_map(|(address, (offset, width))| {
                (*offset..*offset + *width as usize)
                    .any(|at| self.pool_bytes.contains(&at))
                    .then_some(*address)
            })
            .collect();
        if self.ambiguous_boundaries || !collisions.is_empty() {
            // A later discovery can invalidate an earlier seed and every path
            // derived from it. Omit the whole candidate graph rather than keep
            // descendants whose only provenance is a contradicted interpretation.
            self.report.memory_accesses.clear();
            self.report.string_references.clear();
            self.report.literal_references.clear();
            self.report.flow_edges.clear();
            self.report.initialization.clear();
            for address in collisions {
                self.stop(address, "code-literal-overlap");
            }
            self.report.notes.push("Conflicting instruction or literal-pool boundaries were found; the candidate graph and derived facts are omitted. Stops describe the attempted analysis.".into());
            return self.report;
        }
        self.report.instruction_count = self.instructions.len();
        for (address, (offset, width)) in self.instructions {
            if let Some(previous) = self.report.instruction_ranges.last_mut() {
                if previous.address.checked_add(previous.length) == Some(address)
                    && previous.file_offset + u64::from(previous.length) == offset as u64
                {
                    previous.length += width;
                    continue;
                }
            }
            self.report.instruction_ranges.push(CodeInstructionRange {
                address,
                file_offset: offset as u64,
                length: width,
            });
        }
        self.report.function_candidates = self
            .functions
            .into_values()
            .filter(|candidate| !self.pool_bytes.contains(&(candidate.file_offset as usize)))
            .collect();
        self.report
    }
}

fn writes_pc(op: ThumbOp) -> bool {
    match op {
        ThumbOp::MovImm { rd, .. }
        | ThumbOp::MovTop { rd, .. }
        | ThumbOp::MovReg { rd, .. }
        | ThumbOp::AndImm { rd, .. }
        | ThumbOp::OrrImm { rd, .. }
        | ThumbOp::BicImm { rd, .. }
        | ThumbOp::EorImm { rd, .. }
        | ThumbOp::AddImm { rd, .. }
        | ThumbOp::SubImm { rd, .. }
        | ThumbOp::ShiftRightImm { rd, .. }
        | ThumbOp::SubReg { rd, .. }
        | ThumbOp::NegReg { rd, .. } => rd == 15,
        ThumbOp::Load { rt, .. } | ThumbOp::LoadLiteral { rt, .. } => rt == 15,
        _ => false,
    }
}

/// A small explicit set of instructions with known fallthrough but no modeled
/// register effects. Values are cleared except for the explicitly recognized NOP.
fn known_fallthrough(first: u16, width: u32) -> bool {
    width == 2
        && (first == 0xbf00 // NOP
        || first & 0xfe00 == 0xb400 // PUSH
        || first & 0xff00 == 0xbc00 // POP without PC
        || first & 0xff00 == 0xb000) // ADD/SUB SP immediate
}

fn literal_address(bytes: &[u8], offset: usize, address: u32, width: u32) -> Option<u32> {
    let first = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
    let base = address.checked_add(4)? & !3;
    if width == 2 && first & 0xf800 == 0x4800 {
        base.checked_add(u32::from(first & 0xff) * 4)
    } else if width == 4 && first == 0xf8df {
        let second = u16::from_le_bytes(bytes.get(offset + 2..offset + 4)?.try_into().ok()?);
        base.checked_add(u32::from(second & 0xfff))
    } else {
        None
    }
}

fn string_reference(
    bytes: &[u8],
    addressing: &ImageAddressing,
    instruction: u32,
    address: u32,
) -> Option<CodeStringReference> {
    let offset = addressing.offset_of(address)?;
    let tail = bytes.get(offset..addressing.image_len.min(bytes.len()))?;
    let ascii_end = tail
        .iter()
        .take(MAX_STRING_UNITS + 1)
        .position(|byte| *byte == 0);
    let decoded = if let Some(end) = ascii_end.filter(|end| {
        *end >= 4
            && tail[..*end]
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    }) {
        Some(("ascii", String::from_utf8(tail[..end].to_vec()).ok()?))
    } else {
        let units: Vec<u16> = tail
            .as_chunks::<2>()
            .0
            .iter()
            .take(MAX_STRING_UNITS + 1)
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        units
            .iter()
            .position(|unit| *unit == 0)
            .filter(|end| {
                *end >= 4
                    && units[..*end]
                        .iter()
                        .all(|unit| (0x20..=0x7e).contains(unit))
            })
            .and_then(|end| String::from_utf16(&units[..end]).ok())
            .map(|value| ("utf-16le", value))
    };
    decoded.map(|(encoding, value)| CodeStringReference {
        instruction_address: instruction,
        address,
        file_offset: offset as u64,
        encoding: encoding.into(),
        value,
    })
}
