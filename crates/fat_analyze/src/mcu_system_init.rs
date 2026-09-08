//! What `SystemInit` left the hardware in before `main` ran.
//!
//! The startup-chain walk names a `SystemInit` step but says nothing about
//! what it does. That function is small and its side effects are unusually
//! diagnosable: FPU enable, flash wait states, clock-tree bring-up, cache and
//! MPU configuration, and the compare-against-a-memory-base that means "was I
//! started behind a bootloader that already moved the vector table?". Each one
//! is a one-to-three instruction pattern against a known register address, so
//! all of it is recoverable statically — and each one is an analyst fact:
//! wait states bound the clock, an FPU implies float-heavy control code, a
//! bootloader sentinel changes the update-path picture, and D-cache state
//! decides whether DMA buffers need uncached memory.
//!
//! Register values are tracked with a bitwise abstract domain rather than
//! concrete values, because the interesting writes are read-modify-writes:
//! `bic #0xF` then `orr #7` never produces a concrete word, but it does make
//! the low nibble exactly 7, which is the wait-state count. Bits that are not
//! pinned stay unknown and are reported as unknown.

use fat_core::mcu_inspection::{
    CacheEffect, CacheEffectKind, ClockEffect, ClockEffectKind, FpuStatus, ImageLayoutReport,
    PeripheralWriteRecord, StartupChainReport, StartupRole, SystemInitEffectsReport,
    SystemInitEvidence, VtorCheckEvidence, VtorWriteEvidence,
};

use crate::mcu_family::FamilyResolution;
use crate::mcu_init_table::ImageAddressing;
use crate::mcu_inspect::section_provenance;
use crate::mcu_thumb::{decode_function_within, AccessWidth, IndexMode, ThumbInsn, ThumbOp};

/// `SystemInit` bodies are small; a wider window would start decoding whatever
/// the linker placed after them.
const SYSTEM_INIT_WINDOW_BYTES: u32 = 0x200;

/// Architectural Cortex-M register addresses. These come from the ARMv7-M
/// architecture, not from a chip vendor, so they hold for every family pack.
const SCB_VTOR: u32 = 0xE000_ED08;
const SCB_CCR: u32 = 0xE000_ED14;
const SCB_CPACR: u32 = 0xE000_ED88;
const MPU_RNR: u32 = 0xE000_ED98;
const MPU_RBAR: u32 = 0xE000_ED9C;
const MPU_RASR: u32 = 0xE000_EDA0;
const MPU_CTRL: u32 = 0xE000_ED94;
/// Cache maintenance block: `ICIALLU` through `BPIALL` and the D-cache
/// invalidate/clean-by-set-way registers.
const CACHE_MAINTENANCE: std::ops::Range<u32> = 0xE000_EF50..0xE000_EF80;
/// `CSSELR`, the cache-size selection register used by every cache enable
/// sequence that walks set/way.
const SCB_CSSELR: u32 = 0xE000_ED84;

/// `CPACR.CP10`/`CP11`, full access in both.
const CPACR_FPU_MASK: u32 = 0x00F0_0000;
/// `CCR.IC` and `CCR.DC`.
const CCR_ICACHE: u32 = 1 << 17;
const CCR_DCACHE: u32 = 1 << 16;

/// Where the MMIO band starts. A store below this is to RAM, not a peripheral.
const MMIO_FLOOR: u32 = 0x4000_0000;

/// Recover the side effects of the `SystemInit` startup step.
///
/// Returns `None` when the startup walk did not name a `SystemInit` step,
/// which is the honest outcome: nothing was analysed, so nothing is claimed.
pub fn extract_system_init_effects(
    bytes: &[u8],
    startup_chain: Option<&StartupChainReport>,
    family: &FamilyResolution,
    layout: &ImageLayoutReport,
) -> Option<SystemInitEffectsReport> {
    let chain = startup_chain?;
    let reset = chain.steps.first()?.address;
    let system_init = chain
        .steps
        .iter()
        .find(|step| step.role == StartupRole::SystemInit)?;
    let addressing = ImageAddressing::from_layout(reset, layout, bytes.len())?;
    let decoded = decode_function_within(
        bytes,
        system_init.address,
        &addressing,
        SYSTEM_INIT_WINDOW_BYTES,
    )?;

    let mut report = SystemInitEffectsReport {
        function_address: system_init.address,
        function_size: decoded.size(),
        ..SystemInitEffectsReport::default()
    };
    let mut registers = RegisterFile::default();

    for insn in &decoded.instructions {
        if let Some(sentinel) = memory_base_comparison(insn, &registers) {
            report
                .vtor_relocation_check
                .get_or_insert(VtorCheckEvidence {
                    sentinel_value: sentinel,
                    instruction_addr: insn.address,
                });
            report.evidence.push(SystemInitEvidence {
                label: "vtor-relocation-check".to_string(),
                detail: format!("compare against memory base 0x{sentinel:08X}"),
                instruction_addr: insn.address,
            });
        }
        if let Some((target, value)) = resolved_store(insn, &registers) {
            classify_store(&mut report, family, target, value, insn.address);
        }
        registers.apply(insn);
    }

    finish(&mut report, family);
    let mut provenance = section_provenance("system-init-extractor", Some(addressing.flash_base));
    provenance.family_pack = Some(family.pack.family_id.to_string());
    provenance.notes.push(format!(
        "decoded_bytes={} terminated={}",
        decoded.size(),
        decoded.terminated
    ));
    provenance.notes.push(
        "register values are tracked bitwise; bits that are not pinned statically are reported \
         as unknown rather than guessed"
            .to_string(),
    );
    if !family.is_enriching_match() {
        provenance.notes.push(
            "no family pack matched: clock and vendor-accelerator writes cannot be classified"
                .to_string(),
        );
    }
    report.provenance = Some(provenance);
    Some(report)
}

/// A bitwise abstract value: `known` marks the bits whose value is pinned, and
/// `bits` holds those values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Value {
    known: u32,
    bits: u32,
}

impl Value {
    fn constant(value: u32) -> Self {
        Self {
            known: u32::MAX,
            bits: value,
        }
    }

    fn resolved(&self) -> Option<u32> {
        (self.known == u32::MAX).then_some(self.bits)
    }

    /// Whether every bit in `mask` is pinned to one.
    fn all_set(&self, mask: u32) -> bool {
        mask != 0 && self.known & mask == mask && self.bits & mask == mask
    }

    /// Whether every bit in `mask` is pinned to zero.
    fn all_clear(&self, mask: u32) -> bool {
        mask != 0 && self.known & mask == mask && self.bits & mask == 0
    }

    /// The value of `mask`'s bits, when all of them are pinned.
    fn field(&self, mask: u32) -> Option<u32> {
        (self.known & mask == mask).then(|| (self.bits & mask) >> mask.trailing_zeros())
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RegisterFile {
    values: [Value; 16],
}

impl RegisterFile {
    fn get(&self, register: u8) -> Value {
        self.values
            .get(register as usize)
            .copied()
            .unwrap_or_default()
    }

    fn set(&mut self, register: u8, value: Value) {
        if let Some(slot) = self.values.get_mut(register as usize) {
            *slot = value;
        }
    }

    fn clear(&mut self, register: u8) {
        self.set(register, Value::default());
    }

    fn apply(&mut self, insn: &ThumbInsn) {
        // A predicated instruction may not have run; its destination is no
        // longer trustworthy either way.
        if insn.predicated {
            if let Some(rd) = written_register(&insn.op) {
                self.clear(rd);
            }
            return;
        }

        match insn.op {
            ThumbOp::LoadLiteral { rt, value } => self.set(rt, Value::constant(value)),
            ThumbOp::MovImm { rd, imm } => self.set(rd, Value::constant(imm)),
            ThumbOp::MovTop { rd, imm } => {
                let low = self.get(rd);
                self.set(
                    rd,
                    Value {
                        known: (low.known & 0xffff) | 0xffff_0000,
                        bits: (low.bits & 0xffff) | (imm << 16),
                    },
                );
            }
            ThumbOp::MovReg { rd, rm } => {
                let value = self.get(rm);
                self.set(rd, value);
            }
            ThumbOp::OrrImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(
                    rd,
                    Value {
                        known: value.known | imm,
                        bits: value.bits | imm,
                    },
                );
            }
            ThumbOp::BicImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(
                    rd,
                    Value {
                        known: value.known | imm,
                        bits: value.bits & !imm,
                    },
                );
            }
            ThumbOp::AndImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(
                    rd,
                    Value {
                        known: value.known | !imm,
                        bits: value.bits & imm,
                    },
                );
            }
            ThumbOp::EorImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(
                    rd,
                    Value {
                        known: value.known,
                        bits: value.bits ^ imm,
                    },
                );
            }
            ThumbOp::AddImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(rd, add_immediate(value, imm));
            }
            ThumbOp::SubImm { rd, rn, imm } => {
                let value = self.get(rn);
                self.set(
                    rd,
                    match value.resolved() {
                        Some(base) => Value::constant(base.wrapping_sub(imm)),
                        None => Value::default(),
                    },
                );
            }
            // A call clobbers the AAPCS scratch registers.
            ThumbOp::Call { .. } => {
                for register in [0u8, 1, 2, 3, 12, 14] {
                    self.clear(register);
                }
            }
            // An encoding this decoder does not model may write anything.
            ThumbOp::Other => *self = RegisterFile::default(),
            _ => {
                if let Some(rd) = written_register(&insn.op) {
                    self.clear(rd);
                }
                // A post-indexed or pre-indexed access also writes its base.
                match insn.op {
                    ThumbOp::Load { rn, index, .. } | ThumbOp::Store { rn, index, .. }
                        if matches!(index, IndexMode::PostIndexed | IndexMode::PreIndexed) =>
                    {
                        self.clear(rn)
                    }
                    _ => {}
                }
            }
        }
    }
}

/// `rn + imm` when `rn` is fully pinned, or when `imm` fits entirely inside
/// low bits of `rn` that are pinned to zero — which is the `bic #0xF` then
/// `orr`/`add #7` idiom every flash-latency sequence uses.
fn add_immediate(value: Value, imm: u32) -> Value {
    if let Some(base) = value.resolved() {
        return Value::constant(base.wrapping_add(imm));
    }
    let zeroed_low_bits = (!value.known | value.bits).trailing_zeros();
    if zeroed_low_bits == 0 {
        return Value::default();
    }
    let mask = if zeroed_low_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << zeroed_low_bits) - 1
    };
    if imm & !mask != 0 {
        return Value::default();
    }
    Value {
        known: mask,
        bits: imm,
    }
}

fn written_register(op: &ThumbOp) -> Option<u8> {
    match *op {
        ThumbOp::LoadLiteral { rt, .. } | ThumbOp::Load { rt, .. } => Some(rt),
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
        | ThumbOp::NegReg { rd, .. } => Some(rd),
        _ => None,
    }
}

/// The `(target, value)` of a store whose base register is pinned.
fn resolved_store(insn: &ThumbInsn, registers: &RegisterFile) -> Option<(u32, Value)> {
    let ThumbOp::Store {
        rt,
        rn,
        offset,
        width,
        index,
    } = insn.op
    else {
        return None;
    };
    if width == AccessWidth::Multiple || index == IndexMode::Computed {
        return None;
    }
    let base = registers.get(rn).resolved()?;
    // A post-indexed store writes the base address itself; the immediate is
    // the writeback.
    let target = if index == IndexMode::PostIndexed {
        base
    } else {
        base.wrapping_add(offset)
    };
    Some((target, registers.get(rt)))
}

/// A comparison against a constant that looks like a memory-region base: the
/// shape of a bootloader/VTOR relocation sentinel.
fn memory_base_comparison(insn: &ThumbInsn, registers: &RegisterFile) -> Option<u32> {
    let candidate = match insn.op {
        ThumbOp::CmpImm { imm, .. } => imm,
        ThumbOp::CmpReg { rn, rm } => registers
            .get(rn)
            .resolved()
            .or_else(|| registers.get(rm).resolved())?,
        _ => return None,
    };
    // Region bases are 64 KiB aligned and sit in the code or SRAM bands. That
    // rules out the small constants a loop bound or a status-bit test uses.
    let plausible_band = (0x0800_0000..0x0900_0000).contains(&candidate)
        || (0x1000_0000..0x4000_0000).contains(&candidate);
    (plausible_band && candidate.is_multiple_of(0x1_0000)).then_some(candidate)
}

fn classify_store(
    report: &mut SystemInitEffectsReport,
    family: &FamilyResolution,
    target: u32,
    value: Value,
    address: u32,
) {
    match target {
        SCB_CPACR => {
            if value.all_set(CPACR_FPU_MASK) {
                report.fpu = FpuStatus::Enabled;
                report.evidence.push(SystemInitEvidence {
                    label: "fpu-enable".to_string(),
                    detail: "CPACR.CP10 and CPACR.CP11 driven to full access".to_string(),
                    instruction_addr: address,
                });
            } else if value.all_clear(CPACR_FPU_MASK) {
                report.fpu = FpuStatus::Disabled;
                report.evidence.push(SystemInitEvidence {
                    label: "fpu-disable".to_string(),
                    detail: "CPACR.CP10 and CPACR.CP11 driven to zero".to_string(),
                    instruction_addr: address,
                });
            }
            return;
        }
        SCB_VTOR => {
            report.vtor_write = Some(VtorWriteEvidence {
                value: value.resolved(),
                instruction_addr: address,
            });
            report.evidence.push(SystemInitEvidence {
                label: "vtor-write".to_string(),
                detail: match value.resolved() {
                    Some(base) => format!("SCB->VTOR set to 0x{base:08X}"),
                    None => "SCB->VTOR written with an unresolved value".to_string(),
                },
                instruction_addr: address,
            });
            return;
        }
        SCB_CCR => {
            let mut seen = false;
            if value.all_set(CCR_ICACHE) {
                report.cache_effects.push(CacheEffect {
                    kind: CacheEffectKind::ICacheEnable,
                    evidence_addr: address,
                });
                seen = true;
            }
            if value.all_set(CCR_DCACHE) {
                report.cache_effects.push(CacheEffect {
                    kind: CacheEffectKind::DCacheEnable,
                    evidence_addr: address,
                });
                seen = true;
            }
            if seen {
                report.evidence.push(SystemInitEvidence {
                    label: "cache-enable".to_string(),
                    detail: "SCB->CCR cache enable bits driven to one".to_string(),
                    instruction_addr: address,
                });
                return;
            }
        }
        MPU_CTRL | MPU_RNR | MPU_RBAR | MPU_RASR => {
            report.mpu_configured = true;
            report.evidence.push(SystemInitEvidence {
                label: "mpu-config".to_string(),
                detail: format!("MPU register 0x{target:08X} written"),
                instruction_addr: address,
            });
            return;
        }
        SCB_CSSELR => {
            report.cache_effects.push(CacheEffect {
                kind: CacheEffectKind::CacheMaintenance,
                evidence_addr: address,
            });
            return;
        }
        _ => {}
    }

    if CACHE_MAINTENANCE.contains(&target) {
        report.cache_effects.push(CacheEffect {
            kind: CacheEffectKind::CacheMaintenance,
            evidence_addr: address,
        });
        return;
    }

    if let Some(range) = family
        .is_enriching_match()
        .then(|| family.pack.lookup_mmio(target))
        .flatten()
    {
        let offset = target - range.start;
        match range.peripheral_name {
            "FLASH" if offset == 0 => {
                if let Some(latency) = value.field(0xf) {
                    report.flash_latency = Some(latency);
                    report.evidence.push(SystemInitEvidence {
                        label: "flash-latency".to_string(),
                        detail: format!("FLASH_ACR.LATENCY set to {latency} wait states"),
                        instruction_addr: address,
                    });
                    return;
                }
            }
            "RCC" => {
                let kind = classify_rcc_write(family, offset, value);
                report.clock_effects.push(ClockEffect {
                    kind,
                    register_offset: offset,
                    evidence_addr: address,
                });
                report.evidence.push(SystemInitEvidence {
                    label: "clock-effect".to_string(),
                    detail: format!("RCC+0x{offset:02X} written"),
                    instruction_addr: address,
                });
                return;
            }
            "ART" => {
                let enabled = value.all_set(1);
                report.art_accel = Some(enabled);
                report.evidence.push(SystemInitEvidence {
                    label: "art-accelerator".to_string(),
                    detail: format!(
                        "ART+0x{offset:02X} written, enable bit {}",
                        if enabled { "set" } else { "not pinned" }
                    ),
                    instruction_addr: address,
                });
                return;
            }
            _ => {}
        }
    }

    if target >= MMIO_FLOOR {
        report.unclassified_writes.push(PeripheralWriteRecord {
            target,
            value: value.resolved(),
            at: address,
        });
    }
}

/// Map an RCC register write to a clock effect.
///
/// The offsets are STM32H7's (RM0433 section 8.7); other STM32 families lay
/// RCC out differently, so anything else is reported as `Other` rather than
/// being read with the wrong map.
fn classify_rcc_write(family: &FamilyResolution, offset: u32, value: Value) -> ClockEffectKind {
    if family.pack.family_id != "stm32h7" {
        return ClockEffectKind::Other;
    }
    match offset {
        // RCC_CR
        0x00 => {
            if value.all_set(1 << 24) {
                ClockEffectKind::PllEnable
            } else if value.all_clear(1 << 18) {
                ClockEffectKind::HseBypassClear
            } else if value.all_set(1 << 16) {
                ClockEffectKind::HseEnable
            } else if value.all_set(1) {
                ClockEffectKind::HsiEnable
            } else if value.all_clear(1) {
                ClockEffectKind::HsiDisable
            } else {
                ClockEffectKind::Other
            }
        }
        // RCC_CFGR
        0x10 => ClockEffectKind::SysclkSwitch,
        // RCC_PLLCKSELR / RCC_PLLCFGR / RCC_PLL1DIVR
        0x28 | 0x2c | 0x30 => ClockEffectKind::PllConfigure,
        _ => ClockEffectKind::Other,
    }
}

/// Fill in the "looked for, did not find" list and score the report.
fn finish(report: &mut SystemInitEffectsReport, family: &FamilyResolution) {
    let mut observations = 0u32;
    let mut note = |report: &mut SystemInitEffectsReport, found: bool, label: &str| {
        if found {
            observations += 1;
        } else {
            report.not_observed.push(label.to_string());
        }
    };

    note(
        report,
        report.fpu != FpuStatus::Unknown,
        "FPU configuration",
    );
    note(report, report.flash_latency.is_some(), "flash latency");
    note(report, !report.clock_effects.is_empty(), "clock tree setup");
    note(
        report,
        report
            .cache_effects
            .iter()
            .any(|effect| effect.kind == CacheEffectKind::ICacheEnable),
        "I-cache enable",
    );
    note(
        report,
        report
            .cache_effects
            .iter()
            .any(|effect| effect.kind == CacheEffectKind::DCacheEnable),
        "D-cache enable",
    );
    note(report, report.mpu_configured, "MPU configuration");
    note(
        report,
        report.vtor_relocation_check.is_some(),
        "VTOR relocation check",
    );
    note(report, report.vtor_write.is_some(), "SCB->VTOR write");
    note(
        report,
        report.art_accel.is_some(),
        "vendor flash accelerator",
    );

    // Every observation is a resolved store against a known register address,
    // so more of them means more of the function was actually understood.
    let mut confidence = 0.4 + (observations as f32) * 0.07;
    if !family.is_enriching_match() {
        confidence -= 0.15;
    }
    report.confidence = confidence.clamp(0.0, 0.95);
}
