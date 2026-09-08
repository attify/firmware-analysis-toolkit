#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeripheralRole {
    UpdateTransport,
    FlashWritePath,
    CommsBridge,
    HostSidecarLink,
    ErrorDetection,
    Actuation,
    Debug,
    Identity,
    Crypto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    pub start: u32,
    pub end: u32,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRange {
    pub start: u32,
    pub end: u32,
    pub peripheral_name: &'static str,
    pub roles: &'static [PeripheralRole],
}

impl MmioRange {
    pub fn contains(&self, addr: u32) -> bool {
        (self.start..self.end).contains(&addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqLabel {
    pub index: u16,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeripheralRoleHint {
    pub peripheral_name: &'static str,
    pub roles: &'static [PeripheralRole],
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterSpec {
    pub peripheral_name: &'static str,
    pub base: u32,
    pub offset: u32,
    pub register_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct McuFamilyPack {
    pub family_id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub flash_base: u32,
    pub flash_size: Option<u32>,
    pub total_vector_entries: Option<u16>,
    pub sram_ranges: &'static [MemoryRange],
    pub mmio_ranges: &'static [MmioRange],
    pub irq_labels: &'static [IrqLabel],
    pub role_hints: &'static [PeripheralRoleHint],
    pub register_specs: &'static [RegisterSpec],
}

impl McuFamilyPack {
    pub fn lookup_mmio(&self, addr: u32) -> Option<&MmioRange> {
        self.mmio_ranges.iter().find(|range| range.contains(addr))
    }

    pub fn lookup_irq(&self, index: u16) -> Option<&IrqLabel> {
        self.irq_labels.iter().find(|label| label.index == index)
    }

    pub fn role_hint_for_peripheral(&self, name: &str) -> Option<&PeripheralRoleHint> {
        self.role_hints
            .iter()
            .find(|hint| hint.peripheral_name.eq_ignore_ascii_case(name))
    }

    pub fn lookup_register(&self, addr: u32) -> Option<&RegisterSpec> {
        self.register_specs
            .iter()
            .find(|spec| spec.base.saturating_add(spec.offset) == addr)
    }
}

const FALLBACK_SRAM_RANGES: &[MemoryRange] = &[MemoryRange {
    start: 0x2000_0000,
    end: 0x2008_0000,
    label: "generic-sram",
}];

const FALLBACK_PACK: McuFamilyPack = McuFamilyPack {
    family_id: "cortex-m",
    display_name: "Cortex-M",
    aliases: &["cortex-m"],
    flash_base: 0x0000_0000,
    flash_size: None,
    total_vector_entries: None,
    sram_ranges: FALLBACK_SRAM_RANGES,
    mmio_ranges: &[],
    irq_labels: &[],
    role_hints: &[],
    register_specs: &[],
};

/// STM32H743 SRAM windows, per RM0433 table 7 ("Memory map and register
/// boundary addresses"). D2's SRAM1/2/3 are contiguous and are listed as one
/// window because the linker treats them that way; ITCM is deliberately not
/// listed here because it is instruction memory, not a data region.
const STM32H7_SRAM_RANGES: &[MemoryRange] = &[
    MemoryRange {
        start: 0x2000_0000,
        end: 0x2002_0000,
        label: "dtcm-sram",
    },
    MemoryRange {
        start: 0x2400_0000,
        end: 0x2408_0000,
        label: "axi-sram",
    },
    MemoryRange {
        start: 0x3000_0000,
        end: 0x3004_8000,
        label: "d2-sram",
    },
    MemoryRange {
        start: 0x3800_0000,
        end: 0x3801_0000,
        label: "d3-sram",
    },
    MemoryRange {
        start: 0x3880_0000,
        end: 0x3880_1000,
        label: "backup-sram",
    },
];

const STM32H7_COMMS_ROLES: &[PeripheralRole] = &[PeripheralRole::CommsBridge];

const STM32H7_FLASH_ROLES: &[PeripheralRole] = &[PeripheralRole::FlashWritePath];

const STM32H7_CRC_ROLES: &[PeripheralRole] = &[PeripheralRole::ErrorDetection];

const STM32H7_TIMER_ROLES: &[PeripheralRole] = &[];

const STM32H7_MMIO_RANGES: &[MmioRange] = &[
    MmioRange {
        start: 0x4000_1000,
        end: 0x4000_1400,
        peripheral_name: "TIM6",
        roles: STM32H7_TIMER_ROLES,
    },
    MmioRange {
        start: 0x4000_3C00,
        end: 0x4000_4000,
        peripheral_name: "SPI3",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x4000_4C00,
        end: 0x4000_5000,
        peripheral_name: "UART4",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x4000_5400,
        end: 0x4000_5800,
        peripheral_name: "I2C1",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x4000_7800,
        end: 0x4000_7C00,
        peripheral_name: "UART7",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x4000_7C00,
        end: 0x4000_8000,
        peripheral_name: "UART8",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x4002_8000,
        end: 0x4002_9400,
        peripheral_name: "ETH_MAC",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x5100_8000,
        end: 0x5100_8400,
        peripheral_name: "ART",
        roles: &[],
    },
    MmioRange {
        start: 0x5200_2000,
        end: 0x5200_2400,
        peripheral_name: "FLASH",
        roles: STM32H7_FLASH_ROLES,
    },
    MmioRange {
        start: 0x5800_1C00,
        end: 0x5800_2000,
        peripheral_name: "I2C4",
        roles: STM32H7_COMMS_ROLES,
    },
    MmioRange {
        start: 0x5802_4C00,
        end: 0x5802_5000,
        peripheral_name: "CRC",
        roles: STM32H7_CRC_ROLES,
    },
    MmioRange {
        start: 0x4001_1000,
        end: 0x4001_1400,
        peripheral_name: "USART1",
        roles: STM32H7_COMMS_ROLES,
    },
    // D3-domain reset/clock/power/config peripherals touched by SystemInit —
    // detectable as base-address literals even without register-write templates.
    MmioRange {
        start: 0x5800_0400,
        end: 0x5800_0800,
        peripheral_name: "SYSCFG",
        roles: &[],
    },
    MmioRange {
        start: 0x5802_4400,
        end: 0x5802_4800,
        peripheral_name: "RCC",
        roles: &[],
    },
    MmioRange {
        start: 0x5802_4800,
        end: 0x5802_4C00,
        peripheral_name: "PWR",
        roles: &[],
    },
    // ARM Cortex-M System Control Block (includes CPACR @ 0xE000ED88, the FPU
    // enable that SystemInit writes on parts with an FPU).
    MmioRange {
        start: 0xE000_ED00,
        end: 0xE000_EE00,
        peripheral_name: "SCB",
        roles: &[],
    },
];

const STM32H7_IRQ_LABELS: &[IrqLabel] = &[
    IrqLabel {
        index: 22,
        name: "EXTI0",
    },
    IrqLabel {
        index: 27,
        name: "DMA1_Stream0",
    },
    IrqLabel {
        index: 28,
        name: "DMA1_Stream1",
    },
    IrqLabel {
        index: 29,
        name: "DMA1_Stream2",
    },
    IrqLabel {
        index: 30,
        name: "DMA1_Stream3",
    },
    IrqLabel {
        index: 31,
        name: "DMA1_Stream4",
    },
    IrqLabel {
        index: 32,
        name: "DMA1_Stream5",
    },
    IrqLabel {
        index: 33,
        name: "DMA1_Stream6",
    },
    IrqLabel {
        index: 47,
        name: "I2C1_EV",
    },
    IrqLabel {
        index: 48,
        name: "I2C1_ER",
    },
    IrqLabel {
        index: 63,
        name: "DMA1_Stream7",
    },
    IrqLabel {
        index: 67,
        name: "SPI3",
    },
    IrqLabel {
        index: 68,
        name: "UART4",
    },
    IrqLabel {
        index: 70,
        name: "TIM6_DAC",
    },
    IrqLabel {
        index: 72,
        name: "DMA2_Stream0",
    },
    IrqLabel {
        index: 73,
        name: "DMA2_Stream1",
    },
    IrqLabel {
        index: 98,
        name: "UART7",
    },
    IrqLabel {
        index: 99,
        name: "UART8",
    },
    IrqLabel {
        index: 111,
        name: "I2C4_EV",
    },
    IrqLabel {
        index: 112,
        name: "I2C4_ER",
    },
    IrqLabel {
        index: 145,
        name: "BDMA_Channel0",
    },
    IrqLabel {
        index: 146,
        name: "BDMA_Channel1",
    },
];

const STM32H7_ROLE_HINTS: &[PeripheralRoleHint] = &[
    PeripheralRoleHint {
        peripheral_name: "FLASH",
        roles: STM32H7_FLASH_ROLES,
        confidence: 0.99,
    },
    PeripheralRoleHint {
        peripheral_name: "CRC",
        roles: STM32H7_CRC_ROLES,
        confidence: 0.96,
    },
    PeripheralRoleHint {
        peripheral_name: "I2C4",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.94,
    },
    PeripheralRoleHint {
        peripheral_name: "UART4",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.92,
    },
    PeripheralRoleHint {
        peripheral_name: "UART7",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.92,
    },
    PeripheralRoleHint {
        peripheral_name: "UART8",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.92,
    },
    PeripheralRoleHint {
        peripheral_name: "SPI3",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.88,
    },
    PeripheralRoleHint {
        peripheral_name: "TIM6",
        roles: STM32H7_TIMER_ROLES,
        confidence: 0.86,
    },
    PeripheralRoleHint {
        peripheral_name: "ETH_MAC",
        roles: STM32H7_COMMS_ROLES,
        confidence: 0.9,
    },
];

const STM32H7_REGISTER_SPECS: &[RegisterSpec] = &[
    RegisterSpec {
        peripheral_name: "USART1",
        base: 0x4001_1000,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "USART1",
        base: 0x4001_1000,
        offset: 0x04,
        register_name: "CR2",
    },
    RegisterSpec {
        peripheral_name: "USART1",
        base: 0x4001_1000,
        offset: 0x0C,
        register_name: "BRR",
    },
    RegisterSpec {
        peripheral_name: "UART4",
        base: 0x4000_4C00,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "UART4",
        base: 0x4000_4C00,
        offset: 0x0C,
        register_name: "BRR",
    },
    RegisterSpec {
        peripheral_name: "UART7",
        base: 0x4000_7800,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "UART7",
        base: 0x4000_7800,
        offset: 0x0C,
        register_name: "BRR",
    },
    RegisterSpec {
        peripheral_name: "UART8",
        base: 0x4000_7C00,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "UART8",
        base: 0x4000_7C00,
        offset: 0x0C,
        register_name: "BRR",
    },
    RegisterSpec {
        peripheral_name: "I2C1",
        base: 0x4000_5400,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "I2C1",
        base: 0x4000_5400,
        offset: 0x10,
        register_name: "TIMINGR",
    },
    RegisterSpec {
        peripheral_name: "I2C4",
        base: 0x5800_1C00,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "I2C4",
        base: 0x5800_1C00,
        offset: 0x10,
        register_name: "TIMINGR",
    },
    RegisterSpec {
        peripheral_name: "SPI3",
        base: 0x4000_3C00,
        offset: 0x00,
        register_name: "CR1",
    },
    RegisterSpec {
        peripheral_name: "SPI3",
        base: 0x4000_3C00,
        offset: 0x04,
        register_name: "CR2",
    },
    RegisterSpec {
        peripheral_name: "TIM6",
        base: 0x4000_1000,
        offset: 0x28,
        register_name: "PSC",
    },
    RegisterSpec {
        peripheral_name: "TIM6",
        base: 0x4000_1000,
        offset: 0x2C,
        register_name: "ARR",
    },
    RegisterSpec {
        peripheral_name: "CRC",
        base: 0x5802_4C00,
        offset: 0x00,
        register_name: "DR",
    },
    RegisterSpec {
        peripheral_name: "FLASH",
        base: 0x5200_2000,
        offset: 0x0C,
        register_name: "KEYR1",
    },
    RegisterSpec {
        peripheral_name: "FLASH",
        base: 0x5200_2000,
        offset: 0x18,
        register_name: "CR1",
    },
];

const STM32H7_PACK: McuFamilyPack = McuFamilyPack {
    family_id: "stm32h7",
    display_name: "STM32H7",
    aliases: &["stm32h7", "stm32h743", "stm32h7xx"],
    flash_base: 0x0800_0000,
    flash_size: Some(0x0020_0000),
    total_vector_entries: Some(166),
    sram_ranges: STM32H7_SRAM_RANGES,
    mmio_ranges: STM32H7_MMIO_RANGES,
    irq_labels: STM32H7_IRQ_LABELS,
    role_hints: STM32H7_ROLE_HINTS,
    register_specs: STM32H7_REGISTER_SPECS,
};

const STM32_COMMON_PACK: McuFamilyPack = McuFamilyPack {
    family_id: "stm32-common",
    display_name: "STM32 Common",
    aliases: &["stm32", "stm32-common"],
    flash_base: 0x0800_0000,
    flash_size: None,
    total_vector_entries: None,
    sram_ranges: &[MemoryRange {
        start: 0x2000_0000,
        end: 0x2008_0000,
        label: "sram",
    }],
    mmio_ranges: &[],
    irq_labels: &[],
    role_hints: &[],
    register_specs: &[],
};

const MCU_PACKS: &[McuFamilyPack] = &[STM32H7_PACK, STM32_COMMON_PACK];

pub fn resolve_mcu_pack(
    fast_profile_family: Option<&str>,
    forced_family: Option<&str>,
) -> Option<&'static McuFamilyPack> {
    if let Some(forced_family) = forced_family {
        if let Some(pack) = find_pack(forced_family) {
            return Some(pack);
        }
    }

    if let Some(fast_profile_family) = fast_profile_family {
        if let Some(pack) = find_pack(fast_profile_family) {
            return Some(pack);
        }
    }

    Some(&FALLBACK_PACK)
}

fn find_pack(name: &str) -> Option<&'static McuFamilyPack> {
    let normalized = normalize_name(name);
    MCU_PACKS.iter().find(|pack| {
        normalize_name(pack.family_id) == normalized
            || pack
                .aliases
                .iter()
                .any(|alias| normalize_name(alias) == normalized)
    })
}

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}
