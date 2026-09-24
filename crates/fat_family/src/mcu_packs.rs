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
pub struct ExecutableRegion {
    pub start: u32,
    pub end: u32,
    pub kind: &'static str,
}

impl ExecutableRegion {
    pub fn contains(&self, address: u32) -> bool {
        (self.start..self.end).contains(&address)
    }
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

/// The source of a profile fact, independent of firmware evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSource {
    pub title: &'static str,
    pub url: &'static str,
    pub location: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityMarker {
    pub marker: &'static str,
    pub display_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreProfile {
    pub name: &'static str,
    pub source: ProfileSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Register names may share an address. Conditions remain unresolved unless
/// another analysis establishes the relevant peripheral state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentedRegisterSpec {
    pub peripheral_name: &'static str,
    pub address: u32,
    pub register_name: &'static str,
    pub access: RegisterAccess,
    pub width_bytes: u8,
    pub count: u16,
    pub stride: u8,
    pub condition: Option<&'static str>,
    pub source: ProfileSource,
}

impl DocumentedRegisterSpec {
    pub fn index_at(&self, address: u32) -> Option<u16> {
        let offset = address.checked_sub(self.address)?;
        (self.stride > 0
            && offset % u32::from(self.stride) == 0
            && offset / u32::from(self.stride) < u32::from(self.count))
        .then_some((offset / u32::from(self.stride.max(1))) as u16)
    }
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
    pub executable_regions: &'static [ExecutableRegion],
    pub identity_markers: &'static [IdentityMarker],
    /// Distinctive executable ranges that support a tentative family match.
    /// The generic executable region list alone does not imply uniqueness.
    pub address_evidence: &'static [ExecutableRegion],
    pub core: Option<CoreProfile>,
    pub reserved_vector_indices: &'static [u16],
    pub vector_source: Option<ProfileSource>,
    pub documented_registers: &'static [DocumentedRegisterSpec],
    pub core_registers: &'static [DocumentedRegisterSpec],
    pub memory_notes: &'static [&'static str],
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
    executable_regions: &[],
    identity_markers: &[],
    address_evidence: &[],
    core: None,
    reserved_vector_indices: &[],
    vector_source: None,
    documented_registers: &[],
    core_registers: &[],
    memory_notes: &[],
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
    executable_regions: &[ExecutableRegion {
        start: 0x0800_0000,
        end: 0x0820_0000,
        kind: "flash",
    }],
    identity_markers: &[],
    address_evidence: &[],
    core: None,
    reserved_vector_indices: &[],
    vector_source: None,
    documented_registers: &[],
    core_registers: &[],
    memory_notes: &[],
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
    executable_regions: &[ExecutableRegion {
        start: 0x0800_0000,
        end: 0x0900_0000,
        kind: "flash",
    }],
    identity_markers: &[],
    address_evidence: &[],
    core: None,
    reserved_vector_indices: &[],
    vector_source: None,
    documented_registers: &[],
    core_registers: &[],
    memory_notes: &[],
};

const LPC13XX_DATASHEET: ProfileSource = ProfileSource {
    title: "NXP LPC1311/13/42/43 data sheet, Rev. 5",
    url: "https://www.nxp.com/docs/en/data-sheet/LPC1311_13_42_43.pdf",
    location: "Sections 1-2 and Figure 6",
};
const LPC13XX_SVD: ProfileSource = ProfileSource {
    title: "Keil NXP LPC1300 Device Family Pack 1.1.1",
    url: "https://www.keil.com/pack/Keil.LPC1300_DFP.1.1.1.pack",
    location: "SVD/LPC13xx.svd; Device/Include/LPC13xx/LPC13xx.h",
};
const LPC13XX_VECTORS: ProfileSource = ProfileSource {
    title: "Keil NXP LPC1300 Device Family Pack 1.1.1",
    url: "https://www.keil.com/pack/Keil.LPC1300_DFP.1.1.1.pack",
    location: "Device/Source/ARM/startup_LPC13xx.s; Device/Include/LPC13xx/LPC13xx.h",
};
const CORTEX_M3_SOURCE: ProfileSource = ProfileSource {
    title: "Arm CMSIS 5.9.0 Cortex-M3 core register definitions",
    url:
        "https://raw.githubusercontent.com/ARM-software/CMSIS_5/5.9.0/CMSIS/Core/Include/core_cm3.h",
    location: "NVIC_Type, SCB_Type, SysTick_Type; peripheral base address definitions",
};

const fn register(
    peripheral_name: &'static str,
    address: u32,
    register_name: &'static str,
    access: RegisterAccess,
    source: ProfileSource,
    condition: Option<&'static str>,
) -> DocumentedRegisterSpec {
    DocumentedRegisterSpec {
        peripheral_name,
        address,
        register_name,
        access,
        width_bytes: 4,
        count: 1,
        stride: 4,
        condition,
        source,
    }
}
const fn register_array(
    mut spec: DocumentedRegisterSpec,
    count: u16,
    width_bytes: u8,
    stride: u8,
) -> DocumentedRegisterSpec {
    spec.count = count;
    spec.width_bytes = width_bytes;
    spec.stride = stride;
    spec
}

const LPC13XX_MMIO_RANGES: &[MmioRange] = &[
    MmioRange {
        start: 0x40008000,
        end: 0x40008058,
        peripheral_name: "UART",
        roles: &[PeripheralRole::CommsBridge],
    },
    MmioRange {
        start: 0x4000c000,
        end: 0x4000c078,
        peripheral_name: "CT16B0",
        roles: &[],
    },
    MmioRange {
        start: 0x40010000,
        end: 0x40010078,
        peripheral_name: "CT16B1",
        roles: &[],
    },
    MmioRange {
        start: 0x40014000,
        end: 0x40014078,
        peripheral_name: "CT32B0",
        roles: &[],
    },
    MmioRange {
        start: 0x40018000,
        end: 0x40018078,
        peripheral_name: "CT32B1",
        roles: &[],
    },
    MmioRange {
        start: 0x40020000,
        end: 0x40020030,
        peripheral_name: "USB",
        roles: &[PeripheralRole::CommsBridge],
    },
    MmioRange {
        start: 0x40048000,
        end: 0x400483f8,
        peripheral_name: "SYSCON",
        roles: &[],
    },
];

const LPC13XX_IRQ_LABELS: &[IrqLabel] = &[
    IrqLabel {
        index: 16,
        name: "WAKEUP0",
    },
    IrqLabel {
        index: 17,
        name: "WAKEUP1",
    },
    IrqLabel {
        index: 18,
        name: "WAKEUP2",
    },
    IrqLabel {
        index: 19,
        name: "WAKEUP3",
    },
    IrqLabel {
        index: 20,
        name: "WAKEUP4",
    },
    IrqLabel {
        index: 21,
        name: "WAKEUP5",
    },
    IrqLabel {
        index: 22,
        name: "WAKEUP6",
    },
    IrqLabel {
        index: 23,
        name: "WAKEUP7",
    },
    IrqLabel {
        index: 24,
        name: "WAKEUP8",
    },
    IrqLabel {
        index: 25,
        name: "WAKEUP9",
    },
    IrqLabel {
        index: 26,
        name: "WAKEUP10",
    },
    IrqLabel {
        index: 27,
        name: "WAKEUP11",
    },
    IrqLabel {
        index: 28,
        name: "WAKEUP12",
    },
    IrqLabel {
        index: 29,
        name: "WAKEUP13",
    },
    IrqLabel {
        index: 30,
        name: "WAKEUP14",
    },
    IrqLabel {
        index: 31,
        name: "WAKEUP15",
    },
    IrqLabel {
        index: 32,
        name: "WAKEUP16",
    },
    IrqLabel {
        index: 33,
        name: "WAKEUP17",
    },
    IrqLabel {
        index: 34,
        name: "WAKEUP18",
    },
    IrqLabel {
        index: 35,
        name: "WAKEUP19",
    },
    IrqLabel {
        index: 36,
        name: "WAKEUP20",
    },
    IrqLabel {
        index: 37,
        name: "WAKEUP21",
    },
    IrqLabel {
        index: 38,
        name: "WAKEUP22",
    },
    IrqLabel {
        index: 39,
        name: "WAKEUP23",
    },
    IrqLabel {
        index: 40,
        name: "WAKEUP24",
    },
    IrqLabel {
        index: 41,
        name: "WAKEUP25",
    },
    IrqLabel {
        index: 42,
        name: "WAKEUP26",
    },
    IrqLabel {
        index: 43,
        name: "WAKEUP27",
    },
    IrqLabel {
        index: 44,
        name: "WAKEUP28",
    },
    IrqLabel {
        index: 45,
        name: "WAKEUP29",
    },
    IrqLabel {
        index: 46,
        name: "WAKEUP30",
    },
    IrqLabel {
        index: 47,
        name: "WAKEUP31",
    },
    IrqLabel {
        index: 48,
        name: "WAKEUP32",
    },
    IrqLabel {
        index: 49,
        name: "WAKEUP33",
    },
    IrqLabel {
        index: 50,
        name: "WAKEUP34",
    },
    IrqLabel {
        index: 51,
        name: "WAKEUP35",
    },
    IrqLabel {
        index: 52,
        name: "WAKEUP36",
    },
    IrqLabel {
        index: 53,
        name: "WAKEUP37",
    },
    IrqLabel {
        index: 54,
        name: "WAKEUP38",
    },
    IrqLabel {
        index: 55,
        name: "WAKEUP39",
    },
    IrqLabel {
        index: 56,
        name: "I2C",
    },
    IrqLabel {
        index: 57,
        name: "TIMER16_0",
    },
    IrqLabel {
        index: 58,
        name: "TIMER16_1",
    },
    IrqLabel {
        index: 59,
        name: "TIMER32_0",
    },
    IrqLabel {
        index: 60,
        name: "TIMER32_1",
    },
    IrqLabel {
        index: 61,
        name: "SSP0",
    },
    IrqLabel {
        index: 62,
        name: "UART",
    },
    IrqLabel {
        index: 63,
        name: "USB",
    },
    IrqLabel {
        index: 64,
        name: "USB_FIQ",
    },
    IrqLabel {
        index: 65,
        name: "ADC",
    },
    IrqLabel {
        index: 66,
        name: "WDT",
    },
    IrqLabel {
        index: 67,
        name: "BOD",
    },
    IrqLabel {
        index: 69,
        name: "PIOINT3",
    },
    IrqLabel {
        index: 70,
        name: "PIOINT2",
    },
    IrqLabel {
        index: 71,
        name: "PIOINT1",
    },
    IrqLabel {
        index: 72,
        name: "PIOINT0",
    },
    IrqLabel {
        index: 73,
        name: "SSP1",
    },
];

const LPC13XX_REGISTERS: &[DocumentedRegisterSpec] = &[
    register(
        "UART",
        0x40008000,
        "RBR",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LCR.DLAB = 0"),
    ),
    register(
        "UART",
        0x40008000,
        "THR",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LCR.DLAB = 0"),
    ),
    register(
        "UART",
        0x40008000,
        "DLL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LCR.DLAB = 1"),
    ),
    register(
        "UART",
        0x40008004,
        "DLM",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LCR.DLAB = 1"),
    ),
    register(
        "UART",
        0x40008004,
        "IER",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LCR.DLAB = 0"),
    ),
    register(
        "UART",
        0x40008008,
        "IIR",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        None,
    ),
    register(
        "UART",
        0x40008008,
        "FCR",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        None,
    ),
    register(
        "UART",
        0x4000800c,
        "LCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "UART",
        0x40008014,
        "LSR",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        None,
    ),
    register(
        "UART",
        0x40008028,
        "FDR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "UART",
        0x40008030,
        "TER",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "USB",
        0x40020000,
        "DEVINTST",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020004,
        "DEVINTEN",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020008,
        "DEVINTCLR",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x4002000c,
        "DEVINTSET",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020010,
        "CMDCODE",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020014,
        "CMDDATA",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020018,
        "RXDATA",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x4002001c,
        "TXDATA",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020020,
        "RXPLEN",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020024,
        "TXPLEN",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x40020028,
        "CTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "USB",
        0x4002002c,
        "DEVFIQSEL",
        RegisterAccess::WriteOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x40048000,
        "SYSMEMREMAP",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048004,
        "PRESETCTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048008,
        "SYSPLLCTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x4004800c,
        "SYSPLLSTAT",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048010,
        "USBPLLCTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x40048014,
        "USBPLLSTAT",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x40048020,
        "SYSOSCCTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048040,
        "SYSPLLCLKSEL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048044,
        "SYSPLLCLKUEN",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048048,
        "USBPLLCLKSEL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x4004804c,
        "USBPLLCLKUEN",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x40048070,
        "MAINCLKSEL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048074,
        "MAINCLKUEN",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048078,
        "SYSAHBCLKDIV",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048080,
        "SYSAHBCLKCTRL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x40048098,
        "UARTCLKDIV",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x400480c0,
        "USBCLKSEL",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x400480c4,
        "USBCLKUEN",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x400480c8,
        "USBCLKDIV",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        Some("LPC1342/43 only"),
    ),
    register(
        "SYSCON",
        0x40048238,
        "PDRUNCFG",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "SYSCON",
        0x400483f4,
        "DEVICE_ID",
        RegisterAccess::ReadOnly,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B0",
        0x4000c000,
        "IR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B0",
        0x4000c004,
        "TCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B0",
        0x4000c008,
        "TC",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B0",
        0x4000c00c,
        "PR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B0",
        0x4000c014,
        "MCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B1",
        0x40010000,
        "IR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B1",
        0x40010004,
        "TCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B1",
        0x40010008,
        "TC",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B1",
        0x4001000c,
        "PR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT16B1",
        0x40010014,
        "MCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B0",
        0x40014000,
        "IR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B0",
        0x40014004,
        "TCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B0",
        0x40014008,
        "TC",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B0",
        0x4001400c,
        "PR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B0",
        0x40014014,
        "MCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B1",
        0x40018000,
        "IR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B1",
        0x40018004,
        "TCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B1",
        0x40018008,
        "TC",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B1",
        0x4001800c,
        "PR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
    register(
        "CT32B1",
        0x40018014,
        "MCR",
        RegisterAccess::ReadWrite,
        LPC13XX_SVD,
        None,
    ),
];

const CORTEX_M3_REGISTERS: &[DocumentedRegisterSpec] = &[
    register(
        "SysTick",
        0xe000e010,
        "CTRL",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SysTick",
        0xe000e014,
        "LOAD",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SysTick",
        0xe000e018,
        "VAL",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SysTick",
        0xe000e01c,
        "CALIB",
        RegisterAccess::ReadOnly,
        CORTEX_M3_SOURCE,
        None,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e100,
            "ISER",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented interrupt banks are device dependent"),
        ),
        8,
        4,
        4,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e180,
            "ICER",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented interrupt banks are device dependent"),
        ),
        8,
        4,
        4,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e200,
            "ISPR",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented interrupt banks are device dependent"),
        ),
        8,
        4,
        4,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e280,
            "ICPR",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented interrupt banks are device dependent"),
        ),
        8,
        4,
        4,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e300,
            "IABR",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented interrupt banks are device dependent"),
        ),
        8,
        4,
        4,
    ),
    register_array(
        register(
            "NVIC",
            0xe000e400,
            "IP",
            RegisterAccess::ReadWrite,
            CORTEX_M3_SOURCE,
            Some("Implemented priority entries are device dependent"),
        ),
        240,
        1,
        1,
    ),
    register(
        "NVIC",
        0xe000ef00,
        "STIR",
        RegisterAccess::WriteOnly,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed00,
        "CPUID",
        RegisterAccess::ReadOnly,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed04,
        "ICSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed08,
        "VTOR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed0c,
        "AIRCR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed10,
        "SCR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed14,
        "CCR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed24,
        "SHCSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed28,
        "CFSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed2c,
        "HFSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed30,
        "DFSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed34,
        "MMFAR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed38,
        "BFAR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
    register(
        "SCB",
        0xe000ed3c,
        "AFSR",
        RegisterAccess::ReadWrite,
        CORTEX_M3_SOURCE,
        None,
    ),
];

// LPC1311/13/42/43 data sheet, rev. 5, Figure 6 (memory map).
// https://www.nxp.com/docs/en/data-sheet/LPC1311_13_42_43.pdf
// The family range is a union across these parts, not an exact device ID.
const LPC13XX_PACK: McuFamilyPack = McuFamilyPack {
    family_id: "lpc13xx",
    display_name: "NXP LPC13xx",
    aliases: &["lpc13xx", "nxp-lpc13xx", "lpc134x", "nxp-lpc134x"],
    flash_base: 0,
    flash_size: None, // Family union is not an exact device capacity.
    total_vector_entries: Some(74),
    sram_ranges: &[MemoryRange {
        start: 0x1000_0000,
        end: 0x1000_2000,
        label: "sram",
    }],
    mmio_ranges: LPC13XX_MMIO_RANGES,
    irq_labels: LPC13XX_IRQ_LABELS,
    role_hints: &[],
    register_specs: &[],
    executable_regions: &[
        ExecutableRegion {
            start: 0,
            end: 0x8000,
            kind: "flash",
        },
        ExecutableRegion {
            start: 0x1fff_0000,
            end: 0x1fff_4000,
            kind: "boot-rom",
        },
        ExecutableRegion {
            start: 0x1000_0000,
            end: 0x1000_2000,
            kind: "ram",
        },
    ],
    identity_markers: &[
        IdentityMarker { marker: "LPC134X", display_name: "NXP LPC134x" },
        IdentityMarker { marker: "LPC13XX", display_name: "NXP LPC13xx" },
    ],
    address_evidence: &[ExecutableRegion { start: 0x1fff_0000, end: 0x1fff_4000, kind: "boot-rom" }],
    core: Some(CoreProfile { name: "ARM Cortex-M3", source: LPC13XX_DATASHEET }),
    reserved_vector_indices: &[7, 8, 9, 10, 13],
    vector_source: Some(LPC13XX_VECTORS),
    documented_registers: LPC13XX_REGISTERS,
    core_registers: CORTEX_M3_REGISTERS,
    memory_notes: &["SRAM and executable ranges cover the LPC1311/13/42/43 family union; capacities vary by part.",
        "The vector limit is the upper bound across the family; boot-ROM tables can be shorter.",
        "USB registers apply to LPC1342/43."],
};

const MCU_PACKS: &[McuFamilyPack] = &[STM32H7_PACK, STM32_COMMON_PACK, LPC13XX_PACK];

pub fn identity_pack(text: &str) -> Option<&'static McuFamilyPack> {
    MCU_PACKS.iter().find(|pack| {
        pack.identity_markers
            .iter()
            .any(|marker| text.contains(marker.marker))
    })
}

pub fn identity_display_name(text: &str) -> Option<&'static str> {
    let pack = identity_pack(text)?;
    pack.identity_markers
        .iter()
        .find(|marker| text.contains(marker.marker))
        .map(|marker| marker.display_name)
}

/// An address match is tentative. It cannot establish an exact part or core
/// revision, and must only be used after structural architecture recognition.
pub fn address_family_match(sp: u32, reset: u32) -> Option<&'static McuFamilyPack> {
    let mut matches = MCU_PACKS.iter().filter(|pack| {
        pack.sram_ranges
            .iter()
            .any(|range| sp > range.start && sp <= range.end)
            && pack
                .address_evidence
                .iter()
                .any(|range| range.contains(reset & !1))
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

pub fn executable_region(address: u32) -> Option<&'static ExecutableRegion> {
    MCU_PACKS
        .iter()
        .flat_map(|pack| pack.executable_regions)
        .find(|region| region.contains(address))
}

/// Legacy mapping candidates retained for inputs without a documented region.
/// These are historical hints, not documented part-memory-map facts.
struct CodeMappingHint {
    start: u32,
    end: u32,
    base: u32,
}
const LEGACY_CODE_MAPPING_HINTS: &[CodeMappingHint] = &[
    CodeMappingHint {
        start: 0x0800_0000,
        end: 0x0900_0000,
        base: 0x0800_0000,
    },
    CodeMappingHint {
        start: 0x0000_0000,
        end: 0x0100_0000,
        base: 0x0000_0000,
    },
    CodeMappingHint {
        start: 0x0100_0000,
        end: 0x0200_0000,
        base: 0x0100_0000,
    },
    CodeMappingHint {
        start: 0x0400_0000,
        end: 0x0500_0000,
        base: 0x0040_0000,
    },
];

/// Prefer a documented executable region, then the existing generic hints.
/// A returned base is a candidate mapping, never an observed load address.
pub fn infer_code_base(address: u32) -> Option<u32> {
    executable_region(address)
        .map(|region| region.start)
        .or_else(|| {
            LEGACY_CODE_MAPPING_HINTS
                .iter()
                .find(|hint| (hint.start..hint.end).contains(&address))
                .map(|hint| hint.base)
        })
}

pub fn compatible_identity_pack(text: &str, sp: u32, reset: u32) -> Option<&'static McuFamilyPack> {
    let pack = identity_pack(text)?;
    (pack
        .sram_ranges
        .iter()
        .any(|range| sp > range.start && sp <= range.end)
        && pack
            .executable_regions
            .iter()
            .any(|range| range.contains(reset & !1)))
    .then_some(pack)
}

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

/// Legacy address-only hints retained as tentative evidence, never part IDs.
/// Ordered records preserve prior broad family behavior without embedding
/// vendor decisions in the structural vector detector.
struct AddressFamilyHint {
    sp_start: u32,
    sp_end: u32,
    reset_start: u32,
    reset_end: u32,
    label: &'static str,
    confidence: u8,
}
const ADDRESS_FAMILY_HINTS: &[AddressFamilyHint] = &[
    AddressFamilyHint {
        sp_start: 0x24000000,
        sp_end: 0x24080000,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32H7",
        confidence: 95,
    },
    AddressFamilyHint {
        sp_start: 0x30000000,
        sp_end: 0x3003ffff,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32H7",
        confidence: 85,
    },
    AddressFamilyHint {
        sp_start: 0x10000000,
        sp_end: 0x1000ffff,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32 (CCM)",
        confidence: 70,
    },
    AddressFamilyHint {
        sp_start: 0x10000000,
        sp_end: 0x1000ffff,
        reset_start: 0x00000000,
        reset_end: 0x000fffff,
        label: "NXP LPC1xxx",
        confidence: 70,
    },
    AddressFamilyHint {
        sp_start: 0x02000000,
        sp_end: 0x0203ffff,
        reset_start: 0x00000000,
        reset_end: 0xffffffff,
        label: "NXP LPC4300",
        confidence: 80,
    },
    AddressFamilyHint {
        sp_start: 0x20000000,
        sp_end: 0x20004000,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32 (small, F0/L0/G0)",
        confidence: 75,
    },
    AddressFamilyHint {
        sp_start: 0x20004001,
        sp_end: 0x20020000,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32 (medium, F1/F3/L4/G4)",
        confidence: 75,
    },
    AddressFamilyHint {
        sp_start: 0x20020001,
        sp_end: 0x20080000,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32 (large, F4/F7/U5)",
        confidence: 75,
    },
    AddressFamilyHint {
        sp_start: 0x20080001,
        sp_end: 0x20ffffff,
        reset_start: 0x08000000,
        reset_end: 0x08ffffff,
        label: "STM32 (unknown)",
        confidence: 75,
    },
    AddressFamilyHint {
        sp_start: 0x20000000,
        sp_end: 0x20ffffff,
        reset_start: 0x00000000,
        reset_end: 0x000fffff,
        label: "Cortex-M (NXP/Nordic/TI)",
        confidence: 40,
    },
    AddressFamilyHint {
        sp_start: 0x20000000,
        sp_end: 0x20ffffff,
        reset_start: 0x00000000,
        reset_end: 0xffffffff,
        label: "Cortex-M (unknown vendor)",
        confidence: 30,
    },
];

pub fn identify_address_family(sp: u32, reset: u32) -> Option<(&'static str, u8)> {
    if let Some(pack) = address_family_match(sp, reset) {
        return Some((pack.display_name, 70));
    }
    ADDRESS_FAMILY_HINTS
        .iter()
        .find(|hint| {
            (hint.sp_start..=hint.sp_end).contains(&sp)
                && (hint.reset_start..=hint.reset_end).contains(&(reset & !1))
        })
        .map(|hint| (hint.label, hint.confidence))
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn identity_names_are_marker_data_and_require_compatible_memory_for_corrobation() {
        assert_eq!(
            identity_display_name("NXP LPC134X IFLASH"),
            Some("NXP LPC134x")
        );
        assert_eq!(
            identity_display_name("NXP LPC13XX IFLASH"),
            Some("NXP LPC13xx")
        );
        assert!(compatible_identity_pack("LPC134X", 0x2000_1000, 0x0800_0101).is_none());
        assert!(compatible_identity_pack("LPC134X", 0x1000_2000, 0x1fff_0101).is_some());
        assert!(compatible_identity_pack("LPC134X", 0x1000_2004, 0x1fff_0101).is_none());
    }

    #[test]
    fn distinctive_address_evidence_does_not_match_shared_flash_or_outside_rom() {
        assert_eq!(
            address_family_match(0x1000_0ffc, 0x1fff_0101)
                .unwrap()
                .family_id,
            "lpc13xx"
        );
        assert!(address_family_match(0x1000_0ffc, 0x1fff_4001).is_none());
        assert!(address_family_match(0x1000_0ffc, 0x0101).is_none());
        assert!(address_family_match(0x2000_0ffc, 0x1fff_0101).is_none());
    }

    #[test]
    fn union_profile_has_documented_bounds_not_exact_part_capacity() {
        let pack = resolve_mcu_pack(Some("NXP LPC134x"), None).unwrap();
        assert_eq!(pack.total_vector_entries, Some(74));
        assert_eq!(pack.flash_size, None);
        assert!(pack.reserved_vector_indices.contains(&7));
        assert_eq!(pack.lookup_irq(63).unwrap().name, "USB");
        assert_eq!(pack.lookup_irq(64).unwrap().name, "USB_FIQ");
        assert_eq!(pack.core.unwrap().name, "ARM Cortex-M3");
        assert!(pack
            .core
            .unwrap()
            .source
            .url
            .starts_with("https://www.nxp.com/"));
        assert!(pack
            .vector_source
            .unwrap()
            .location
            .contains("startup_LPC13xx.s"));
    }

    #[test]
    fn register_definitions_preserve_overlapping_access_aliases_and_provenance() {
        let specs: Vec<_> = LPC13XX_PACK
            .documented_registers
            .iter()
            .filter(|spec| spec.index_at(0x4000_8000).is_some())
            .collect();
        assert_eq!(specs.len(), 3);
        assert!(specs
            .iter()
            .any(|spec| spec.register_name == "RBR" && spec.access == RegisterAccess::ReadOnly));
        assert!(specs
            .iter()
            .any(|spec| spec.register_name == "THR" && spec.access == RegisterAccess::WriteOnly));
        assert!(specs
            .iter()
            .any(|spec| spec.register_name == "DLL" && spec.condition.is_some()));
        for spec in LPC13XX_PACK
            .documented_registers
            .iter()
            .chain(LPC13XX_PACK.core_registers)
        {
            assert!(spec.source.url.starts_with("https://"));
            assert!(!spec.source.location.is_empty());
        }
        assert!(LPC13XX_PACK
            .documented_registers
            .iter()
            .all(|spec| spec.index_at(0x4000_8001).is_none()));
    }

    #[test]
    fn code_mapping_profiles_precede_legacy_hints_and_keep_unknowns_unresolved() {
        assert_eq!(infer_code_base(0x1fff_0104), Some(0x1fff_0000));
        assert_eq!(infer_code_base(0x1000_0104), Some(0x1000_0000));
        for (first, last, base) in [
            (0, 0x00ff_ffff, 0),
            (0x0100_0000, 0x01ff_ffff, 0x0100_0000),
            (0x0400_0000, 0x04ff_ffff, 0x0040_0000),
            (0x0800_0000, 0x08ff_ffff, 0x0800_0000),
        ] {
            assert_eq!(infer_code_base(first), Some(base));
            assert_eq!(infer_code_base(last), Some(base));
        }
        for address in [
            0x0200_0000,
            0x0500_0000,
            0x0900_0000,
            0x1fff_4000,
            0x6000_0000,
        ] {
            assert!(infer_code_base(address).is_none());
        }
    }

    #[test]
    fn tentative_legacy_address_labels_remain_stable_at_boundaries() {
        assert_eq!(
            identify_address_family(0x2000_4000, 0x0800_0101).unwrap().0,
            "STM32 (small, F0/L0/G0)"
        );
        assert_eq!(
            identify_address_family(0x2000_4004, 0x0800_0101).unwrap().0,
            "STM32 (medium, F1/F3/L4/G4)"
        );
        assert_eq!(
            identify_address_family(0x2408_0000, 0x0800_0101),
            Some(("STM32H7", 95))
        );
        assert!(identify_address_family(0x1000_0ffc, 0x6000_0101).is_none());
    }
}
