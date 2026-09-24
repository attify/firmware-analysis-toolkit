use serde::{Deserialize, Serialize};

pub const MCU_INSPECTION_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct McuInspectionReport {
    pub schema_version: String,
    pub artifact_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_identity: Option<ArtifactIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_measurements: Option<ByteMeasurements>,
    #[serde(default)]
    pub analysis_provenance: AnalysisProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_profile: Option<McuProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identification: Option<McuIdentification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degradations: Option<Vec<InspectionDegradation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_layout: Option<ImageLayoutReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_hypotheses: Option<Vec<AddressHypothesis>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_map: Option<Vec<MemoryRegion>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector_table: Option<InterruptVectorReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_chain: Option<StartupChainReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_analysis: Option<crate::mcu_code::McuCodeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_annotations: Option<crate::mcu_registers::RegisterAnnotationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_table: Option<InitTableReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sram_partitions: Option<SramPartitionReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_init_effects: Option<SystemInitEffectsReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_entry: Option<MainEntryReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_model: Option<ExecutionModelReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peripheral_map: Option<PeripheralMapReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peripheral_surface: Option<PeripheralSurfaceReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_surface: Option<SecuritySurfaceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_checks: Option<Vec<IntegrityCheckReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity_checks: Option<Vec<AuthenticityMechanismReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_checks: Option<Vec<RollbackResistanceReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_authority: Option<Vec<WriteAuthorityReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_state_risk: Option<SharedStateRiskReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_paths: Option<Vec<UpdatePathReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<Vec<TrustChainReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<EvidenceRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ByteMeasurements {
    pub total_bytes: u64,
    pub content_prefix_bytes: u64,
    pub trailing_uniform_byte: Option<u8>,
    pub trailing_uniform_offset: Option<u64>,
    pub trailing_uniform_bytes: u64,
    pub trailing_uniform_percent: f64,
    pub whole_entropy_bits_per_byte: f64,
    pub content_entropy_bits_per_byte: Option<f64>,
    #[serde(default)]
    pub repetition: RepetitionMeasurements,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UniformRegion {
    pub offset: u64,
    pub length: u64,
    pub byte: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RepetitionMeasurements {
    pub block_size: usize,
    pub total_block_count: usize,
    pub duplicate_block_count: usize,
    pub repeated_unit_bytes: Option<u64>,
    pub copies: usize,
    pub duplicate_blocks_from_copies: usize,
    pub duplicate_uniform_blocks: usize,
    pub unexplained_duplicate_blocks: usize,
    pub uniform_regions: Vec<UniformRegion>,
    pub uniform_regions_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct McuVectorCandidate {
    pub offset: u64,
    pub initial_sp: u32,
    pub reset_vector: u32,
    pub accepted: bool,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub contradictions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct McuIdentityString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct McuIdentification {
    pub architecture: Option<String>,
    pub architecture_confidence: String,
    pub family: Option<String>,
    pub family_confidence: String,
    pub family_evidence: Vec<String>,
    pub image_role: Option<String>,
    pub vector_candidates: Vec<McuVectorCandidate>,
    pub identity_strings: Vec<McuIdentityString>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ImageMeasurements {
    pub identity: ArtifactIdentity,
    pub bytes: ByteMeasurements,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AnalysisProvenance {
    pub backend: String,
    pub backend_version: Option<String>,
    pub user_base: Option<u32>,
    pub user_family: Option<String>,
    pub family_selection_mode: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum InspectionDegradation {
    #[default]
    WeakSignal,
    NonCortexMLikely,
    PackedOrEncryptedLikely,
    BaseAddressAmbiguous,
    DisassemblyUnavailable,
    FamilyPackWeak,
    CrossArtifactContextMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ImageLayoutKind {
    FullFlashDump,
    AppOnlyImage,
    BootloaderOnlyImage,
    BootloaderPlusAppConcat,
    RelocatedImage,
    PackedOrEncrypted,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ImageLayoutReport {
    #[serde(default)]
    pub kind: Interpretation<ImageLayoutKind>,
    #[serde(default)]
    pub candidate_offsets: Vec<u32>,
    /// Address corresponding to the selected vector table's file offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector_address: Option<u32>,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AddressHypothesis {
    pub base: u32,
    pub confidence: f32,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interpretation<T> {
    pub value: T,
    pub confidence: f32,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

impl<T> Default for Interpretation<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            value: T::default(),
            confidence: 0.0,
            rationale: Vec::new(),
            evidence_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ClaimKind {
    #[default]
    Fact,
    Derived,
    Inference,
    Hypothesis,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ClaimRecord {
    pub claim_id: String,
    pub title: String,
    #[serde(default)]
    pub kind: ClaimKind,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum EvidenceKind {
    #[default]
    RawBytes,
    VectorWord,
    Disassembly,
    Xref,
    StringHit,
    MmioAccess,
    FileRelation,
    SourceAnchor,
    ToolOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceLocation {
    pub offset: Option<u64>,
    pub address: Option<u32>,
    pub symbol: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    #[serde(default)]
    pub kind: EvidenceKind,
    pub summary: String,
    pub location: Option<EvidenceLocation>,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SectionProvenance {
    pub extractor: String,
    pub backend: Option<String>,
    pub family_pack: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum MemoryRegionKind {
    Flash,
    Ram,
    Mmio,
    VectorTable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: Option<u64>,
    #[serde(default)]
    pub kind: MemoryRegionKind,
    pub label: Option<String>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum InterruptHandlerKind {
    InitialStackPointer,
    ResetHandler,
    Interrupt,
    DefaultHandler,
    Reserved,
    Unpopulated,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InterruptVectorEntry {
    pub index: u16,
    pub address: u32,
    #[serde(default)]
    pub handler_kind: InterruptHandlerKind,
    pub family_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_exception: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_irq_number: Option<u16>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RepeatedVectorTarget {
    pub aligned_address: u32,
    pub reference_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InterruptVectorReport {
    pub entry_count: usize,
    /// Legacy field name: populated core and external handler pointers, not activity.
    pub active_count: usize,
    pub default_handler_count: usize,
    /// Populated core handler entries, including Reset; not runtime activity.
    #[serde(default)]
    pub core_exception_count: usize,
    /// Populated external vector entries, not the device's IRQ capacity.
    #[serde(default)]
    pub external_irq_count: usize,
    #[serde(default)]
    pub reserved_entry_count: usize,
    #[serde(default)]
    pub unpopulated_entry_count: usize,
    #[serde(default)]
    pub scanned_word_count: usize,
    #[serde(default)]
    pub handler_candidate_count: usize,
    #[serde(default)]
    pub unique_aligned_target_count: usize,
    #[serde(default)]
    pub repeated_targets: Vec<RepeatedVectorTarget>,
    #[serde(default)]
    pub scan_boundary: String,
    #[serde(default)]
    pub scan_boundary_rationale: Vec<String>,
    #[serde(default)]
    pub entries: Vec<InterruptVectorEntry>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum StartupRole {
    ResetStub,
    /// A trampoline reached by a tail branch out of the reset stub: it
    /// typically re-loads SP from a literal before calling runtime init.
    StartupStub,
    SystemInit,
    RuntimeInit,
    Main,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StartupStep {
    pub ordinal: u8,
    pub address: u32,
    #[serde(default)]
    pub role: StartupRole,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StartupChainReport {
    #[serde(default)]
    pub steps: Vec<StartupStep>,
    pub confidence: f32,
    pub provenance: Option<SectionProvenance>,
}

/// Layout of a single startup init-descriptor table.
///
/// ARM EABI toolchains emit two structurally different descriptor tables and
/// the record stride is what tells them apart:
///
/// * CMSIS `startup_ARMCMx.c` emits a `__copy_table` of 12-byte
///   `{src, dst, size}` triples plus a *separate* `__zero_table` of 8-byte
///   `{dst, size}` pairs. The copy/zero semantics come from which table the
///   record lives in; there is no per-record handler pointer.
/// * Scatter-load style startup code (armlink `__scatterload`, and the
///   GCC/ld equivalent) emits a single table of 16-byte
///   `{src, dst, size, handler}` records and dispatches `handler(src, dst, size)`
///   per record, so copy/zero/decompress is decided per record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum InitTableFormat {
    /// 12-byte `{src, dst, size}` copy triples (`__copy_table_start__`).
    CmsisCopyTable,
    /// 8-byte `{dst, size}` zero pairs (`__zero_table_start__`).
    CmsisZeroTable,
    /// 16-byte `{src, dst, size, handler}` records with a per-record handler.
    ScatterLoad,
    #[default]
    Unknown,
}

impl InitTableFormat {
    /// Record stride in bytes for this table format.
    pub fn stride(self) -> u32 {
        match self {
            InitTableFormat::CmsisCopyTable => 12,
            InitTableFormat::CmsisZeroTable => 8,
            InitTableFormat::ScatterLoad => 16,
            InitTableFormat::Unknown => 0,
        }
    }
}

/// Classification of the per-record handler function referenced by a
/// scatter-load descriptor, or implied by the table a CMSIS record lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum InitHandlerKind {
    /// Word-granular copy loop (`__aeabi_copy4` / `__scatterload_copy`).
    WordCopy,
    /// Zero-fill loop (`__aeabi_memclr` / `__scatterload_zeroinit`).
    ZeroInit,
    /// LZ-style decompressing loader: a control-byte codec that expands a
    /// packed `.data` image out of flash instead of copying it.
    Decompress,
    /// Recognisable load/store loop that is neither a word copy nor a
    /// zero fill (for example a byte-granular loop).
    Custom,
    #[default]
    Unknown,
}

/// One `{src, dst, size}` (+ optional handler) descriptor record.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct InitRecord {
    pub index: usize,
    /// Index into [`InitTableReport::segments`] of the table this record came from.
    pub segment_index: usize,
    /// MCU address of the record itself.
    pub record_address: u32,
    /// Flash source address, or `None` for zero-init records.
    pub src: Option<u32>,
    /// RAM destination address.
    pub dst: u32,
    pub size: u32,
    /// Handler function address with the Thumb bit cleared, when the format
    /// carries one.
    pub handler: Option<u32>,
    #[serde(default)]
    pub handler_kind: InitHandlerKind,
    /// Why the handler was classified the way it was. `None` for CMSIS
    /// records, whose semantics come from the table they live in rather than
    /// from a handler body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_classification: Option<InitHandlerClassification>,
}

/// One contiguous descriptor table recovered from a startup function.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InitTableSegment {
    pub index: usize,
    #[serde(default)]
    pub format: InitTableFormat,
    pub base_address: u32,
    pub end_address: u32,
    pub record_stride: u32,
    pub record_count: usize,
    /// Address of the startup function whose literal pool carried the bounds.
    pub source_function: u32,
    /// Whether the record stride was also observed in that function's
    /// instruction stream (`adds rN, #stride` or a post-indexed load).
    pub stride_observed: bool,
}

/// Recovered startup init-descriptor tables and the static memory layout they
/// describe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InitTableReport {
    /// Lowest table base address across all recovered segments.
    pub base_address: u32,
    /// Highest table end address across all recovered segments.
    pub end_address: u32,
    /// Record stride of the primary (largest) segment.
    pub record_stride: u32,
    /// Format of the primary (largest) segment.
    #[serde(default)]
    pub format: InitTableFormat,
    #[serde(default)]
    pub segments: Vec<InitTableSegment>,
    #[serde(default)]
    pub records: Vec<InitRecord>,
    /// Sum of all record sizes.
    pub total_dst_coverage: u64,
    /// Highest `dst + size` across all records.
    pub max_dst_end: u32,
    /// Initial stack pointer taken from vector word 0, when available.
    pub initial_sp: Option<u32>,
    /// `max_dst_end == initial_sp`: on classic CubeIDE/CMSIS layouts the
    /// linker places the stack immediately above `.bss`, so this is a strong
    /// (but not required) correctness check on the parse.
    pub matches_initial_sp: bool,
    /// Toolchain hint derived from how `.data` is initialised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain_fingerprint: Option<ToolchainFingerprint>,
    pub provenance: Option<SectionProvenance>,
    pub confidence: f32,
}

/// A single observation supporting an [`InitHandlerClassification`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandlerEvidenceKind {
    /// A control byte split into a literal count and a match count.
    ControlByteSplit { literal_bits: u8, match_bits: u8 },
    /// A count field that reads zero is re-read from the next byte.
    ExtendedCountFallback,
    /// A byte-granular copy loop feeding the output from the input stream.
    LiteralCopyLoop,
    /// A byte-granular copy loop feeding the output from itself.
    BackReferenceLoop,
    /// A word-granular load/store loop.
    WordCopyLoop,
    /// A store loop with no load and a zero constant in scope.
    ZeroInitLoop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerEvidence {
    pub kind: HandlerEvidenceKind,
    pub description: String,
    pub instruction_addr: u32,
}

/// The compression scheme a decompressing handler implements.
///
/// Deliberately shape-level rather than vendor-level: the control-byte split
/// is what static analysis can actually establish, and several vendors' packed
/// copy runtimes share a split. Vendor guesses belong in
/// [`ToolchainFingerprint::consistent_with`], which is labelled as a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompressorVariant {
    /// LZ77/LZSS control-byte codec with the observed field widths.
    Lzss { literal_bits: u8, match_bits: u8 },
    /// A decompressing shape whose control-byte split could not be recovered.
    UnclassifiedLz,
}

/// Why a per-record handler was classified the way it was.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InitHandlerClassification {
    #[serde(default)]
    pub kind: InitHandlerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressor: Option<CompressorVariant>,
    #[serde(default)]
    pub evidence: Vec<HandlerEvidence>,
    pub confidence: f32,
}

/// Toolchain hint derived from how a firmware initialises `.data`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ToolchainFingerprint {
    /// The compressor found on a `.data` record, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_compression: Option<CompressorVariant>,
    /// Toolchains whose packed-copy runtime is known to use this shape. A
    /// shape match narrows the candidates; it does not identify the vendor.
    #[serde(default)]
    pub consistent_with: Vec<String>,
    pub confidence: f32,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ExecutionModelKind {
    Superloop,
    Rtos,
    IsrDriven,
    Mixed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SharedAccessPattern {
    PollingFlag,
    RingBuffer,
    SharedCounter,
    SharedBuffer,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SharedStateEdge {
    pub irq_handler: u32,
    pub consumer: u32,
    pub variable: Option<String>,
    pub producer_label: Option<String>,
    pub consumer_label: Option<String>,
    #[serde(default)]
    pub access_pattern: SharedAccessPattern,
    pub touches_flash_or_update: bool,
    pub touches_actuation: bool,
    pub touches_comms: bool,
    pub touches_watchdog: bool,
    pub touches_dma: bool,
    pub touches_safety: bool,
    pub confidence: f32,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExecutionModelReport {
    #[serde(default)]
    pub model: Interpretation<ExecutionModelKind>,
    #[serde(default)]
    pub loop_heads: Vec<u32>,
    #[serde(default)]
    pub scheduler_candidates: Vec<u32>,
    #[serde(default)]
    pub task_spawn_sites: Vec<u32>,
    #[serde(default)]
    pub isr_shared_state_edges: Vec<SharedStateEdge>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
    #[serde(default)]
    pub supporting_evidence: Vec<ExecutionModelEvidence>,
    #[serde(default)]
    pub anti_evidence: Vec<ExecutionModelEvidence>,
    #[serde(default)]
    pub metrics: ExecutionModelMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceHeuristicKind {
    RtosMarkerAbsent {
        family: String,
    },
    RtosMarkerPresent {
        family: String,
        symbol: String,
    },
    SysTickHandlerDefault,
    SysTickHandlerCustom,
    NonDefaultVectorDensity {
        non_default: u32,
        total: u32,
    },
    /// Degradation marker only: emitted when the Main startup step is
    /// unavailable and the Main-CFG dominating-loop heuristic
    /// cannot be evaluated.
    MainDominatingLoopUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionModelEvidence {
    pub kind: EvidenceHeuristicKind,
    pub description: String,
    pub artifact_ref: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExecutionModelMetrics {
    #[serde(default)]
    pub loop_heads_total: u32,
    #[serde(default)]
    pub non_default_irq_handlers: u32,
    #[serde(default)]
    pub vector_table_entries: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum PeripheralRole {
    UpdateTransport,
    FlashWritePath,
    Actuation,
    SafetyCriticalSensor,
    Cryptography,
    Identity,
    Watchdog,
    CommsBridge,
    HostSidecarLink,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum PeripheralEvidenceSource {
    Mmio,
    Irq,
    String,
    Mixed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PeripheralUse {
    pub family: Option<String>,
    pub peripheral_name: String,
    pub base: u64,
    #[serde(default)]
    pub roles: Vec<PeripheralRole>,
    #[serde(default)]
    pub source: PeripheralEvidenceSource,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PeripheralMapReport {
    #[serde(default)]
    pub uses: Vec<PeripheralUse>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum PeripheralConfigKind {
    Uart,
    I2c,
    Spi,
    Timer,
    Watchdog,
    Flash,
    Crc,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RegisterBlockObservation {
    pub family: Option<String>,
    pub peripheral_name: String,
    pub base: u64,
    #[serde(default)]
    pub observed_registers: Vec<String>,
    #[serde(default)]
    pub sample_offsets: Vec<u64>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RecoveredConfigField {
    pub name: String,
    pub value: String,
    pub normalized: Option<String>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RecoveredPeripheralConfig {
    pub peripheral_name: String,
    #[serde(default)]
    pub kind: PeripheralConfigKind,
    pub summary: String,
    #[serde(default)]
    pub fields: Vec<RecoveredConfigField>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PeripheralSurfaceReport {
    #[serde(default)]
    pub register_blocks: Vec<RegisterBlockObservation>,
    #[serde(default)]
    pub recovered_configs: Vec<RecoveredPeripheralConfig>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SecuritySurfaceSummary {
    #[serde(default)]
    pub update_surface: Vec<String>,
    #[serde(default)]
    pub flash_surface: Vec<String>,
    #[serde(default)]
    pub actuation_surface: Vec<String>,
    #[serde(default)]
    pub comms_surface: Vec<String>,
    #[serde(default)]
    pub debug_surface: Vec<String>,
    #[serde(default)]
    pub crypto_surface: Vec<String>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct IntegrityCheckReport {
    pub description: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AuthenticityMechanismReport {
    pub description: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RollbackResistanceReport {
    pub description: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct WriteAuthorityReport {
    pub description: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SharedStateRiskTag {
    Update,
    FlashWrite,
    Actuation,
    Safety,
    Watchdog,
    #[default]
    HostComms,
    NetworkIngress,
    Dma,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SharedStateFinding {
    pub title: String,
    #[serde(default)]
    pub tags: Vec<SharedStateRiskTag>,
    pub confidence: f32,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SharedStateRiskReport {
    #[serde(default)]
    pub edges: Vec<SharedStateEdge>,
    #[serde(default)]
    pub ranked_findings: Vec<SharedStateFinding>,
    #[serde(default)]
    pub degradation_notes: Vec<InspectionDegradation>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct UpdatePathReport {
    pub path_id: String,
    pub source_artifact: String,
    pub target_artifact: String,
    pub transport: String,
    pub mechanism: String,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct TrustChainReport {
    pub source_artifact: String,
    pub source_role: String,
    pub target_artifact: String,
    pub operation: String,
    pub trust_check: Option<String>,
    pub rollback_check: Option<String>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MainEntryReport {
    pub entrypoint: Interpretation<u32>,
    pub provenance: Option<SectionProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct McuProfile {
    pub architecture: String,
    pub chip_family: String,
    pub chip_family_confidence: u8, // 0-100
    pub initial_sp: u32,
    pub reset_vector: u32,
    pub flash_base: u32,
    /// Legacy field name: populated handler pointers, including Reset, not activity.
    pub active_interrupt_count: usize,
    pub total_interrupt_slots: usize,
    pub code_size: Option<u64>,
    pub total_size: u64,
    pub padding_percent: Option<u8>,
    pub is_power_of_two_size: bool,
    pub detected_sdk: Option<String>,
    pub detected_rtos: Option<String>,
    #[serde(default)]
    pub detected_stacks: Vec<String>,
    #[serde(default)]
    pub peripheral_hints: Vec<String>,
}

/// Half-open `[start, end)` MCU address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u32,
    pub end: u32,
}

impl AddressRange {
    pub fn new(start: u32, end: u32) -> Self {
        Self {
            start,
            end: end.max(start),
        }
    }

    /// Length in bytes. `u64` because a full 4 GiB range does not fit `u32`.
    pub fn len(&self) -> u64 {
        u64::from(self.end.saturating_sub(self.start))
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn contains(&self, address: u32) -> bool {
        (self.start..self.end).contains(&address)
    }
}

/// What pinned the top of the linker-managed part of an SRAM region.
///
/// The two independent anchors are the init-descriptor table (`.data` + `.bss`
/// destinations) and the initial stack pointer (which sits above the stack
/// reserve). When both are available the cap is the higher of the two, because
/// the stack reserve between `.bss` and the initial SP is linker-managed too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum LinkerCapBasis {
    /// Both the descriptor table and the initial SP land in this region.
    InitTableAndStackPointer,
    /// Only descriptor-table destinations land in this region.
    InitTable,
    /// Only the initial SP lands in this region.
    StackPointer,
    /// Nothing observed claims any of this region.
    #[default]
    NoEvidence,
}

/// A 32-bit literal in the image whose value points into a runtime-managed
/// SRAM window: a candidate DMA descriptor or pool base address.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuntimeLiteralRef {
    /// The referenced RAM address.
    pub target: u32,
    /// Image addresses of the words holding this value.
    pub referenced_from: Vec<u32>,
    /// Largest power-of-two `target` is aligned to, capped at 32. Descriptor
    /// rings and DMA pools are usually cache-line (32-byte) aligned, so a
    /// higher value ranks a candidate up; every reported candidate is at
    /// least word-aligned.
    pub alignment: u32,
}

/// Whether anything other than the CPU can write a memory region.
///
/// This is derived from peripheral *names* recovered by the peripheral map,
/// not from a bus-matrix model, so it says "a DMA-capable master was detected
/// in this image", not "that master is wired to this region".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ThreatModelHint {
    /// DMA-capable masters were detected in the image.
    DmaReachable { masters: Vec<String> },
    /// A peripheral map was available and held no DMA-capable master.
    CpuOnly,
    /// No peripheral map was available.
    #[default]
    Unknown,
}

/// One SRAM region split into its linker-managed and runtime-managed halves.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SramRegionPartition {
    pub region: MemoryRegion,
    /// `[region.start, cap)`: `.data` + `.bss` + stack reserve.
    pub linker_managed: AddressRange,
    /// `[cap, region.end)`: not claimed by anything static in the image.
    pub runtime_managed: AddressRange,
    pub linker_bytes: u64,
    pub runtime_bytes: u64,
    #[serde(default)]
    pub linker_cap_basis: LinkerCapBasis,
    /// Candidate pool/descriptor bases, word-aligned first, capped.
    #[serde(default)]
    pub runtime_literal_references: Vec<RuntimeLiteralRef>,
    /// How many distinct targets were found before the report cap was applied.
    #[serde(default)]
    pub runtime_literal_total: usize,
    pub threat_model_hint: Option<ThreatModelHint>,
}

/// SRAM split into linker-managed and runtime-managed windows.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SramPartitionReport {
    #[serde(default)]
    pub sram_regions: Vec<SramRegionPartition>,
    pub provenance: Option<SectionProvenance>,
}

/// Whether `SystemInit` turned the FPU on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum FpuStatus {
    /// `CPACR.CP10` and `CPACR.CP11` both driven to full access (`0b11`).
    Enabled,
    /// `CPACR` written with those fields driven to zero.
    Disabled,
    /// `CPACR` never written, or written with a value that could not be
    /// resolved statically.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ClockEffectKind {
    HsiEnable,
    HsiDisable,
    HseEnable,
    HseBypassClear,
    PllConfigure,
    PllEnable,
    SysclkSwitch,
    /// A write to the clock controller whose register is known but whose
    /// meaning this build does not model.
    #[default]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClockEffect {
    #[serde(default)]
    pub kind: ClockEffectKind,
    pub register_offset: u32,
    pub evidence_addr: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum CacheEffectKind {
    ICacheEnable,
    DCacheEnable,
    /// An invalidate or clean operation on a cache maintenance register.
    CacheMaintenance,
    #[default]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CacheEffect {
    #[serde(default)]
    pub kind: CacheEffectKind,
    pub evidence_addr: u32,
}

/// A comparison against a memory-base constant, the usual shape of "did a
/// bootloader already relocate the vector table?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VtorCheckEvidence {
    pub sentinel_value: u32,
    pub instruction_addr: u32,
}

/// A write to `SCB->VTOR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VtorWriteEvidence {
    /// The written value, when it resolved statically.
    pub value: Option<u32>,
    pub instruction_addr: u32,
}

/// A store to a peripheral register that matched no known category. Preserved
/// rather than dropped: an unmodelled write is a lead, not noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PeripheralWriteRecord {
    pub target: u32,
    pub value: Option<u32>,
    pub at: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SystemInitEvidence {
    pub label: String,
    pub detail: String,
    pub instruction_addr: u32,
}

/// What the `SystemInit` step left the hardware in before `main` ran.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SystemInitEffectsReport {
    pub function_address: u32,
    /// Bytes decoded before the function terminated or the window ran out.
    pub function_size: u32,
    #[serde(default)]
    pub fpu: FpuStatus,
    /// `FLASH_ACR.LATENCY` in wait states.
    pub flash_latency: Option<u32>,
    #[serde(default)]
    pub clock_effects: Vec<ClockEffect>,
    #[serde(default)]
    pub cache_effects: Vec<CacheEffect>,
    pub vtor_relocation_check: Option<VtorCheckEvidence>,
    pub vtor_write: Option<VtorWriteEvidence>,
    #[serde(default)]
    pub mpu_configured: bool,
    pub art_accel: Option<bool>,
    #[serde(default)]
    pub unclassified_writes: Vec<PeripheralWriteRecord>,
    #[serde(default)]
    pub evidence: Vec<SystemInitEvidence>,
    /// Categories this analysis looked for and did not find, so a reader can
    /// tell "absent" from "not checked".
    #[serde(default)]
    pub not_observed: Vec<String>,
    pub confidence: f32,
    pub provenance: Option<SectionProvenance>,
}
