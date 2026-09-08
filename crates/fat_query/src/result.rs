use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathKind {
    ArgFlowProven,
    ReturnFlowProven,
    BufferFlowProven,
    ControlReachable,
    ConstantSinkArg,
    CallgraphOnly,
    Blocked,
    NoPath,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResult {
    pub path_kind: PathKind,
    pub connected: bool,
    pub trace: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantSiteResult {
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantResult {
    pub rule: String,
    pub satisfying: Vec<InvariantSiteResult>,
    pub violating: Vec<InvariantSiteResult>,
    pub unknown: Vec<InvariantSiteResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_plan: Option<crate::planner::SourceAnalysisPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_analysis: Option<SourceAnalysisSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fused_source: Option<FusedSourceEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<DerivedAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slice_expansion: Option<crate::slice_expander::SliceExpansionReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<RollResolution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_leads: Option<Vec<VariantLead>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_leads: Option<Vec<crate::discovery::DiscoveryLead>>,
}

impl InvariantResult {
    pub fn new(rule: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            satisfying: Vec::new(),
            violating: Vec::new(),
            unknown: Vec::new(),
            source_plan: None,
            source_analysis: None,
            fused_source: None,
            derived: None,
            slice_expansion: None,
            locality: None,
            replay: None,
            variant_leads: None,
            discovery_leads: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainQueryResult {
    pub goal: String,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VisibilityStatus {
    Present,
    Absent,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseStatus {
    Parsed,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalityStatus {
    RepoLocal,
    VendoredLocal,
    Generated,
    UpstreamReferenced,
    UpstreamHidden,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceSource {
    Direct,
    Indirect,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdequacyIntent {
    ReplaySiting,
    VariantHunting,
    Proof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdequacyTier {
    ReplaySitingAdequate,
    VariantHuntingAdequate,
    ProofInadequate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdequacyForQuery {
    pub family: String,
    pub intent: AdequacyIntent,
    pub tier: AdequacyTier,
    #[serde(default)]
    pub required_facts_satisfied: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterDiagnostics {
    pub visibility: VisibilityStatus,
    pub parse: ParseStatus,
    pub locality: LocalityStatus,
    pub confidence_source: ConfidenceSource,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
    #[serde(default)]
    pub adequacy: Vec<AdequacyForQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceBackendKind {
    AstDumpJson,
    LibclangBackend,
    TextScan,
    SyntheticSliceRepair,
}

impl SourceBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceBackendKind::AstDumpJson => "AstDumpJson",
            SourceBackendKind::LibclangBackend => "LibclangBackend",
            SourceBackendKind::TextScan => "TextScan",
            SourceBackendKind::SyntheticSliceRepair => "SyntheticSliceRepair",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceBasis {
    ObservedFromAstFacts,
    InferredFromLocalStructure,
    InferredFromRepairedSlice,
    InferredFromRollMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMethodFact {
    pub qualified_name: String,
    pub signature_hash: String,
    pub file: PathBuf,
    pub line: u32,
    pub begin_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCallFact {
    pub callee_name: String,
    pub enclosing_symbol: String,
    pub file: PathBuf,
    pub line: u32,
    pub basis: EvidenceBasis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreTrace {
    #[serde(default)]
    pub adapters: Vec<String>,
    #[serde(default)]
    pub family_pack_hits: Vec<String>,
    #[serde(default)]
    pub penalties: Vec<String>,
    #[serde(default)]
    pub locality_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEvidenceReport {
    pub adapter_id: String,
    pub backend: SourceBackendKind,
    pub backend_version: String,
    pub tu_file: PathBuf,
    pub tu_spec_hash: String,
    pub toolchain_profile_hash: String,
    pub diagnostics: AdapterDiagnostics,
    #[serde(default)]
    pub methods: Vec<SourceMethodFact>,
    #[serde(default)]
    pub calls: Vec<SourceCallFact>,
    pub score_trace: ScoreTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAnalysisSummary {
    #[serde(default)]
    pub reports: Vec<SourceEvidenceReport>,
    #[serde(default)]
    pub merged_observed: Vec<String>,
    #[serde(default)]
    pub merged_inferred: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<SourceFactCacheTelemetry>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceFactCacheStatus {
    FreshWrite,
    ReusedCachedReports,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFactCacheTelemetry {
    pub cache_key: String,
    pub status: SourceFactCacheStatus,
    pub cache_path: Option<PathBuf>,
    pub report_count: usize,
    #[serde(default)]
    pub backend_kinds: Vec<String>,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FamilyPack {
    LifetimeOwnership,
    BoundsSizeArithmetic,
    GpuProtocolLifecycle,
    ValidationPolicy,
    DependencyRollUpstreamHidden,
    SourceVisibility,
}

impl FamilyPack {
    pub fn as_str(&self) -> &'static str {
        match self {
            FamilyPack::LifetimeOwnership => "lifetime-ownership",
            FamilyPack::BoundsSizeArithmetic => "bounds-size-arithmetic",
            FamilyPack::GpuProtocolLifecycle => "gpu-protocol-order-lifecycle",
            FamilyPack::ValidationPolicy => "validation-policy",
            FamilyPack::DependencyRollUpstreamHidden => "dependency-roll-upstream-hidden",
            FamilyPack::SourceVisibility => "source-visibility",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedFact {
    pub family_pack: FamilyPack,
    pub kind: String,
    pub subject: String,
    /// Source file this fact was derived from. Used to disambiguate
    /// same-named functions in different translation units.
    #[serde(default)]
    pub source_file: Option<PathBuf>,
    pub evidence_basis: EvidenceBasis,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DerivedAnalysis {
    #[serde(default)]
    pub facts: Vec<DerivedFact>,
    #[serde(default)]
    pub family_scores: BTreeMap<String, usize>,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FusedSourceEvidence {
    #[serde(default)]
    pub methods: Vec<SourceMethodFact>,
    #[serde(default)]
    pub calls: Vec<SourceCallFact>,
    #[serde(default)]
    pub adapters: Vec<String>,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayRole {
    AllocationSize,
    CopySize,
    PitchStrideDepth,
    ProtocolOrdering,
    AsyncLifecycle,
    GuardValidation,
    PermissionOverride,
    CallbackTeardown,
    PostHandoffObservation,
    Truncation,
}

impl ReplayRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplayRole::AllocationSize => "allocation-size",
            ReplayRole::CopySize => "copy-size",
            ReplayRole::PitchStrideDepth => "pitch-stride-depth",
            ReplayRole::ProtocolOrdering => "protocol-ordering",
            ReplayRole::AsyncLifecycle => "async-lifecycle",
            ReplayRole::GuardValidation => "guard-validation",
            ReplayRole::PermissionOverride => "permission-override",
            ReplayRole::CallbackTeardown => "callback-teardown",
            ReplayRole::PostHandoffObservation => "post-handoff-observation",
            ReplayRole::Truncation => "truncation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCandidate {
    pub symbol: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub score: i32,
    #[serde(default)]
    pub matched_roles: Vec<ReplayRole>,
    #[serde(default)]
    pub missing_roles: Vec<ReplayRole>,
    #[serde(default)]
    pub family_pack_hits: Vec<String>,
    pub score_trace: ScoreTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBenchmarkStageMetrics {
    pub positive_cases: usize,
    pub negative_cases: usize,
    pub top1: f64,
    pub top3: f64,
    pub precision_at_3: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplayAnalysis {
    #[serde(default)]
    pub reference_symbols: Vec<String>,
    #[serde(default)]
    pub required_roles: Vec<ReplayRole>,
    #[serde(default)]
    pub candidates: Vec<ReplayCandidate>,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollResolution {
    pub locality: LocalityStatus,
    #[serde(default)]
    pub likely_upstream_repo: Option<String>,
    #[serde(default)]
    pub vendored_nearby_path: Option<PathBuf>,
    pub local_patch_touching_vendored_code: bool,
    pub no_local_vulnerable_source_likely: bool,
    pub allow_vendored_scan: bool,
    #[serde(default)]
    pub observed: Vec<String>,
    #[serde(default)]
    pub inferred: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantLead {
    pub symbol: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub fingerprint: String,
    pub score: i32,
    #[serde(default)]
    pub family_pack_hits: Vec<String>,
    pub score_trace: ScoreTrace,
}
