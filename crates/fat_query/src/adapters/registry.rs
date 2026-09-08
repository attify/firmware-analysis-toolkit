use super::traits::{
    AdapterDescriptor, AdapterFamily, ExecutionMode, QueryKind, QueryRequest, SourceLanguageFamily,
};
use crate::target_detection::{DetectedTarget, TargetKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterPlan {
    pub target_kind: TargetKind,
    pub query_kind: QueryKind,
    pub adapter_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdapterRegistry {
    descriptors: Vec<AdapterDescriptor>,
}

impl AdapterRegistry {
    pub fn new(descriptors: Vec<AdapterDescriptor>) -> Self {
        Self { descriptors }
    }

    pub fn descriptors(&self) -> &[AdapterDescriptor] {
        &self.descriptors
    }

    pub fn plan(
        &self,
        target: &DetectedTarget,
        query: &QueryRequest,
    ) -> Result<AdapterPlan, String> {
        let mut candidates = self
            .descriptors
            .iter()
            .filter(|descriptor| descriptor.supports(&target.kind, &query.kind))
            .collect::<Vec<_>>();

        candidates.sort_by_key(|descriptor| descriptor.confidence_rank);

        if candidates.is_empty() {
            return Err(format!(
                "no adapters support target {:?} for query {:?}",
                target.kind, query.kind
            ));
        }

        Ok(AdapterPlan {
            target_kind: target.kind.clone(),
            query_kind: query.kind.clone(),
            adapter_ids: candidates
                .into_iter()
                .map(|descriptor| descriptor.id.to_string())
                .collect(),
        })
    }
}

pub fn default_registry() -> AdapterRegistry {
    AdapterRegistry::new(vec![
        AdapterDescriptor {
            id: "elf-angr",
            family: AdapterFamily::BinaryFlow,
            target_kinds: vec![TargetKind::ElfBinary],
            query_kinds: vec![QueryKind::Path, QueryKind::Slice],
            confidence_rank: 0,
            supported_extensions: vec!["elf"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage, ExecutionMode::Deep],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "raw-blob-angr",
            family: AdapterFamily::BinaryFlow,
            target_kinds: vec![TargetKind::RawBlob],
            query_kinds: vec![QueryKind::Path, QueryKind::Slice],
            confidence_rank: 0,
            supported_extensions: vec!["bin"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage, ExecutionMode::Deep],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "elf-r2",
            family: AdapterFamily::BinaryStructural,
            target_kinds: vec![TargetKind::ElfBinary],
            query_kinds: vec![
                QueryKind::LauncherClassification,
                QueryKind::HandoffInspection,
                QueryKind::RoleDiff,
            ],
            confidence_rank: 1,
            supported_extensions: vec!["elf"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "macho-r2",
            family: AdapterFamily::BinaryStructural,
            target_kinds: vec![TargetKind::MachOBinary],
            query_kinds: vec![
                QueryKind::LauncherClassification,
                QueryKind::HandoffInspection,
                QueryKind::RoleDiff,
            ],
            confidence_rank: 0,
            supported_extensions: vec!["macho"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "apple-bundle",
            family: AdapterFamily::BundleMetadata,
            target_kinds: vec![TargetKind::MachOBinary],
            query_kinds: vec![QueryKind::BundleReality, QueryKind::HandoffInspection],
            confidence_rank: 0,
            supported_extensions: vec!["macho"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "apple-dyld-plane",
            family: AdapterFamily::RuntimePlane,
            target_kinds: vec![TargetKind::MachOBinary, TargetKind::Rootfs],
            query_kinds: vec![QueryKind::RuntimePlane, QueryKind::RoleDiff],
            confidence_rank: 0,
            supported_extensions: vec!["macho"],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "source-text-scan",
            family: AdapterFamily::Source,
            target_kinds: vec![TargetKind::SourceTree, TargetKind::CodeQlDatabase],
            query_kinds: vec![QueryKind::Invariant, QueryKind::PatchInvariant],
            confidence_rank: 0,
            supported_extensions: vec!["c", "cc", "cpp", "cxx", "m", "mm", "h", "hpp", "rs", "py"],
            language_families: vec![
                SourceLanguageFamily::CLike,
                SourceLanguageFamily::ObjectiveC,
                SourceLanguageFamily::ObjectiveCpp,
                SourceLanguageFamily::Rust,
                SourceLanguageFamily::Python,
            ],
            modes: vec![ExecutionMode::Triage, ExecutionMode::Deep],
            authoritative: false,
        },
        AdapterDescriptor {
            id: "source-tree-sitter-c",
            family: AdapterFamily::Source,
            target_kinds: vec![TargetKind::SourceTree],
            query_kinds: vec![QueryKind::Invariant, QueryKind::PatchInvariant],
            confidence_rank: 0,
            supported_extensions: vec!["c", "cc", "cpp", "cxx", "m", "mm", "h", "hpp", "rs"],
            language_families: vec![
                SourceLanguageFamily::CLike,
                SourceLanguageFamily::ObjectiveC,
                SourceLanguageFamily::ObjectiveCpp,
                SourceLanguageFamily::Rust,
            ],
            modes: vec![ExecutionMode::Triage],
            authoritative: false,
        },
        AdapterDescriptor {
            id: "source-clang-facts",
            family: AdapterFamily::Source,
            target_kinds: vec![TargetKind::SourceTree, TargetKind::CodeQlDatabase],
            query_kinds: vec![QueryKind::Invariant, QueryKind::PatchInvariant],
            confidence_rank: 1,
            supported_extensions: vec!["c", "cc", "cpp", "cxx", "m", "mm", "h", "hpp"],
            language_families: vec![
                SourceLanguageFamily::CLike,
                SourceLanguageFamily::ObjectiveC,
                SourceLanguageFamily::ObjectiveCpp,
            ],
            modes: vec![ExecutionMode::Triage, ExecutionMode::Deep],
            authoritative: true,
        },
        AdapterDescriptor {
            id: "runtime-observer",
            family: AdapterFamily::RuntimeObservation,
            target_kinds: vec![TargetKind::RuntimeSession],
            query_kinds: vec![QueryKind::RuntimeVerify],
            confidence_rank: 0,
            supported_extensions: vec![],
            language_families: vec![],
            modes: vec![ExecutionMode::Triage, ExecutionMode::Deep],
            authoritative: true,
        },
    ])
}
