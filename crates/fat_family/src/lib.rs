pub mod classifier;
pub mod discovery_specs;
pub mod mcu_packs;
pub mod model;
pub mod runtime_hints;

pub use classifier::classify;
pub use discovery_specs::{discovery_family_spec, discovery_family_specs};
pub use mcu_packs::{
    resolve_mcu_pack, IrqLabel, McuFamilyPack, MemoryRange, MmioRange, PeripheralRole,
    PeripheralRoleHint,
};
pub use model::{
    DiscoveryFamilySpec, LocalityPolicy, ProofClass, RequiredRoleGroup, Suppressor,
    TargetPreference, TriggerTemplate,
};
pub use model::{FamilyEvidence, FamilyGuess, FamilyTraits};
pub use runtime_hints::{
    runtime_hints_for_family, RuntimeHintAction, RuntimeHintActionKind, RuntimeHints,
};
