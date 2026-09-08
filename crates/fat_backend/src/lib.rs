pub mod driver;
pub mod emux;
pub mod managed_linux_vm;
pub mod model;
pub mod native_host;
pub mod qemu_direct;
pub mod service_user_mode;
pub mod substrate;
pub mod traits;

pub use driver::{BackendDriverContract, BackendDriverPhase};
pub use model::{
    logical_substrate_for_backend, logical_substrates_for_backend_id, BackendAvailability,
    BackendRegistry, BackendScore, CommandProbe, PathCommandProbe,
};
pub use substrate::{
    BackendLogicalSubstrateContract, BackendSubstrateAdapter, BackendSubstrateCapability,
    BackendSubstrateContract, BackendSubstrateHealth, BackendSubstrateKind,
    BackendSubstratePrecondition, BackendSubstrateStatus,
};
pub use traits::{Backend, BackendAdapterMetadata, BackendCapability, BackendKind, FamilyMatch};
