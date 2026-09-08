pub mod bootloader_image;
pub mod bootplan;
pub mod compatibility;
pub mod discovery;
pub mod env;
pub mod profile;
pub mod project;
pub mod qemu;

pub use bootloader_image::{BootChainPlan, BootloaderCompatibility, BootloaderImage};
pub use bootplan::{BootArtifact, BootArtifactSet, BootExecutionResult, BootPlan};
pub use compatibility::evaluate_true_boot_chain;
pub use discovery::{discover_boot_artifacts, BootArtifactDiscovery};
pub use env::render_env;
pub use profile::{
    load_profile, load_profile_with_resolver, BootloaderProfile, BootloaderProfileError,
};
pub use project::{materialize_workspace, BootloaderWorkspace, BootloaderWorkspaceManifest};
pub use qemu::{
    assist_boot, classify_serial_output, inspect_tmux_session, launch_in_tmux,
    list_managed_tmux_sessions, prepare_launch, stop_all_tmux_sessions, stop_tmux_session,
    BootAssistResult, BootloaderQemuError, BootloaderQemuLaunch, BootloaderSessionStatus,
    BootloaderStopOutcome, DEFAULT_TMUX_SESSION_PREFIX,
};
