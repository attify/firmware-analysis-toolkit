//! fat_taint — Binary and shell taint analysis with shared finding types.
//!
//! The CLI uses angr for binary analysis and shell AST tracking for shell scripts.
//! Normalizer and Joern CPG helpers support decompiled-source analysis.

pub mod cache;
pub mod finding;
pub mod normalizer;
pub mod profile;
pub mod proof;
pub mod query;
pub mod recon;
pub mod shared_state_families;
pub mod shell_profile;
pub mod shell_scan;
pub mod shell_taint;
pub mod sink_discovery;

pub use finding::{ChainStep, EdgeType, FindingStatus, SourceClass, TaintFinding};
pub use normalizer::cluster::Cluster;
pub use recon::source_map::{
    analyze_rootfs as analyze_source_map_rootfs, BackendCandidate, FrontendSurface,
    ParameterConstraint, SourceHint, SourceMapParameter, SourceMapReport,
};
