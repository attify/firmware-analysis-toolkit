pub mod clean;
pub mod cluster;
pub mod decompile;
pub mod resolve;

use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum NormalizerError {
    #[error("decompile error: {0}")]
    Decompile(#[from] decompile::DecompileError),
    #[error("resolve error: {0}")]
    Resolve(#[from] resolve::ResolveError),
    #[error("clean error: {0}")]
    Clean(#[from] clean::CleanError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Output of the normalizer stage: a prepared source tree for one cluster.
pub struct NormalizedCluster {
    pub cluster: cluster::Cluster,
    pub source_dir: PathBuf,
    pub symbol_map: resolve::SymbolMap,
    pub decompiled_files: Vec<PathBuf>,
}

/// Run the full normalizer pipeline for a single cluster.
pub fn normalize_cluster(
    cluster: &cluster::Cluster,
    output_root: &Path,
    ghidra_home: Option<&Path>,
) -> Result<NormalizedCluster, NormalizerError> {
    let cluster_dir = output_root.join(&cluster.name);
    let source_dir = cluster_dir.join("source");
    std::fs::create_dir_all(&source_dir)?;

    // 1. Build symbol map for this cluster's binaries
    let all_binaries: Vec<PathBuf> = cluster
        .all_binaries()
        .iter()
        .map(|p| p.to_path_buf())
        .collect();
    let symbol_map = resolve::SymbolMap::build(&all_binaries)?;

    info!(
        cluster = %cluster.name,
        binaries = all_binaries.len(),
        exports = symbol_map.exports.len(),
        "Symbol map built"
    );

    // 2. Decompile all binaries in the cluster
    let decompile_config = if let Some(home) = ghidra_home {
        decompile::DecompileConfig {
            ghidra_home: home.to_path_buf(),
            export_script: home.join("fat_scripts/ExportDecompiledC.java"),
            output_dir: source_dir.clone(),
        }
    } else {
        decompile::DecompileConfig::auto_detect(source_dir.clone())?
    };

    let binary_refs: Vec<&Path> = cluster.all_binaries();
    let decompiled_files = decompile::decompile_cluster(&binary_refs, &decompile_config)?;

    info!(
        cluster = %cluster.name,
        files = decompiled_files.len(),
        "Decompilation complete"
    );

    // 3. Clean all decompiled C files
    let cleaned = clean::clean_all(&source_dir)?;
    info!(cluster = %cluster.name, cleaned, "Cleaned decompiled C");

    Ok(NormalizedCluster {
        cluster: cluster.clone(),
        source_dir,
        symbol_map,
        decompiled_files,
    })
}
