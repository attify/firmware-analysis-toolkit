//! Reachability clusters — the primary execution unit.
//!
//! A cluster is: 1 CGI binary + the transitive closure of its imported shared libraries.
//! Each cluster becomes one Joern CPG.

use super::resolve::SymbolMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// The entry-point binary (e.g., quick.cgi)
    pub entry: PathBuf,
    /// All libraries this binary transitively depends on
    pub libraries: Vec<PathBuf>,
    /// Human-readable name derived from the entry binary
    pub name: String,
}

impl Cluster {
    /// Build a cluster for a single CGI binary by resolving its transitive library dependencies.
    pub fn build(entry: &Path, symbol_map: &SymbolMap) -> Self {
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let mut queue: Vec<PathBuf> = vec![entry.to_path_buf()];

        while let Some(current) = queue.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            for dep in symbol_map.dependencies_of(&current) {
                if !visited.contains(&dep) {
                    queue.push(dep);
                }
            }
        }

        // Remove the entry binary itself from the library set
        visited.remove(entry);

        let name = entry
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let mut libraries: Vec<PathBuf> = visited.into_iter().collect();
        libraries.sort();

        Cluster {
            entry: entry.to_path_buf(),
            libraries,
            name,
        }
    }

    /// All binaries in this cluster (entry + libraries).
    pub fn all_binaries(&self) -> Vec<&Path> {
        let mut bins: Vec<&Path> = vec![self.entry.as_path()];
        bins.extend(self.libraries.iter().map(|p| p.as_path()));
        bins
    }
}

/// Build clusters for all CGI binaries in a directory.
pub fn build_clusters(cgi_binaries: &[PathBuf], symbol_map: &SymbolMap) -> Vec<Cluster> {
    cgi_binaries
        .iter()
        .map(|cgi| Cluster::build(cgi, symbol_map))
        .collect()
}
