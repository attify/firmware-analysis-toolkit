//! Symbol resolution via rabin2 — maps imports to exports across binaries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("rabin2 not found in PATH")]
    Rabin2NotFound,
    #[error("rabin2 failed on {path}: {msg}")]
    Rabin2Failed { path: String, msg: String },
    #[error("failed to parse rabin2 output: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMap {
    /// symbol_name → (library_path, decompiled_c_path if available)
    pub exports: HashMap<String, ExportInfo>,
    /// binary_path → list of imported symbol names
    pub imports: HashMap<PathBuf, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub library_path: PathBuf,
    pub decompiled_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Rabin2ImportEntry {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Rabin2ExportEntry {
    name: Option<String>,
    #[serde(rename = "type")]
    sym_type: Option<String>,
}

impl SymbolMap {
    /// Build a symbol map from a list of ELF binaries.
    pub fn build(binaries: &[PathBuf]) -> Result<Self, ResolveError> {
        check_rabin2()?;

        let mut exports: HashMap<String, ExportInfo> = HashMap::new();
        let mut imports: HashMap<PathBuf, Vec<String>> = HashMap::new();

        for binary in binaries {
            let binary_imports = extract_imports(binary)?;
            let binary_exports = extract_exports(binary)?;

            imports.insert(binary.clone(), binary_imports);

            for sym in binary_exports {
                exports.entry(sym).or_insert_with(|| ExportInfo {
                    library_path: binary.clone(),
                    decompiled_path: None,
                });
            }
        }

        Ok(Self { exports, imports })
    }

    /// Set the decompiled C path for a library's exports.
    pub fn set_decompiled_path(&mut self, library: &Path, c_path: PathBuf) {
        for info in self.exports.values_mut() {
            if info.library_path == library {
                info.decompiled_path = Some(c_path.clone());
            }
        }
    }

    /// Resolve an import: given a binary and a symbol name, find which library exports it.
    pub fn resolve(&self, symbol: &str) -> Option<&ExportInfo> {
        self.exports.get(symbol)
    }

    /// Get all libraries that a binary depends on (via its imports).
    pub fn dependencies_of(&self, binary: &Path) -> Vec<PathBuf> {
        let Some(binary_imports) = self.imports.get(binary) else {
            return Vec::new();
        };

        let mut deps: Vec<PathBuf> = binary_imports
            .iter()
            .filter_map(|sym| self.exports.get(sym))
            .map(|info| info.library_path.clone())
            .collect();

        deps.sort();
        deps.dedup();
        // Don't include the binary itself as its own dependency
        deps.retain(|p| p != binary);
        deps
    }
}

fn check_rabin2() -> Result<(), ResolveError> {
    Command::new("rabin2")
        .arg("-v")
        .output()
        .map_err(|_| ResolveError::Rabin2NotFound)?;
    Ok(())
}

fn extract_imports(binary: &Path) -> Result<Vec<String>, ResolveError> {
    let output = Command::new("rabin2")
        .args(["-i", "-j"])
        .arg(binary)
        .output()
        .map_err(|e| ResolveError::Rabin2Failed {
            path: binary.display().to_string(),
            msg: e.to_string(),
        })?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<Rabin2ImportEntry> = serde_json::from_str(&stdout).unwrap_or_default();

    Ok(entries
        .into_iter()
        .filter_map(|e| e.name)
        .filter(|n| !n.is_empty())
        .collect())
}

fn extract_exports(binary: &Path) -> Result<Vec<String>, ResolveError> {
    let output = Command::new("rabin2")
        .args(["-E", "-j"])
        .arg(binary)
        .output()
        .map_err(|e| ResolveError::Rabin2Failed {
            path: binary.display().to_string(),
            msg: e.to_string(),
        })?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<Rabin2ExportEntry> = serde_json::from_str(&stdout).unwrap_or_default();

    Ok(entries
        .into_iter()
        .filter(|e| e.sym_type.as_deref() == Some("FUNC"))
        .filter_map(|e| e.name)
        .filter(|n| !n.is_empty())
        .collect())
}
