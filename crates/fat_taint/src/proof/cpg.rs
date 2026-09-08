//! Joern c2cpg invocation — build CPG from normalized source tree and run queries.

use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum CpgError {
    #[error("Joern c2cpg not found in PATH")]
    C2cpgNotFound,
    #[error("Joern not found in PATH")]
    JoernNotFound,
    #[error("c2cpg failed: {0}")]
    C2cpgFailed(String),
    #[error("Joern query failed: {0}")]
    QueryFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Build a CPG from a directory of C source files.
pub fn build_cpg(source_dir: &Path, output_cpg: &Path) -> Result<(), CpgError> {
    check_c2cpg()?;

    info!(source = %source_dir.display(), cpg = %output_cpg.display(), "Building CPG");

    let c2cpg = find_c2cpg()?;

    let output = Command::new(&c2cpg)
        .arg(source_dir)
        .arg("--output")
        .arg(output_cpg)
        .output()
        .map_err(|e| CpgError::C2cpgFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CpgError::C2cpgFailed(stderr.into_owned()));
    }

    info!(cpg = %output_cpg.display(), "CPG built successfully");
    Ok(())
}

/// Run a Joern query script against a CPG and return stdout.
pub fn run_query(cpg_path: &Path, query_script: &Path) -> Result<String, CpgError> {
    check_joern()?;

    info!(cpg = %cpg_path.display(), query = %query_script.display(), "Running query");

    let output = Command::new("joern")
        .arg("--script")
        .arg(query_script)
        .arg(cpg_path)
        .output()
        .map_err(|e| CpgError::QueryFailed(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(CpgError::QueryFailed(format!(
            "stdout: {stdout}\nstderr: {stderr}"
        )));
    }

    Ok(stdout)
}

/// Run an inline Joern query string against a CPG.
pub fn run_inline_query(cpg_path: &Path, query: &str) -> Result<String, CpgError> {
    let tmp = tempfile::NamedTempFile::new()?;
    let script_path = tmp.path().to_path_buf();

    // Write the query with CPG import
    let full_query = format!("importCpg(\"{}\")\n{}\n", cpg_path.display(), query);
    std::fs::write(&script_path, &full_query)?;

    run_query(&script_path, &script_path)
}

/// Load a semantics file into a Joern session.
pub fn load_semantics(semantics_path: &Path) -> String {
    format!(
        "importCpg.semantics.fromFile(\"{}\")\n",
        semantics_path.display()
    )
}

fn find_c2cpg() -> Result<PathBuf, CpgError> {
    // Check PATH
    if let Ok(output) = Command::new("which").arg("c2cpg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Ok(PathBuf::from(path));
        }
    }

    // Check Joern installation directory
    let joern_dirs = ["/opt/homebrew/Cellar/joern", "/usr/local/share/joern"];
    for dir in &joern_dirs {
        let pattern = format!("{dir}/*/libexec/frontends/c2cpg/bin/c2cpg");
        if let Ok(mut entries) = glob::glob(&pattern) {
            if let Some(entry) = entries.by_ref().flatten().next() {
                return Ok(entry.to_path_buf());
            }
        }
        // Try without glob
        let path = PathBuf::from(dir);
        if path.exists() {
            for e in walkdir::WalkDir::new(&path)
                .max_depth(5)
                .into_iter()
                .flatten()
            {
                if e.file_name() == "c2cpg" && e.file_type().is_file() {
                    return Ok(e.path().to_path_buf());
                }
            }
        }
    }

    Err(CpgError::C2cpgNotFound)
}

fn check_c2cpg() -> Result<(), CpgError> {
    find_c2cpg().map(|_| ())
}

fn check_joern() -> Result<(), CpgError> {
    Command::new("joern")
        .arg("--help")
        .output()
        .map_err(|_| CpgError::JoernNotFound)?;
    Ok(())
}
