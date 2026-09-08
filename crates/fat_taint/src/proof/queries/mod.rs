//! Pre-built vulnerability query templates for Joern CPGQL.

pub mod command_injection;

use std::path::Path;

/// Write a query script to a file, prepending CPG import and semantics loading.
pub fn prepare_query(cpg_path: &Path, semantics_paths: &[&Path], query_body: &str) -> String {
    let mut script = format!("importCpg(\"{}\")\n\n", cpg_path.display());

    for sem in semantics_paths {
        script.push_str(&format!(
            "importCpg.semantics.fromFile(\"{}\")\n",
            sem.display()
        ));
    }

    script.push('\n');
    script.push_str(query_body);
    script
}
