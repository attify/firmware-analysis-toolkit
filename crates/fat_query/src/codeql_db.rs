use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CodeQlDatabaseMetadata {
    #[serde(rename = "sourceLocationPrefix")]
    pub source_location_prefix: Option<PathBuf>,
    #[serde(rename = "primaryLanguage")]
    pub primary_language: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeQlDatabaseCandidate {
    pub db_root: PathBuf,
    pub source_root: Option<PathBuf>,
    pub primary_language: Option<String>,
}

pub fn discover_codeql_databases(path: &Path) -> Result<Vec<CodeQlDatabaseCandidate>, String> {
    let manifests = WalkDir::new(path)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .filter(|candidate| {
            candidate.file_name().and_then(|name| name.to_str()) == Some("codeql-database.yml")
        })
        .collect::<Vec<_>>();

    manifests
        .into_iter()
        .map(|manifest_path| {
            let metadata = load_codeql_metadata(&manifest_path)?;
            Ok(CodeQlDatabaseCandidate {
                db_root: manifest_path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.to_path_buf()),
                source_root: metadata.source_location_prefix,
                primary_language: metadata.primary_language,
            })
        })
        .collect()
}

pub fn load_codeql_metadata(manifest_path: &Path) -> Result<CodeQlDatabaseMetadata, String> {
    let text = fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;
    serde_yaml::from_str(&text)
        .map_err(|e| format!("invalid CodeQL metadata {}: {e}", manifest_path.display()))
}
