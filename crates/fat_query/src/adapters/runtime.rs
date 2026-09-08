use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVerificationResult {
    pub finding_id: String,
    pub verdict: String,
    pub observed_sink: String,
    pub evidence: Vec<String>,
}

impl RuntimeVerificationResult {
    pub fn verdict_name(&self) -> &str {
        &self.verdict
    }
}

pub fn confirm_fixture(path: impl AsRef<Path>) -> Result<RuntimeVerificationResult, String> {
    let runtime_path = path.as_ref().join("runtime.json");
    let text = std::fs::read_to_string(&runtime_path)
        .map_err(|e| format!("failed to read {}: {}", runtime_path.display(), e))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid runtime fixture: {e}"))
}
