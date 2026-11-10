use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCampaignManifest {
    pub schema_version: String,
    pub campaign_id: String,
    pub engine: ExternalCampaignEngine,
    pub proof_scope: String,
    pub setup_artifacts: Vec<ExternalArtifactPin>,
    pub cases: Vec<ExternalReplayCase>,
    pub evidence: Vec<ExternalArtifactPin>,
    pub cleanup: ExternalCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCampaignEngine {
    pub name: String,
    pub version: String,
    pub revision: String,
    pub substrate_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalArtifactPin {
    pub role: String,
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReplayCase {
    pub id: String,
    pub kind: String,
    pub input: ExternalInputPin,
    pub command: Vec<String>,
    pub timeout_seconds: u64,
    pub expected_exit_codes: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalInputPin {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCleanup {
    pub command: Vec<String>,
    pub timeout_seconds: u64,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalCampaignValidationError {
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

pub fn validate_external_campaign(
    manifest: &ExternalCampaignManifest,
    root: &Path,
) -> Result<usize, Vec<ExternalCampaignValidationError>> {
    let mut errors = Vec::new();

    if manifest.schema_version != "external-campaign/v1" {
        error(
            &mut errors,
            "schema-version-unsupported",
            "schema_version",
            "schema version must be external-campaign/v1",
        );
    }
    for (path, value) in [
        ("campaign_id", manifest.campaign_id.as_str()),
        ("engine.name", manifest.engine.name.as_str()),
        ("engine.version", manifest.engine.version.as_str()),
        ("engine.revision", manifest.engine.revision.as_str()),
        ("proof_scope", manifest.proof_scope.as_str()),
    ] {
        if value.trim().is_empty() {
            error(&mut errors, "value-empty", path, "value must not be empty");
        }
    }
    if !matches!(
        manifest.engine.substrate_kind.as_str(),
        "native-host" | "docker-engine" | "managed-linux-vm"
    ) {
        error(
            &mut errors,
            "substrate-kind-invalid",
            "engine.substrate_kind",
            "substrate kind must be native-host, docker-engine, or managed-linux-vm",
        );
    }
    if manifest.setup_artifacts.is_empty() {
        error(
            &mut errors,
            "setup-artifacts-empty",
            "setup_artifacts",
            "at least one setup artifact must be pinned",
        );
    }
    if manifest.cases.is_empty() {
        error(
            &mut errors,
            "replay-cases-empty",
            "cases",
            "at least one replay case is required",
        );
    }
    if manifest.evidence.is_empty() {
        error(
            &mut errors,
            "evidence-empty",
            "evidence",
            "at least one evidence artifact must be pinned",
        );
    }
    if !manifest.cleanup.required {
        error(
            &mut errors,
            "cleanup-not-required",
            "cleanup.required",
            "external campaigns must declare cleanup as required",
        );
    }
    if manifest.cleanup.command.is_empty() {
        error(
            &mut errors,
            "cleanup-command-empty",
            "cleanup.command",
            "cleanup command must not be empty",
        );
    }

    for (index, artifact) in manifest.setup_artifacts.iter().enumerate() {
        validate_pin(
            artifact.role.as_str(),
            &artifact.path,
            &artifact.sha256,
            root,
            format!("setup_artifacts.{index}"),
            &mut errors,
        );
    }
    for (index, artifact) in manifest.evidence.iter().enumerate() {
        validate_pin(
            artifact.role.as_str(),
            &artifact.path,
            &artifact.sha256,
            root,
            format!("evidence.{index}"),
            &mut errors,
        );
    }
    for case in &manifest.cases {
        let base = format!("cases.{}", case.id);
        if case.id.trim().is_empty() {
            error(
                &mut errors,
                "value-empty",
                format!("{base}.id"),
                "case id must not be empty",
            );
        }
        if case.kind.trim().is_empty() {
            error(
                &mut errors,
                "value-empty",
                format!("{base}.kind"),
                "case kind must not be empty",
            );
        }
        if case.command.is_empty() {
            error(
                &mut errors,
                "replay-command-empty",
                format!("{base}.command"),
                "replay command must not be empty",
            );
        } else if case
            .command
            .iter()
            .filter(|argument| argument.as_str() == "{input}")
            .count()
            != 1
        {
            error(
                &mut errors,
                "replay-input-placeholder-invalid",
                format!("{base}.command"),
                "replay command must contain {input} exactly once as a complete argument",
            );
        }
        if case.expected_exit_codes.is_empty() {
            error(
                &mut errors,
                "expected-exit-codes-empty",
                format!("{base}.expected_exit_codes"),
                "at least one expected exit code is required",
            );
        }
        if case.timeout_seconds == 0 {
            error(
                &mut errors,
                "replay-timeout-invalid",
                format!("{base}.timeout_seconds"),
                "replay timeout must be a positive number of seconds",
            );
        }
        validate_pin(
            "replay-input",
            &case.input.path,
            &case.input.sha256,
            root,
            format!("{base}.input"),
            &mut errors,
        );
    }
    if manifest.cleanup.timeout_seconds == 0 {
        error(
            &mut errors,
            "cleanup-timeout-invalid",
            "cleanup.timeout_seconds",
            "cleanup timeout must be a positive number of seconds",
        );
    }

    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.code.cmp(right.code))
    });
    errors.dedup();
    if errors.is_empty() {
        Ok(manifest.setup_artifacts.len() + manifest.cases.len() + manifest.evidence.len())
    } else {
        Err(errors)
    }
}

fn validate_pin(
    role: &str,
    path: &Path,
    expected_digest: &str,
    root: &Path,
    base: String,
    errors: &mut Vec<ExternalCampaignValidationError>,
) {
    if role.trim().is_empty() {
        error(
            errors,
            "value-empty",
            format!("{base}.role"),
            "artifact role must not be empty",
        );
    }
    if !is_safe_relative_path(path) {
        error(
            errors,
            "artifact-path-invalid",
            format!("{base}.path"),
            "artifact path must be relative and must not contain parent traversal",
        );
        return;
    }
    if !is_sha256_digest(expected_digest) {
        error(
            errors,
            "artifact-digest-invalid",
            format!("{base}.sha256"),
            "artifact digest must use sha256:<64 lowercase hex characters>",
        );
        return;
    }
    let resolved = root.join(path);
    match fs::read(&resolved) {
        Ok(bytes) => {
            let actual = format!("sha256:{:x}", Sha256::digest(bytes));
            if actual != expected_digest {
                error(
                    errors,
                    "artifact-digest-mismatch",
                    format!("{base}.sha256"),
                    format!("artifact digest does not match {}", resolved.display()),
                );
            }
        }
        Err(read_error) => error(
            errors,
            "artifact-read-failed",
            format!("{base}.path"),
            format!("failed to read {}: {read_error}", resolved.display()),
        ),
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn error(
    errors: &mut Vec<ExternalCampaignValidationError>,
    code: &'static str,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    errors.push(ExternalCampaignValidationError {
        code,
        path: path.into(),
        message: message.into(),
    });
}
