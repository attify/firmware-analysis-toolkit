//! angr-based binary taint analysis via Reaching Definitions.
//!
//! This module invokes the `angr_taint.py` script as a subprocess and parses
//! its JSON output into TaintFinding objects.
//!
//! angr operates on ELF binaries directly — no decompilation needed.
//! It uses Reaching Definitions analysis (NOT symbolic execution) which
//! completes in seconds per binary instead of hours.

use crate::finding::{ChainStep, EdgeType, SourceClass, TaintFinding};
use crate::profile::{CatalogProvenance, ExternalTaintProfile};
use fat_core::finding::FindingSeverity;
use serde::Deserialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum AngrError {
    #[error("python3 not found")]
    PythonNotFound,
    #[error("angr not installed or not usable in the detected Python interpreters: {0}\nSet FAT_PYTHON=/path/to/python to force a known-good interpreter.")]
    AngrNotInstalled(String),
    #[error("angr analysis failed for {binary}: {msg}")]
    AnalysisFailed { binary: String, msg: String },
    #[error("failed to parse angr output: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Raw finding from angr_taint.py JSON output.
#[derive(Debug, Deserialize, Clone)]
struct RawAngrFinding {
    function: String,
    source: String,
    source_addr: Option<String>,
    source_class: String,
    sink: String,
    sink_addr: Option<String>,
    method: String,
    call_path: Option<Vec<String>>,
    parameter: Option<String>,
    endpoint: Option<String>,
    symbolic_analysis: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct AngrQueryFinding {
    pub function: String,
    pub source: String,
    pub source_addr: Option<String>,
    pub source_class: String,
    pub sink: String,
    pub sink_addr: Option<String>,
    pub method: String,
    pub call_path: Option<Vec<String>>,
    pub parameter: Option<String>,
    pub endpoint: Option<String>,
    pub symbolic_analysis: Option<serde_json::Value>,
}

/// Run angr taint analysis on a single binary.
///
/// For ELF binaries: `arch` and `base_addr` are optional (auto-detected).
/// For raw blobs (flat firmware): `arch` and `base_addr` are required.
pub fn analyze_binary(binary: &Path) -> Result<Vec<TaintFinding>, AngrError> {
    analyze_binary_with_opts(binary, None, None)
}

/// Run angr taint analysis with explicit architecture and base address.
pub fn analyze_binary_with_opts(
    binary: &Path,
    arch: Option<&str>,
    base_addr: Option<&str>,
) -> Result<Vec<TaintFinding>, AngrError> {
    analyze_binary_with_sink_candidates(binary, arch, base_addr, None)
}

/// Run angr taint analysis with optional SinkDiscoveryReport candidate sinks.
pub fn analyze_binary_with_sink_candidates(
    binary: &Path,
    arch: Option<&str>,
    base_addr: Option<&str>,
    sink_candidates: Option<&Path>,
) -> Result<Vec<TaintFinding>, AngrError> {
    analyze_binary_with_profile(binary, arch, base_addr, sink_candidates, None)
}

/// Run with core models plus a validated, explicitly selected external profile.
pub fn analyze_binary_with_profile(
    binary: &Path,
    arch: Option<&str>,
    base_addr: Option<&str>,
    sink_candidates: Option<&Path>,
    source_profile: Option<&ExternalTaintProfile>,
) -> Result<Vec<TaintFinding>, AngrError> {
    let raw_findings = run_angr(binary, arch, base_addr, sink_candidates, source_profile)?;
    let provenance = source_profile
        .map(|profile| profile.provenance().clone())
        .unwrap_or(CatalogProvenance::Core);

    let binary_name = binary
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    let findings: Vec<TaintFinding> = raw_findings
        .into_iter()
        .enumerate()
        .map(|(i, raw)| {
            let mut finding = convert_finding(i, raw, &binary_name);
            finding.model_provenance = Some(provenance.clone());
            finding
        })
        .collect();

    info!(
        binary = %binary.display(),
        findings = findings.len(),
        "angr analysis complete"
    );

    Ok(findings)
}

pub fn analyze_binary_for_query(binary: &Path) -> Result<Vec<AngrQueryFinding>, AngrError> {
    analyze_binary_for_query_with_opts(binary, None, None)
}

pub fn analyze_binary_for_query_with_opts(
    binary: &Path,
    arch: Option<&str>,
    base_addr: Option<&str>,
) -> Result<Vec<AngrQueryFinding>, AngrError> {
    let raw_findings = run_angr(binary, arch, base_addr, None, None)?;
    Ok(raw_findings.into_iter().map(Into::into).collect())
}

/// Run angr analysis on all binaries in a cluster.
pub fn analyze_cluster(binaries: &[&Path]) -> Result<Vec<TaintFinding>, AngrError> {
    let mut all_findings = Vec::new();

    for binary in binaries {
        match analyze_binary(binary) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                warn!(binary = %binary.display(), error = %e, "angr analysis failed, skipping");
            }
        }
    }

    Ok(all_findings)
}

fn convert_finding(index: usize, raw: RawAngrFinding, binary_name: &str) -> TaintFinding {
    let source_class = match raw.source_class.as_str() {
        "primary" => SourceClass::Primary,
        _ => SourceClass::Secondary,
    };

    let mut chain = Vec::new();

    // Build chain from the raw finding
    if let Some(call_path) = &raw.call_path {
        // Cross-function finding — build chain from call path
        for (i, step) in call_path.iter().enumerate() {
            // angr-confirmed call graph edge — direct flow for every step
            let edge_type = EdgeType::DirectFlow;

            chain.push(ChainStep {
                binary: binary_name.to_string(),
                function: step.clone(),
                location: String::new(),
                action: if i == 0 {
                    format!("calls {}", raw.source)
                } else if i == call_path.len() - 1 {
                    format!("calls {}", raw.sink)
                } else {
                    "intermediate call".into()
                },
                edge_type,
            });
        }
    } else {
        // Co-occurrence finding — source and sink in same function
        chain.push(ChainStep {
            binary: binary_name.to_string(),
            function: raw.function.clone(),
            location: raw.source_addr.clone().unwrap_or_default(),
            action: format!("{}()", raw.source),
            edge_type: EdgeType::DirectFlow,
        });
        chain.push(ChainStep {
            binary: binary_name.to_string(),
            function: raw.function.clone(),
            location: raw.sink_addr.clone().unwrap_or_default(),
            action: format!("{}()", raw.sink),
            edge_type: EdgeType::DirectFlow,
        });
    }

    let status = TaintFinding::classify(&chain);
    let confidence = TaintFinding::compute_confidence(&chain);

    // Symbolic analysis can upgrade confirmed-rd findings to Critical when
    // shell metacharacters survive from source to command execution sink.
    let has_symbolic_injection = raw
        .symbolic_analysis
        .as_ref()
        .and_then(|v| v.get("injectable"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let severity = if has_symbolic_injection && raw.method == "confirmed-rd" {
        // Symbolic execution proved metacharacters survive to system()/popen()
        FindingSeverity::Critical
    } else {
        match (source_class, raw.method.as_str()) {
            (SourceClass::Primary, "confirmed-rd") => FindingSeverity::High,
            (SourceClass::Primary, "co-occurrence-only") => FindingSeverity::Medium,
            (SourceClass::Primary, _) => FindingSeverity::Medium,
            (SourceClass::Secondary, "confirmed-rd") => FindingSeverity::Medium,
            (SourceClass::Secondary, "co-occurrence-only") => FindingSeverity::Low,
            _ => FindingSeverity::Low,
        }
    };

    TaintFinding {
        model_provenance: None,
        state_model_provenance: None,
        id: format!("ANGR-{:04}", index + 1),
        title: format!("{} → {} in {}", raw.source, raw.sink, raw.function),
        severity,
        chain,
        status,
        status_reason: raw.method.clone(),
        confidence,
        source_class,
    }
}

impl From<RawAngrFinding> for AngrQueryFinding {
    fn from(raw: RawAngrFinding) -> Self {
        Self {
            function: raw.function,
            source: raw.source,
            source_addr: raw.source_addr,
            source_class: raw.source_class,
            sink: raw.sink,
            sink_addr: raw.sink_addr,
            method: raw.method,
            call_path: raw.call_path,
            parameter: raw.parameter,
            endpoint: raw.endpoint,
            symbolic_analysis: raw.symbolic_analysis,
        }
    }
}

fn run_angr(
    binary: &Path,
    arch: Option<&str>,
    base_addr: Option<&str>,
    sink_candidates: Option<&Path>,
    source_profile: Option<&ExternalTaintProfile>,
) -> Result<Vec<RawAngrFinding>, AngrError> {
    let python = resolve_angr_python()?;

    let runtime = materialize_runtime(source_profile)?;
    let output_file = tempfile::NamedTempFile::new()?;
    let output_path = output_file.path().to_path_buf();

    info!(binary = %binary.display(), "Running angr taint analysis");

    let mut cmd = Command::new(&python);
    cmd.arg(&runtime.script_path)
        .arg(binary)
        .arg(&output_path)
        .arg("--profiles")
        .arg(&runtime.profile_dir_path);

    if let Some(arch) = arch {
        cmd.arg("--arch").arg(arch);
    }
    if let Some(base) = base_addr {
        cmd.arg("--base").arg(base);
    }
    if let Some(sink_candidates) = sink_candidates {
        cmd.arg("--sink-candidates").arg(sink_candidates);
    }

    let result = cmd.output().map_err(|e| AngrError::AnalysisFailed {
        binary: binary.display().to_string(),
        msg: e.to_string(),
    })?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(AngrError::AnalysisFailed {
            binary: binary.display().to_string(),
            msg: stderr.into_owned(),
        });
    }

    let json_str = std::fs::read_to_string(&output_path)?;
    serde_json::from_str(&json_str).map_err(|e| AngrError::ParseError(e.to_string()))
}

fn resolve_angr_python() -> Result<PathBuf, AngrError> {
    if let Some(override_value) = std::env::var_os("FAT_PYTHON") {
        let resolved =
            resolve_python_candidate(&override_value).ok_or(AngrError::PythonNotFound)?;
        return match probe_angr_python(&resolved) {
            Ok(()) => Ok(resolved),
            Err(message) => Err(AngrError::AngrNotInstalled(message)),
        };
    }

    let mut saw_candidate = false;
    let mut failures = Vec::new();
    for candidate in python_candidates() {
        let Some(path) = resolve_python_candidate(candidate) else {
            continue;
        };
        saw_candidate = true;
        match probe_angr_python(&path) {
            Ok(()) => return Ok(path),
            Err(message) => failures.push(format!("{}: {}", path.display(), message.trim())),
        }
    }

    if !saw_candidate {
        return Err(AngrError::PythonNotFound);
    }

    Err(AngrError::AngrNotInstalled(failures.join("\n")))
}

fn python_candidates() -> Vec<OsString> {
    let mut candidates = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(
            cwd.join(".fat-runtime")
                .join("angr311")
                .join("bin")
                .join("python")
                .into_os_string(),
        );
        candidates.push(
            cwd.join(".venv")
                .join("bin")
                .join("python")
                .into_os_string(),
        );
    }
    candidates.extend(
        ["python3", "python3.12", "python3.11", "python3.10"]
            .into_iter()
            .map(OsString::from),
    );
    candidates
}

fn resolve_python_candidate(candidate: impl Into<OsString>) -> Option<PathBuf> {
    let candidate = candidate.into();
    let candidate_path = PathBuf::from(&candidate);
    if candidate_path.components().count() > 1 || candidate_path.is_absolute() {
        return candidate_path.is_file().then_some(candidate_path);
    }

    let path_var = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path_var) {
        let path = entry.join(&candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn probe_angr_python(python: &Path) -> Result<(), String> {
    let output = Command::new(python)
        .args(["-c", "import angr; print(angr.__version__)"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stderr.is_empty() {
        Err(stderr)
    } else if !stdout.is_empty() {
        Err(stdout)
    } else {
        Err(format!("process exited with status {}", output.status))
    }
}

/// The angr bridge script, embedded at compile time.
/// Extracted to a temp file at runtime — the user never sees a .py file.
const EMBEDDED_ANGR_SCRIPT: &str = include_str!("../../scripts/angr_taint.py");

/// The core taint models, embedded at compile time.
///
/// This is the same `profiles/core.yaml` the Rust catalog uses — angr reads
/// one source of truth rather than its own copy. FAT embeds no other profile:
/// additional models are supplied by the operator as an explicit external
/// profile and materialized alongside this one.
const PROFILE_CORE: &str = include_str!("../../profiles/core.yaml");

const EMBEDDED_PROFILES: &[(&str, &str)] = &[("core.yaml", PROFILE_CORE)];

/// Return the embedded profile contents for cache key computation.
pub fn embedded_profile_contents() -> Vec<&'static str> {
    EMBEDDED_PROFILES
        .iter()
        .map(|(_, content)| *content)
        .collect()
}

struct MaterializedRuntime {
    _script: tempfile::NamedTempFile,
    _profile_dir: tempfile::TempDir,
    script_path: std::path::PathBuf,
    profile_dir_path: std::path::PathBuf,
}

fn materialize_runtime(
    source_profile: Option<&ExternalTaintProfile>,
) -> Result<MaterializedRuntime, AngrError> {
    use std::io::Write;

    // Write script
    let mut script = tempfile::Builder::new()
        .prefix("fat-angr-")
        .suffix(".py")
        .tempfile()?;
    script.write_all(EMBEDDED_ANGR_SCRIPT.as_bytes())?;
    script.flush()?;
    let script_path = script.path().to_path_buf();

    // Write profiles to a temp directory
    let profile_dir = tempfile::Builder::new().prefix("fat-profiles-").tempdir()?;
    for (filename, content) in EMBEDDED_PROFILES {
        let profile_path = profile_dir.path().join(filename);
        std::fs::write(&profile_path, content)?;
    }
    if let Some(selected) = source_profile {
        // Fixed distinct name: an input named core.yaml cannot replace core.
        std::fs::write(
            profile_dir.path().join("external.yaml"),
            selected.contents(),
        )?;
    }
    let profile_dir_path = profile_dir.path().to_path_buf();

    Ok(MaterializedRuntime {
        _script: script,
        _profile_dir: profile_dir,
        script_path,
        profile_dir_path,
    })
}

#[cfg(test)]
#[path = "../../../../tests/support/subprocess.rs"]
mod test_subprocess;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    fn write_fake_python(path: &Path, body: &str) {
        fs::write(path, body).expect("write fake python");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod");
    }

    #[test]
    fn resolve_angr_python_prefers_fat_python_override() {
        let Some(mut command) = test_subprocess::isolated_test(
            "proof::angr::tests::resolve_angr_python_prefers_fat_python_override",
        ) else {
            let expected = PathBuf::from(std::env::var_os("FAT_PYTHON").expect("override"));
            assert_eq!(resolve_angr_python().expect("resolve python"), expected);
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let preferred = dir.path().join("preferred-python");
        let default_python = dir.path().join("python3");
        write_fake_python(&preferred, "#!/bin/sh\nprintf 'override-angr\\n'\nexit 0\n");
        write_fake_python(
            &default_python,
            "#!/bin/sh\nprintf 'default-angr\\n'\nexit 0\n",
        );
        command
            .env("PATH", dir.path())
            .env("FAT_PYTHON", &preferred);
        test_subprocess::assert_success(&mut command);
    }

    #[test]
    fn resolve_angr_python_falls_back_when_python3_is_broken() {
        let Some(mut command) = test_subprocess::isolated_test(
            "proof::angr::tests::resolve_angr_python_falls_back_when_python3_is_broken",
        ) else {
            let expected =
                PathBuf::from(std::env::var_os("PATH").expect("fixture path")).join("python3.11");
            assert_eq!(
                resolve_angr_python().expect("resolve fallback python"),
                expected
            );
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        write_fake_python(
            &dir.path().join("python3"),
            "#!/bin/sh\necho 'KeyError: r3' 1>&2\nexit 1\n",
        );
        write_fake_python(
            &dir.path().join("python3.11"),
            "#!/bin/sh\nprintf 'fallback-angr\\n'\nexit 0\n",
        );
        command
            .env("PATH", dir.path())
            .env_remove("FAT_PYTHON")
            .current_dir(dir.path());
        test_subprocess::assert_success(&mut command);
    }

    #[test]
    fn resolve_angr_python_prefers_repo_local_runtime_before_path_python3() {
        let Some(mut command) = test_subprocess::isolated_test(
            "proof::angr::tests::resolve_angr_python_prefers_repo_local_runtime_before_path_python3",
        ) else {
            let expected = std::env::current_dir().expect("fixture cwd")
                .join(".fat-runtime/angr311/bin/python");
            assert_eq!(
                resolve_angr_python().expect("resolve repo-local python").canonicalize().expect("canonical resolved"),
                expected.canonicalize().expect("canonical runtime"),
            );
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime_python = dir.path().join(".fat-runtime/angr311/bin/python");
        fs::create_dir_all(runtime_python.parent().expect("runtime parent")).expect("mkdir");
        write_fake_python(
            &runtime_python,
            "#!/bin/sh\nprintf 'repo-runtime-angr\\n'\nexit 0\n",
        );
        write_fake_python(
            &dir.path().join("python3"),
            "#!/bin/sh\necho 'global python broken' 1>&2\nexit 1\n",
        );
        command
            .env("PATH", dir.path())
            .env_remove("FAT_PYTHON")
            .current_dir(dir.path());
        test_subprocess::assert_success(&mut command);
    }

    #[test]
    fn angr_not_installed_error_mentions_fat_python_override() {
        let err = AngrError::AngrNotInstalled("python3: import angr failed".into());
        let rendered = err.to_string();

        assert!(rendered.contains("FAT_PYTHON"));
        assert!(rendered.contains("python3: import angr failed"));
    }
}
