use crate::analyzers::{dlc_model, magik_model, onnx_model, tflite_model};
use anyhow::{bail, Result};
use fat_core::finding::{Finding, FindingSubject};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeAiFormat {
    Magik,
    Tflite,
    Onnx,
    Dlc,
}

impl EdgeAiFormat {
    pub fn all() -> Vec<Self> {
        vec![Self::Magik, Self::Tflite, Self::Onnx, Self::Dlc]
    }
}

impl fmt::Display for EdgeAiFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Magik => "magik",
            Self::Tflite => "tflite",
            Self::Onnx => "onnx",
            Self::Dlc => "dlc",
        };
        f.write_str(value)
    }
}

impl FromStr for EdgeAiFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "magik" | "jzdl" | "venus" => Ok(Self::Magik),
            "tflite" | "tensorflow-lite" | "tensorflowlite" => Ok(Self::Tflite),
            "onnx" => Ok(Self::Onnx),
            "dlc" | "snpe" | "qnn" | "qualcomm-dlc" => Ok(Self::Dlc),
            other => Err(format!(
                "unknown Edge AI format `{other}`; expected one of: magik, tflite, onnx, dlc"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeAiScanReport {
    pub schema_version: String,
    pub root: String,
    pub formats: Vec<EdgeAiFormat>,
    pub finding_count: usize,
    pub findings: Vec<Finding>,
}

pub fn scan_edge_ai_root(root: &Path, formats: &[EdgeAiFormat]) -> Result<EdgeAiScanReport> {
    if !root.exists() {
        bail!("rootfs path does not exist: {}", root.display());
    }
    if !root.is_dir() {
        bail!("rootfs path is not a directory: {}", root.display());
    }

    let selected_formats = normalize_formats(formats);
    let mut findings = Vec::new();

    for format in &selected_formats {
        match format {
            EdgeAiFormat::Magik => findings.extend(magik_model::scan_rootfs(root)),
            EdgeAiFormat::Tflite => findings.extend(tflite_model::scan_rootfs(root)),
            EdgeAiFormat::Onnx => findings.extend(onnx_model::scan_rootfs(root)),
            EdgeAiFormat::Dlc => findings.extend(dlc_model::scan_rootfs(root)),
        }
    }

    findings.sort_by_key(finding_sort_key);
    let finding_count = findings.len();

    Ok(EdgeAiScanReport {
        schema_version: "edge-ai-scan/v1".to_string(),
        root: root.display().to_string(),
        formats: selected_formats,
        finding_count,
        findings,
    })
}

fn normalize_formats(formats: &[EdgeAiFormat]) -> Vec<EdgeAiFormat> {
    let source = if formats.is_empty() {
        EdgeAiFormat::all()
    } else {
        formats.to_vec()
    };

    let mut selected = Vec::new();
    for format in source {
        if !selected.contains(&format) {
            selected.push(format);
        }
    }
    selected
}

fn finding_sort_key(finding: &Finding) -> (String, String, String) {
    (
        finding.plugin_id.clone().unwrap_or_default(),
        subject_key(&finding.subject),
        finding.id.clone(),
    )
}

fn subject_key(subject: &FindingSubject) -> String {
    match subject {
        FindingSubject::Binary { binary_id } => binary_id.clone(),
        FindingSubject::File { rel_path } => rel_path.clone(),
        FindingSubject::Bootloader { family } => family.clone(),
        FindingSubject::Project => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_does_not_identify_runtimes_from_non_elf_filenames() {
        let dir = tempfile::tempdir().unwrap();
        for contents in [b"".as_slice(), b"not an ELF", b"\x7fEL"] {
            for name in [
                "libonnxruntime.so",
                "libSNPE.so",
                "libtflite.so",
                "libncnn.so",
            ] {
                std::fs::write(dir.path().join(name), contents).unwrap();
            }
            let report = scan_edge_ai_root(dir.path(), &[]).unwrap();
            assert!(report.findings.is_empty(), "{report:#?}");
        }
    }

    #[test]
    fn default_scan_labels_elf_library_names_as_filename_evidence_only() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "libonnxruntime.so",
            "libSNPE.so",
            "libtflite.so",
            "libncnn.so",
        ] {
            std::fs::write(dir.path().join(name), b"\x7fELF").unwrap();
        }
        let report = scan_edge_ai_root(dir.path(), &[]).unwrap();
        for plugin in ["magik-model", "tflite-model", "onnx-model", "dlc-model"] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.plugin_id.as_deref() == Some(plugin)),
                "{plugin} lost filename observations"
            );
        }
        for finding in &report.findings {
            assert_eq!(
                finding.metadata.get("artifact_kind").map(String::as_str),
                Some("filename-match")
            );
            assert!(
                !finding.metadata.contains_key("format"),
                "filename asserted a format: {finding:?}"
            );
            assert!(
                !finding.metadata.contains_key("runtime"),
                "filename asserted a runtime: {finding:?}"
            );
            assert_eq!(
                finding.metadata.get("evidence").map(String::as_str),
                Some("filename and ELF magic")
            );
            assert!(finding.metadata.contains_key("matched_pattern"));
        }
    }
}
