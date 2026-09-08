use super::edge_ai_common::{
    find_extracted_root, infer_extracted_root_from_observed_path, inference_filename_finding,
};
use super::model_metadata::{
    first_assignment_value, insert_if_present, join_limited, metadata, printable_strings,
    unique_limited,
};
use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};
use std::fs;
use std::path::Path;

// Qualcomm SNPE/QAIRT library patterns
const DLC_LIBRARY_PATTERNS: &[&str] = &[
    "libSNPE.so",
    "libsnpe-",
    "libQnn",
    "libqnn",
    "libhta.so",
    "libhexagon",
    "snpe-net-run",
    "snpe-dlc-diff",
];

// DLC file extensions
const DLC_EXTENSIONS: &[&str] = &["dlc"];

const MIN_DLC_SIZE: u64 = 50 * 1024;

#[derive(Debug, Default)]
pub struct DLCModelAnalyzer;

#[derive(Debug, Clone)]
struct DlcMetadata {
    file_size: u64,
    model_name: Option<String>,
    source_framework: Option<String>,
    quantization: Option<String>,
    accelerator_hints: Vec<String>,
}

fn parse_dlc_metadata(data: &[u8], file_size: u64) -> DlcMetadata {
    let strings = printable_strings(&data[..data.len().min(1024 * 1024)], 3, 512);
    let haystack = strings.join("\n").to_ascii_lowercase();

    let accelerator_hints = unique_limited(
        [
            ("snpe", "SNPE"),
            ("qnn", "QNN"),
            ("hexagon", "Hexagon"),
            ("hta", "HTA"),
            ("dsp", "DSP"),
        ]
        .into_iter()
        .filter(|&(needle, _label)| haystack.contains(needle))
        .map(|(_needle, label)| label.to_string()),
        8,
    );

    DlcMetadata {
        file_size,
        model_name: first_assignment_value(&strings, "model_name"),
        source_framework: first_assignment_value(&strings, "source_framework"),
        quantization: first_assignment_value(&strings, "quantization").or_else(|| {
            ["int8", "uint8", "float16", "float32"]
                .iter()
                .find(|marker| haystack.contains(**marker))
                .map(|marker| (*marker).to_string())
        }),
        accelerator_hints,
    }
}

fn dlc_metadata(metadata_value: &DlcMetadata) -> super::model_metadata::ModelMetadata {
    let mut values = metadata([
        ("format", "dlc".to_string()),
        ("artifact_kind", "model".to_string()),
        ("file_size_bytes", metadata_value.file_size.to_string()),
        (
            "accelerator_hints",
            join_limited(&metadata_value.accelerator_hints, 8),
        ),
    ]);
    insert_if_present(&mut values, "model_name", metadata_value.model_name.clone());
    insert_if_present(
        &mut values,
        "source_framework",
        metadata_value.source_framework.clone(),
    );
    insert_if_present(
        &mut values,
        "quantization",
        metadata_value.quantization.clone(),
    );
    values
}

pub fn scan_rootfs(root: &Path) -> Vec<Finding> {
    scan_directory(root, root)
}

pub(crate) fn scan_directory(root: &Path, base_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut model_count: usize = 0;
    let mut lib_count: usize = 0;
    scan_dir_recurse(
        root,
        base_root,
        &mut findings,
        &mut model_count,
        &mut lib_count,
    );
    findings
}

fn scan_dir_recurse(
    dir: &Path,
    base_root: &Path,
    findings: &mut Vec<Finding>,
    model_count: &mut usize,
    lib_count: &mut usize,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir_recurse(&path, base_root, findings, model_count, lib_count);
            continue;
        }

        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // A name match is an observation, not a runtime or model identity.
        for pattern in DLC_LIBRARY_PATTERNS {
            if let Some(finding) = inference_filename_finding(
                &path,
                base_root,
                pattern,
                format!("ai-library-dlc-{}", *lib_count + 1),
                "dlc-model",
            ) {
                *lib_count += 1;
                findings.push(finding);
            }
        }

        // Check for .dlc files
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !DLC_EXTENSIONS.contains(&ext) {
            continue;
        }

        let Ok(metadata) = path.metadata() else {
            continue;
        };
        if metadata.len() < MIN_DLC_SIZE {
            continue;
        }

        let Ok(data) = fs::read(&path) else { continue };
        let model_metadata = parse_dlc_metadata(&data, metadata.len());

        *model_count += 1;
        let rel = path
            .strip_prefix(base_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let description = format!(
            "Qualcomm DLC model: {} ({:.0}KB) — extractable for adversarial attacks",
            fname,
            metadata.len() as f64 / 1024.0,
        );
        findings.push(
            Finding::new(
                format!("dlc-model-{model_count}"),
                description,
                FindingSeverity::High,
                FindingSubject::File { rel_path: rel },
            )
            .with_metadata(dlc_metadata(&model_metadata))
            .with_plugin_id("dlc-model"),
        );
    }
}

impl Analyzer for DLCModelAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "dlc-model",
            "Qualcomm DLC Model Scanner",
            AnalyzerClass::Static,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![
            AnalysisTrigger::ExtractionCompleted,
            AnalysisTrigger::AnalysisRequested,
        ])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(
            fat_core::artifacts::ArtifactKind::Analysis,
        )])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let root = match request.snapshot.as_ref().and_then(find_extracted_root) {
            Some(path) => path,
            None => {
                let candidate = request
                    .artifact_documents
                    .iter()
                    .filter_map(|doc| doc.rel_path.as_ref())
                    .find_map(|p| infer_extracted_root_from_observed_path(Path::new(p)));
                match candidate {
                    Some(p) => p,
                    None => return AnalysisResult::default(),
                }
            }
        };
        let base_root = root.parent().unwrap_or(&root).to_path_buf();
        let findings = scan_directory(&root, &base_root);
        if findings.is_empty() {
            return AnalysisResult::default();
        }
        AnalysisResult {
            findings,
            diagnostics: vec![],
            produced_artifacts: vec![],
            produced_artifact_ids: vec![],
        }
    }
}
