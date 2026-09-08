use super::edge_ai_common::{
    find_extracted_root, infer_extracted_root_from_observed_path, inference_filename_finding,
};
use super::model_metadata::metadata;
use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};
use std::fs;
use std::path::Path;

// Known MAGIK magic numbers (little-endian u32 at offset 0)
const MAGIK_MAGICS: &[(u32, &str)] = &[
    (0x08AC, "MAGIK persondet"),
    (0x1D4C, "MAGIK YOLOv5"),
    (0x0428, "MAGIK MNIST"),
];

/// Shared-object names published by open-source inference runtimes.
///
/// A match here is a filename observation and nothing more. It does not
/// identify the runtime, and it never establishes a model format: `format:
/// magik` is claimed only where [`parse_magik_header`] actually parses a
/// header. Device-vendor library names are deliberately absent — that a file
/// called `libvendoredgeai.so` is that vendor's AI runtime is a claim about one
/// product, and it belongs in an operator-supplied profile rather than in a
/// generic analyzer.
const AI_LIBRARY_NAME_PATTERNS: &[&str] = &["libtflite", "libonnxruntime", "libncnn"];

#[derive(Debug, Default)]
pub struct MagikModelAnalyzer;

#[derive(Debug, Clone)]
struct MagikHeader {
    variant: String,
    width: u32,
    height: u32,
    channels: u32,
    num_layers: u32,
    file_size: u64,
}

fn parse_magik_header(data: &[u8]) -> Option<MagikHeader> {
    if data.len() < 36 {
        return None;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let reserved = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if reserved != 0 {
        return None;
    }

    let variant = MAGIK_MAGICS
        .iter()
        .find(|(m, _)| *m == magic)
        .map(|(_, name)| name.to_string())?;

    let _config = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let width = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let height = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let channels = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let _unknown = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let num_layers = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let _header_size = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

    // Sanity checks
    if width == 0 || width > 4096 {
        return None;
    }
    if height == 0 || height > 4096 {
        return None;
    }
    if channels > 4 {
        return None;
    }
    if num_layers == 0 || num_layers > 1000 {
        return None;
    }

    Some(MagikHeader {
        variant,
        width,
        height,
        channels,
        num_layers,
        file_size: data.len() as u64,
    })
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

        // A name match is an observation, not a runtime or model identity.
        for pattern in AI_LIBRARY_NAME_PATTERNS {
            if let Some(finding) = inference_filename_finding(
                &path,
                base_root,
                pattern,
                format!("ai-library-{}", *lib_count + 1),
                "magik-model",
            ) {
                *lib_count += 1;
                findings.push(finding);
            }
        }

        // Check file extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.is_empty() && ext != "bin" && ext != "so" {
            continue;
        }

        // Skip very small files
        let Ok(path_metadata) = path.metadata() else {
            continue;
        };
        if path_metadata.len() < 36 {
            continue;
        }

        // Read and check for MAGIK magic
        let Ok(data) = fs::read(&path) else {
            continue;
        };
        if let Some(header) = parse_magik_header(&data) {
            *model_count += 1;
            let rel = path
                .strip_prefix(base_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            let description = format!(
                "MAGIK model: {} ({}x{}x{}, {} layers, {:.0}KB) — extractable for white-box adversarial attacks",
                header.variant,
                header.width,
                header.height,
                header.channels,
                header.num_layers,
                header.file_size as f64 / 1024.0
            );

            findings.push(
                Finding::new(
                    format!("magik-model-{model_count}"),
                    description,
                    FindingSeverity::High,
                    FindingSubject::File { rel_path: rel },
                )
                .with_metadata(metadata([
                    ("format", "magik".to_string()),
                    ("artifact_kind", "model".to_string()),
                    ("variant", header.variant),
                    (
                        "input_shape",
                        format!("{}x{}x{}", header.width, header.height, header.channels),
                    ),
                    ("width", header.width.to_string()),
                    ("height", header.height.to_string()),
                    ("channels", header.channels.to_string()),
                    ("layer_count", header.num_layers.to_string()),
                    ("file_size_bytes", header.file_size.to_string()),
                ]))
                .with_plugin_id("magik-model"),
            );
        }
    }
}

impl Analyzer for MagikModelAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "magik-model",
            "MAGIK Model Extractor",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(extra: &[u8]) -> Vec<u8> {
        let mut bytes = b"\x7fELF".to_vec();
        bytes.extend_from_slice(extra);
        bytes
    }

    fn scan(files: &[(&str, Vec<u8>)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, bytes) in files {
            fs::write(dir.path().join(name), bytes).expect("write fixture");
        }
        scan_directory(dir.path(), dir.path())
    }

    fn library_findings(findings: &[Finding]) -> Vec<&Finding> {
        findings
            .iter()
            .filter(|finding| {
                finding.metadata.get("artifact_kind").map(String::as_str) == Some("filename-match")
            })
            .collect()
    }

    /// The vendor filename table is gone: a file named after one product's AI
    /// library is now just a file, whatever it contains.
    #[test]
    fn a_device_vendor_library_name_produces_no_finding() {
        for name in [
            "libvendoredgeai.so",
            "libvendorAiTxx.so",
            "libjzdl.so",
            "libvenus.so",
        ] {
            let findings = scan(&[(name, elf(&[0u8; 64]))]);
            assert!(
                library_findings(&findings).is_empty(),
                "{name} produced a finding from its name"
            );
        }
    }

    /// The control the review asked for: same name, no content. An empty file
    /// carrying a runtime library's name is not a runtime library.
    #[test]
    fn an_empty_file_with_a_runtime_library_name_produces_no_finding() {
        let findings = scan(&[("libtflite.so", Vec::new())]);
        assert!(library_findings(&findings).is_empty(), "{findings:?}");

        let findings = scan(&[("libtflite.so", b"not an elf at all".to_vec())]);
        assert!(library_findings(&findings).is_empty(), "{findings:?}");
    }

    /// A matching name on a real ELF is reported as what it is — a filename
    /// match — with no format or runtime identity attached.
    #[test]
    fn a_matching_name_on_an_elf_reports_only_the_observation() {
        let findings = scan(&[("libtflite.so", elf(&[0u8; 64]))]);
        let library = library_findings(&findings);
        assert_eq!(library.len(), 1, "{findings:?}");

        let finding = library[0];
        assert_eq!(
            finding.metadata.get("matched_pattern").map(String::as_str),
            Some("libtflite")
        );
        assert!(
            !finding.metadata.contains_key("format"),
            "a filename match claimed a model format: {:?}",
            finding.metadata
        );
        assert!(
            !finding.metadata.contains_key("runtime"),
            "a filename match claimed a runtime identity: {:?}",
            finding.metadata
        );
        assert!(
            finding.title.contains("filename matches"),
            "{}",
            finding.title
        );
    }

    /// Parsed-format detection is untouched: a real MAGIK header still yields
    /// the format claim and its parsed fields.
    #[test]
    fn an_actual_magik_header_still_reports_the_parsed_format() {
        let mut model = Vec::new();
        for word in [0x08ACu32, 0, 0, 320, 240, 3, 0, 6, 36] {
            model.extend_from_slice(&word.to_le_bytes());
        }
        model.extend_from_slice(&[0u8; 64]);

        let findings = scan(&[("persondet.bin", model)]);
        let model_finding = findings
            .iter()
            .find(|finding| {
                finding.metadata.get("artifact_kind").map(String::as_str) == Some("model")
            })
            .expect("parsed MAGIK finding");
        assert_eq!(
            model_finding.metadata.get("format").map(String::as_str),
            Some("magik")
        );
        assert_eq!(
            model_finding
                .metadata
                .get("input_shape")
                .map(String::as_str),
            Some("320x240x3")
        );
    }
}
