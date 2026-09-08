use super::edge_ai_common::{
    find_extracted_root, infer_extracted_root_from_observed_path, inference_filename_finding,
};
use super::model_metadata::{
    insert_if_present, join_limited, metadata, printable_strings, unique_limited,
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

// TFLite FlatBuffer magic: 'TFL3' at bytes 4-7
const TFLITE_MAGIC: &[u8; 4] = b"TFL3";

// Minimum model size (10KB for TFLite Micro)
const MIN_MODEL_SIZE: u64 = 10 * 1024;

// Known TFLite / Edge AI inference library patterns
const AI_LIBRARY_PATTERNS: &[&str] = &[
    "libtflite",
    "libtensorflowlite",
    "libedgetpu",
    "libcoral",
    "libonnxruntime",
    "libncnn",
    "libmace",
    "libesp-nn",
    "libarmnn",
    "libcmsis-nn",
];

// C array embedding patterns — common symbol names for embedded TFLite models
const EMBEDDED_SYMBOLS: &[&str] = &[
    "g_model",
    "model_data",
    "g_person_detect_model_data",
    "g_keyword_spotting_model_data",
    "g_micro_speech_model_data",
    "ei_model",
    "tflite_model",
];

#[derive(Debug, Default)]
pub struct TFLiteModelAnalyzer;

#[derive(Debug, Clone)]
struct TFLiteHeader {
    file_size: u64,
    op_count: u32,
    tensor_count: u32,
    input_shapes: Vec<String>,
    input_names: Vec<String>,
    output_names: Vec<String>,
    op_types: Vec<String>,
    quantization: Option<String>,
}

fn parse_tflite_header(data: &[u8]) -> Option<TFLiteHeader> {
    if data.len() < 8 {
        return None;
    }

    // Check TFL3 magic at bytes 4-7
    if &data[4..8] != TFLITE_MAGIC {
        return None;
    }

    let root_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if root_offset as usize > data.len() {
        return None;
    }

    // Heuristic operator and tensor counting
    let op_count = estimate_op_count(data);
    let tensor_count = estimate_tensor_count(data);
    let strings = printable_strings(&data[..data.len().min(256 * 1024)], 3, 256);

    Some(TFLiteHeader {
        file_size: data.len() as u64,
        op_count,
        tensor_count,
        input_shapes: detect_common_nhwc_shapes(data),
        input_names: detect_tensor_names(&strings, &["input", "image", "audio", "tensor"]),
        output_names: detect_tensor_names(&strings, &["output", "score", "prob", "logit"]),
        op_types: detect_tflite_op_types(&strings),
        quantization: detect_quantization(&strings),
    })
}

fn estimate_op_count(data: &[u8]) -> u32 {
    let mut count: u32 = 0;
    let max_offset = data.len().min(8192);
    let mut offset: usize = 8;
    while offset + 4 <= max_offset {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if (1..=150).contains(&val) {
            count += 1;
            offset += 4;
        } else {
            offset += 1;
        }
    }
    count.min(200)
}

fn estimate_tensor_count(data: &[u8]) -> u32 {
    let mut count: u32 = 0;
    let max_offset = data.len().min(8192);
    let mut offset: usize = 8;
    while offset + 4 <= max_offset {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if val <= 1000 {
            count += 1;
            offset += 4;
        } else {
            offset += 1;
        }
    }
    count.min(500)
}

fn detect_common_nhwc_shapes(data: &[u8]) -> Vec<String> {
    let max_offset = data.len().min(64 * 1024);
    if max_offset < 16 {
        return Vec::new();
    }

    let mut shapes = Vec::new();
    for offset in 0..=(max_offset - 16) {
        let dims = [
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]),
            u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]),
            u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]),
            u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]),
        ];

        if dims[0] == 1
            && (8..=4096).contains(&dims[1])
            && (8..=4096).contains(&dims[2])
            && matches!(dims[3], 1 | 3 | 4)
        {
            shapes.push(format!("{}x{}x{}x{}", dims[0], dims[1], dims[2], dims[3]));
        }
    }

    unique_limited(shapes, 4)
}

fn detect_tensor_names(strings: &[String], markers: &[&str]) -> Vec<String> {
    unique_limited(
        strings
            .iter()
            .filter(|value| {
                let lower = value.to_ascii_lowercase();
                markers.iter().any(|marker| lower.contains(marker))
                    && value.len() <= 80
                    && !lower.contains("tensorflow")
            })
            .cloned(),
        6,
    )
}

fn detect_tflite_op_types(strings: &[String]) -> Vec<String> {
    const OPS: &[&str] = &[
        "CONV_2D",
        "DEPTHWISE_CONV_2D",
        "FULLY_CONNECTED",
        "AVERAGE_POOL_2D",
        "MAX_POOL_2D",
        "RESHAPE",
        "SOFTMAX",
        "LOGISTIC",
        "ADD",
        "MUL",
        "LSTM",
        "SVDF",
    ];

    unique_limited(
        OPS.iter()
            .filter(|&op| strings.iter().any(|value| value.contains(op)))
            .map(|op| (*op).to_string()),
        12,
    )
}

fn detect_quantization(strings: &[String]) -> Option<String> {
    let haystack = strings.join("\n").to_ascii_lowercase();
    for marker in ["int8", "uint8", "int16", "float16", "float32"] {
        if haystack.contains(marker) {
            return Some(marker.to_string());
        }
    }
    None
}

fn tflite_metadata(header: &TFLiteHeader, embedding: &str) -> super::model_metadata::ModelMetadata {
    let mut values = metadata([
        ("format", "tflite".to_string()),
        ("artifact_kind", "model".to_string()),
        ("embedding", embedding.to_string()),
        ("file_size_bytes", header.file_size.to_string()),
        ("operator_count_estimate", header.op_count.to_string()),
        ("tensor_count_estimate", header.tensor_count.to_string()),
        ("input_shapes", join_limited(&header.input_shapes, 4)),
        ("input_names", join_limited(&header.input_names, 6)),
        ("output_names", join_limited(&header.output_names, 6)),
        ("op_types", join_limited(&header.op_types, 12)),
    ]);
    insert_if_present(&mut values, "quantization", header.quantization.clone());
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
        for pattern in AI_LIBRARY_PATTERNS {
            if let Some(finding) = inference_filename_finding(
                &path,
                base_root,
                pattern,
                format!("ai-library-tflite-{}", *lib_count + 1),
                "tflite-model",
            ) {
                *lib_count += 1;
                findings.push(finding);
            }
        }

        // Check file metadata
        let Ok(metadata) = path.metadata() else {
            continue;
        };
        if metadata.len() < 8 {
            continue;
        }

        // Direct .tflite files
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_tflite_ext = ext == "tflite" || ext == "lite";

        // Source files that commonly embed TFLite arrays
        let is_source_ext = matches!(ext, "cc" | "cpp" | "c" | "h" | "hpp" | "inc");

        // ELF files and shared objects
        let is_elf = ext == "so" || ext == "o" || ext == "ko" || ext == "a";

        // Generic binaries
        let is_binary = ext.is_empty() || ext == "bin" || ext == "dat" || ext == "fw";

        if !is_tflite_ext && !is_source_ext && !is_elf && !is_binary {
            continue;
        }

        // Read file data
        let Ok(data) = fs::read(&path) else {
            continue;
        };

        // --- Method 1: Direct .tflite file ---
        if is_tflite_ext {
            if let Some(header) = parse_tflite_header(&data) {
                *model_count += 1;
                let rel = path
                    .strip_prefix(base_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let description = format!(
                    "TFLite model: {} ({:.0}KB, ~{} ops, ~{} tensors) — extractable for white-box adversarial attacks",
                    fname,
                    header.file_size as f64 / 1024.0,
                    header.op_count,
                    header.tensor_count,
                );
                findings.push(
                    Finding::new(
                        format!("tflite-model-{model_count}"),
                        description,
                        FindingSeverity::High,
                        FindingSubject::File { rel_path: rel },
                    )
                    .with_metadata(tflite_metadata(&header, "direct-file"))
                    .with_plugin_id("tflite-model"),
                );
                continue;
            }
        }

        // --- Method 2: Source files with embedded C arrays ---
        if is_source_ext && metadata.len() > 100 {
            // Look for common embedded model symbol names
            for symbol in EMBEDDED_SYMBOLS {
                if let Some(pos) = data
                    .windows(symbol.len())
                    .position(|w| w == symbol.as_bytes())
                {
                    // Look for array assignment pattern after the symbol
                    let after = &data[pos + symbol.len()..];
                    // Crude check: does it look like an array initialization?
                    if after.len() > 10 {
                        let after_trimmed = after
                            .iter()
                            .skip_while(|b| b.is_ascii_whitespace())
                            .take(4)
                            .copied()
                            .collect::<Vec<u8>>();
                        if after_trimmed == b"[] =" || after_trimmed.starts_with(b"[") {
                            // Search nearby for TFLite magic
                            let search_start = pos.saturating_sub(100);
                            let search_end = (pos + 8192).min(data.len());
                            if let Some(tflite_pos) = data[search_start..search_end]
                                .windows(4)
                                .position(|w| w == TFLITE_MAGIC)
                            {
                                let model_start = search_start + tflite_pos - 4;
                                if model_start < data.len() {
                                    if let Some(header) = parse_tflite_header(&data[model_start..])
                                    {
                                        *model_count += 1;
                                        let rel = path
                                            .strip_prefix(base_root)
                                            .unwrap_or(&path)
                                            .to_string_lossy()
                                            .to_string();
                                        let description = format!(
                                            "TFLite model (embedded C array): {} → {} ({:.0}KB)",
                                            fname,
                                            symbol,
                                            metadata.len() as f64 / 1024.0,
                                        );
                                        findings.push(
                                            Finding::new(
                                                format!("tflite-embedded-{model_count}"),
                                                description,
                                                FindingSeverity::High,
                                                FindingSubject::File { rel_path: rel },
                                            )
                                            .with_metadata(tflite_metadata(&header, "c-array"))
                                            .with_plugin_id("tflite-model"),
                                        );
                                    }
                                }
                            }
                            break; // One find per file
                        }
                    }
                }
            }
        }

        // --- Method 3: Scan ELF/binary for TFLite magic ---
        if (is_elf || (is_binary && metadata.len() > 65536)) && data.len() >= 8 {
            // Quick scan for TFL3 magic in the first pass
            if let Some(tflite_pos) = data.windows(4).position(|w| w == TFLITE_MAGIC) {
                if tflite_pos >= 4 {
                    let model_start = tflite_pos - 4;
                    if let Some(header) = parse_tflite_header(&data[model_start..]) {
                        if header.file_size >= MIN_MODEL_SIZE {
                            *model_count += 1;
                            let rel = path
                                .strip_prefix(base_root)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .to_string();
                            let description = format!(
                                "TFLite model (embedded in binary): offset 0x{:X}, ~{}KB, ~{} ops",
                                model_start,
                                header.file_size / 1024,
                                header.op_count,
                            );
                            findings.push(
                                Finding::new(
                                    format!("tflite-binary-{model_count}"),
                                    description,
                                    FindingSeverity::High,
                                    FindingSubject::File { rel_path: rel },
                                )
                                .with_metadata(tflite_metadata(&header, "embedded-binary"))
                                .with_plugin_id("tflite-model"),
                            );
                        }
                    }
                }
            }
        }
    }
}

impl Analyzer for TFLiteModelAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "tflite-model",
            "TFLite Model Scanner",
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
