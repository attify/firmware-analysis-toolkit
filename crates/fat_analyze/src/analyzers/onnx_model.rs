use super::edge_ai_common::{
    find_extracted_root, infer_extracted_root_from_observed_path, inference_filename_finding,
};
use super::model_metadata::{join_limited, metadata, unique_limited};
use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};
use std::fs;
use std::path::Path;

// ONNX ModelProto: ir_version is field 1, wire type 0 (varint) → tag byte = 0x08
const ONNX_IR_VERSION_TAG: u8 = 0x08;

// Valid ONNX IR versions: 1-12
const VALID_IR_VERSIONS: std::ops::RangeInclusive<u32> = 1..=12;

// ONNX runtime library patterns
const ONNX_LIBRARY_PATTERNS: &[&str] = &[
    "libonnxruntime",
    "libonnx",
    "libopenvino",
    "libvitis_ai",
    "libtensorrt",
];

// Standard ONNX extensions
const ONNX_EXTENSIONS: &[&str] = &["onnx"];

#[derive(Debug, Default)]
pub struct OnnxModelAnalyzer;

#[derive(Debug, Clone)]
struct OnnxMetadata {
    ir_version: u32,
    file_size: u64,
    producer_name: Option<String>,
    graph_name: Option<String>,
    op_types: Vec<String>,
    input_names: Vec<String>,
    output_names: Vec<String>,
    input_shapes: Vec<String>,
    output_shapes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct ProtoField<'a> {
    number: u32,
    value: ProtoValue<'a>,
}

#[derive(Debug, Clone, Copy)]
enum ProtoValue<'a> {
    Varint(u64),
    LengthDelimited(&'a [u8]),
    Other,
}

fn parse_onnx_header(data: &[u8]) -> Option<OnnxMetadata> {
    if data.len() < 4 {
        return None;
    }

    if data[0] != ONNX_IR_VERSION_TAG {
        return None;
    }

    let mut ir_version = None;
    let mut producer_name = None;
    let mut graph = None;

    for field in proto_fields(data) {
        match (field.number, field.value) {
            (1, ProtoValue::Varint(value)) => ir_version = u32::try_from(value).ok(),
            (2, ProtoValue::LengthDelimited(value)) => producer_name = proto_string(value),
            (7, ProtoValue::LengthDelimited(value)) => graph = Some(value),
            _ => {}
        }
    }

    let ir_version = ir_version?;
    if !VALID_IR_VERSIONS.contains(&ir_version) {
        return None;
    }

    let graph = graph.map(parse_onnx_graph).unwrap_or_default();

    Some(OnnxMetadata {
        ir_version,
        file_size: data.len() as u64,
        producer_name,
        graph_name: graph.name,
        op_types: graph.op_types,
        input_names: graph.input_names,
        output_names: graph.output_names,
        input_shapes: graph.input_shapes,
        output_shapes: graph.output_shapes,
    })
}

#[derive(Default)]
struct OnnxGraphMetadata {
    name: Option<String>,
    op_types: Vec<String>,
    input_names: Vec<String>,
    output_names: Vec<String>,
    input_shapes: Vec<String>,
    output_shapes: Vec<String>,
}

fn parse_onnx_graph(data: &[u8]) -> OnnxGraphMetadata {
    let mut graph = OnnxGraphMetadata::default();

    for field in proto_fields(data) {
        match (field.number, field.value) {
            (1, ProtoValue::LengthDelimited(value)) => {
                if let Some(op_type) = parse_onnx_node_op_type(value) {
                    graph.op_types.push(op_type);
                }
            }
            (2, ProtoValue::LengthDelimited(value)) => graph.name = proto_string(value),
            (11, ProtoValue::LengthDelimited(value)) => {
                if let Some(value_info) = parse_onnx_value_info(value) {
                    if !value_info.name.is_empty() {
                        graph.input_names.push(value_info.name.clone());
                    }
                    if let Some(shape) = value_info.shape {
                        graph
                            .input_shapes
                            .push(format!("{}:{}", value_info.name, shape));
                    }
                }
            }
            (12, ProtoValue::LengthDelimited(value)) => {
                if let Some(value_info) = parse_onnx_value_info(value) {
                    if !value_info.name.is_empty() {
                        graph.output_names.push(value_info.name.clone());
                    }
                    if let Some(shape) = value_info.shape {
                        graph
                            .output_shapes
                            .push(format!("{}:{}", value_info.name, shape));
                    }
                }
            }
            _ => {}
        }
    }

    graph.op_types = unique_limited(graph.op_types, 32);
    graph.input_names = unique_limited(graph.input_names, 16);
    graph.output_names = unique_limited(graph.output_names, 16);
    graph.input_shapes = unique_limited(graph.input_shapes, 16);
    graph.output_shapes = unique_limited(graph.output_shapes, 16);
    graph
}

fn parse_onnx_node_op_type(data: &[u8]) -> Option<String> {
    for field in proto_fields(data) {
        if let (4, ProtoValue::LengthDelimited(value)) = (field.number, field.value) {
            return proto_string(value);
        }
    }
    None
}

struct OnnxValueInfo {
    name: String,
    shape: Option<String>,
}

fn parse_onnx_value_info(data: &[u8]) -> Option<OnnxValueInfo> {
    let mut name = None;
    let mut type_proto = None;

    for field in proto_fields(data) {
        match (field.number, field.value) {
            (1, ProtoValue::LengthDelimited(value)) => name = proto_string(value),
            (2, ProtoValue::LengthDelimited(value)) => type_proto = Some(value),
            _ => {}
        }
    }

    Some(OnnxValueInfo {
        name: name?,
        shape: type_proto.and_then(parse_onnx_type_shape),
    })
}

fn parse_onnx_type_shape(data: &[u8]) -> Option<String> {
    for field in proto_fields(data) {
        if let (1, ProtoValue::LengthDelimited(tensor_type)) = (field.number, field.value) {
            for tensor_field in proto_fields(tensor_type) {
                if let (2, ProtoValue::LengthDelimited(shape)) =
                    (tensor_field.number, tensor_field.value)
                {
                    return parse_onnx_shape(shape);
                }
            }
        }
    }
    None
}

fn parse_onnx_shape(data: &[u8]) -> Option<String> {
    let mut dims = Vec::new();
    for field in proto_fields(data) {
        if let (1, ProtoValue::LengthDelimited(dim)) = (field.number, field.value) {
            dims.push(parse_onnx_dim(dim));
        }
    }

    (!dims.is_empty()).then(|| dims.join("x"))
}

fn parse_onnx_dim(data: &[u8]) -> String {
    for field in proto_fields(data) {
        match (field.number, field.value) {
            (1, ProtoValue::Varint(value)) => return value.to_string(),
            (2, ProtoValue::LengthDelimited(value)) => {
                if let Some(value) = proto_string(value) {
                    return value;
                }
            }
            _ => {}
        }
    }
    "?".to_string()
}

fn proto_fields(data: &[u8]) -> Vec<ProtoField<'_>> {
    let mut offset = 0;
    let mut fields = Vec::new();

    while offset < data.len() {
        let Some((tag, next_offset)) = read_varint(data, offset) else {
            break;
        };
        offset = next_offset;
        let number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match wire_type {
            0 => {
                let Some((value, next_offset)) = read_varint(data, offset) else {
                    break;
                };
                offset = next_offset;
                fields.push(ProtoField {
                    number,
                    value: ProtoValue::Varint(value),
                });
            }
            2 => {
                let Some((len, data_offset)) = read_varint(data, offset) else {
                    break;
                };
                let len = len as usize;
                let Some(end) = data_offset.checked_add(len) else {
                    break;
                };
                if end > data.len() {
                    break;
                }
                offset = end;
                fields.push(ProtoField {
                    number,
                    value: ProtoValue::LengthDelimited(&data[data_offset..end]),
                });
            }
            1 => {
                let Some(next_offset) = offset.checked_add(8) else {
                    break;
                };
                if next_offset > data.len() {
                    break;
                }
                offset = next_offset;
                fields.push(ProtoField {
                    number,
                    value: ProtoValue::Other,
                });
            }
            5 => {
                let Some(next_offset) = offset.checked_add(4) else {
                    break;
                };
                if next_offset > data.len() {
                    break;
                }
                offset = next_offset;
                fields.push(ProtoField {
                    number,
                    value: ProtoValue::Other,
                });
            }
            _ => break,
        }
    }

    fields
}

fn read_varint(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    while offset < data.len() && shift <= 63 {
        let byte = data[offset];
        offset += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }

    None
}

fn proto_string(data: &[u8]) -> Option<String> {
    std::str::from_utf8(data)
        .ok()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn onnx_metadata(metadata_value: &OnnxMetadata) -> super::model_metadata::ModelMetadata {
    let mut values = metadata([
        ("format", "onnx".to_string()),
        ("artifact_kind", "model".to_string()),
        ("ir_version", metadata_value.ir_version.to_string()),
        ("file_size_bytes", metadata_value.file_size.to_string()),
        ("op_types", join_limited(&metadata_value.op_types, 32)),
        ("input_names", join_limited(&metadata_value.input_names, 16)),
        (
            "output_names",
            join_limited(&metadata_value.output_names, 16),
        ),
        (
            "input_shapes",
            join_limited(&metadata_value.input_shapes, 16),
        ),
        (
            "output_shapes",
            join_limited(&metadata_value.output_shapes, 16),
        ),
    ]);

    if let Some(value) = &metadata_value.producer_name {
        values.insert("producer_name".to_string(), value.clone());
    }
    if let Some(value) = &metadata_value.graph_name {
        values.insert("graph_name".to_string(), value.clone());
    }

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
        for pattern in ONNX_LIBRARY_PATTERNS {
            if let Some(finding) = inference_filename_finding(
                &path,
                base_root,
                pattern,
                format!("ai-library-onnx-{}", *lib_count + 1),
                "onnx-model",
            ) {
                *lib_count += 1;
                findings.push(finding);
            }
        }

        // Check extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_onnx_ext = ONNX_EXTENSIONS.contains(&ext);

        if !is_onnx_ext {
            continue;
        }

        let Ok(metadata) = path.metadata() else {
            continue;
        };
        if metadata.len() < 4 {
            continue;
        }

        let Ok(data) = fs::read(&path) else { continue };
        if let Some(model_metadata) = parse_onnx_header(&data) {
            *model_count += 1;
            let rel = path
                .strip_prefix(base_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let description = format!(
                "ONNX model: {} ({:.0}KB, IR v{}) — extractable for adversarial attacks",
                fname,
                model_metadata.file_size as f64 / 1024.0,
                model_metadata.ir_version,
            );
            findings.push(
                Finding::new(
                    format!("onnx-model-{model_count}"),
                    description,
                    FindingSeverity::High,
                    FindingSubject::File { rel_path: rel },
                )
                .with_metadata(onnx_metadata(&model_metadata))
                .with_plugin_id("onnx-model"),
            );
        }
    }
}

impl Analyzer for OnnxModelAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "onnx-model",
            "ONNX Model Scanner",
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
