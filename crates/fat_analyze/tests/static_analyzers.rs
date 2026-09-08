use fat_analyze::analyzers::binary_static::BinaryStaticAnalyzer;
use fat_analyze::analyzers::config_static::ConfigStaticAnalyzer;
use fat_analyze::analyzers::credential_static::CredentialStaticAnalyzer;
use fat_analyze::analyzers::web_surface_static::WebSurfaceStaticAnalyzer;
use fat_analyze::edge_ai::{scan_edge_ai_root, EdgeAiFormat};
use fat_analyze::engine::{AnalysisEngine, AnalyzerRegistry};
use fat_analyze::request::{ArtifactDocument, NormalizedAnalysisRequest};
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{FindingSeverity, FindingSubject};
use fat_core::inventory::{AnalysisSnapshot, BinaryRecord};
use fat_core::project::Architecture;
use fat_plugin_api::{AnalysisTrigger, ArtifactRef, ArtifactScope};

#[test]
fn static_analyzers_emit_findings_from_normalized_extraction_and_target_artifacts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(BinaryStaticAnalyzer);
    registry.register(CredentialStaticAnalyzer);
    registry.register(ConfigStaticAnalyzer);
    registry.register(WebSurfaceStaticAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::AnalysisRequested,
        "project-demo",
        "target-demo",
    )
    .with_artifacts(vec![
        ArtifactRef::new(
            "art-analysis-1",
            ArtifactKind::Analysis,
            ArtifactScope::Target,
        ),
        ArtifactRef::new(
            "art-config-1",
            ArtifactKind::Analysis,
            ArtifactScope::Target,
        ),
    ])
    .with_artifact_documents(vec![
        ArtifactDocument::new(
            "art-credential-1",
            ArtifactKind::Analysis,
            ArtifactScope::Target,
            "credential-summary",
            Some("analysis/credentials.txt".to_string()),
            "text/plain",
            Some("default_password=admin".to_string()),
        ),
        ArtifactDocument::new(
            "art-config-1",
            ArtifactKind::Analysis,
            ArtifactScope::Target,
            "config",
            Some("etc/config/uhttpd".to_string()),
            "text/plain",
            Some("option listen_http 0.0.0.0:80".to_string()),
        ),
        ArtifactDocument::new(
            "art-web-1",
            ArtifactKind::Analysis,
            ArtifactScope::Target,
            "web-surface",
            Some("www/cgi-bin/status.cgi".to_string()),
            "text/plain",
            Some("cgi endpoint".to_string()),
        ),
    ])
    .with_snapshot(AnalysisSnapshot {
        binaries: vec![BinaryRecord {
            id: "bin-1".to_string(),
            name: "httpd".to_string(),
            rel_path: "bin/httpd".to_string(),
            architecture: Architecture::Armel,
            nx: Some(false),
            pie: Some(false),
            canary: Some(true),
        }],
        findings: Vec::new(),
    });

    let result = engine.analyze_request(&request);
    assert!(result.findings.len() >= 4);
    assert!(result.findings.iter().any(|finding| {
        matches!(
            finding.subject,
            FindingSubject::Binary { ref binary_id } if binary_id == "bin-1"
        )
    }));
}

#[test]
fn static_analyzers_attach_supporting_artifact_ids_and_plugin_identity() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(CredentialStaticAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::AnalysisRequested,
        "project-demo",
        "target-demo",
    )
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-credential-1",
        ArtifactKind::Analysis,
        ArtifactScope::Target,
        "credential-summary",
        Some("analysis/credentials.txt".to_string()),
        "text/plain",
        Some("default_password=admin".to_string()),
    )]);

    let result = engine.analyze_request(&request);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].plugin_id.as_deref(),
        Some("credential-static")
    );
    assert_eq!(
        result.findings[0].evidence_artifact_ids,
        vec!["art-credential-1".to_string()]
    );
}

#[test]
fn static_analyzers_do_not_depend_on_backend_specific_layouts() {
    let mut registry = AnalyzerRegistry::new();
    registry.register(WebSurfaceStaticAnalyzer);
    let engine = AnalysisEngine::new(registry);

    let request = NormalizedAnalysisRequest::new(
        AnalysisTrigger::AnalysisRequested,
        "project-demo",
        "target-demo",
    )
    .with_artifact_documents(vec![ArtifactDocument::new(
        "art-web-1",
        ArtifactKind::Analysis,
        ArtifactScope::Target,
        "web-surface",
        Some("generic/www/index.html".to_string()),
        "text/plain",
        Some("http management".to_string()),
    )]);

    let result = engine.analyze_request(&request);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].plugin_id.as_deref(),
        Some("web-surface-static")
    );
}

#[test]
fn edge_ai_scan_api_reuses_rust_magik_scanner_for_arbitrary_rootfs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rootfs = dir.path().join("squashfs-root");
    let models = rootfs.join("usr/share/ai");
    std::fs::create_dir_all(&models).expect("model dir");

    let mut magik = Vec::new();
    for word in [0x08ACu32, 0, 1, 320, 240, 3, 0, 6, 36] {
        magik.extend_from_slice(&word.to_le_bytes());
    }
    magik.extend_from_slice(&[0u8; 64]);
    std::fs::write(models.join("persondet.bin"), magik).expect("magik fixture");

    let report = scan_edge_ai_root(&rootfs, &[EdgeAiFormat::Magik]).expect("scan rootfs");

    assert_eq!(report.schema_version, "edge-ai-scan/v1");
    assert_eq!(report.formats, vec![EdgeAiFormat::Magik]);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].plugin_id.as_deref(), Some("magik-model"));
    assert_eq!(report.findings[0].severity, FindingSeverity::High);
    assert!(
        matches!(
            &report.findings[0].subject,
            FindingSubject::File { rel_path } if rel_path == "usr/share/ai/persondet.bin"
        ),
        "expected rootfs-relative MAGIK finding, got {:?}",
        report.findings[0].subject
    );
}

#[test]
fn edge_ai_scan_json_reports_structured_metadata_for_all_model_formats() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rootfs = dir.path().join("edge-rootfs");
    let models = rootfs.join("opt/models");
    std::fs::create_dir_all(&models).expect("model dir");

    let mut magik = Vec::new();
    for word in [0x08ACu32, 0, 1, 320, 240, 3, 0, 6, 36] {
        magik.extend_from_slice(&word.to_le_bytes());
    }
    magik.extend_from_slice(&[0u8; 64]);
    std::fs::write(models.join("persondet.bin"), magik).expect("magik fixture");

    let mut tflite = Vec::new();
    tflite.extend_from_slice(&8u32.to_le_bytes());
    tflite.extend_from_slice(b"TFL3");
    for value in [1u32, 96, 96, 3, 42, 17, 9] {
        tflite.extend_from_slice(&value.to_le_bytes());
    }
    tflite.extend_from_slice(b"input_tensor\0output_scores\0CONV_2D\0RESHAPE\0INT8\0");
    tflite.resize(12 * 1024, 0);
    std::fs::write(models.join("wake_word.tflite"), tflite).expect("tflite fixture");

    std::fs::write(models.join("vision.onnx"), minimal_onnx_model()).expect("onnx fixture");

    let mut dlc = Vec::new();
    dlc.extend_from_slice(
        b"model_name=lane_policy\0source_framework=onnx\0quantization=int8\0QNN\0Hexagon\0HTA\0",
    );
    dlc.resize(64 * 1024, 0);
    std::fs::write(models.join("lane_policy.dlc"), dlc).expect("dlc fixture");

    let report = scan_edge_ai_root(&rootfs, &[]).expect("scan rootfs");
    let report_json = serde_json::to_value(&report).expect("json report");
    let findings = report_json["findings"].as_array().expect("findings array");

    let magik = finding_by_plugin(findings, "magik-model", "magik-model-1");
    assert_eq!(magik["metadata"]["format"], "magik");
    assert_eq!(magik["metadata"]["variant"], "MAGIK persondet");
    assert_eq!(magik["metadata"]["input_shape"], "320x240x3");
    assert_eq!(magik["metadata"]["layer_count"], "6");

    let tflite = finding_by_plugin(findings, "tflite-model", "tflite-model-1");
    assert_eq!(tflite["metadata"]["format"], "tflite");
    assert_eq!(tflite["metadata"]["embedding"], "direct-file");
    assert_eq!(tflite["metadata"]["input_shapes"], "1x96x96x3");
    assert_eq!(tflite["metadata"]["quantization"], "int8");
    assert!(tflite["metadata"]["op_types"]
        .as_str()
        .expect("tflite op_types")
        .contains("CONV_2D"));

    let onnx = finding_by_plugin(findings, "onnx-model", "onnx-model-1");
    assert_eq!(onnx["metadata"]["format"], "onnx");
    assert_eq!(onnx["metadata"]["ir_version"], "8");
    assert_eq!(onnx["metadata"]["graph_name"], "edge_graph");
    assert_eq!(onnx["metadata"]["input_names"], "camera_input");
    assert_eq!(onnx["metadata"]["output_names"], "person_score");
    assert_eq!(onnx["metadata"]["input_shapes"], "camera_input:1x224x224x3");
    assert!(onnx["metadata"]["op_types"]
        .as_str()
        .expect("onnx op_types")
        .contains("Conv"));

    let dlc = finding_by_plugin(findings, "dlc-model", "dlc-model-1");
    assert_eq!(dlc["metadata"]["format"], "dlc");
    assert_eq!(dlc["metadata"]["model_name"], "lane_policy");
    assert_eq!(dlc["metadata"]["source_framework"], "onnx");
    assert_eq!(dlc["metadata"]["quantization"], "int8");
    assert!(dlc["metadata"]["accelerator_hints"]
        .as_str()
        .expect("dlc accelerator_hints")
        .contains("Hexagon"));
}

#[test]
fn edge_ai_scan_covers_deterministic_synthetic_model_fixtures() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_root = temp.path();
    std::fs::create_dir_all(fixture_root.join("magik")).unwrap();
    std::fs::create_dir_all(fixture_root.join("onnx")).unwrap();
    let mut magik = Vec::new();
    for word in [0x08ACu32, 0, 1, 320, 240, 3, 0, 6, 36] {
        magik.extend_from_slice(&word.to_le_bytes());
    }
    magik.extend_from_slice(&[0u8; 64]);
    std::fs::write(fixture_root.join("magik/persondet.bin"), magik).unwrap();
    std::fs::write(fixture_root.join("onnx/sigmoid.onnx"), minimal_onnx_model()).unwrap();

    let report = scan_edge_ai_root(fixture_root, &[EdgeAiFormat::Magik, EdgeAiFormat::Onnx])
        .expect("scan real model fixtures");

    let report_json = serde_json::to_value(&report).expect("json report");
    let findings = report_json["findings"].as_array().expect("findings array");

    let magik = findings
        .iter()
        .find(|finding| finding["plugin_id"] == "magik-model")
        .expect("MAGIK finding from real fixture");
    assert_eq!(magik["metadata"]["format"], "magik");
    assert_ne!(
        magik["metadata"]["file_size_bytes"],
        serde_json::Value::Null
    );

    let onnx = findings
        .iter()
        .find(|finding| finding["plugin_id"] == "onnx-model")
        .expect("ONNX finding from real fixture");
    assert_eq!(onnx["metadata"]["format"], "onnx");
    assert_ne!(onnx["metadata"]["ir_version"], serde_json::Value::Null);
}

fn finding_by_plugin<'a>(
    findings: &'a [serde_json::Value],
    plugin_id: &str,
    finding_id: &str,
) -> &'a serde_json::Value {
    findings
        .iter()
        .find(|finding| finding["plugin_id"] == plugin_id && finding["id"] == finding_id)
        .unwrap_or_else(|| panic!("missing finding {plugin_id}/{finding_id}: {findings:#?}"))
}

fn minimal_onnx_model() -> Vec<u8> {
    let conv = onnx_node("conv_1", "Conv", &["camera_input"], &["conv_out"]);
    let relu = onnx_node("relu_1", "Relu", &["conv_out"], &["person_score"]);
    let graph = onnx_message(vec![
        onnx_bytes_field(1, &conv),
        onnx_bytes_field(1, &relu),
        onnx_string_field(2, "edge_graph"),
        onnx_bytes_field(11, &onnx_value_info("camera_input", &[1, 224, 224, 3])),
        onnx_bytes_field(12, &onnx_value_info("person_score", &[1, 1])),
    ]);

    onnx_message(vec![
        onnx_varint_field(1, 8),
        onnx_string_field(2, "fat-fixture"),
        onnx_bytes_field(7, &graph),
    ])
}

fn onnx_node(name: &str, op_type: &str, inputs: &[&str], outputs: &[&str]) -> Vec<u8> {
    let mut fields = Vec::new();
    for input in inputs {
        fields.push(onnx_string_field(1, input));
    }
    for output in outputs {
        fields.push(onnx_string_field(2, output));
    }
    fields.push(onnx_string_field(3, name));
    fields.push(onnx_string_field(4, op_type));
    onnx_message(fields)
}

fn onnx_value_info(name: &str, dims: &[u64]) -> Vec<u8> {
    let dim_fields = dims
        .iter()
        .map(|dim| onnx_bytes_field(1, &onnx_message(vec![onnx_varint_field(1, *dim)])))
        .collect::<Vec<_>>();
    let shape = onnx_message(dim_fields);
    let tensor_type = onnx_message(vec![onnx_varint_field(1, 1), onnx_bytes_field(2, &shape)]);
    let type_proto = onnx_message(vec![onnx_bytes_field(1, &tensor_type)]);
    onnx_message(vec![
        onnx_string_field(1, name),
        onnx_bytes_field(2, &type_proto),
    ])
}

fn onnx_message(fields: Vec<Vec<u8>>) -> Vec<u8> {
    fields.into_iter().flatten().collect()
}

fn onnx_string_field(field_number: u64, value: &str) -> Vec<u8> {
    onnx_bytes_field(field_number, value.as_bytes())
}

fn onnx_bytes_field(field_number: u64, value: &[u8]) -> Vec<u8> {
    let mut out = encode_varint((field_number << 3) | 2);
    out.extend(encode_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

fn onnx_varint_field(field_number: u64, value: u64) -> Vec<u8> {
    let mut out = encode_varint(field_number << 3);
    out.extend(encode_varint(value));
    out
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
