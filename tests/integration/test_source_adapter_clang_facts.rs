use fat_query::adapters::source_clang_facts::{
    maybe_analyze_source_tree, maybe_analyze_source_tree_with_options, SourceAnalysisOptions,
};
use fat_query::adapters::traits::ExecutionMode;
use fat_query::result::SourceBackendKind;
use std::fs;

fn write_objcpp_fixture(root: &std::path::Path) {
    let sample = root.join("TextureMtl.mm");
    fs::write(
        &sample,
        r#"
int MakeBuffer(int x) { return x; }
void SaturateDepth(int) {}
void CopyBufferToOriginalTextureIfDstIsAView(int, int) {}

class TextureMtl {
public:
  void setPerSliceSubImage(int srcBytesPerImage, int pixelsDepthPitch)
  {
    auto buffer = MakeBuffer(pixelsDepthPitch);
    SaturateDepth(srcBytesPerImage);
    CopyBufferToOriginalTextureIfDstIsAView(buffer, srcBytesPerImage);
  }
};
"#,
    )
    .expect("write fixture source");

    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-target", "arm64-apple-darwin", "{}"]
}}]"#,
            root.display(),
            sample.display(),
            sample.display()
        ),
    )
    .expect("write compile commands");

    fs::write(
        root.join("fat-toolchain-profile.json"),
        r#"{
  "target_triple": "arm64-apple-darwin",
  "runtime_hints": ["vertical-slice"]
}"#,
    )
    .expect("write toolchain profile");
}

#[test]
fn clang_facts_adapter_recovers_methods_and_calls_from_objcpp_fixture() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_objcpp_fixture(dir.path());

    let summary = maybe_analyze_source_tree(dir.path())
        .expect("analyze source tree")
        .expect("source analysis summary");

    assert_eq!(summary.reports.len(), 2, "expected dual-backend analysis");
    assert!(
        summary
            .reports
            .iter()
            .any(|report| report.backend == SourceBackendKind::AstDumpJson),
        "missing ast dump backend: {:?}",
        summary.reports
    );
    assert!(
        summary
            .reports
            .iter()
            .any(|report| report.backend == SourceBackendKind::LibclangBackend),
        "missing libclang backend: {:?}",
        summary.reports
    );

    let method_names = summary
        .reports
        .iter()
        .flat_map(|report| {
            report
                .methods
                .iter()
                .map(|method| method.qualified_name.clone())
        })
        .collect::<Vec<_>>();
    assert!(
        method_names
            .iter()
            .any(|name| name.contains("setPerSliceSubImage")),
        "expected setPerSliceSubImage in {method_names:?}"
    );

    let call_names = summary
        .reports
        .iter()
        .flat_map(|report| report.calls.iter().map(|call| call.callee_name.clone()))
        .collect::<Vec<_>>();
    assert!(call_names.iter().any(|name| name == "MakeBuffer"));
    assert!(call_names.iter().any(|name| name == "SaturateDepth"));
    assert!(call_names
        .iter()
        .any(|name| name == "CopyBufferToOriginalTextureIfDstIsAView"));

    assert!(
        summary
            .merged_observed
            .iter()
            .any(|entry| entry.contains("recovered 1 methods")
                || entry.contains("recovered 3 callsites")),
        "expected merged observations in {:?}",
        summary.merged_observed
    );
}

#[test]
fn clang_facts_adapter_persists_debug_bundle_when_requested() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_objcpp_fixture(dir.path());
    let bundle_dir = dir.path().join("debug-bundle");

    let summary = maybe_analyze_source_tree_with_options(
        dir.path(),
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: Some(bundle_dir.clone()),
            budgets: None,
        },
    )
    .expect("analyze with bundle")
    .expect("summary");
    let bundle_dir_string = bundle_dir.display().to_string();

    assert_eq!(
        summary.metadata.get("debug_bundle_dir").map(String::as_str),
        Some(bundle_dir_string.as_str())
    );
    assert!(bundle_dir.join("summary.json").is_file());
    assert!(bundle_dir.join("AstDumpJson-report.json").is_file());
    assert!(bundle_dir.join("AstDumpJson.ast.json").is_file());
}
