use fat_query::adapters::source_clang_facts::{
    maybe_analyze_source_tree_with_options, SourceAnalysisOptions,
};
use fat_query::adapters::traits::ExecutionMode;
use fat_query::fusion::fuse_source_analysis;
use fat_query::planner::ResourceBudgets;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;

#[test]
fn slice_repair_recovers_facts_when_parser_backends_fail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("TextureMtl.mm");
    fs::write(
        &sample,
        r#"
int MakeBuffer(int x) { return x; }
void SaturateDepth(int) {}
void CopyBufferToOriginalTextureIfDstIsAView(int, int) {}

class TextureMtl {
public:
  void setPerSliceSubImageVariant(int srcBytesPerImage, int pixelsDepthPitch)
  {
    auto buffer = MakeBuffer(pixelsDepthPitch);
    CopyBufferToOriginalTextureIfDstIsAView(buffer, srcBytesPerImage);
    SaturateDepth(srcBytesPerImage);
  }
};
"#,
    )
    .expect("write source");
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-target", "bogus-unknown-none", "{}"]
}}]"#,
            root.display(),
            sample.display(),
            sample.display()
        ),
    )
    .expect("write compile commands");

    let mut summary = maybe_analyze_source_tree_with_options(
        root,
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: None,
            budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
        },
    )
    .expect("analyze source tree")
    .expect("summary");
    assert!(summary
        .reports
        .iter()
        .all(|report| report.methods.is_empty()));

    let repaired = fat_query::slice_expander::repair_source_analysis(
        root,
        &mut summary,
        &ResourceBudgets::for_mode(ExecutionMode::Deep),
    )
    .expect("repair source analysis")
    .expect("repair report");

    assert_eq!(repaired.backend.as_str(), "SyntheticSliceRepair");
    assert!(repaired
        .methods
        .iter()
        .any(|method| method.qualified_name.contains("setPerSliceSubImageVariant")));
    let fused = fuse_source_analysis(Some(&summary));
    assert!(fused
        .calls
        .iter()
        .any(|call| call.callee_name == "MakeBuffer"));
}

#[cfg(unix)]
#[test]
fn slice_repair_follows_symlinked_source_roots() {
    let backing = tempfile::tempdir().expect("backing");
    let fixture = tempfile::tempdir().expect("fixture");
    let source_root = backing.path().join("src");
    fs::create_dir_all(&source_root).expect("create source root");
    let sample = source_root.join("TextureMtl.mm");
    fs::write(
        &sample,
        r#"
int MakeBuffer(int x) { return x; }
void SaturateDepth(int) {}
void CopyBufferToOriginalTextureIfDstIsAView(int, int) {}

class TextureMtl {
public:
  void setPerSliceSubImageVariant(int srcBytesPerImage, int pixelsDepthPitch)
  {
    auto buffer = MakeBuffer(pixelsDepthPitch);
    CopyBufferToOriginalTextureIfDstIsAView(buffer, srcBytesPerImage);
    SaturateDepth(srcBytesPerImage);
  }
};
"#,
    )
    .expect("write source");

    let linked_src = fixture.path().join("src");
    symlink(&source_root, &linked_src).expect("symlink source root");
    let linked_sample = linked_src.join("TextureMtl.mm");
    fs::write(
        fixture.path().join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-target", "bogus-unknown-none", "{}"]
}}]"#,
            fixture.path().display(),
            linked_sample.display(),
            linked_sample.display()
        ),
    )
    .expect("write compile commands");

    let mut summary = maybe_analyze_source_tree_with_options(
        fixture.path(),
        &SourceAnalysisOptions {
            mode: ExecutionMode::Deep,
            debug_bundle_dir: None,
            budgets: Some(ResourceBudgets::for_mode(ExecutionMode::Deep)),
        },
    )
    .expect("analyze source tree")
    .expect("summary");
    assert!(summary
        .reports
        .iter()
        .all(|report| report.methods.is_empty()));

    let repaired = fat_query::slice_expander::repair_source_analysis(
        fixture.path(),
        &mut summary,
        &ResourceBudgets::for_mode(ExecutionMode::Deep),
    )
    .expect("repair source analysis")
    .expect("repair report");

    assert!(repaired
        .methods
        .iter()
        .any(|method| method.qualified_name.contains("setPerSliceSubImageVariant")));
    assert!(repaired
        .calls
        .iter()
        .any(|call| call.callee_name == "CopyBufferToOriginalTextureIfDstIsAView"));
}
