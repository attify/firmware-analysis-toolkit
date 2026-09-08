use std::fs;
use std::process::Command;

#[test]
fn invariant_query_json_includes_dual_backend_source_analysis_for_objcpp_fixture() {
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
  void setPerSliceSubImage(int srcBytesPerImage, int pixelsDepthPitch)
  {
    auto buffer = MakeBuffer(pixelsDepthPitch);
    SaturateDepth(srcBytesPerImage);
    CopyBufferToOriginalTextureIfDstIsAView(buffer, srcBytesPerImage);
  }
};
"#,
    )
    .expect("write source fixture");
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
  "target_triple": "arm64-apple-darwin"
}"#,
    )
    .expect("write toolchain profile");

    let debug_bundle = root.join("debug-bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "invariant",
            "query",
            "--fixture",
            &root.display().to_string(),
            "--rule",
            "Any invariant rule",
            "--mode",
            "deep",
            "--debug-bundle-dir",
            &debug_bundle.display().to_string(),
            "--json",
        ])
        .output()
        .expect("fat invariant query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"source_analysis\""), "{stdout}");
    assert!(stdout.contains("\"cache\""), "{stdout}");
    assert!(stdout.contains("\"source_plan\""), "{stdout}");
    assert!(stdout.contains("\"discovery_leads\""), "{stdout}");
    assert!(stdout.contains("AstDumpJson"), "{stdout}");
    assert!(stdout.contains("LibclangBackend"), "{stdout}");
    assert!(stdout.contains("setPerSliceSubImage"), "{stdout}");
    assert!(stdout.contains("SizeStrideArithmetic"), "{stdout}");
    assert!(debug_bundle.join("summary.json").is_file());
    assert!(debug_bundle.join("AstDumpJson-report.json").is_file());

    let human_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "invariant",
            "query",
            "--fixture",
            &root.display().to_string(),
            "--rule",
            "Any invariant rule",
            "--mode",
            "deep",
            "--debug-bundle-dir",
            &debug_bundle.display().to_string(),
        ])
        .output()
        .expect("fat invariant query runs");

    assert!(human_output.status.success(), "{human_output:?}");
    let human_stdout = String::from_utf8_lossy(&human_output.stdout);
    assert!(
        human_stdout.contains("cache/source-facts"),
        "{human_stdout}"
    );
    assert!(
        human_stdout.contains("reused-cached-reports"),
        "{human_stdout}"
    );
}
