use std::fs;
use std::process::Command;

#[test]
fn discover_cli_emits_family_scoped_discovery_leads_in_json_and_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("buffer_upload.cpp");
    fs::write(
        &sample,
        r#"
unsigned long MakeBuffer(unsigned long x) { return x; }
void copyBytes(unsigned long, unsigned long) {}
void saturateStride(unsigned long) {}

void referenceBufferUpload(unsigned long len, unsigned long pitch)
{
  auto buffer = MakeBuffer(pitch);
  copyBytes(buffer, len);
  saturateStride(pitch);
}

void replay_buffer_copy(unsigned long len, unsigned long pitch)
{
  auto buffer = MakeBuffer(pitch);
  copyBytes(buffer, len);
  saturateStride(pitch);
}
"#,
    )
    .expect("write source fixture");
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "c++", "-std=c++17", "{}"]
}}]"#,
            root.display(),
            sample.display(),
            sample.display()
        ),
    )
    .expect("write compile commands");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "discover",
            "--fixture",
            &root.display().to_string(),
            "--family",
            "size-stride-arithmetic",
            "--json",
        ])
        .output()
        .expect("fat discover json runs");

    assert!(json_output.status.success(), "{json_output:?}");
    let json_stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(json_stdout.contains("\"lead_count\""), "{json_stdout}");
    assert!(
        json_stdout.contains("\"family_filter\": \"size-stride-arithmetic\""),
        "{json_stdout}"
    );
    assert!(
        json_stdout.contains("\"family\": \"SizeStrideArithmetic\""),
        "{json_stdout}"
    );
    assert!(
        json_stdout.contains("pitch-depth-mismatch"),
        "{json_stdout}"
    );
    assert!(
        json_stdout.contains("asan-heap-buffer-overflow"),
        "{json_stdout}"
    );
    assert!(json_stdout.contains("replay_buffer_copy"), "{json_stdout}");

    let text_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "discover",
            "--fixture",
            &root.display().to_string(),
            "--family",
            "size-stride-arithmetic",
        ])
        .output()
        .expect("fat discover text runs");

    assert!(text_output.status.success(), "{text_output:?}");
    let text_stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(text_stdout.contains("Discover Leads"), "{text_stdout}");
    assert!(
        text_stdout.contains("family: size-stride-arithmetic"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("trigger: pitch-depth-mismatch"),
        "{text_stdout}"
    );
    assert!(
        text_stdout.contains("proof: asan-heap-buffer-overflow"),
        "{text_stdout}"
    );
}

#[test]
fn discover_cli_supports_python_source_trees() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("remote_validation.py");
    fs::write(
        &sample,
        r#"
def validate_remote_action(payload):
    if not payload:
        reject_bad_message(payload)
    dispatch_remote_action(payload)

def reject_bad_message(payload):
    return payload

def dispatch_remote_action(payload):
    return payload
"#,
    )
    .expect("write python fixture");

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "discover",
            "--fixture",
            &root.display().to_string(),
            "--family",
            "validation",
            "--json",
        ])
        .output()
        .expect("fat discover python runs");

    assert!(json_output.status.success(), "{json_output:?}");
    let json_stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(json_stdout.contains("\"lead_count\""), "{json_stdout}");
    assert!(
        json_stdout.contains("\"family\": \"ValidationTrustBoundary\""),
        "{json_stdout}"
    );
    assert!(
        json_stdout.contains("validate_remote_action"),
        "{json_stdout}"
    );
}
