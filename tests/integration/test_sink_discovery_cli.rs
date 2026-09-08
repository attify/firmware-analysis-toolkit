use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn sink_discovery_profiles_list_shows_builtin_profile() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sink-discovery", "profiles", "list"])
        .output()
        .expect("fat sink-discovery profiles list runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("linux-command-exec"), "{stdout}");
}

#[test]
fn sink_discovery_profiles_validate_accepts_valid_profile() {
    let dir = tempdir().expect("tempdir");
    let profile_path = dir.path().join("profile.yaml");
    fs::write(
        &profile_path,
        r#"
name: local-test
version: 1
families:
  command-exec:
    dangerous_arg: 0
    string_seeds:
      - value: "/bin/sh"
        weight: 0.5
    confidence:
      weak: 0.2
      probable: 0.5
      strong: 0.8
"#,
    )
    .expect("write profile");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "profiles",
            "validate",
            profile_path.to_str().expect("utf8"),
        ])
        .output()
        .expect("fat sink-discovery profiles validate runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid sink profile"), "{stdout}");
    assert!(stdout.contains("local-test"), "{stdout}");
}

#[test]
fn sink_discovery_help_shows_top_level_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sink-discovery", "--help"])
        .output()
        .expect("fat sink-discovery --help runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--file"), "{stdout}");
    assert!(stdout.contains("profiles"), "{stdout}");
}

#[test]
fn sink_discovery_requires_a_file_or_profiles_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sink-discovery"])
        .output()
        .expect("fat sink-discovery without args runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("provide a firmware binary with `--file`"),
        "{stderr}"
    );
    assert!(stderr.contains("sink-discovery profiles"), "{stderr}");
}

#[test]
fn sink_discovery_without_json_renders_text_summary() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    fs::write(&elf_path, synthetic_sink_elf32_mips()).expect("write elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sink-discovery", "--file", elf_path.to_str().expect("utf8")])
        .output()
        .expect("fat sink-discovery --file runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sink-discovery:"), "{stdout}");
    assert!(stdout.contains("sink-0"), "{stdout}");
}

#[test]
fn sink_discovery_scans_string_and_pointer_evidence_for_json() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    fs::write(&elf_path, synthetic_sink_elf32_mips()).expect("write elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["candidates"][0]["family"], "command-exec");
    let evidence = json["candidates"][0]["evidence"]
        .as_array()
        .expect("evidence");
    assert!(
        evidence.iter().any(|item| item["kind"] == "string_ref"),
        "{json}"
    );
    assert!(
        evidence.iter().any(|item| item["kind"] == "pointer_xref"),
        "{json}"
    );
}

#[test]
fn sink_discovery_attribs_pointer_xref_to_mips_function() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-function-fixture.elf");
    fs::write(&elf_path, synthetic_mips_function_sink_elf()).expect("write elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidate = &json["candidates"][0];
    assert_eq!(candidate["family"], "command-exec", "{json}");
    assert_eq!(candidate["address"], "0x00400100", "{json}");
    assert_eq!(candidate["confidence"], "probable", "{json}");

    let evidence = candidate["evidence"].as_array().expect("evidence");
    assert!(
        evidence.iter().any(|item| item["kind"] == "string_ref"),
        "{json}"
    );
    assert!(
        evidence.iter().any(|item| item["kind"] == "pointer_xref"),
        "{json}"
    );
    assert!(
        evidence
            .iter()
            .any(|item| { item["kind"] == "code_ref" && item["function"] == "0x00400100" }),
        "{json}"
    );
}

#[test]
fn instrument_hooks_from_sinks_generates_yaml_for_probable_command_exec() {
    let dir = tempdir().expect("tempdir");
    let sinks_path = dir.path().join("sinks.json");
    let out_path = dir.path().join("hooks.yaml");
    let report = serde_json::json!({
        "file": "./bin/httpd",
        "binary": {
            "format": "ELF",
            "arch": "mips",
            "bits": 32,
            "endianness": "little",
            "class": "ELF32",
            "stripped": true
        },
        "profiles": ["linux-command-exec"],
        "summary": {
            "candidates": 1,
            "families": {"command-exec": 1}
        },
        "candidates": [
            {
                "id": "sink-0",
                "family": "command-exec",
                "family_key": "command-exec",
                "address": "0x00413f10",
                "symbolic_name": "candidate_system",
                "confidence": "probable",
                "score": 0.82,
                "providers": ["string_ref", "pointer_xref"],
                "evidence": [
                    {
                        "kind": "string_ref",
                        "profile": "linux-command-exec",
                        "rule": "string_seeds:/bin/sh",
                        "value": "/bin/sh",
                        "vaddr": "0x004f2ed0",
                        "score_delta": 0.35
                    }
                ],
                "limitations": ["function context not proven"]
            }
        ]
    });
    fs::write(&sinks_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "instrument-hooks",
            "--from-sinks",
            sinks_path.to_str().expect("utf8"),
            "--output",
            out_path.to_str().expect("utf8"),
        ])
        .output()
        .expect("fat instrument-hooks --from-sinks runs");

    assert!(output.status.success(), "{output:?}");
    let content = fs::read_to_string(&out_path).expect("hooks yaml");
    assert!(content.contains("candidate_system"), "{content}");
    assert!(content.contains("0x00413f10"), "{content}");
}

#[test]
fn instrument_hooks_requires_one_source_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["instrument-hooks", "--json"])
        .output()
        .expect("fat instrument-hooks --json runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--file"), "{stderr}");
}

#[test]
fn sink_discovery_preserves_custom_profile_name_in_evidence() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    let profile_path = dir.path().join("profile.yaml");
    fs::write(&elf_path, synthetic_sink_elf32_mips()).expect("write elf");
    fs::write(
        &profile_path,
        r#"
name: local-command-profile
version: 1
families:
  command-exec:
    string_seeds:
      - value: "/bin/sh"
        weight: 0.35
    pointer_xrefs:
      enabled: true
      weight: 0.20
      scan: non-executable
    confidence:
      weak: 0.25
      probable: 0.55
      strong: 0.80
"#,
    )
    .expect("write profile");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--profile",
            profile_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --profile --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["profiles"][0], "local-command-profile");
    let evidence = json["candidates"][0]["evidence"]
        .as_array()
        .expect("evidence");
    assert!(
        evidence
            .iter()
            .all(|item| item["profile"] == "local-command-profile"),
        "{json}"
    );
}

#[test]
fn sink_discovery_preserves_custom_family_key() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    let profile_path = dir.path().join("profile.yaml");
    fs::write(&elf_path, synthetic_sink_elf32_mips()).expect("write elf");
    fs::write(
        &profile_path,
        r#"
name: custom-family-profile
version: 1
families:
  vendor-shell-wrapper:
    string_seeds:
      - value: "/bin/sh"
        weight: 0.35
    confidence:
      weak: 0.25
      probable: 0.55
      strong: 0.80
"#,
    )
    .expect("write profile");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--profile",
            profile_path.to_str().expect("utf8"),
            "--family",
            "vendor-shell-wrapper",
            "--json",
        ])
        .output()
        .expect("fat sink-discovery custom family runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["candidates"][0]["family"], "unknown");
    assert_eq!(json["candidates"][0]["family_key"], "vendor-shell-wrapper");
}

#[test]
fn sink_discovery_rejects_seed_without_nul_inside_load_segment() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    let mut elf = synthetic_sink_elf32_mips();
    elf[0x44..0x48].copy_from_slice(&7u32.to_le_bytes());
    fs::write(&elf_path, elf).expect("write elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["candidates"], serde_json::json!([]), "{json}");
}

#[test]
fn sink_discovery_suppresses_candidates_below_weak_threshold() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("sink-fixture.elf");
    let profile_path = dir.path().join("profile.yaml");
    fs::write(&elf_path, synthetic_sink_elf32_mips()).expect("write elf");
    fs::write(
        &profile_path,
        r#"
name: low-weight-profile
version: 1
families:
  command-exec:
    string_seeds:
      - value: "/bin/sh"
        weight: 0.20
    confidence:
      weak: 0.25
      probable: 0.55
      strong: 0.80
"#,
    )
    .expect("write profile");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--profile",
            profile_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --profile --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(json["candidates"], serde_json::json!([]), "{json}");
}

#[test]
fn sink_discovery_keeps_repeated_string_only_hits_addressless() {
    let dir = tempdir().expect("tempdir");
    let elf_path = dir.path().join("string-only-fixture.elf");
    let mut elf = synthetic_sink_elf32_mips();
    elf[0x210..0x214].copy_from_slice(&0u32.to_le_bytes());
    elf[0x218..0x220].copy_from_slice(b"/bin/sh\0");
    elf[0x228..0x230].copy_from_slice(b"/bin/sh\0");
    fs::write(&elf_path, elf).expect("write elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "sink-discovery",
            "--file",
            elf_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("fat sink-discovery --file --json runs");

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidate = &json["candidates"][0];
    assert_eq!(candidate["confidence"], "weak", "{json}");
    assert_eq!(candidate["score"], 0.35, "{json}");
    assert!(candidate["address"].is_null(), "{json}");
}

#[test]
fn sink_discovery_profiles_show_builtin_profile_renders_yaml() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sink-discovery", "profiles", "show", "linux-command-exec"])
        .output()
        .expect("fat sink-discovery profiles show runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("name: linux-command-exec"), "{stdout}");
    assert!(stdout.contains("families:"), "{stdout}");
}

fn synthetic_sink_elf32_mips() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELF32
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // version
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&52u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&1u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&0u16.to_le_bytes());

    // Single non-executable LOAD segment containing /bin/sh and a pointer to it.
    bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x44..0x48].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x48..0x4c].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x4c..0x50].copy_from_slice(&0x6u32.to_le_bytes()); // PF_R | PF_W
    bytes[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes());

    // One section header used as the section-name string table.
    bytes[0x100..0x104].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x104..0x108].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x110..0x114].copy_from_slice(&0x300u32.to_le_bytes());
    bytes[0x114..0x118].copy_from_slice(&0x0bu32.to_le_bytes());
    bytes[0x124..0x128].copy_from_slice(&1u32.to_le_bytes());

    bytes[0x200..0x208].copy_from_slice(b"/bin/sh\0");
    bytes[0x210..0x214].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x300..0x30b].copy_from_slice(b"\0.shstrtab\0");

    bytes
}

fn synthetic_mips_function_sink_elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELF32
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // version
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x0040_0100u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&52u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&0u16.to_le_bytes());

    // RX LOAD segment containing a small MIPS function at the ELF entrypoint.
    bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x0040_0100u32.to_le_bytes());
    bytes[0x44..0x48].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x48..0x4c].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x4c..0x50].copy_from_slice(&0x5u32.to_le_bytes()); // PF_R | PF_X
    bytes[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes());

    // RW LOAD segment containing /bin/sh and a data pointer to it.
    bytes[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x58..0x5c].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x5c..0x60].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x64..0x68].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x68..0x6c].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x6c..0x70].copy_from_slice(&0x6u32.to_le_bytes()); // PF_R | PF_W
    bytes[0x70..0x74].copy_from_slice(&0x1000u32.to_le_bytes());

    // One section header used as the section-name string table.
    bytes[0x80..0x84].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&0x500u32.to_le_bytes());
    bytes[0x94..0x98].copy_from_slice(&0x0bu32.to_le_bytes());
    bytes[0xa4..0xa8].copy_from_slice(&1u32.to_le_bytes());

    // lui a0, 0x004f; addiu a0, a0, 0; jr ra; nop
    bytes[0x100..0x104].copy_from_slice(&0x3c04_004fu32.to_le_bytes());
    bytes[0x104..0x108].copy_from_slice(&0x2484_0000u32.to_le_bytes());
    bytes[0x108..0x10c].copy_from_slice(&0x03e0_0008u32.to_le_bytes());
    bytes[0x10c..0x110].copy_from_slice(&0u32.to_le_bytes());

    bytes[0x200..0x208].copy_from_slice(b"/bin/sh\0");
    bytes[0x210..0x214].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x500..0x50b].copy_from_slice(b"\0.shstrtab\0");

    bytes
}
