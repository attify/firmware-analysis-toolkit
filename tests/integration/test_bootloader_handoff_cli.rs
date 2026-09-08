use serde_json::Value;
use std::process::Command;

fn write_raw_mips_pic_handoff_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x18000];
    let string_offset = 0x16a44usize;
    bytes[string_offset..string_offset + "Starting kernel".len()]
        .copy_from_slice(b"Starting kernel");
    bytes[string_offset + "Starting kernel".len()] = 0;

    // lui gp, imm; addiu gp, gp, imm; addu gp, gp, t9
    bytes[0x0f24..0x0f28].copy_from_slice(&0x3c1c_0002u32.to_le_bytes());
    bytes[0x0f28..0x0f2c].copy_from_slice(&0x279c_8000u32.to_le_bytes());
    bytes[0x0f2c..0x0f30].copy_from_slice(&0x0399_e021u32.to_le_bytes());

    // addiu a0, a0, 0x6a44: low-16 reference to "Starting kernel".
    bytes[0x12e8..0x12ec].copy_from_slice(&0x2484_6a44u32.to_le_bytes());

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_handoff_decompile(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"
undefined4 candidate_mips_pic_0x00000f24(void)
{
  uint uVar17;
  int iVar20;
  int iVar12;
  int iVar15;
  int iVar1;
  int iVar5;

  (**(*(iVar20 + 0x10) + -0x7fb8))(*(*(iVar20 + 0x10) + -0x7fc8) + 0x6a44);
  (*(uVar17 >> 0x18 | uVar17 << 0x18 | (uVar17 & 0xff00) << 8 |
      uVar17 >> 8 & 0xff00U))(*(iVar12 + -0x5cf4),*(iVar15 + -0x5cf8),
                                *(iVar1 + -0x5d00),iVar5);
  return 0;
}
"#,
    )
    .expect("decompile fixture written");
}

#[test]
fn bootloader_handoff_json_reports_static_candidate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("boot.raw");
    let decompile = dir.path().join("f24.raw.c");
    write_raw_mips_pic_handoff_fixture(&binary);
    write_handoff_decompile(&decompile);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "handoff",
            "--file",
            binary.to_str().unwrap(),
            "--raw",
            "--arch",
            "mips-pic",
            "--base",
            "0x0",
            "--landmark",
            "Starting kernel",
            "--decompile-file",
            decompile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("fat bootloader handoff runs");

    assert!(
        output.status.success(),
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(value["schema"], "bootloader-handoff/v1");
    assert_eq!(value["status"], "candidate");
    assert_eq!(
        value["candidates"][0]["function"]["name"],
        "candidate_mips_pic_0x00000f24"
    );
    assert_eq!(value["candidates"][0]["function"]["address"], "0x00000f24");
    assert_eq!(
        value["candidates"][0]["landmark"]["string"],
        "Starting kernel"
    );
    assert_eq!(value["candidates"][0]["transform"]["kind"], "bswap32");
    assert_eq!(value["candidates"][0]["call"]["type"], "indirect");
    assert!(value["candidates"][0]["evidence_window"]
        .as_array()
        .unwrap()
        .iter()
        .any(|line| line.as_str().unwrap().contains("0xff00")));
    assert!(value["does_not_prove"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("runtime boot succeeds")));
}

#[test]
fn bootloader_handoff_text_is_compact_operator_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("boot.raw");
    let decompile = dir.path().join("f24.raw.c");
    write_raw_mips_pic_handoff_fixture(&binary);
    write_handoff_decompile(&decompile);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "handoff",
            "--file",
            binary.to_str().unwrap(),
            "--raw",
            "--arch",
            "mips-pic",
            "--base",
            "0x0",
            "--landmark",
            "Starting kernel",
            "--decompile-file",
            decompile.to_str().unwrap(),
        ])
        .output()
        .expect("fat bootloader handoff runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bootloader handoff"));
    assert!(stdout.contains("candidate_mips_pic_0x00000f24"));
    assert!(stdout.contains("code_hit"));
    assert!(stdout.contains("bswap32"));
    assert!(stdout.contains("indirect"));
    assert!(!stdout.contains("Integrity vocabulary"));
    assert!(!stdout.contains("What this proves"));
    assert!(!stdout.contains("What this does not prove"));
}

#[test]
fn bootloader_handoff_json_reports_no_match_without_indirect_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("boot.raw");
    let decompile = dir.path().join("f24.raw.c");
    write_raw_mips_pic_handoff_fixture(&binary);
    std::fs::write(
        &decompile,
        "uVar17 >> 0x18 | uVar17 << 0x18 | (uVar17 & 0xff00) << 8;",
    )
    .expect("decompile fixture written");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "handoff",
            "--file",
            binary.to_str().unwrap(),
            "--raw",
            "--arch",
            "mips-pic",
            "--base",
            "0x0",
            "--landmark",
            "Starting kernel",
            "--decompile-file",
            decompile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("fat bootloader handoff runs");

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(value["schema"], "bootloader-handoff/v1");
    assert_eq!(value["status"], "no_match");
    assert!(value["candidates"].as_array().unwrap().is_empty());
}

#[test]
fn bootloader_handoff_help_mentions_raw_mips_pic_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bootloader", "handoff", "--help"])
        .output()
        .expect("fat bootloader handoff help runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bootloader handoff"));
    assert!(stdout.contains("--landmark"));
    assert!(stdout.contains("--decompile-file"));
    assert!(stdout.contains("--raw"));
    assert!(stdout.contains("mips-pic"));
}
