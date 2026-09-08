use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn write_rabin2_stub_with_output(path: &std::path::Path, json_output: &str) {
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "-zj" ]; then
  cat <<'JSON'
{json_output}
JSON
  exit 0
fi
echo "unexpected rabin2 args: $@" >&2
exit 1
"#
    );
    std::fs::write(path, script).expect("rabin2 stub written");
    let mut perms = std::fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod");
}

fn write_rabin2_stub(path: &std::path::Path) {
    write_rabin2_stub_with_output(
        path,
        r#"[
  {"string":"/setform/alpha","vaddr":4195840,"length":14},
  {"string":"/setform/beta","vaddr":4195872,"length":13},
  {"string":"/setform/gamma","vaddr":4195904,"length":14}
]"#,
    );
}

fn write_handler_table_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x3800];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x400000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&5u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&4u16.to_le_bytes());

    write_load(&mut bytes, 0x34, 0x0, 0x400000, 0x1000, 5);
    write_load(&mut bytes, 0x54, 0x2000, 0x600000, 0x1000, 6);

    write_cstr(&mut bytes, 0x600, b"/setform/alpha");
    write_cstr(&mut bytes, 0x620, b"/setform/beta");
    write_cstr(&mut bytes, 0x640, b"/setform/gamma");

    write_entry(&mut bytes, 0x2100, 0x400600, 3);
    write_entry(&mut bytes, 0x2108, 0x400620, 3);
    write_entry(&mut bytes, 0x2110, 0x400640, 3);

    write_section(&mut bytes, 0x3000 + 40, 1, 1, 6, 0x400000, 0, 0x500);
    write_section(&mut bytes, 0x3000 + 80, 7, 1, 2, 0x400600, 0x600, 0x100);
    write_section(&mut bytes, 0x3000 + 120, 15, 1, 3, 0x600000, 0x2000, 0x1000);
    write_section(&mut bytes, 0x3000 + 160, 21, 3, 0, 0, 0x3400, 0x1f);
    bytes[0x3400..0x341f].copy_from_slice(b"\0.text\0.rodata\0.data\0.shstrtab\0");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_mips_registration_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x3800];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x400000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&5u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&4u16.to_le_bytes());

    write_load(&mut bytes, 0x34, 0x0, 0x400000, 0x1000, 5);
    write_load(&mut bytes, 0x54, 0x1000, 0x500000, 0x1000, 4);

    write_cstr(&mut bytes, 0x1100, b"/app/openapi");
    write_cstr(&mut bytes, 0x1120, b"tp.openapi.cam.system");

    // callsite 1: move a0,s1; lui a1,0x50; lui a2,0x40; addiu a2,a2,0x300; addiu a1,a1,0x100; jal 0x401000; nop
    bytes[0x200..0x204].copy_from_slice(&0x0220_2021u32.to_le_bytes());
    bytes[0x204..0x208].copy_from_slice(&0x3c05_0050u32.to_le_bytes());
    bytes[0x208..0x20c].copy_from_slice(&0x3c06_0040u32.to_le_bytes());
    bytes[0x20c..0x210].copy_from_slice(&0x24c6_0300u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&0x24a5_0100u32.to_le_bytes());
    bytes[0x214..0x218].copy_from_slice(&0x0c10_0400u32.to_le_bytes());
    bytes[0x218..0x21c].copy_from_slice(&0u32.to_le_bytes());

    // callsite 2: move a0,s1; lui a1,0x50; lui a2,0x40; addiu a1,a1,0x120; addiu a2,a2,0x340; jal 0x401000; nop
    bytes[0x230..0x234].copy_from_slice(&0x0220_2021u32.to_le_bytes());
    bytes[0x234..0x238].copy_from_slice(&0x3c05_0050u32.to_le_bytes());
    bytes[0x238..0x23c].copy_from_slice(&0x3c06_0040u32.to_le_bytes());
    bytes[0x23c..0x240].copy_from_slice(&0x24a5_0120u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x24c6_0340u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&0x0c10_0400u32.to_le_bytes());
    bytes[0x248..0x24c].copy_from_slice(&0u32.to_le_bytes());

    write_section(&mut bytes, 0x3000 + 40, 1, 1, 6, 0x400000, 0, 0x400);
    write_section(&mut bytes, 0x3000 + 80, 7, 1, 2, 0x500000, 0x1000, 0x200);
    write_section(&mut bytes, 0x3000 + 120, 15, 1, 3, 0x0, 0x0, 0x0);
    write_section(&mut bytes, 0x3000 + 160, 21, 3, 0, 0, 0x3400, 0x1f);
    bytes[0x3400..0x341f].copy_from_slice(b"\0.text\0.rodata\0.data\0.shstrtab\0");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_mips_data_registration_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x3800];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x400000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&5u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&4u16.to_le_bytes());

    write_load(&mut bytes, 0x34, 0x0, 0x400000, 0x1000, 5);
    write_load(&mut bytes, 0x54, 0x1000, 0x500000, 0x1000, 4);

    write_cstr(&mut bytes, 0x1100, b"/app/openapi");
    write_cstr(&mut bytes, 0x1120, b"tp.openapi.cam.system");
    write_cstr(&mut bytes, 0x1180, b"module.system");
    write_cstr(&mut bytes, 0x11c0, b"module.account");

    // callsite 1: lui a0,0x50; lui a1,0x50; addiu a0,a0,0x100; addiu a1,a1,0x180; jal 0x401200; addiu a2,zero,1
    bytes[0x200..0x204].copy_from_slice(&0x3c04_0050u32.to_le_bytes());
    bytes[0x204..0x208].copy_from_slice(&0x3c05_0050u32.to_le_bytes());
    bytes[0x208..0x20c].copy_from_slice(&0x2484_0100u32.to_le_bytes());
    bytes[0x20c..0x210].copy_from_slice(&0x24a5_0180u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&0x0c10_0480u32.to_le_bytes());
    bytes[0x214..0x218].copy_from_slice(&0x2406_0001u32.to_le_bytes());

    // callsite 2: lui a0,0x50; lui a1,0x50; addiu a0,a0,0x120; addiu a1,a1,0x1c0; jal 0x401200; addiu a2,zero,2
    bytes[0x230..0x234].copy_from_slice(&0x3c04_0050u32.to_le_bytes());
    bytes[0x234..0x238].copy_from_slice(&0x3c05_0050u32.to_le_bytes());
    bytes[0x238..0x23c].copy_from_slice(&0x2484_0120u32.to_le_bytes());
    bytes[0x23c..0x240].copy_from_slice(&0x24a5_01c0u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x0c10_0480u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&0x2406_0002u32.to_le_bytes());

    write_section(&mut bytes, 0x3000 + 40, 1, 1, 6, 0x400000, 0, 0x400);
    write_section(&mut bytes, 0x3000 + 80, 7, 1, 2, 0x500000, 0x1000, 0x240);
    write_section(&mut bytes, 0x3000 + 120, 15, 1, 3, 0x0, 0x0, 0x0);
    write_section(&mut bytes, 0x3000 + 160, 21, 3, 0, 0, 0x3400, 0x1f);
    bytes[0x3400..0x341f].copy_from_slice(b"\0.text\0.rodata\0.data\0.shstrtab\0");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_load(bytes: &mut [u8], base: usize, offset: u32, vaddr: u32, size: u32, flags: u32) {
    bytes[base..base + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&offset.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&vaddr.to_le_bytes());
    bytes[base + 16..base + 20].copy_from_slice(&size.to_le_bytes());
    bytes[base + 20..base + 24].copy_from_slice(&size.to_le_bytes());
    bytes[base + 24..base + 28].copy_from_slice(&flags.to_le_bytes());
    bytes[base + 28..base + 32].copy_from_slice(&0x1000u32.to_le_bytes());
}

fn write_section(
    bytes: &mut [u8],
    base: usize,
    name: u32,
    section_type: u32,
    flags: u32,
    address: u32,
    offset: u32,
    size: u32,
) {
    bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&section_type.to_le_bytes());
    bytes[base + 8..base + 12].copy_from_slice(&flags.to_le_bytes());
    bytes[base + 12..base + 16].copy_from_slice(&address.to_le_bytes());
    bytes[base + 16..base + 20].copy_from_slice(&offset.to_le_bytes());
    bytes[base + 20..base + 24].copy_from_slice(&size.to_le_bytes());
}

fn write_cstr(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
    bytes[offset + value.len()] = 0;
}

fn write_entry(bytes: &mut [u8], offset: usize, string_vaddr: u32, flags: u32) {
    bytes[offset..offset + 4].copy_from_slice(&string_vaddr.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&flags.to_le_bytes());
}

#[test]
fn handler_table_json_decodes_string_flag_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("fixture.elf");
    let source_map = dir.path().join("source-map.json");
    let path_dir = dir.path().join("bin");
    std::fs::create_dir(&path_dir).expect("bin dir");
    write_handler_table_fixture(&binary);
    write_rabin2_stub(&path_dir.join("rabin2"));
    std::fs::write(
        &source_map,
        r#"{
  "frontend_surfaces": [
    {
      "path": "www/system.htm",
      "kind": "html-form",
      "endpoint": "/setform/beta",
      "methods": ["POST"],
      "parameters": [{"name": "SystemCommand"}]
    }
  ]
}"#,
    )
    .expect("source-map fixture written");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "handler-table",
            "--file",
            binary.to_str().unwrap(),
            "--patterns",
            "/setform/",
            "--source-map",
            source_map.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("fat handler-table runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("handler-table returns JSON");

    assert_eq!(report["summary"]["tables_discovered"], 1);
    assert_eq!(report["tables"][0]["structure"]["entry_stride"], 8);
    assert_eq!(report["tables"][0]["structure"]["entry_count"], 3);
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][0]["resolved"],
        "/setform/beta"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][1]["resolved"],
        "flags: 0x3"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["frontend_match"]["file"],
        "www/system.htm"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["frontend_match"]["parameters"][0],
        "SystemCommand"
    );
}

#[test]
fn handler_table_mips_registration_fallback_recovers_entries_without_pointer_hits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("mips-registration.elf");
    let path_dir = dir.path().join("bin");
    std::fs::create_dir(&path_dir).expect("bin dir");
    write_mips_registration_fixture(&binary);
    write_rabin2_stub_with_output(
        &path_dir.join("rabin2"),
        r#"[
  {"string":"/app/openapi","vaddr":5243136,"length":12},
  {"string":"tp.openapi.cam.system","vaddr":5243168,"length":21}
]"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "handler-table",
            "--file",
            binary.to_str().unwrap(),
            "--patterns",
            "/app/openapi,tp.openapi.cam.",
            "--json",
        ])
        .output()
        .expect("fat handler-table runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("handler-table returns JSON");

    assert_eq!(report["summary"]["pointer_hits"], 0);
    assert_eq!(report["summary"]["tables_discovered"], 1);
    assert_eq!(report["tables"][0]["structure"]["entry_count"], 2);
    assert!(report["tables"][0]["structure"]["entry_format"]
        .as_str()
        .expect("entry format")
        .contains("mips-registration-calls"));
    assert_eq!(
        report["tables"][0]["entries"][0]["fields"][0]["resolved"],
        "/app/openapi"
    );
    assert_eq!(
        report["tables"][0]["entries"][0]["fields"][1]["resolved"],
        "code: 0x400300"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][0]["resolved"],
        "tp.openapi.cam.system"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][1]["resolved"],
        "code: 0x400340"
    );
}

#[test]
fn handler_table_mips_registration_fallback_handles_data_and_delay_slot_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("mips-data-registration.elf");
    let path_dir = dir.path().join("bin");
    std::fs::create_dir(&path_dir).expect("bin dir");
    write_mips_data_registration_fixture(&binary);
    write_rabin2_stub_with_output(
        &path_dir.join("rabin2"),
        r#"[
  {"string":"/app/openapi","vaddr":5243136,"length":12},
  {"string":"tp.openapi.cam.system","vaddr":5243168,"length":21}
]"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "handler-table",
            "--file",
            binary.to_str().unwrap(),
            "--patterns",
            "/app/openapi,tp.openapi.cam.",
            "--json",
        ])
        .output()
        .expect("fat handler-table runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("handler-table returns JSON");

    assert_eq!(report["summary"]["pointer_hits"], 0);
    assert_eq!(report["summary"]["tables_discovered"], 1);
    assert_eq!(report["tables"][0]["structure"]["entry_count"], 2);
    assert!(report["tables"][0]["structure"]["entry_format"]
        .as_str()
        .expect("entry format")
        .contains("a0:string_ptr"));
    assert!(report["tables"][0]["structure"]["entry_format"]
        .as_str()
        .expect("entry format")
        .contains("a2:flags"));
    assert_eq!(
        report["tables"][0]["entries"][0]["fields"][1]["resolved"],
        "module.system"
    );
    assert_eq!(
        report["tables"][0]["entries"][0]["fields"][2]["resolved"],
        "flags: 0x1"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][1]["resolved"],
        "module.account"
    );
    assert_eq!(
        report["tables"][0]["entries"][1]["fields"][2]["resolved"],
        "flags: 0x2"
    );
}
