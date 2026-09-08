use std::process::Command;

fn write_pointer_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x3400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELF32
    bytes[5] = 1; // little-endian
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x400000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
    bytes[44..46].copy_from_slice(&3u16.to_le_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
    bytes[48..50].copy_from_slice(&2u16.to_le_bytes());
    bytes[50..52].copy_from_slice(&1u16.to_le_bytes());

    write_load(&mut bytes, 0x34, 0x0, 0x400000, 0x1000, 5);
    write_load(&mut bytes, 0x54, 0x1000, 0x500000, 0x1000, 4);
    write_load(&mut bytes, 0x74, 0x2000, 0x600000, 0x1000, 6);

    bytes[0x100..0x104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
    bytes[0x1100..0x1104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());
    bytes[0x2100..0x2104].copy_from_slice(&0x0046a5b0u32.to_le_bytes());

    let shstr = 0x3000 + 40;
    bytes[shstr..shstr + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[shstr + 4..shstr + 8].copy_from_slice(&3u32.to_le_bytes());
    bytes[shstr + 16..shstr + 20].copy_from_slice(&0x3300u32.to_le_bytes());
    bytes[shstr + 20..shstr + 24].copy_from_slice(&10u32.to_le_bytes());
    bytes[0x3300..0x330a].copy_from_slice(b"\0.shstrtab");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_mips_direct_load_fixture(path: &std::path::Path) {
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

    bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x0040_0100u32.to_le_bytes());
    bytes[0x44..0x48].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x48..0x4c].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x4c..0x50].copy_from_slice(&0x5u32.to_le_bytes()); // PF_R | PF_X
    bytes[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes());

    bytes[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x58..0x5c].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x5c..0x60].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x64..0x68].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x68..0x6c].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x6c..0x70].copy_from_slice(&0x6u32.to_le_bytes()); // PF_R | PF_W
    bytes[0x70..0x74].copy_from_slice(&0x1000u32.to_le_bytes());

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
    bytes[0x500..0x50b].copy_from_slice(b"\0.shstrtab\0");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_mips_windowed_load_fixture(path: &std::path::Path) {
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

    bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x0040_0100u32.to_le_bytes());
    bytes[0x44..0x48].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x48..0x4c].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x4c..0x50].copy_from_slice(&0x5u32.to_le_bytes()); // PF_R | PF_X
    bytes[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes());

    bytes[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x58..0x5c].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x5c..0x60].copy_from_slice(&0x004f_0000u32.to_le_bytes());
    bytes[0x64..0x68].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x68..0x6c].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x6c..0x70].copy_from_slice(&0x6u32.to_le_bytes()); // PF_R | PF_W
    bytes[0x70..0x74].copy_from_slice(&0x1000u32.to_le_bytes());

    bytes[0x80..0x84].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x84..0x88].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&0x500u32.to_le_bytes());
    bytes[0x94..0x98].copy_from_slice(&0x0bu32.to_le_bytes());
    bytes[0xa4..0xa8].copy_from_slice(&1u32.to_le_bytes());

    // lui a1, 0x004f; move a0, s1; addiu a1, a1, 0; jr ra; nop
    bytes[0x100..0x104].copy_from_slice(&0x3c05_004fu32.to_le_bytes());
    bytes[0x104..0x108].copy_from_slice(&0x0220_2021u32.to_le_bytes());
    bytes[0x108..0x10c].copy_from_slice(&0x24a5_0000u32.to_le_bytes());
    bytes[0x10c..0x110].copy_from_slice(&0x03e0_0008u32.to_le_bytes());
    bytes[0x110..0x114].copy_from_slice(&0u32.to_le_bytes());

    bytes[0x200..0x208].copy_from_slice(b"/bin/sh\0");
    bytes[0x500..0x50b].copy_from_slice(b"\0.shstrtab\0");

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_raw_mips_pic_boot_string_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x17000];
    bytes[0x169d4..0x169dc].copy_from_slice(b"bootargs");
    bytes[0x169dc] = 0;

    // MIPS PIC prologue: lui gp, 2; addiu gp, gp, 0xb8c; addu gp, gp, t9.
    bytes[0x0f24..0x0f28].copy_from_slice(&0x3c1c_0002u32.to_le_bytes());
    bytes[0x0f28..0x0f2c].copy_from_slice(&0x279c_0b8cu32.to_le_bytes());
    bytes[0x0f2c..0x0f30].copy_from_slice(&0x0399_e021u32.to_le_bytes());

    // addiu a0, a0, 0x69d4 references the low half of the raw string offset.
    bytes[0x0f9c..0x0fa0].copy_from_slice(&0x2484_69d4u32.to_le_bytes());

    std::fs::write(path, bytes).expect("fixture written");
}

fn write_raw_cortex_m_string_xref_fixture(path: &std::path::Path) {
    let mut bytes = vec![0u8; 0x80];
    // Function candidate at 0x08000020: push {r4, lr}.
    bytes[0x20..0x22].copy_from_slice(&0xb510u16.to_le_bytes());
    // At 0x08000026: adr r3, 0x2c -> 0x08000054.
    bytes[0x26..0x28].copy_from_slice(&0xa30bu16.to_le_bytes());
    bytes[0x54..0x6f].copy_from_slice(b"../LWIP/Target/ethernetif.c");
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

#[test]
fn xref_search_json_reports_non_executable_pointer_hits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("fixture.elf");
    write_pointer_fixture(&binary);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "xref-search",
            "--file",
            binary.to_str().unwrap(),
            "--vaddr",
            "0x0046a5b0",
            "--json",
        ])
        .output()
        .expect("fat xref-search runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("xref-search returns JSON");

    let hits = report["targets"][0]["hits"].as_array().expect("hits array");
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0]["file_offset"], 0x1100);
    assert_eq!(hits[0]["vaddr"], 0x500100);
    assert_eq!(hits[1]["file_offset"], 0x2100);
    assert_eq!(hits[1]["vaddr"], 0x600100);
}

#[test]
fn xref_search_json_reports_mips_direct_load_code_hits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("mips.elf");
    write_mips_direct_load_fixture(&binary);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "xref-search",
            "--file",
            binary.to_str().unwrap(),
            "--vaddr",
            "0x004f0000",
            "--json",
        ])
        .output()
        .expect("fat xref-search runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("xref-search returns JSON");

    assert_eq!(report["architecture"], "mips");
    let target = &report["targets"][0];
    assert!(target["hits"].as_array().expect("hits").is_empty());
    let code_hits = target["code_hits"].as_array().expect("code hits");
    assert_eq!(code_hits.len(), 1);
    assert_eq!(code_hits[0]["instruction_vaddr"], 0x0040_0104);
    assert_eq!(code_hits[0]["function_vaddr"], 0x0040_0100);
    assert_eq!(code_hits[0]["register"], "a0");
    assert_eq!(code_hits[0]["pattern"], "lui+addiu");
}

#[test]
fn xref_search_json_reports_windowed_mips_code_hits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("mips-window.elf");
    write_mips_windowed_load_fixture(&binary);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "xref-search",
            "--file",
            binary.to_str().unwrap(),
            "--vaddr",
            "0x004f0000",
            "--json",
        ])
        .output()
        .expect("fat xref-search runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("xref-search returns JSON");

    let code_hits = report["targets"][0]["code_hits"]
        .as_array()
        .expect("code hits");
    assert_eq!(code_hits.len(), 1);
    assert_eq!(code_hits[0]["instruction_vaddr"], 0x0040_0108);
    assert_eq!(code_hits[0]["register"], "a1");
    assert_eq!(code_hits[0]["pattern"], "lui+addiu");
}

#[test]
fn xref_search_raw_mips_pic_string_reports_candidate_function() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("boot.raw");
    write_raw_mips_pic_boot_string_fixture(&binary);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "xref-search",
            "--file",
            binary.to_str().unwrap(),
            "--raw",
            "--arch",
            "mips-pic",
            "--base",
            "0x0",
            "--string",
            "bootargs",
            "--json",
        ])
        .output()
        .expect("fat xref-search runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("xref-search returns JSON");

    assert_eq!(report["architecture"], "mips-pic");
    assert_eq!(report["targets"][0]["vaddr"], 0x169d4);
    let code_hits = report["targets"][0]["code_hits"]
        .as_array()
        .expect("code hits");
    assert_eq!(code_hits.len(), 1);
    assert_eq!(code_hits[0]["instruction_vaddr"], 0x0f9c);
    assert_eq!(code_hits[0]["function_vaddr"], 0x0f24);
    assert_eq!(
        code_hits[0]["function_name"],
        "candidate_mips_pic_0x00000f24"
    );
    assert_eq!(code_hits[0]["pattern"], "mips-pic-low16");
}

#[test]
fn xref_search_raw_cortex_m_string_reports_thumb_adr_reference() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = dir.path().join("firmware.bin");
    write_raw_cortex_m_string_xref_fixture(&binary);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "xref-search",
            "--file",
            binary.to_str().unwrap(),
            "--raw",
            "--arch",
            "cortex-m",
            "--base",
            "0x08000000",
            "--string",
            "ethernetif.c",
            "--json",
        ])
        .output()
        .expect("fat xref-search runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("xref-search returns JSON");

    assert_eq!(report["architecture"], "cortex-m");
    assert_eq!(report["targets"][0]["vaddr"], 0x0800_0054u64);
    assert_eq!(report["targets"][0]["label"], "../LWIP/Target/ethernetif.c");
    let code_hits = report["targets"][0]["code_hits"]
        .as_array()
        .expect("code hits");
    assert_eq!(code_hits.len(), 1);
    assert_eq!(code_hits[0]["instruction_vaddr"], 0x0800_0026u64);
    assert_eq!(code_hits[0]["function_vaddr"], 0x0800_0020u64);
    assert_eq!(
        code_hits[0]["function_name"],
        "candidate_cortex_m_0x08000020"
    );
    assert_eq!(code_hits[0]["register"], "r3");
    assert_eq!(code_hits[0]["pattern"], "thumb-adr");
}
