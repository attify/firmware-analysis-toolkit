use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn thumb_b(from: u32, to: u32) -> [u8; 2] {
    let pc = from.wrapping_add(4);
    let offset = to.wrapping_sub(pc) as i32;
    let imm11 = ((offset >> 1) as u16) & 0x07ff;
    (0xe000u16 | imm11).to_le_bytes()
}

fn build_blob() -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_2001);
    write_u32(&mut bytes, 0x0800_3001);
    for _ in 4..32 {
        write_u32(&mut bytes, 0x0800_4001);
    }
    bytes.resize(0x100, 0x00);
    if bytes.len() < 0x222 {
        bytes.resize(0x222, 0x00);
    }
    bytes[0x200..0x202].copy_from_slice(&thumb_b(0x0800_0200, 0x0800_0220));
    bytes[0x220..0x222].copy_from_slice(&[0x70, 0x47]);
    let literals = [
        0x4001_100Cu32,
        0x0000_0138,
        0x5800_1C10,
        0x00C0_EAFF,
        0x4000_1028,
        0x0000_0010,
        0x4000_102C,
        0x0000_03E8,
    ];
    let start = 0x180;
    if bytes.len() < start + literals.len() * 4 {
        bytes.resize(start + literals.len() * 4, 0x00);
    }
    for (index, word) in literals.iter().enumerate() {
        let offset = start + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes.resize(0x800, 0xFF);
    bytes
}

#[test]
fn fat_inspect_peripheral_map_json_emits_surface_report() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "peripheral-map",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect peripheral-map runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "mcu-peripheral-surface/v1");
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
    assert!(report["peripheral_map"]["uses"].is_array());
    assert!(report["peripheral_surface"]["register_blocks"].is_array());
    assert!(report["peripheral_surface"]["recovered_configs"].is_array());
    let blocks = report["peripheral_surface"]["register_blocks"]
        .as_array()
        .expect("register blocks");
    assert!(
        blocks
            .iter()
            .any(|block| block["peripheral_name"] == "USART1"),
        "expected USART1 block in {report}"
    );
}

#[test]
fn fat_inspect_peripheral_map_help_mentions_family_backed_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "peripheral-map", "--help"])
        .output()
        .expect("help runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("register-block"));
    assert!(stdout.contains("--family"));
}
