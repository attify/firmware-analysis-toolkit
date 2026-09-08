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
    for _ in 4..12 {
        write_u32(&mut bytes, 0x0800_4001);
    }
    write_u32(&mut bytes, 0x0800_5001);
    write_u32(&mut bytes, 0x0800_5001);
    write_u32(&mut bytes, 0x0800_5101);
    write_u32(&mut bytes, 0x0800_5201);
    for _ in 16..32 {
        write_u32(&mut bytes, 0x0800_5301);
    }
    bytes.resize(0x100, 0x00);
    if bytes.len() < 0x242 {
        bytes.resize(0x242, 0x00);
    }
    bytes[0x200..0x202].copy_from_slice(&thumb_b(0x0800_0200, 0x0800_0220));
    bytes[0x220..0x222].copy_from_slice(&thumb_b(0x0800_0220, 0x0800_0240));
    bytes[0x240..0x242].copy_from_slice(&thumb_b(0x0800_0240, 0x0800_0240));
    let payload = b"irq main shared_flag dma uart update watchdog motor buffer comms";
    let start = 0x300;
    if bytes.len() < start + payload.len() {
        bytes.resize(start + payload.len(), 0x00);
    }
    bytes[start..start + payload.len()].copy_from_slice(payload);
    bytes.resize(0x800, 0xFF);
    bytes
}

#[test]
fn fat_inspect_isr_state_json_emits_ranked_findings() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "isr-state",
            "--file",
            blob.to_str().expect("blob"),
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat inspect isr-state runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "mcu-isr-state/v1");
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
    assert!(report["shared_state_risk"]["edges"].is_array());
    assert!(report["shared_state_risk"]["ranked_findings"].is_array());
}

#[test]
fn fat_inspect_isr_state_help_mentions_interrupt_boundary_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "isr-state", "--help"])
        .output()
        .expect("help runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("interrupt-boundary"));
    assert!(stdout.contains("--family"));
}
