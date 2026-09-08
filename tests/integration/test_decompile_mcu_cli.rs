use std::process::Command;
use tempfile::tempdir;

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn build_blob() -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    bytes.resize(0x400, 0xFF);
    bytes
}

#[test]
fn fat_decompile_rejects_malformed_base_override() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "decompile",
            "--file",
            blob.to_str().expect("blob"),
            "--function",
            "0x080002ac",
            "--base",
            "not-a-number",
        ])
        .output()
        .expect("fat decompile runs");

    assert!(
        !output.status.success(),
        "expected malformed base to fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid --base"),
        "expected malformed-base error\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
