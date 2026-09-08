use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn write_executable(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).expect("tool stub");
    let mut permissions = std::fs::metadata(path)
        .expect("tool stub metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("tool stub chmod");
}

#[cfg(unix)]
fn write_radare2_stubs(path_dir: &std::path::Path) {
    write_executable(&path_dir.join("rabin2"), "#!/bin/sh\nprintf '[]'\n");
    write_executable(
        &path_dir.join("r2"),
        "#!/bin/sh\nprintf '\\0'\nwhile IFS= read -r command; do\n  case \"$command\" in\n    'q!') printf '\\0'; exit 0 ;;\n    *) printf '[]\\0' ;;\n  esac\ndone\n",
    );
}

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
fn fat_r2_triage_rejects_malformed_base_override() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "r2-triage",
            "--file",
            blob.to_str().expect("blob"),
            "--base",
            "not-a-number",
        ])
        .output()
        .expect("fat r2-triage runs");

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

#[test]
#[cfg(unix)]
fn fat_r2_triage_raw_blob_json_emits_honest_profile() {
    let dir = tempdir().expect("tempdir");
    let path_dir = tempdir().expect("path dir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_blob()).expect("blob");
    write_radare2_stubs(path_dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "r2-triage",
            "--file",
            blob.to_str().expect("blob"),
            "--arch",
            "cortex-m",
            "--base",
            "0x08000000",
            "--family",
            "STM32H7",
            "--json",
        ])
        .output()
        .expect("fat r2-triage runs");

    assert!(
        output.status.success(),
        "expected raw blob triage to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["profile"]["class"], "raw-firmware");
    assert_eq!(report["profile"]["raw_blob"], true);
    assert_eq!(report["profile"]["family"], "STM32H7");
    assert_eq!(report["profile"]["arch"], "arm");
    assert_eq!(report["profile"]["bits"], 16);
}
