use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn fat_cli_shows_sdk_trace_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sdk-trace", "--help"])
        .output()
        .expect("fat sdk-trace help runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sdk-trace"));
    assert!(stdout.contains("--dir"));
}

#[test]
fn fat_sdk_trace_reports_layered_local_dependency_chain() {
    let sdk = tempdir().expect("sdk dir");
    let path_dir = tempdir().expect("path dir");

    for name in ["libIOTCAPIs.so", "libRDTAPIs.so", "libP2PTunnelAPIs.so"] {
        std::fs::write(sdk.path().join(name), [0x7f, b'E', b'L', b'F', 0, 0, 0, 0])
            .expect("write fake elf");
    }

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:libP2PTunnelAPIs.so)
    printf '{"imports":[{"name":"IOTC_Connect_ByUID"},{"name":"IOTC_Listen"},{"name":"RDT_Create"},{"name":"RDT_Read"},{"name":"RDT_Write"}]}'
    ;;
  -lj:libP2PTunnelAPIs.so)
    printf '{"libs":["libRDTAPIs.so","libIOTCAPIs.so","libc.so.6"]}'
    ;;
  -Ej:libP2PTunnelAPIs.so)
    printf '{"exports":[{"name":"P2PTunnelAgent_Connect","size":100}]}'
    ;;
  -ij:libRDTAPIs.so)
    printf '{"imports":[{"name":"IOTC_Session_Close"},{"name":"IOTC_Get_SessionID"}]}'
    ;;
  -lj:libRDTAPIs.so)
    printf '{"libs":["libIOTCAPIs.so","libc.so.6"]}'
    ;;
  -Ej:libRDTAPIs.so)
    printf '{"exports":[{"name":"RDT_Create","size":100},{"name":"RDT_Read","size":100},{"name":"RDT_Write","size":100}]}'
    ;;
  -ij:libIOTCAPIs.so)
    printf '{"imports":[]}'
    ;;
  -lj:libIOTCAPIs.so)
    printf '{"libs":["libc.so.6"]}'
    ;;
  -Ej:libIOTCAPIs.so)
    printf '{"exports":[{"name":"IOTC_Connect_ByUID","size":100},{"name":"IOTC_Listen","size":100},{"name":"IOTC_Session_Close","size":100},{"name":"IOTC_Get_SessionID","size":100}]}'
    ;;
  *)
    printf '{"imports":[],"exports":[],"libs":[]}'
    ;;
esac
"#;
    std::fs::write(&rabin2_path, script).expect("fake rabin2");
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&rabin2_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&rabin2_path, perms).expect("chmod");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["sdk-trace", "--dir", sdk.path().to_str().expect("sdk path")])
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat sdk-trace runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "SDK trace",
        "Dependency chains",
        "libP2PTunnelAPIs.so -> libRDTAPIs.so -> libIOTCAPIs.so",
        "IOTC_Connect_ByUID",
        "RDT_Read",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}
