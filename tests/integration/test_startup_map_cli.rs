use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

#[cfg(unix)]
fn write_elf(path: &std::path::Path, payload: &[u8]) {
    let mut bytes = vec![
        0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 8, 0,
    ];
    bytes.extend_from_slice(payload);
    std::fs::write(path, bytes).expect("write elf");
}

#[cfg(unix)]
fn make_startup_rootfs() -> tempfile::TempDir {
    let dir = tempdir().expect("rootfs");
    let rootfs = dir.path();
    std::fs::create_dir_all(rootfs.join("etc/rc.d")).expect("rc.d");
    std::fs::create_dir_all(rootfs.join("etc/init.d")).expect("init.d");
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    std::fs::write(
        rootfs.join("etc/init.d/cloud_client"),
        r#"
        CLOUD_CLIENT_BIN="/bin/cloud-client"
        service_start $CLOUD_CLIENT_BIN
        "#,
    )
    .expect("cloud init");
    std::fs::write(
        rootfs.join("etc/init.d/cloud_service"),
        r#"
        CLOUD_SERVICE_BIN="/bin/cloud-service"
        service_start $CLOUD_SERVICE_BIN
        "#,
    )
    .expect("service init");
    std::fs::write(
        rootfs.join("etc/init.d/commented"),
        r#"
        COMMENTED_BIN="/bin/commented"
        # service_start /bin/commented
        "#,
    )
    .expect("commented init");

    symlink(
        "../init.d/cloud_client",
        rootfs.join("etc/rc.d/S44cloud_client"),
    )
    .expect("cloud symlink");
    symlink(
        "../init.d/cloud_service",
        rootfs.join("etc/rc.d/S45cloud_service"),
    )
    .expect("service symlink");
    symlink("../init.d/missing", rootfs.join("etc/rc.d/S99broken")).expect("broken symlink");

    write_elf(
        &rootfs.join("bin/cloud-client"),
        b"\0libcurl.so.4\0libssl.so.1.0.0\0CURLOPT_URL\0https://device-api.example\0",
    );
    write_elf(
        &rootfs.join("bin/cloud-service"),
        b"\0libssl.so.1.0.0\0https://device-api.example\0",
    );

    dir
}

#[cfg(unix)]
fn fake_rabin2() -> tempfile::TempDir {
    let dir = tempdir().expect("path dir");
    let path = dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:cloud-client)
    printf '{"imports":[{"name":"curl_easy_setopt"},{"name":"curl_easy_perform"},{"name":"getaddrinfo"}]}'
    ;;
  -lj:cloud-client)
    printf '{"libs":["libcurl.so.4","libssl.so.1.0.0"]}'
    ;;
  -ij:cloud-service)
    printf '{"imports":[{"name":"SSL_connect"},{"name":"SSL_read"},{"name":"SSL_write"},{"name":"getaddrinfo"}]}'
    ;;
  -lj:cloud-service)
    printf '{"libs":["libssl.so.1.0.0"]}'
    ;;
  *)
    printf '{"imports":[],"libs":[]}'
    ;;
esac
"#;
    std::fs::write(&path, script).expect("fake rabin2");
    let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    dir
}

#[cfg(unix)]
#[test]
fn fat_startup_map_text_contains_startup_chain_and_bounded_claims() {
    let root = make_startup_rootfs();
    let rabin2 = fake_rabin2();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "startup-map",
            "--rootfs",
            root.path().to_str().expect("rootfs path"),
            "--profile",
            "cloud-tls",
            "--explain",
            "--emit-actions",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                rabin2.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat startup-map runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FAT Startup Map"));
    assert!(stdout.contains("/etc/rc.d/S44cloud_client -> /etc/init.d/cloud_client"));
    assert!(stdout.contains("/bin/cloud-client"));
    assert!(stdout.contains("libcurl-http-client"));
    assert!(stdout.contains("runtime_proven=false"));
    assert!(stdout.contains("call path not proven"));
    assert!(stdout.contains("Suggested next commands:"));
}

#[cfg(unix)]
#[test]
fn fat_startup_map_json_ranks_libcurl_candidate_first() {
    let root = make_startup_rootfs();
    let rabin2 = fake_rabin2();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "startup-map",
            "--rootfs",
            root.path().to_str().expect("rootfs path"),
            "--profile",
            "cloud-tls",
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                rabin2.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat startup-map json runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(report["schema"], "startup-map/v1");
    assert_eq!(report["summary"]["startup_entries"], 3);
    assert_eq!(report["summary"]["r2_available"], true);
    assert!(report["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .any(|entry| entry["path"] == "/etc/rc.d/S99broken" && entry["target_exists"] == false));

    let candidates = report["candidates"].as_array().expect("candidates");
    assert_eq!(candidates[0]["binary"], "/bin/cloud-client");
    let roles = candidates[0]["profiles"][0]["roles"]
        .as_array()
        .expect("roles");
    assert!(roles.iter().any(|role| role == "libcurl-http-client"));
    assert!(
        candidates[0]["profiles"][0]["score"]
            .as_u64()
            .expect("score")
            > candidates[1]["profiles"][0]["score"]
                .as_u64()
                .expect("score")
    );
}

#[cfg(unix)]
#[test]
fn fat_startup_map_runs_without_rabin2_and_reports_gap() {
    let root = make_startup_rootfs();
    let empty_path = tempdir().expect("empty PATH");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "startup-map",
            "--rootfs",
            root.path().to_str().expect("rootfs path"),
            "--profile",
            "curl",
            "--json",
        ])
        .env("PATH", empty_path.path())
        .output()
        .expect("fat startup-map without rabin2 runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(report["summary"]["r2_available"], false);
    assert!(report["gaps"]
        .as_array()
        .expect("gaps")
        .iter()
        .any(|gap| gap == "r2-import-analysis-unavailable"));
    assert!(report["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .any(|candidate| candidate["binary"] == "/bin/cloud-client"));
}

#[test]
fn fat_startup_map_help_mentions_profiles_and_epistemic_limit() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["startup-map", "--help"])
        .output()
        .expect("fat startup-map help runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cloud-tls"));
    assert!(stdout.contains("startup-map/v1"));
    assert!(stdout.contains("not runtime proof or exploitability proof"));
}
