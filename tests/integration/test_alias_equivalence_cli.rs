use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x1357_9BDF;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xff) as u8);
    }
    out
}

fn assert_normalized_semantic_equality(left: &Value, right: &Value) {
    assert_eq!(
        left, right,
        "expected semantic equality\nleft: {left}\nright: {right}"
    );
}

#[test]
fn fat_detect_encryption_is_json_equivalent_to_inspect_envelope() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let inspect = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            blob.to_str().expect("blob path"),
            "--json",
        ])
        .output()
        .expect("fat inspect envelope json runs");
    let detect = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "detect-encryption",
            "--file",
            blob.to_str().expect("blob path"),
            "--json",
        ])
        .output()
        .expect("fat detect-encryption json runs");

    assert!(
        inspect.status.success(),
        "inspect failed: {:?}",
        inspect.status
    );
    assert!(
        detect.status.success(),
        "detect failed: {:?}",
        detect.status
    );

    let inspect_json: Value = serde_json::from_slice(&inspect.stdout).expect("inspect json");
    let detect_json: Value = serde_json::from_slice(&detect.stdout).expect("detect json");
    assert_normalized_semantic_equality(&inspect_json, &detect_json);
}

#[test]
fn fat_compare_is_json_equivalent_to_inspect_envelope_with_reference() {
    let dir = tempdir().expect("tempdir");
    let left = dir.path().join("left.bin");
    let right = dir.path().join("right.bin");

    let mut left_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    left_bytes.extend_from_slice(&pseudo_random_bytes(2048));
    let mut right_bytes = vec![0x55, 0xAA, 0x01, 0x02];
    right_bytes.extend_from_slice(&[0x66; 2048]);
    std::fs::write(&left, left_bytes).expect("left");
    std::fs::write(&right, right_bytes).expect("right");

    let inspect = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "envelope",
            "--file",
            left.to_str().expect("left path"),
            "--reference",
            right.to_str().expect("right path"),
            "--json",
        ])
        .output()
        .expect("fat inspect envelope reference json runs");
    let compare = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "compare",
            "--encrypted",
            left.to_str().expect("left path"),
            "--reference",
            right.to_str().expect("right path"),
            "--json",
        ])
        .output()
        .expect("fat compare json runs");

    assert!(
        inspect.status.success(),
        "inspect failed: {:?}",
        inspect.status
    );
    assert!(
        compare.status.success(),
        "compare failed: {:?}",
        compare.status
    );

    let inspect_json: Value = serde_json::from_slice(&inspect.stdout).expect("inspect json");
    let compare_json: Value = serde_json::from_slice(&compare.stdout).expect("compare json");
    assert_normalized_semantic_equality(&inspect_json, &compare_json);
}

#[test]
fn fat_update_path_is_json_equivalent_to_trust_map() {
    let root = tempdir().expect("rootfs");
    let path_dir = tempdir().expect("path dir");
    let rootfs = root.path();

    std::fs::create_dir_all(rootfs.join("sbin")).expect("sbin");
    std::fs::create_dir_all(rootfs.join("usr/lib")).expect("usr lib");
    std::fs::write(
        rootfs.join("sbin").join("slpupgrade"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("slpupgrade");
    std::fs::write(
        rootfs.join("usr/lib").join("libsecurity.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("libsecurity");

    let rabin2_path = path_dir.path().join("rabin2");
    let script = r#"#!/bin/sh
mode="$1"
target="$2"
name="$(basename "$target")"
case "$mode:$name" in
  -ij:slpupgrade)
    printf '{"imports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"}]}'
    ;;
  -lj:slpupgrade)
    printf '{"libs":["libsecurity.so","libc.so.0"]}'
    ;;
  -Ej:slpupgrade)
    printf '{"exports":[]}'
    ;;
  -ij:libsecurity.so)
    printf '{"imports":[]}'
    ;;
  -lj:libsecurity.so)
    printf '{"libs":["libc.so.0"]}'
    ;;
  -Ej:libsecurity.so)
    printf '{"exports":[{"name":"rsaVerifySignByBase64EncodePublicKeyBlob"}]}'
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

    let trust_map = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "trust-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat trust-map json runs");
    let update_path = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "update-path",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.path().display(),
                std::env::var("PATH").expect("system PATH")
            ),
        )
        .output()
        .expect("fat update-path json runs");

    assert!(
        trust_map.status.success(),
        "trust-map failed: {:?}",
        trust_map.status
    );
    assert!(
        update_path.status.success(),
        "update-path failed: {:?}",
        update_path.status
    );

    let trust_map_json: Value = serde_json::from_slice(&trust_map.stdout).expect("trust-map json");
    let update_path_json: Value =
        serde_json::from_slice(&update_path.stdout).expect("update-path json");
    assert_normalized_semantic_equality(&trust_map_json, &update_path_json);
}
