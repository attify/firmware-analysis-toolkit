use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn fat_diff_firmware_help_lists_binary_layer() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["diff", "firmware", "--help"])
        .output()
        .expect("fat diff firmware --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fat diff firmware --help failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("filesystem, config, binary")
            && stdout.contains("Layer to diff")
            && stdout.contains("all"),
        "help should list the binary layer, got:\n{stdout}"
    );
    assert!(
        stdout.contains("radare2") || stdout.contains("r2"),
        "help should explain the binary layer backend, got:\n{stdout}"
    );
}

#[test]
fn fat_diff_firmware_produces_json_report() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Create minimal rootfs structures
    let base_etc = base_dir.path().join("rootfs").join("etc");
    let head_etc = head_dir.path().join("rootfs").join("etc");
    let head_cgi = head_dir.path().join("rootfs").join("www").join("cgi-bin");
    fs::create_dir_all(&base_etc).unwrap();
    fs::create_dir_all(&head_etc).unwrap();
    fs::create_dir_all(&head_cgi).unwrap();

    fs::write(base_etc.join("hostname"), "router-v1").unwrap();
    fs::write(head_etc.join("hostname"), "router-v2").unwrap();
    fs::write(head_cgi.join("admin.cgi"), "#!/bin/sh\necho admin").unwrap();

    // Create "extracted" symlinks pointing to rootfs
    std::os::unix::fs::symlink(
        base_dir.path().join("rootfs"),
        base_dir.path().join("extracted"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        head_dir.path().join("rootfs"),
        head_dir.path().join("extracted"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "diff",
            "firmware",
            "--base",
            base_dir.path().to_str().unwrap(),
            "--head",
            head_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("fat diff firmware");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fat diff firmware failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Parse JSON output
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    // Verify report structure
    assert!(report.get("filesystem").is_some(), "missing filesystem key");
    assert!(report.get("summary").is_some(), "missing summary key");

    // The added CGI should appear in filesystem diff
    let fs_diff = report.get("filesystem").unwrap();
    let added = fs_diff.get("added").and_then(|v| v.as_array()).unwrap();
    assert!(
        added.iter().any(|f| {
            f.get("path")
                .and_then(|v| v.as_str())
                .is_some_and(|p| p.contains("admin.cgi"))
        }),
        "expected admin.cgi in added files, got: {added:?}"
    );
}

#[test]
fn fat_diff_firmware_text_output_includes_summary() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Create minimal rootfs structures
    let base_etc = base_dir.path().join("rootfs").join("etc");
    let head_etc = head_dir.path().join("rootfs").join("etc");
    fs::create_dir_all(&base_etc).unwrap();
    fs::create_dir_all(&head_etc).unwrap();

    fs::write(base_etc.join("hostname"), "router-v1").unwrap();
    fs::write(head_etc.join("hostname"), "router-v2").unwrap();

    // Create "extracted" symlinks
    std::os::unix::fs::symlink(
        base_dir.path().join("rootfs"),
        base_dir.path().join("extracted"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        head_dir.path().join("rootfs"),
        head_dir.path().join("extracted"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "diff",
            "firmware",
            "--base",
            base_dir.path().to_str().unwrap(),
            "--head",
            head_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("fat diff firmware text");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fat diff firmware failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Text output should contain summary section
    assert!(
        stdout.contains("Firmware Diff") || stdout.contains("Summary"),
        "expected summary heading in text output, got:\n{stdout}"
    );
}

#[test]
fn fat_diff_firmware_security_flag_filters_output() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Create rootfs with security-relevant and non-security changes
    let base_root = base_dir.path().join("rootfs");
    let head_root = head_dir.path().join("rootfs");

    let base_etc = base_root.join("etc");
    let head_etc = head_root.join("etc");
    let head_cgi = head_root.join("www").join("cgi-bin");
    fs::create_dir_all(&base_etc).unwrap();
    fs::create_dir_all(&head_etc).unwrap();
    fs::create_dir_all(&head_cgi).unwrap();

    // Non-security change
    fs::write(base_etc.join("hostname"), "router-v1").unwrap();
    fs::write(head_etc.join("hostname"), "router-v2").unwrap();

    // Security-relevant change
    fs::write(head_cgi.join("remote.cgi"), "#!/bin/sh\necho pwned").unwrap();

    std::os::unix::fs::symlink(&base_root, base_dir.path().join("extracted")).unwrap();
    std::os::unix::fs::symlink(&head_root, head_dir.path().join("extracted")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "diff",
            "firmware",
            "--base",
            base_dir.path().to_str().unwrap(),
            "--head",
            head_dir.path().to_str().unwrap(),
            "--security",
            "--json",
        ])
        .output()
        .expect("fat diff firmware --security");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let fs_diff = report.get("filesystem").unwrap();
    let added = fs_diff.get("added").and_then(|v| v.as_array()).unwrap();

    // In security mode, only security-tagged entries should be present
    for entry in added {
        let tags = entry.get("security-tags").and_then(|v| v.as_array());
        assert!(
            tags.is_some_and(|t| !t.is_empty()),
            "expected all entries to have security tags in --security mode, got: {entry:?}"
        );
    }
}
