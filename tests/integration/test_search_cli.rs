use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn write_elf_file(path: &Path, strings: &[&str]) {
    let mut bytes = vec![0x7f, b'E', b'L', b'F', 1, 1, 1, 0];
    bytes.extend_from_slice(&[0; 24]);
    for s in strings {
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
    }
    std::fs::write(path, bytes).expect("fixture written");
}

fn run_search(rootfs: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command.args(["search", "--rootfs", rootfs.to_str().expect("rootfs path")]);
    command.args(args);
    command.output().expect("fat search runs")
}

fn run_search_with_env(
    rootfs: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command.args(["search", "--rootfs", rootfs.to_str().expect("rootfs path")]);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("fat search runs")
}

fn prepare_nested_rootfs_fixture(rootfs: &Path) {
    std::fs::create_dir_all(rootfs.join("app_payload/bin")).expect("app_payload/bin");
    std::fs::create_dir_all(rootfs.join("app_payload/lib")).expect("app_payload/lib");
    write_elf_file(
        &rootfs.join("app_payload/bin/camera_daemon"),
        &["ota_update"],
    );
}

fn prepare_false_positive_nested_rootfs_fixture(rootfs: &Path) {
    std::fs::create_dir_all(rootfs.join("bundle/bin")).expect("bundle/bin");
    std::fs::create_dir_all(rootfs.join("bundle/lib")).expect("bundle/lib");
    std::fs::create_dir_all(rootfs.join("bundle/nested_rootfs/bin"))
        .expect("bundle/nested_rootfs/bin");
    std::fs::create_dir_all(rootfs.join("bundle/nested_rootfs/lib"))
        .expect("bundle/nested_rootfs/lib");

    write_elf_file(
        &rootfs.join("bundle/nested_rootfs/bin/camera_daemon"),
        &["ota_update"],
    );
}

fn prepare_multiple_nested_rootfs_candidates_fixture(rootfs: &Path) {
    std::fs::create_dir_all(rootfs.join("app_payload/bin")).expect("app_payload/bin");
    std::fs::create_dir_all(rootfs.join("app_payload/lib")).expect("app_payload/lib");
    std::fs::create_dir_all(rootfs.join("nested_rootfs/sbin")).expect("nested_rootfs/sbin");
    std::fs::create_dir_all(rootfs.join("nested_rootfs/lib")).expect("nested_rootfs/lib");

    write_elf_file(
        &rootfs.join("app_payload/bin/camera_daemon"),
        &["ota_update"],
    );
    write_elf_file(&rootfs.join("nested_rootfs/sbin/updater"), &["ota_update"]);
}

#[test]
fn fat_search_help_mentions_core_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["search", "--help"])
        .output()
        .expect("fat search help runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "search",
        "--rootfs",
        "--include",
        "--profile",
        "--case-insensitive",
        "--context",
        "--unique",
        "--no-discover-rootfs",
        "--all-files",
        "--verbose",
        "--summary",
        "--format",
        "--color",
        "--show-empty",
        "--min-strength",
        "--context-filter",
    ] {
        assert!(
            stdout.contains(needle),
            "expected help output to mention {needle}, got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("--emit-actions"));
}

#[test]
fn fat_search_profile_without_include_is_accepted() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["password", "ota"]);

    let output = run_search(rootfs, &["--profile", "credentials", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "search-report/v2");
    assert_eq!(report["profiles"], serde_json::json!(["credentials"]));
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    assert_eq!(strings[0]["value"], "password");
}

#[test]
fn fat_search_json_reports_offsets_strength_and_line_numbers() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    std::fs::create_dir_all(rootfs.join("etc")).expect("etc");
    write_elf_file(
        &rootfs.join("bin/app"),
        &[
            "noise",
            "/configs/.product_config",
            "product_config_get_mac_addr",
        ],
    );
    std::fs::write(
        rootfs.join("etc/config.txt"),
        b"first line\nproduct_config_get_text\n",
    )
    .expect("text");

    let output = run_search(
        rootfs,
        &[
            "-i",
            "/configs/\\.product_config|product_config_get_",
            "--all-files",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let app = report["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .find(|file| file["path"] == "/bin/app")
        .expect("app match");
    assert_eq!(app["file_kind"], "elf");
    assert_eq!(app["score"], 11);
    assert_eq!(app["strength"], "STRONG");
    let app_strings = app["strings"].as_array().expect("app strings");
    assert_eq!(app_strings[0]["value"], "/configs/.product_config");
    assert_eq!(app_strings[0]["offset"], 38);
    assert_eq!(app_strings[0]["kind"], "literal-path");
    assert_eq!(app_strings[0]["strength"], "STRONG");
    assert_eq!(app_strings[0]["score"], 10);
    assert_eq!(app_strings[1]["kind"], "accessor");
    assert_eq!(app_strings[1]["strength"], "MEDIUM");

    let text = report["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .find(|file| file["path"] == "/etc/config.txt")
        .expect("text match");
    assert_eq!(text["file_kind"], "text");
    let text_strings = text["strings"].as_array().expect("text strings");
    assert_eq!(text_strings[0]["line_number"], 2);
    assert_eq!(text_strings[0]["offset"], 11);
}

#[test]
fn fat_search_requires_include_or_profile() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["password"]);

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "search",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .output()
        .expect("fat search runs");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("provide --include or --profile"),
        "stderr: {stderr}"
    );
}

#[test]
fn fat_search_case_insensitive_matches_mixed_case_strings() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["PaSsWoRd", "OTA"]);

    let output = run_search(rootfs, &["-I", "--include", "password", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(report["case_insensitive"].as_bool().unwrap_or(false));
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    assert_eq!(strings[0]["value"], "PaSsWoRd");
}

#[test]
fn fat_search_unknown_profile_lists_valid_names() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["password"]);

    let output = run_search(rootfs, &["--profile", "unknown-profile"]);
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown search profile"),
        "stderr: {stderr}"
    );
    for needle in ["credentials", "urls", "crypto", "sinks", "debug"] {
        assert!(stderr.contains(needle), "stderr: {stderr}");
    }
}

#[test]
fn fat_search_default_mode_scans_elfs_and_ignores_text_files() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin/nested")).expect("bin");
    std::fs::create_dir_all(rootfs.join("etc")).expect("etc");

    write_elf_file(
        &rootfs.join("bin/nested/updater"),
        &["system ota upgrade", "firmware_update"],
    );
    std::fs::write(rootfs.join("bin/nested/readme.txt"), b"ota text match").expect("text");
    std::fs::write(rootfs.join("etc/config.txt"), b"ota outside bin").expect("text");

    let output = run_search(rootfs, &["-i", "ota|update|upgrade"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("/bin/nested/updater"), "stdout: {stdout}");
    assert!(stdout.contains("ota"), "stdout: {stdout}");
    assert!(!stdout.contains("readme.txt"), "stdout: {stdout}");
    assert!(!stdout.contains("config.txt"), "stdout: {stdout}");
}

#[test]
fn fat_search_default_output_is_compact_and_uses_offsets() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("app_payload/bin")).expect("bin");
    write_elf_file(
        &rootfs.join("app_payload/bin/camera_daemon"),
        &[
            "VENDOR_TAG",
            "/configs/.product_config",
            "product_config_get_mac_addr",
        ],
    );

    let output = run_search(
        rootfs,
        &[
            "-i",
            "/configs/\\.product_config|product_config_get_",
            "--path",
            "app_payload/bin",
            "--context",
            "1",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Search\n"), "stdout: {stdout}");
    assert!(
        stdout.contains("  scope    ELF under app_payload/bin"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("  pattern  /configs/\\.product_config|product_config_get_"));
    assert!(stdout.contains("  matched  1/1 files"), "stdout: {stdout}");
    assert!(stdout.contains("Results\n"), "stdout: {stdout}");
    assert!(stdout.contains("1. camera_daemon"), "stdout: {stdout}");
    assert!(
        stdout.contains("   path /app_payload/bin/"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("1. /app_payload/bin/camera_daemon"),
        "stdout still uses full path as result title: {stdout}"
    );
    assert!(
        stdout.contains("strength STRONG"),
        "stdout missing file strength: {stdout}"
    );
    assert!(
        !stdout.contains("-- 1."),
        "stdout still uses old file divider: {stdout}"
    );
    assert!(!stdout.contains("Rootfs candidates:"), "stdout: {stdout}");
    assert!(!stdout.contains("Min len:"), "stdout: {stdout}");
    assert!(stdout.contains("@ 0x"), "stdout: {stdout}");
    assert!(stdout.contains("STRONG"), "stdout: {stdout}");
    assert!(stdout.contains("literal-path"), "stdout: {stdout}");
    assert!(
        stdout.contains("4.0") || stdout.contains("bytes"),
        "stdout: {stdout}"
    );
}

#[test]
fn fat_search_verbose_output_includes_full_execution_metadata() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["ota_update"]);

    let output = run_search(rootfs, &["-i", "ota", "--verbose"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Rootfs candidates:"), "stdout: {stdout}");
    assert!(stdout.contains("Min len: 4"), "stdout: {stdout}");
}

#[test]
fn fat_search_progress_human_writes_scan_updates_to_stderr_without_polluting_json_stdout() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["ota_update"]);
    write_elf_file(&rootfs.join("bin/other"), &["not_a_match"]);

    let output = run_search(rootfs, &["-i", "ota", "--json", "--progress", "human"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(report["files_scanned"], 2);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Search progress"),
        "stderr missing progress header: {stderr}"
    );
    assert!(
        stderr.contains("scan candidates: 2 files"),
        "stderr missing candidate count: {stderr}"
    );
    assert!(
        stderr.contains("scanned 2/2 files"),
        "stderr missing final scan count: {stderr}"
    );
}

#[test]
fn fat_search_context_omits_other_matches_in_same_file() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/app"),
        &[
            "before_one",
            "product_config_get_model",
            "product_config_get_mac_addr",
            "after_one",
        ],
    );

    let output = run_search(rootfs, &["-i", "product_config_get_", "--context", "1"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Nearby strings by offset"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("before_one"), "stdout: {stdout}");
    assert!(stdout.contains("after_one"), "stdout: {stdout}");
    assert!(
        !stdout.contains("+1  product_config_get_mac_addr")
            && !stdout.contains("-1  product_config_get_model"),
        "stdout: {stdout}"
    );
}

#[test]
fn fat_search_human_output_demangles_cpp_symbol_strings() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/ota_utils"),
        &[
            "_ZNSt10shared_ptrIN7unitree6common14LogBlockBufferEEC1Ev",
            "_ZN7unitree7package13TEADecodeFileERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES8_PKh",
            "_ZN7unitree7package7Package9CheckSignEPKhS3_",
            "_ZNK7unitree3ota7OTATask8GetTokenB5cxx11Ev",
        ],
    );

    let output = run_search(
        rootfs,
        &["-i", "TEADecodeFile|CheckSign|GetToken", "--context", "1"],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("unitree::package::TEADecodeFile("),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("unitree::package::Package::CheckSign("),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("unitree::ota::OTATask::GetToken() const"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("_ZN7unitree7package13TEADecodeFile"),
        "stdout still shows raw mangled symbol: {stdout}"
    );
    if Command::new("c++filt").arg("--version").output().is_ok() {
        assert!(
            stdout.contains("std::shared_ptr<unitree::common::LogBlockBuffer>::shared_ptr()"),
            "stdout: {stdout}"
        );
        assert!(
            !stdout.contains("_ZNSt10shared_ptr"),
            "stdout still shows raw nearby context symbol: {stdout}"
        );
    }
}

#[test]
fn fat_search_context_filter_drops_boilerplate_runtime_strings() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/app"),
        &[
            "libgcc_s.so.1",
            "product_config_get_model",
            "useful_context",
        ],
    );

    let output = run_search(rootfs, &["-i", "product_config_get_", "--context", "1"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("libgcc_s.so.1"), "stdout: {stdout}");
    assert!(stdout.contains("useful_context"), "stdout: {stdout}");
}

#[test]
fn fat_search_min_strength_filters_weaker_hits() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/app"),
        &["/configs/.product_config", "product_config_get_model"],
    );

    let output = run_search(
        rootfs,
        &[
            "-i",
            "/configs/\\.product_config|product_config_get_",
            "--min-strength",
            "strong",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["min_strength"], "strong");
    let strings = report["matches"][0]["strings"].as_array().expect("strings");
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0]["value"], "/configs/.product_config");
}

#[test]
fn fat_search_forced_color_highlights_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["product_config_get_model"]);

    let output = run_search_with_env(
        rootfs,
        &["-i", "product_config_get_", "--color", "always"],
        &[("NO_COLOR", "1")],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{1b}["), "stdout: {stdout}");
}

#[test]
fn fat_search_discovers_nested_rootfs_candidates_from_parent() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    prepare_nested_rootfs_fixture(rootfs);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidates = report["rootfs_candidates"].as_array().expect("candidates");
    assert!(
        candidates
            .iter()
            .any(|value| value.as_str() == Some("/app_payload")),
        "report: {report}"
    );
    let matches = report["matches"].as_array().expect("matches");
    assert_eq!(matches[0]["path"], "/app_payload/bin/camera_daemon");
}

#[test]
fn fat_search_discovery_does_not_prune_deeper_rootfs_candidates() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    prepare_false_positive_nested_rootfs_fixture(rootfs);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidates = report["rootfs_candidates"].as_array().expect("candidates");
    assert!(
        candidates
            .iter()
            .any(|value| value.as_str() == Some("/bundle/nested_rootfs")),
        "report: {report}"
    );

    let matches = report["matches"].as_array().expect("matches");
    assert!(
        matches
            .iter()
            .any(|value| value["path"] == "/bundle/nested_rootfs/bin/camera_daemon"),
        "report: {report}"
    );
}

#[test]
fn fat_search_discovers_multiple_nested_rootfs_candidates() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    prepare_multiple_nested_rootfs_candidates_fixture(rootfs);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidates = report["rootfs_candidates"].as_array().expect("candidates");
    assert!(
        candidates
            .iter()
            .any(|value| value.as_str() == Some("/app_payload")),
        "report: {report}"
    );
    assert!(
        candidates
            .iter()
            .any(|value| value.as_str() == Some("/nested_rootfs")),
        "report: {report}"
    );

    let matches = report["matches"].as_array().expect("matches");
    assert!(
        matches
            .iter()
            .any(|value| value["path"] == "/app_payload/bin/camera_daemon"),
        "report: {report}"
    );
    assert!(
        matches
            .iter()
            .any(|value| value["path"] == "/nested_rootfs/sbin/updater"),
        "report: {report}"
    );
}

#[test]
fn fat_search_no_discover_rootfs_preserves_strict_top_level_scope() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    prepare_nested_rootfs_fixture(rootfs);

    let output = run_search(rootfs, &["-i", "ota", "--no-discover-rootfs", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["files_scanned"], 0);
    assert!(report["matches"].as_array().expect("matches").is_empty());
}

#[test]
fn fat_search_all_files_includes_non_elf_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("etc")).expect("etc");
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    std::fs::write(rootfs.join("etc/config.txt"), b"device_password=secret").expect("config");
    write_elf_file(&rootfs.join("bin/app"), &["password", "secret"]);

    let output = run_search(rootfs, &["-i", "password|secret", "--all-files", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(report["exclude"].is_array());
    assert!(report["path_filter"].is_null());
    assert_eq!(report["max_per_file"], 20);
    assert_eq!(report["min_len"], 4);
    let matches = report["matches"].as_array().expect("matches array");
    let paths: Vec<_> = matches
        .iter()
        .map(|m| m["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/etc/config.txt"));
    assert!(paths.contains(&"/bin/app"));
}

#[test]
fn fat_search_exclude_filters_noisy_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["ota_update", "ota_noise", "noise_only"],
    );

    let output = run_search(rootfs, &["-i", "ota|noise", "-e", "noise", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(report["exclude"].as_array().is_some());
    assert_eq!(report["exclude"][0], "noise");
    let file = &report["matches"][0];
    let strings: Vec<_> = file["strings"]
        .as_array()
        .expect("strings")
        .iter()
        .map(|value| value["value"].as_str().expect("string"))
        .collect();
    assert!(strings.contains(&"ota_update"));
    assert!(!strings.iter().any(|s| s.contains("noise")));
}

#[test]
fn fat_search_max_truncates_results_per_file() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["ota-one", "ota-two", "ota-three", "ota-four"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--max", "2", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    assert_eq!(strings.len(), 2);
    assert_eq!(file["match_count"], 4);
    assert_eq!(file["unique_match_count"], 4);
    assert_eq!(file["truncated"], true);
}

#[test]
fn fat_search_context_reports_neighboring_strings() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["before_one", "ota_match", "after_one"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--context", "1", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    assert_eq!(strings[0]["value"], "ota_match");
    assert_eq!(strings[0]["context_before"][0], "before_one");
    assert_eq!(strings[0]["context_after"][0], "after_one");
}

#[test]
fn fat_search_text_files_clip_large_single_line_matches_to_snippets() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("web")).expect("web");

    let long_prefix = "A".repeat(220);
    let long_suffix = "B".repeat(220);
    let content = format!("{long_prefix}asp-match{long_suffix}\nneighbor line\n");
    std::fs::write(rootfs.join("web/app.css.map"), content).expect("sourcemap");

    let output = run_search(
        rootfs,
        &[
            "-i",
            "asp",
            "--all-files",
            "--context",
            "1",
            "--unique",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let file = report["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .find(|entry| entry["path"] == "/web/app.css.map")
        .expect("text match");
    let strings = file["strings"].as_array().expect("strings");
    let snippet = strings[0]["value"].as_str().expect("snippet");
    assert!(snippet.contains("asp-match"), "snippet: {snippet}");
    assert!(snippet.starts_with("..."), "snippet: {snippet}");
    assert!(snippet.ends_with("..."), "snippet: {snippet}");
    assert!(snippet.len() < 200, "snippet too long: {}", snippet.len());
    assert_eq!(strings[0]["line_number"], 1);
    assert_eq!(strings[0]["context_after"][0], "neighbor line");
}

#[test]
fn fat_search_all_files_skips_obvious_binary_assets() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("web")).expect("web");
    std::fs::write(rootfs.join("web/app.js"), b"location.href='login.asp';\n").expect("text");

    let mut font_like = vec![0u8; 64];
    font_like[8..12].copy_from_slice(b"gasp");
    font_like[20..24].copy_from_slice(b"glyf");
    std::fs::write(rootfs.join("web/font.ttf"), font_like).expect("binary");

    let output = run_search(rootfs, &["-i", "asp", "--all-files", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let matches = report["matches"].as_array().expect("matches");
    assert!(
        matches.iter().any(|entry| entry["path"] == "/web/app.js"),
        "report: {report}"
    );
    assert!(
        !matches.iter().any(|entry| entry["path"] == "/web/font.ttf"),
        "report: {report}"
    );
}

#[test]
fn fat_search_explicit_path_scans_raw_binary_strings_with_offsets() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    let mut bytes = vec![0u8; 128];
    bytes[0x40..0x5b].copy_from_slice(b"../LWIP/Target/ethernetif.c");
    std::fs::write(rootfs.join("firmware.bin"), bytes).expect("raw firmware");

    let output = run_search(
        rootfs,
        &[
            "-i",
            "ethernetif\\.c",
            "--path",
            "firmware.bin",
            "--all-files",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(report["files_skipped"], 0);
    assert_eq!(report["matches"][0]["path"], "/firmware.bin");
    assert_eq!(report["matches"][0]["file_kind"], "raw");
    assert_eq!(report["matches"][0]["strings"][0]["offset"], 0x40);
    assert_eq!(
        report["matches"][0]["strings"][0]["value"],
        "../LWIP/Target/ethernetif.c"
    );
}

#[test]
fn fat_search_all_files_recognizes_raw_cortex_m_firmware() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    let mut bytes = vec![0u8; 1024];
    bytes[0..4].copy_from_slice(&0x2401_a058u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x0800_0011u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x0800_0021u32.to_le_bytes());
    bytes[0x100..0x11b].copy_from_slice(b"../LWIP/Target/ethernetif.c");
    std::fs::write(rootfs.join("firmware.bin"), bytes).expect("raw firmware");

    let output = run_search(rootfs, &["-i", "ethernetif\\.c", "--all-files", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(report["files_skipped"], 0);
    assert_eq!(report["matches"][0]["file_kind"], "raw");
    assert_eq!(report["matches"][0]["strings"][0]["offset"], 0x100);
}

#[test]
fn fat_search_context_saturates_oversized_context() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["before_one", "ota_match", "after_one"],
    );

    let context = usize::MAX.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "search",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "-i",
            "ota",
            "--context",
            &context,
            "--json",
        ])
        .output()
        .expect("fat search runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let strings = report["matches"][0]["strings"].as_array().expect("strings");
    assert_eq!(
        strings[0]["context_before"],
        serde_json::json!(["before_one"])
    );
    assert_eq!(
        strings[0]["context_after"],
        serde_json::json!(["after_one"])
    );
}

#[test]
fn fat_search_reports_file_size_for_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    let app = rootfs.join("bin/app");
    write_elf_file(&app, &["ota_match"]);
    let expected_size = std::fs::metadata(&app).expect("metadata").len();

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["matches"][0]["size_bytes"], expected_size);
    assert_eq!(report["ranked_files"][0]["size_bytes"], expected_size);
}

#[test]
fn fat_search_ranks_files_by_match_count() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(&rootfs.join("bin/alpha"), &["ota_one"]);
    write_elf_file(&rootfs.join("bin/beta"), &["ota_one", "ota_two"]);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let ranked = report["ranked_files"].as_array().expect("ranked_files");
    assert_eq!(ranked[0]["path"], "/bin/beta");
    assert_eq!(ranked[0]["match_count"], 2);
    assert_eq!(ranked[0]["unique_match_count"], 2);
    assert_eq!(ranked[1]["path"], "/bin/alpha");
    assert_eq!(ranked[1]["match_count"], 1);
    assert_eq!(ranked[1]["unique_match_count"], 1);
}

#[test]
fn fat_search_weighted_ranking_prefers_literal_paths_over_more_accessors() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/accessors"),
        &[
            "product_config_get_model",
            "product_config_get_mac_addr",
            "product_config_get_firmware_version",
        ],
    );
    write_elf_file(&rootfs.join("bin/pathref"), &["/configs/.product_config"]);

    let output = run_search(
        rootfs,
        &[
            "-i",
            "/configs/\\.product_config|product_config_get_",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let ranked = report["ranked_files"].as_array().expect("ranked_files");
    assert_eq!(ranked[0]["path"], "/bin/pathref");
    assert_eq!(ranked[0]["score"], 10);
    assert_eq!(ranked[0]["strength"], "STRONG");
    assert_eq!(ranked[1]["score"], 3);
    assert_eq!(ranked[1]["strength"], "MEDIUM");
}

#[test]
fn fat_search_json_reports_scoring_weights_and_empty_scanned_files() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/match"), &["/configs/.product_config"]);
    write_elf_file(&rootfs.join("bin/empty"), &["no interesting strings"]);

    let output = run_search(rootfs, &["-i", "/configs/\\.product_config", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["scoring"]["literal_path"], 10);
    assert_eq!(report["scoring"]["accessor"], 1);
    assert_eq!(
        report["scanned_files_without_matches"],
        serde_json::json!(["/bin/empty"])
    );
}

#[test]
fn fat_search_show_empty_prints_scanned_files_without_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/match"), &["product_config_get_model"]);
    write_elf_file(&rootfs.join("bin/empty"), &["boring"]);

    let output = run_search(rootfs, &["-i", "product_config_get_", "--show-empty"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Files without matches"), "stdout: {stdout}");
    assert!(stdout.contains("/bin/empty"), "stdout: {stdout}");
}

#[test]
fn fat_search_human_output_splits_discriminating_and_common_strings() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/alpha"),
        &[
            "product_config_get_model",
            "product_config_get_userdata_encryption_key",
        ],
    );
    write_elf_file(
        &rootfs.join("bin/beta"),
        &["product_config_get_model", "product_config_get_pub_key"],
    );

    let output = run_search(rootfs, &["-i", "product_config_get_"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let discriminating = stdout
        .find("Discriminating strings")
        .expect("discriminating block");
    let common = stdout.find("Common strings").expect("common block");
    assert!(discriminating < common, "stdout: {stdout}");
    assert!(
        stdout[discriminating..common].contains("userdata_encryption_key"),
        "stdout: {stdout}"
    );
    assert!(
        stdout[common..].contains("product_config_get_model"),
        "stdout: {stdout}"
    );
    assert!(
        !stdout[common..].contains("userdata_encryption_key"),
        "stdout: {stdout}"
    );
}

#[test]
fn fat_search_single_file_signal_block_omits_repeated_file_suffixes() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/app"),
        &["Alpha Lab", "Beta Lab", "Gamma University"],
    );

    let output = run_search(rootfs, &["-i", "Lab|University", "--unique"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let signals = stdout
        .split("Discriminating strings")
        .nth(1)
        .expect("discriminating block");
    assert!(
        signals.contains("  from /bin/app"),
        "stdout missing single-file context: {stdout}"
    );
    assert!(signals.contains("  Alpha Lab"), "stdout: {stdout}");
    assert!(signals.contains("  Beta Lab"), "stdout: {stdout}");
    assert!(
        !signals.contains("(files: 1, /bin/app)"),
        "stdout repeats single-file suffixes: {stdout}"
    );
}

#[test]
fn fat_search_human_output_does_not_repeat_strength_inside_accessor_group() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["product_config_get_model"]);

    let output = run_search(rootfs, &["-i", "product_config_get_"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[accessor]"), "stdout: {stdout}");
    assert!(
        !stdout.contains("MEDIUM  product_config_get_model"),
        "stdout: {stdout}"
    );
}

#[test]
fn fat_search_ranking_uses_total_matches_when_results_are_truncated() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(&rootfs.join("bin/aaa-small"), &["ota_one"]);
    write_elf_file(
        &rootfs.join("bin/zzz-large"),
        &["ota_one", "ota_two", "ota_three"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--max", "1", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let ranked = report["ranked_files"].as_array().expect("ranked_files");
    assert_eq!(ranked[0]["path"], "/bin/zzz-large");
    assert_eq!(ranked[0]["match_count"], 3);
    assert_eq!(ranked[0]["truncated"], true);
    assert_eq!(ranked[1]["path"], "/bin/aaa-small");
    assert_eq!(ranked[1]["match_count"], 1);
}

#[test]
fn fat_search_reports_shared_strings_across_files() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(&rootfs.join("bin/alpha"), &["ota_shared", "ota_unique"]);
    write_elf_file(&rootfs.join("bin/beta"), &["ota_shared"]);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let shared = report["shared_strings"].as_array().expect("shared_strings");
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0]["value"], "ota_shared");
    assert_eq!(shared[0]["file_count"], 2);
    assert_eq!(
        shared[0]["files"],
        serde_json::json!(["/bin/alpha", "/bin/beta"])
    );
}

#[test]
fn fat_search_shared_strings_use_total_matches_when_results_are_truncated() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(&rootfs.join("bin/alpha"), &["ota_first", "ota_shared"]);
    write_elf_file(&rootfs.join("bin/beta"), &["ota_shared"]);

    let output = run_search(rootfs, &["-i", "ota", "--max", "1", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let shared = report["shared_strings"].as_array().expect("shared_strings");
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0]["value"], "ota_shared");
    assert_eq!(shared[0]["file_count"], 2);
}

#[test]
fn fat_search_summary_mode_prints_one_line_per_ranked_file() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/camera_daemon"),
        &["/configs/.product_config", "product_config_get_ota_app_key"],
    );
    write_elf_file(&rootfs.join("bin/sinker"), &["product_config_get_model"]);

    let output = run_search(
        rootfs,
        &[
            "-i",
            "/configs/\\.product_config|product_config_get_",
            "--summary",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("camera_daemon"), "stdout: {stdout}");
    assert!(stdout.contains("STRONG"), "stdout: {stdout}");
    assert!(stdout.contains("path-ref + 1 accessor"), "stdout: {stdout}");
    assert!(stdout.contains("sinker"), "stdout: {stdout}");
    assert!(!stdout.contains("Search report"), "stdout: {stdout}");
}

#[test]
fn fat_search_does_not_add_suggestions() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/camera_daemon"),
        &["/configs/.product_config"],
    );

    let output = run_search(rootfs, &["-i", "/configs/\\.product_config"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bin/camera_daemon"), "stdout: {stdout}");
    assert!(
        stdout.contains("/configs/.product_config"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("Suggested next steps"), "stdout: {stdout}");
    assert!(!stdout.contains("fat r2-triage"), "stdout: {stdout}");
    assert!(!stdout.contains("fat xref-search"), "stdout: {stdout}");
}

#[test]
fn fat_search_preserves_discriminating_values_without_suggestions() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/camera_daemon"),
        &["product_config_get_model", "/configs/.product_config"],
    );
    write_elf_file(
        &rootfs.join("bin/dumpload"),
        &[
            "product_config_get_model",
            "product_config_get_userdata_encryption_key",
        ],
    );
    write_elf_file(
        &rootfs.join("bin/assis"),
        &[
            "product_config_get_model",
            "product_config_get_log_encryption_key",
        ],
    );

    let output = run_search(
        rootfs,
        &["-i", "/configs/\\.product_config|product_config_get_"],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bin/dumpload"), "stdout: {stdout}");
    assert!(
        stdout.contains("product_config_get_userdata_encryption_key"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("bin/assis"), "stdout: {stdout}");
    assert!(
        stdout.contains("product_config_get_log_encryption_key"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("Suggested next steps"), "stdout: {stdout}");
    assert!(!stdout.contains("fat xref-search"), "stdout: {stdout}");
}

#[test]
fn fat_search_anchor_format_emits_notebook_anchors() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(
        &rootfs.join("bin/camera_daemon"),
        &["/configs/.product_config"],
    );

    let output = run_search(
        rootfs,
        &["-i", "/configs/\\.product_config", "--format", "anchor"],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!-- anchor"), "stdout: {stdout}");
    assert!(
        stdout.contains("uri: bin/camera_daemon"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("region: { stringOffset: 0x"),
        "stdout: {stdout}"
    );
    let open_count = stdout.matches("<!-- anchor").count();
    let close_count = stdout.matches("-->").count();
    assert_eq!(open_count, 1, "stdout: {stdout}");
    assert_eq!(close_count, open_count, "stdout: {stdout}");
    assert!(
        stdout.contains("label: camera_daemon@0x"),
        "stdout: {stdout}"
    );
}

#[test]
fn fat_search_unique_deduplicates_matches_per_file() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["ota_repeat", "ota_repeat", "ota_unique"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--unique", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    let values: Vec<_> = strings
        .iter()
        .map(|value| value["value"].as_str().expect("string"))
        .collect();
    assert_eq!(file["match_count"], 2);
    assert_eq!(file["unique_match_count"], 2);
    assert_eq!(values, ["ota_repeat", "ota_unique"]);
}

#[test]
fn fat_search_without_unique_preserves_duplicate_matches() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/app"),
        &["ota_repeat", "ota_repeat", "ota_unique"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let file = &report["matches"][0];
    let strings = file["strings"].as_array().expect("strings");
    let values: Vec<_> = strings
        .iter()
        .map(|value| value["value"].as_str().expect("string"))
        .collect();
    assert_eq!(file["match_count"], 3);
    assert_eq!(file["unique_match_count"], 2);
    assert_eq!(values, ["ota_repeat", "ota_repeat", "ota_unique"]);
}

#[test]
fn fat_search_json_reports_selected_path_filter() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin/nested")).expect("bin");

    write_elf_file(
        &rootfs.join("bin/nested/updater"),
        &["ota_update", "firmware"],
    );

    let output = run_search(rootfs, &["-i", "ota", "--path", "bin/nested", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["path_filter"], "bin/nested");
    assert_eq!(report["rootfs_candidates"], serde_json::json!(["/"]));
    assert_eq!(report["max_per_file"], 20);
    assert_eq!(report["matches"][0]["match_count"], 1);
}

#[test]
fn fat_search_invalid_include_regex_fails() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["ota"]);

    let output = run_search(rootfs, &["-i", "["]);
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid include regex"), "stderr: {stderr}");
}

#[test]
fn fat_search_zero_max_fails() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["ota"]);

    let output = run_search(rootfs, &["-i", "ota", "--max", "0"]);
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("max"), "stderr: {stderr}");
}

#[test]
fn fat_search_zero_min_len_fails() {
    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    write_elf_file(&rootfs.join("bin/app"), &["ota"]);

    let output = run_search(rootfs, &["-i", "ota", "--min-len", "0"]);
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("min"), "stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn fat_search_rejects_symlink_path_escape() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    let outside = tempdir().expect("outside");
    std::fs::create_dir_all(rootfs.join("bin")).expect("bin");
    std::fs::write(outside.path().join("secret.bin"), b"secret").expect("outside file");
    symlink(outside.path(), rootfs.join("escape")).expect("escape symlink");

    let output = run_search(rootfs, &["-i", "secret", "--path", "escape", "--all-files"]);
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rootfs") || stderr.contains("escape"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn fat_search_counts_unreadable_traversal_errors() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().expect("rootfs");
    let rootfs = root.path();
    std::fs::create_dir_all(rootfs.join("bin/blocked")).expect("bin");
    write_elf_file(&rootfs.join("bin/visible"), &["ota"]);
    write_elf_file(&rootfs.join("bin/blocked/hidden"), &["ota"]);

    let mut perms = std::fs::metadata(rootfs.join("bin/blocked"))
        .expect("blocked metadata")
        .permissions();
    perms.set_mode(0o0);
    std::fs::set_permissions(rootfs.join("bin/blocked"), perms).expect("restrict blocked");

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(
        report["files_skipped"].as_u64().unwrap_or(0) >= 1,
        "report: {report}"
    );
}

/// Rootfs auto-discovery used to carry two vendor directory names, so what FAT
/// scanned depended on a product name rather than on what was in the tree.
/// Discovery is now evidence-based: a directory is descended because it looks
/// like a root filesystem, never because of what it is called.
#[test]
fn a_vendor_directory_name_alone_does_not_make_a_tree_discoverable() {
    let temp = tempdir().expect("tempdir");
    let rootfs = temp.path();

    // Named like a known product, but with none of the structure of a rootfs.
    std::fs::create_dir_all(rootfs.join("wyze_app/assets")).expect("named dir");
    write_elf_file(
        &rootfs.join("wyze_app/assets/camera_daemon"),
        &["ota_update"],
    );

    // Same content, in a directory that does look like a rootfs.
    std::fs::create_dir_all(rootfs.join("payload/bin")).expect("marker dir");
    std::fs::create_dir_all(rootfs.join("payload/lib")).expect("marker dir");
    write_elf_file(&rootfs.join("payload/bin/camera_daemon"), &["ota_update"]);

    let output = run_search(rootfs, &["-i", "ota", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    let candidates = report["rootfs_candidates"].as_array().expect("candidates");
    assert!(
        candidates
            .iter()
            .any(|value| value.as_str() == Some("/payload")),
        "a tree with rootfs markers is still discovered: {report}"
    );
    assert!(
        !candidates
            .iter()
            .any(|value| value.as_str() == Some("/wyze_app")),
        "a tree discoverable only by its vendor name must not be scanned: {report}"
    );
}
