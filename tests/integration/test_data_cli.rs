#[path = "../support/subprocess.rs"]
mod test_subprocess;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde_json::json;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_data_tree(root: &Path, version: &str, profile: &[u8]) {
    let profile_path = root.join("profiles/rehosting/acme/router.yaml");
    fs::create_dir_all(profile_path.parent().unwrap()).unwrap();
    fs::write(&profile_path, profile).unwrap();
    let manifest = json!({
        "schema_version": 1,
        "data_version": version,
        "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
        "files": [{
            "path": "profiles/rehosting/acme/router.yaml",
            "sha256": digest(profile),
            "required": true
        }]
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn user_data_root(home: &Path) -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        home.join("FAT")
    }
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/FAT")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        home.join(".local/share/fat")
    }
}

fn write_managed_data_tree(root: &Path, version: &str, profile: &[u8]) {
    let active_root = root.join("versions").join(version);
    fs::create_dir_all(&active_root).unwrap();
    write_data_tree(&active_root, version, profile);
    fs::write(
        root.join("active.json"),
        serde_json::to_vec_pretty(&json!({
            "data_version": version,
            "relative_path": format!("versions/{version}")
        }))
        .unwrap(),
    )
    .unwrap();
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .output()
        .expect("fat runs")
}

#[test]
fn data_install_status_verify_and_list_manage_a_versioned_tree() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    write_data_tree(source.path(), "2.0.0-alpha.2", b"id: acme/router\n");

    let install = run(&[
        "data",
        "install",
        "--archive",
        source.path().to_str().unwrap(),
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(install.status.success(), "{install:?}");
    let installed: serde_json::Value = serde_json::from_slice(&install.stdout).unwrap();
    assert_eq!(installed["data_version"], "2.0.0-alpha.2");
    assert_eq!(installed["verified_files"], 1);

    let status = run(&[
        "data",
        "status",
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(status.status.success(), "{status:?}");
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["status"], "ready");
    assert_eq!(status_json["data_version"], "2.0.0-alpha.2");
    assert_eq!(status_json["origin"], "explicit");

    let verify = run(&[
        "data",
        "verify",
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(verify.status.success(), "{verify:?}");

    let list = run(&[
        "data",
        "list",
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(list.status.success(), "{list:?}");
    let versions: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(versions["versions"], json!(["2.0.0-alpha.2"]));
}

#[test]
fn data_status_resolves_and_verifies_executable_relative_share_data() {
    // Keep writable executable-copy handles out of concurrently spawned test
    // children, which can otherwise make exec fail with ETXTBSY on Linux.
    if let Some(mut command) = test_subprocess::isolated_test(
        "data_status_resolves_and_verifies_executable_relative_share_data",
    ) {
        test_subprocess::assert_success(&mut command);
        return;
    }
    let prefix = tempfile::tempdir().unwrap();
    let isolated_home = tempfile::tempdir().unwrap();
    let bin_dir = prefix.path().join("bin");
    let data_root = prefix.path().join("share/fat");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&data_root).unwrap();
    write_data_tree(&data_root, "2.0.0-alpha.7", b"id: bundled/router\n");
    let installed_fat = bin_dir.join("fat");
    fs::copy(env!("CARGO_BIN_EXE_fat"), &installed_fat).unwrap();

    let output = Command::new(&installed_fat)
        .args(["data", "status", "--json"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");

    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["status"], "ready");
    assert_eq!(status["data_version"], "2.0.0-alpha.7");
    assert_eq!(status["origin"], "executable-relative");
    assert_eq!(status["data_root"], data_root.display().to_string());
    assert_eq!(status["active_path"], data_root.display().to_string());

    let human = Command::new(&installed_fat)
        .args(["data", "status"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");
    assert!(human.status.success(), "{human:?}");
    assert!(
        String::from_utf8_lossy(&human.stdout).contains("Origin: executable-relative"),
        "{}",
        String::from_utf8_lossy(&human.stdout)
    );

    let verify = Command::new(&installed_fat)
        .args(["data", "verify", "--json"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");
    assert!(verify.status.success(), "{verify:?}");
    let verified: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verified["status"], "verified");
    assert_eq!(verified["data_version"], "2.0.0-alpha.7");
    assert_eq!(verified["data_root"], data_root.display().to_string());
}

#[test]
fn data_verify_does_not_fall_back_past_corrupt_executable_relative_data() {
    if let Some(mut command) = test_subprocess::isolated_test(
        "data_verify_does_not_fall_back_past_corrupt_executable_relative_data",
    ) {
        test_subprocess::assert_success(&mut command);
        return;
    }
    let prefix = tempfile::tempdir().unwrap();
    let isolated_home = tempfile::tempdir().unwrap();
    let bin_dir = prefix.path().join("bin");
    let bundled_root = prefix.path().join("share/fat");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&bundled_root).unwrap();
    write_data_tree(&bundled_root, "2.0.0-alpha.7", b"id: bundled/router\n");
    fs::write(
        bundled_root.join("profiles/rehosting/acme/router.yaml"),
        b"corrupt bundled data\n",
    )
    .unwrap();

    let managed_root = user_data_root(isolated_home.path());
    fs::create_dir_all(&managed_root).unwrap();
    write_managed_data_tree(&managed_root, "2.0.0-alpha.8", b"id: managed/router\n");

    let installed_fat = bin_dir.join("fat");
    fs::copy(env!("CARGO_BIN_EXE_fat"), &installed_fat).unwrap();
    let verify = Command::new(&installed_fat)
        .args(["data", "verify", "--json"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");

    assert!(
        !verify.status.success(),
        "must verify the authoritative bundled tree, not the valid managed fallback: {verify:?}"
    );
}

#[test]
fn stale_executable_relative_active_record_is_broken_without_managed_fallback() {
    if let Some(mut command) = test_subprocess::isolated_test(
        "stale_executable_relative_active_record_is_broken_without_managed_fallback",
    ) {
        test_subprocess::assert_success(&mut command);
        return;
    }
    let prefix = tempfile::tempdir().unwrap();
    let isolated_home = tempfile::tempdir().unwrap();
    let bin_dir = prefix.path().join("bin");
    let bundled_root = prefix.path().join("share/fat");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&bundled_root).unwrap();
    fs::write(
        bundled_root.join("active.json"),
        serde_json::to_vec_pretty(&json!({
            "data_version": "2.0.0-alpha.7",
            "relative_path": "versions/missing"
        }))
        .unwrap(),
    )
    .unwrap();

    let managed_root = user_data_root(isolated_home.path());
    fs::create_dir_all(&managed_root).unwrap();
    write_managed_data_tree(&managed_root, "2.0.0-alpha.8", b"id: managed/router\n");

    let installed_fat = bin_dir.join("fat");
    fs::copy(env!("CARGO_BIN_EXE_fat"), &installed_fat).unwrap();
    let status = Command::new(&installed_fat)
        .args(["data", "status", "--json"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");
    assert!(status.status.success(), "{status:?}");
    let reported: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(reported["status"], "broken");
    assert_eq!(reported["origin"], "executable-relative");
    assert_ne!(reported["data_version"], "2.0.0-alpha.8");

    let verify = Command::new(&installed_fat)
        .args(["data", "verify", "--json"])
        .env_remove("FAT_DATA_DIR")
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");
    assert!(
        !verify.status.success(),
        "stale bundled activation must not verify managed fallback: {verify:?}"
    );
}

#[test]
fn data_verify_uses_the_authoritative_environment_tree() {
    let configured = tempfile::tempdir().unwrap();
    let isolated_home = tempfile::tempdir().unwrap();
    write_data_tree(
        configured.path(),
        "2.0.0-alpha.9",
        b"id: environment/router\n",
    );

    let managed_root = user_data_root(isolated_home.path());
    fs::create_dir_all(&managed_root).unwrap();
    write_managed_data_tree(&managed_root, "2.0.0-alpha.8", b"id: managed/router\n");

    let ready = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["data", "verify", "--json"])
        .env("FAT_DATA_DIR", configured.path())
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .output()
        .expect("fat runs");
    assert!(ready.status.success(), "{ready:?}");
    let verified: serde_json::Value = serde_json::from_slice(&ready.stdout).unwrap();
    assert_eq!(verified["data_version"], "2.0.0-alpha.9");
    assert_eq!(
        verified["data_root"],
        configured.path().display().to_string()
    );

    fs::write(
        configured
            .path()
            .join("profiles/rehosting/acme/router.yaml"),
        b"corrupt configured data\n",
    )
    .unwrap();
    let corrupt = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["data", "verify", "--json"])
        .env("FAT_DATA_DIR", configured.path())
        .env("HOME", isolated_home.path())
        .env("LOCALAPPDATA", isolated_home.path())
        .output()
        .expect("fat runs");
    assert!(
        !corrupt.status.success(),
        "must not fall back to valid managed data: {corrupt:?}"
    );
}

#[test]
fn data_status_does_not_fall_back_past_a_configured_broken_environment_root() {
    if let Some(mut command) = test_subprocess::isolated_test(
        "data_status_does_not_fall_back_past_a_configured_broken_environment_root",
    ) {
        test_subprocess::assert_success(&mut command);
        return;
    }
    let prefix = tempfile::tempdir().unwrap();
    let configured = tempfile::tempdir().unwrap();
    let bin_dir = prefix.path().join("bin");
    let bundled_root = prefix.path().join("share/fat");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&bundled_root).unwrap();
    write_data_tree(&bundled_root, "2.0.0-alpha.7", b"id: bundled/router\n");
    fs::write(
        configured.path().join("active.json"),
        r#"{"data_version":"2.0.0-alpha.9","relative_path":"versions/2.0.0-alpha.9"}"#,
    )
    .unwrap();
    let installed_fat = bin_dir.join("fat");
    fs::copy(env!("CARGO_BIN_EXE_fat"), &installed_fat).unwrap();

    let output = Command::new(&installed_fat)
        .args(["data", "status", "--json"])
        .env("FAT_DATA_DIR", configured.path())
        .current_dir(prefix.path())
        .output()
        .expect("installed fat runs");

    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["status"], "broken");
    assert_eq!(status["data_version"], "2.0.0-alpha.9");
    assert_eq!(status["origin"], "environment");
    assert_eq!(status["data_root"], configured.path().display().to_string());
}

#[test]
fn data_status_reports_malformed_authoritative_active_record_as_broken() {
    let configured = tempfile::tempdir().unwrap();
    fs::write(configured.path().join("active.json"), b"{not-json").unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["data", "status", "--json"])
        .env("FAT_DATA_DIR", configured.path())
        .output()
        .expect("fat runs");
    assert!(json_output.status.success(), "{json_output:?}");
    let status: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(status["status"], "broken");
    assert_eq!(status["data_version"], serde_json::Value::Null);
    assert_eq!(status["active_path"], serde_json::Value::Null);
    assert_eq!(status["origin"], "environment");
    assert_eq!(status["data_root"], configured.path().display().to_string());

    let human = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["data", "status"])
        .env("FAT_DATA_DIR", configured.path())
        .output()
        .expect("fat runs");
    assert!(human.status.success(), "{human:?}");
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("FAT data: broken"), "{stdout}");
    assert!(stdout.contains("Origin: environment"), "{stdout}");
    assert!(!stdout.contains("not installed"), "{stdout}");

    let verify = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["data", "verify", "--json"])
        .env("FAT_DATA_DIR", configured.path())
        .output()
        .expect("fat runs");
    assert!(
        !verify.status.success(),
        "verify must remain strict: {verify:?}"
    );
}

#[test]
fn data_status_reports_malformed_direct_manifest_as_broken() {
    let configured = tempfile::tempdir().unwrap();
    fs::write(configured.path().join("manifest.json"), b"{not-json").unwrap();

    let json_output = run(&[
        "data",
        "status",
        "--data-dir",
        configured.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(json_output.status.success(), "{json_output:?}");
    let status: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(status["status"], "broken");
    assert_eq!(status["data_version"], serde_json::Value::Null);
    assert_eq!(
        status["active_path"],
        configured.path().display().to_string()
    );
    assert_eq!(status["origin"], "explicit");
    assert_eq!(status["data_root"], configured.path().display().to_string());

    let human = run(&[
        "data",
        "status",
        "--data-dir",
        configured.path().to_str().unwrap(),
    ]);
    assert!(human.status.success(), "{human:?}");
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("FAT data: broken"), "{stdout}");
    assert!(stdout.contains("Origin: explicit"), "{stdout}");
    assert!(!stdout.contains("not installed"), "{stdout}");

    let verify = run(&[
        "data",
        "verify",
        "--data-dir",
        configured.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(
        !verify.status.success(),
        "verify must remain strict: {verify:?}"
    );
}

#[test]
fn data_install_accepts_a_safe_zip_archive() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("fat-data.zip");
    let profile = b"id: acme/router\n";
    let manifest = json!({
        "schema_version": 1,
        "data_version": "2.0.0-alpha.3",
        "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
        "files": [{
            "path": "profiles/rehosting/acme/router.yaml",
            "sha256": digest(profile),
            "required": true
        }]
    });
    let archive_file = fs::File::create(&archive_path).unwrap();
    let mut zip = zip::ZipWriter::new(archive_file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("manifest.json", options).unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&manifest).unwrap())
        .unwrap();
    zip.start_file("profiles/rehosting/acme/router.yaml", options)
        .unwrap();
    zip.write_all(profile).unwrap();
    zip.finish().unwrap();

    let output = run(&[
        "data",
        "install",
        "--archive",
        archive_path.to_str().unwrap(),
        "--data-dir",
        destination.path().to_str().unwrap(),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(destination
        .path()
        .join("versions/2.0.0-alpha.3/profiles/rehosting/acme/router.yaml")
        .is_file());
}

#[test]
fn failed_data_install_preserves_the_previous_active_version() {
    let valid = tempfile::tempdir().unwrap();
    let invalid = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    write_data_tree(valid.path(), "2.0.0-alpha.2", b"id: valid/router\n");
    write_data_tree(invalid.path(), "2.0.0-alpha.3", b"id: invalid/router\n");
    fs::write(
        invalid.path().join("profiles/rehosting/acme/router.yaml"),
        b"tampered\n",
    )
    .unwrap();

    let first = run(&[
        "data",
        "install",
        "--archive",
        valid.path().to_str().unwrap(),
        "--data-dir",
        destination.path().to_str().unwrap(),
    ]);
    assert!(first.status.success(), "{first:?}");

    let second = run(&[
        "data",
        "install",
        "--archive",
        invalid.path().to_str().unwrap(),
        "--data-dir",
        destination.path().to_str().unwrap(),
    ]);
    assert!(!second.status.success(), "{second:?}");

    let active: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.path().join("active.json")).unwrap()).unwrap();
    assert_eq!(active["data_version"], "2.0.0-alpha.2");
    assert!(!destination.path().join("versions/2.0.0-alpha.3").exists());
}

#[test]
fn data_install_rejects_zip_path_traversal() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("unsafe.zip");
    let archive_file = fs::File::create(&archive_path).unwrap();
    let mut zip = zip::ZipWriter::new(archive_file);
    zip.start_file("../escape", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"escape").unwrap();
    zip.finish().unwrap();

    let output = run(&[
        "data",
        "install",
        "--archive",
        archive_path.to_str().unwrap(),
        "--data-dir",
        destination.path().to_str().unwrap(),
    ]);

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsafe archive path"),
        "{output:?}"
    );
    assert!(!archive_dir.path().join("escape").exists());
    assert!(!destination.path().join("versions").exists());
}

#[test]
fn data_status_reports_broken_active_record_and_verify_fails() {
    let destination = tempfile::tempdir().unwrap();
    fs::write(
        destination.path().join("active.json"),
        r#"{"data_version":"2.0.0-alpha.9","relative_path":"versions/2.0.0-alpha.9"}"#,
    )
    .unwrap();

    let status = run(&[
        "data",
        "status",
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(status.status.success(), "{status:?}");
    let payload: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(payload["status"], "broken");
    assert_eq!(payload["data_version"], "2.0.0-alpha.9");

    let verify = run(&[
        "data",
        "verify",
        "--data-dir",
        destination.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(!verify.status.success(), "{verify:?}");
}

#[test]
fn data_install_rejects_undeclared_zip_payload_without_activation() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("undeclared.zip");
    write_zip_with_manifest(
        &archive_path,
        "2.0.0-alpha.4",
        &[("profiles/rehosting/acme/router.yaml", b"id: acme/router\n")],
        &[("surprise.bin", b"not declared")],
    );

    let output = install_zip(&archive_path, destination.path());

    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("undeclared archive payload"));
    assert!(!destination.path().join("active.json").exists());
    assert!(!destination.path().join("versions").exists());
}

#[test]
fn data_install_rejects_excessive_zip_entries_without_activation() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("too-many.zip");
    let archive_file = fs::File::create(&archive_path).unwrap();
    let mut zip = zip::ZipWriter::new(archive_file);
    let options = zip::write::SimpleFileOptions::default();
    for index in 0..1_025 {
        zip.start_file(format!("entry-{index}"), options).unwrap();
    }
    zip.finish().unwrap();

    let output = install_zip(&archive_path, destination.path());

    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("too many entries"));
    assert!(!destination.path().join("active.json").exists());
    assert!(!destination.path().join("versions").exists());
}

#[test]
fn data_install_preflights_declared_zip_entry_count() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("declared-too-many.zip");
    let mut eocd = vec![0_u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    eocd[8..10].copy_from_slice(&1_025_u16.to_le_bytes());
    eocd[10..12].copy_from_slice(&1_025_u16.to_le_bytes());
    fs::write(&archive_path, eocd).unwrap();

    let output = install_zip(&archive_path, destination.path());

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("preflight: too many entries"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!destination.path().join("versions").exists());
}

#[test]
fn data_install_rejects_excessive_expanded_zip_bytes_without_activation() {
    let archive_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("too-large.zip");
    let profile = vec![b'x'; 32 * 1024 * 1024 + 1];
    write_zip_with_manifest(
        &archive_path,
        "2.0.0-alpha.5",
        &[("profiles/rehosting/acme/router.yaml", profile.as_slice())],
        &[],
    );

    let output = install_zip(&archive_path, destination.path());

    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("expanded byte limit"));
    assert!(!destination.path().join("active.json").exists());
    assert!(!destination.path().join("versions").exists());
}

fn install_zip(archive: &Path, destination: &Path) -> std::process::Output {
    run(&[
        "data",
        "install",
        "--archive",
        archive.to_str().unwrap(),
        "--data-dir",
        destination.to_str().unwrap(),
    ])
}

fn write_zip_with_manifest(
    archive: &Path,
    version: &str,
    declared: &[(&str, &[u8])],
    extra: &[(&str, &[u8])],
) {
    let files: Vec<_> = declared
        .iter()
        .map(|(path, bytes)| json!({"path": path, "sha256": digest(bytes), "required": true}))
        .collect();
    let manifest = json!({
        "schema_version": 1,
        "data_version": version,
        "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
        "files": files,
    });
    let archive_file = fs::File::create(archive).unwrap();
    let mut zip = zip::ZipWriter::new(archive_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("manifest.json", options).unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&manifest).unwrap())
        .unwrap();
    for (path, bytes) in declared.iter().chain(extra.iter()) {
        zip.start_file(*path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}
