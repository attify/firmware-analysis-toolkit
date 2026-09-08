#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// The binary bytes are unique to this test. Track only its exact cache paths
// so cleanup never scans or removes another run's records.
struct CacheCleanup(Vec<PathBuf>);
impl Drop for CacheCleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn selected_profile_reaches_the_bridge_and_invalidates_cached_results() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let marker = format!(
        "profile_probe_{}",
        root.file_name().unwrap().to_string_lossy()
    );
    let mut cleanup = CacheCleanup(Vec::new());
    let binary = root.join("example.elf");
    fs::write(&binary, format!("\u{7f}ELF{marker}")).unwrap();
    let response = root.join("response.json");
    fs::write(
        &response,
        serde_json::to_vec(&serde_json::json!([{
            "function": "example_handler", "source": marker, "source_class": "primary",
            "sink": "system", "method": "co-occurrence-only"
        }]))
        .unwrap(),
    )
    .unwrap();
    let python = root.join("python");
    fs::write(
        &python,
        r#"#!/bin/sh
if [ "$1" = "-c" ]; then exit 0; fi
printf 'run\n' >> "$FAT_TEST_RUNS"
cat "$5"/*.yaml > "$FAT_TEST_PROFILES"
cp "$FAT_TEST_RESPONSE" "$3"
"#,
    )
    .unwrap();
    fs::set_permissions(&python, fs::Permissions::from_mode(0o755)).unwrap();
    let runs = root.join("runs");
    let captured = root.join("profiles");
    let mut run = |profile: Option<&Path>| {
        let provenance = fat_taint::profile::catalog_provenance(profile).unwrap();
        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let contents = profile.map(|path| fs::read_to_string(path).unwrap());
        let mut inputs = fat_taint::proof::angr::embedded_profile_contents();
        // Include the old key too, so this test cleans up when run against the
        // broken implementation during regression verification.
        cleanup.0.push(fat_taint::cache::cache_path(
            &fat_taint::cache::compute_cache_key(&binary, &inputs),
        ));
        inputs.push(&provenance_json);
        if let Some(contents) = contents.as_deref() {
            inputs.push(contents);
        }
        cleanup.0.push(fat_taint::cache::cache_path(
            &fat_taint::cache::compute_cache_key(&binary, &inputs),
        ));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fat"));
        cmd.current_dir(root)
            .args(["taint", "--file"])
            .arg(&binary)
            .arg("--json")
            .env("FAT_PYTHON", &python)
            .env("FAT_TEST_RUNS", &runs)
            .env("FAT_TEST_PROFILES", &captured)
            .env("FAT_TEST_RESPONSE", &response);
        if let Some(profile) = profile {
            cmd.arg("--source-profile").arg(profile);
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let core = run(None);
    let profile = root.join("core.yaml"); // must not overwrite the embedded core
    let original = "name: example\nsources:\n  primary:\n    - name: example_external_input\n";
    fs::write(&profile, original).unwrap();
    let external = run(Some(&profile));
    assert_eq!(
        fs::read_to_string(&runs).unwrap().lines().count(),
        2,
        "selected profile reused the core cache"
    );
    let bridge = fs::read_to_string(&captured).unwrap();
    assert!(
        bridge.contains("example_external_input"),
        "external profile never reached angr"
    );
    assert!(
        bridge.contains("name: core"),
        "external basename replaced core models"
    );
    assert_eq!(core[0]["model_provenance"]["kind"], "core");
    assert_eq!(external[0]["model_provenance"]["name"], "example");
    assert_eq!(
        external[0]["model_provenance"]["path"],
        profile.to_str().unwrap()
    );
    let cached = run(Some(&profile));
    assert_eq!(cached, external);
    assert_eq!(fs::read_to_string(&runs).unwrap().lines().count(), 2);
    fs::write(
        &profile,
        original.replace("example_external_input", "changed_external_input"),
    )
    .unwrap();
    let changed = run(Some(&profile));
    assert_eq!(
        fs::read_to_string(&runs).unwrap().lines().count(),
        3,
        "edited profile reused stale results"
    );
    assert!(fs::read_to_string(&captured)
        .unwrap()
        .contains("changed_external_input"));
    assert_ne!(
        changed[0]["model_provenance"]["sha256"],
        external[0]["model_provenance"]["sha256"]
    );
}
