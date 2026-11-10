#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

use fat_core::database::ProjectDb;
use fat_core::project::Project;
use fat_core::runtime_store::RuntimeStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn write_manifest(root: &std::path::Path) -> std::path::PathBuf {
    fs::create_dir_all(root.join("inputs")).expect("inputs dir");
    fs::create_dir_all(root.join("evidence")).expect("evidence dir");
    fs::write(root.join("target.bin"), b"firmware-target").expect("target");
    fs::write(root.join("inputs/crash.bin"), b"exact-replay-input").expect("input");
    fs::write(root.join("evidence/replay.log"), b"fault at 0x41414141\n").expect("evidence");

    let manifest = json!({
        "schema_version": "external-campaign/v1",
        "campaign_id": "test-campaign",
        "engine": {
            "name": "test-engine",
            "version": "1.0",
            "revision": "0123456789abcdef",
            "substrate_kind": "native-host"
        },
        "proof_scope": "local process replay only",
        "setup_artifacts": [
            {
                "role": "target",
                "path": "target.bin",
                "sha256": digest(b"firmware-target")
            }
        ],
        "cases": [
            {
                "id": "crash",
                "kind": "failure-replay",
                "input": {
                    "path": "inputs/crash.bin",
                    "sha256": digest(b"exact-replay-input")
                },
                "command": ["/usr/bin/true", "{input}"],
                "timeout_seconds": 10,
                "expected_exit_codes": [0]
            }
        ],
        "evidence": [
            {
                "role": "replay-log",
                "path": "evidence/replay.log",
                "sha256": digest(b"fault at 0x41414141\n")
            }
        ],
        "cleanup": {
            "command": ["/usr/bin/true"],
            "timeout_seconds": 10,
            "required": true
        }
    });
    let path = root.join("campaign.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest");
    path
}

fn write_script(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).expect("script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("script permissions");
}

#[test]
fn external_validate_checks_setup_input_and_evidence_digests() {
    let dir = tempdir().expect("tempdir");
    let manifest = write_manifest(dir.path());

    let valid = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "experiment",
            "external",
            "validate",
            "--file",
            manifest.to_str().expect("manifest path"),
            "--root",
            dir.path().to_str().expect("root path"),
            "--json",
        ])
        .output()
        .expect("fat experiment external validate runs");
    assert!(valid.status.success(), "{valid:?}");
    let report: Value = serde_json::from_slice(&valid.stdout).expect("validation json");
    assert_eq!(report["schema_version"], "external-campaign-command/v1");
    assert_eq!(report["valid"], true);
    assert_eq!(report["checked_artifacts"], 3);

    fs::write(dir.path().join("inputs/crash.bin"), b"tampered").expect("tampered input");
    let invalid = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "experiment",
            "external",
            "validate",
            "--file",
            manifest.to_str().expect("manifest path"),
            "--root",
            dir.path().to_str().expect("root path"),
            "--json",
        ])
        .output()
        .expect("fat experiment external validate runs");
    assert!(!invalid.status.success(), "{invalid:?}");
    let report: Value = serde_json::from_slice(&invalid.stdout).expect("validation json");
    assert_eq!(report["valid"], false);
    assert!(report["errors"]
        .as_array()
        .expect("errors")
        .iter()
        .any(|error| {
            error["code"] == "artifact-digest-mismatch"
                && error["path"] == "cases.crash.input.sha256"
        }));
}

#[test]
fn external_run_uses_exact_input_persists_evidence_and_always_cleans_up() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path().join("campaign");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
    let manifest_path = write_manifest(&root);
    write_script(
        &root.join("bin/replay.sh"),
        "#!/bin/sh\nprintf 'input=%s\\n' \"$1\"\ncat \"$1\"\nprintf '\\nliteral=%s\\n' \"$2\"\nexit 7\n",
    );
    write_script(
        &root.join("bin/cleanup.sh"),
        "#!/bin/sh\nprintf 'clean\\n' > cleanup.marker\n",
    );
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
            .expect("manifest json");
    manifest["cases"][0]["command"] = json!(["bin/replay.sh", "{input}", "literal value"]);
    manifest["cases"][0]["expected_exit_codes"] = json!([7]);
    manifest["cleanup"]["command"] = json!(["bin/cleanup.sh"]);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest");

    let project_dir = dir.path().join("project");
    let db = ProjectDb::open(&project_dir).expect("project db");
    db.save(&Project::new("project".into(), "firmware.bin".into()))
        .expect("project metadata");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "experiment",
            "external",
            "run",
            "--project",
            project_dir.to_str().expect("project path"),
            "--file",
            manifest_path.to_str().expect("manifest path"),
            "--root",
            root.to_str().expect("root path"),
            "--case",
            "crash",
            "--json",
        ])
        .output()
        .expect("fat experiment external run runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("run json");
    assert_eq!(report["schema_version"], "external-campaign-command/v1");
    assert_eq!(report["case_id"], "crash");
    assert_eq!(report["exit_code"], 7);
    assert_eq!(report["expected_outcome"], true);
    assert_eq!(report["cleanup"]["status"], "passed");
    assert_eq!(
        report["command"][1],
        root.join("inputs/crash.bin").to_string_lossy().as_ref()
    );
    assert_eq!(
        fs::read(root.join("cleanup.marker")).expect("cleanup"),
        b"clean\n"
    );

    let store = RuntimeStore::open_read_only(&project_dir).expect("runtime store");
    let artifacts = store.read_artifact_index().expect("artifact index");
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.subkind == "external-replay-input"));
    let stdout = artifacts
        .iter()
        .find(|artifact| artifact.subkind == "external-replay-stdout")
        .expect("stdout artifact");
    let stdout_text = fs::read_to_string(&stdout.path).expect("stdout text");
    assert!(stdout_text.contains("exact-replay-input"), "{stdout_text}");
    assert!(
        stdout_text.contains("literal=literal value"),
        "{stdout_text}"
    );
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.subkind == "external-campaign-evidence"));
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.subkind == "external-replay-result"));
}

#[test]
fn external_run_cleans_up_and_records_an_unexpected_replay_exit() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path().join("campaign");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
    let manifest_path = write_manifest(&root);
    write_script(&root.join("bin/replay.sh"), "#!/bin/sh\nexit 5\n");
    write_script(
        &root.join("bin/cleanup.sh"),
        "#!/bin/sh\nprintf 'clean\n' > cleanup.marker\n",
    );
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
            .expect("manifest json");
    manifest["cases"][0]["command"] = json!(["bin/replay.sh", "{input}"]);
    manifest["cases"][0]["expected_exit_codes"] = json!([0]);
    manifest["cleanup"]["command"] = json!(["bin/cleanup.sh"]);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest");

    let project_dir = dir.path().join("project");
    let db = ProjectDb::open(&project_dir).expect("project db");
    db.save(&Project::new("project".into(), "firmware.bin".into()))
        .expect("project metadata");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "experiment",
            "external",
            "run",
            "--project",
            project_dir.to_str().expect("project path"),
            "--file",
            manifest_path.to_str().expect("manifest path"),
            "--root",
            root.to_str().expect("root path"),
            "--case",
            "crash",
            "--json",
        ])
        .output()
        .expect("fat experiment external run runs");
    assert!(!output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("run json");
    assert_eq!(report["exit_code"], 5);
    assert_eq!(report["expected_outcome"], false);
    assert_eq!(report["cleanup"]["status"], "passed");
    assert_eq!(
        fs::read(root.join("cleanup.marker")).expect("cleanup"),
        b"clean\n"
    );

    let store = RuntimeStore::open_read_only(&project_dir).expect("runtime store");
    let artifacts = store.read_artifact_index().expect("artifact index");
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.subkind == "external-replay-result"));
}

#[test]
fn external_run_times_out_a_stuck_replay_then_cleans_up() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path().join("campaign");
    fs::create_dir_all(root.join("bin")).expect("bin dir");
    let manifest_path = write_manifest(&root);
    write_script(&root.join("bin/replay.sh"), "#!/bin/sh\nsleep 5\n");
    write_script(
        &root.join("bin/cleanup.sh"),
        "#!/bin/sh\nprintf 'clean\n' > cleanup.marker\n",
    );
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
            .expect("manifest json");
    manifest["cases"][0]["command"] = json!(["bin/replay.sh", "{input}"]);
    manifest["cases"][0]["timeout_seconds"] = json!(1);
    manifest["cleanup"]["command"] = json!(["bin/cleanup.sh"]);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest");

    let project_dir = dir.path().join("project");
    let db = ProjectDb::open(&project_dir).expect("project db");
    db.save(&Project::new("project".into(), "firmware.bin".into()))
        .expect("project metadata");

    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "experiment",
            "external",
            "run",
            "--project",
            project_dir.to_str().expect("project path"),
            "--file",
            manifest_path.to_str().expect("manifest path"),
            "--root",
            root.to_str().expect("root path"),
            "--case",
            "crash",
            "--json",
        ])
        .output()
        .expect("fat experiment external run runs");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "timeout did not terminate the replay process tree: {:?}",
        started.elapsed()
    );
    assert!(!output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("run json");
    assert_eq!(report["timed_out"], true);
    assert_eq!(report["exit_code"], Value::Null);
    assert_eq!(report["cleanup"]["status"], "passed");
    assert_eq!(
        fs::read(root.join("cleanup.marker")).expect("cleanup"),
        b"clean\n"
    );
}
