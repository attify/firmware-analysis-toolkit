use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

use fat_core::artifacts::{ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::diagnostics::DiagnosticClass;
use fat_core::project::ProjectStatus;
use fat_core::readiness::{BlockerRecord, ConfidenceLevel, ConfidenceReport};
use fat_core::rehosting::{AttemptRecord, ReadinessReport, TargetExecutionProfile};
use fat_core::rehosting_policy::{
    SelectionTrace, SubstrateAttemptState, SubstrateKind, SubstratePreference,
};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::runs::RuntimeEndpointKind;
use fat_core::runtime_store::RuntimeStore;
use fat_core::staging::{StagingManifest, StagingStrategy};
use fat_core::target_model::TargetModel;
use fat_core::targets::derive_target_id;

#[test]
fn fat_cli_still_exposes_the_existing_top_level_command_family() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg("--help")
        .output()
        .expect("fat help runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "new",
        "extract",
        "analyze",
        "preflight",
        "emulate",
        "diff",
        "inspect",
    ] {
        assert!(
            stdout.contains(flag),
            "expected help output to mention {flag}, got:\n{stdout}"
        );
    }
}

#[test]
fn invalid_explicit_rehosting_pack_does_not_mutate_project_status() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let invalid_pack = firmware_dir.path().join("invalid.yaml");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    std::fs::write(&invalid_pack, "not: [valid").expect("invalid pack");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            invalid_pack.to_str().expect("pack path"),
            "--experimental-rehosting",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let project = ProjectDb::open(&project_dir)
        .expect("project db")
        .get("demo")
        .expect("project lookup")
        .expect("project record");
    assert_eq!(project.status, ProjectStatus::Created);
}

#[test]
fn invalid_substrate_policy_does_not_mutate_project_status() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--substrate-policy",
            "not-a-policy",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let project = ProjectDb::open(&project_dir)
        .expect("project db")
        .get("demo")
        .expect("project lookup")
        .expect("project record");
    assert_eq!(project.status, ProjectStatus::Created);
}

#[test]
fn signal_less_project_rejects_emulation_without_mutating_status() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    assert!(
        String::from_utf8_lossy(&emulate_output.stderr).contains("fat analyze"),
        "{emulate_output:?}"
    );
    let project = ProjectDb::open(&project_dir)
        .expect("project db")
        .get("demo")
        .expect("lookup")
        .expect("project");
    assert_eq!(project.status, ProjectStatus::Created);
    assert!(!project_dir.join("work/runtime/sessions").exists());
}

#[test]
fn fat_doctor_prints_a_structured_host_health_summary() {
    let path_dir = tempdir().expect("tempdir");
    make_executable(path_dir.path().join("qemu-system-arm"));

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("host os:"));
    assert!(stdout.contains("host arch:"));
    assert!(stdout.contains("Available Backends"));
    assert!(stdout.contains("Unavailable Backends"));
    assert!(stdout.contains("Backend Checks"));
    assert!(stdout.contains("qemu-direct command qemu-system-arm: pass"));
    assert!(
        stdout.contains("debugfs found") || stdout.contains("debugfs not found (optional)"),
        "{stdout}"
    );
}

#[test]
fn fat_doctor_strict_fails_without_an_extraction_engine() {
    let path_dir = tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["doctor", "--strict"])
        .output()
        .expect("fat doctor runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no usable extraction engine"), "{stderr}");
}

#[test]
#[cfg(unix)]
fn fat_doctor_strict_rejects_extraction_engine_names_that_are_not_usable() {
    use std::os::unix::fs::symlink;

    let path_dir = tempdir().expect("tempdir");
    symlink("/usr/bin/false", path_dir.path().join("binwalk")).expect("binwalk alias");
    symlink("/usr/bin/false", path_dir.path().join("unblob")).expect("unblob alias");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["doctor", "--strict"])
        .output()
        .expect("fat doctor runs");

    assert!(
        !output.status.success(),
        "unusable aliases must fail strict mode: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("binwalk unusable"), "{stdout}");
    assert!(stdout.contains("unblob unusable"), "{stdout}");
    assert!(stderr.contains("no usable extraction engine"), "{stderr}");
}

#[test]
fn fat_doctor_bounds_extraction_engine_version_output() {
    let path_dir = tempdir().expect("tempdir");
    let flood = "#!/bin/sh\ni=0\nwhile [ $i -lt 50000 ]; do printf '0123456789012345678901234567890123456789\\n'; i=$((i+1)); done\nexit 1\n";
    make_executable_with_contents(path_dir.path().join("binwalk"), flood);
    make_executable_with_contents(path_dir.path().join("unblob"), flood);
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["doctor", "--strict"])
        .output()
        .expect("fat doctor runs");

    assert!(!output.status.success(), "{output:?}");
    assert!(
        output.stdout.len() < 128 * 1024,
        "doctor retained unbounded output"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("output truncated"));
}

#[test]
fn fat_emulate_writes_durable_session_run_and_recipe_records() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(project_dir.join("analysis/signals.txt"), "arch:unknown\n").expect("signals");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--port",
            "8080",
            "--session-id",
            "smoke-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let recipe_id = parsed.get("recipe").expect("recipe id");

    assert_eq!(
        parsed.get("backend").map(String::as_str),
        Some("qemu-direct")
    );
    assert!(parsed.contains_key("status"));

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    assert!(store.session_path(session_id).exists());
    assert!(store.run_path(session_id, run_id).exists());
    assert!(store.recipe_path(session_id, recipe_id).exists());
    let run = store.read_run(session_id, run_id).expect("run");
    let session = store.read_session(session_id).expect("session");
    let recipe = store.read_recipe(session_id, recipe_id).expect("recipe");
    let expected_target_id = derive_target_id("demo", "demo.bin");
    assert_eq!(session.project_id, "demo");
    assert_eq!(run.status, fat_core::runs::RunStatus::Failed);
    assert_eq!(session.target_id, expected_target_id);
    assert_eq!(recipe.target_id, expected_target_id);
    let project = ProjectDb::open(&project_dir)
        .expect("project db")
        .get("demo")
        .expect("project lookup")
        .expect("project record");
    assert_eq!(project.status, ProjectStatus::Error);

    let target_profile = read_single_json_record::<TargetExecutionProfile>(
        &store
            .target_path(&expected_target_id)
            .parent()
            .expect("target parent")
            .join("rehosting")
            .join("profiles"),
    );
    assert_eq!(target_profile.project_id, "demo");
    assert_eq!(target_profile.target_id, expected_target_id);
    let target_model = read_single_json_record::<TargetModel>(
        &store
            .target_path(&expected_target_id)
            .parent()
            .expect("target parent")
            .join("rehosting")
            .join("models"),
    );
    assert_eq!(target_model.project_id, "demo");
    assert_eq!(target_model.target_id, expected_target_id);
    assert_eq!(target_model.to_execution_profile(), target_profile);

    let attempt = read_single_json_record::<AttemptRecord>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("attempts"),
    );
    assert_eq!(attempt.project_id, "demo");
    assert_eq!(attempt.target_id, expected_target_id);
    assert_eq!(attempt.session_id, session_id.as_str());
    assert_eq!(attempt.run_id, run_id.as_str());
    let rehosting_recipe = read_single_json_record::<RehostingRecipe>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("recipes"),
    );
    assert_eq!(rehosting_recipe.target_id, expected_target_id);
    assert_eq!(rehosting_recipe.run_id, run_id.as_str());
    assert_eq!(rehosting_recipe.target_model_id, target_model.model_id);
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );
    assert_eq!(selection_trace.project_id, "demo");
    assert_eq!(selection_trace.target_id, expected_target_id);
    assert_eq!(selection_trace.session_id, session_id.as_str());
    assert_eq!(selection_trace.run_id, run_id.as_str());

    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert_eq!(readiness.project_id, "demo");
    assert_eq!(readiness.target_id, expected_target_id);
    assert_eq!(readiness.session_id, session_id.as_str());
    assert_eq!(readiness.run_id, run_id.as_str());
    assert!(!readiness.requested_goals.is_empty());
    assert!(!readiness.surfaces.is_empty());
}

#[test]
fn managed_pack_backend_reports_native_system_actions_as_unsupported() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("native-actions.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("image");
    make_executable_with_contents(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'firmadyne-probe-ok\\n'; fi\nexit 0\n",
    );
    std::fs::write(
        &pack_path,
        r#"
id: test/native-actions
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
runtime:
  substrate: system
  qemu_machine: malta
repairs:
  init:
    materialize_paths: ["/configs"]
validators:
  - goal: shell-access
    kind: surface-ready
"#,
    )
    .expect("pack");
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\n",
    )
    .expect("signals");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--pack",
            pack_path.to_str().unwrap(),
            "--experimental-rehosting",
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("qemu-machine"), "{stderr}");
    assert!(
        stderr.contains("materialize:directory:/configs"),
        "{stderr}"
    );
}

#[test]
fn fat_emulate_auto_selects_the_only_project_when_project_is_omitted() {
    let workspace_dir = tempdir().expect("workspace dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .current_dir(workspace_dir.path())
        .args(["new", firmware_path.to_str().expect("firmware path")])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = workspace_dir.path().join(".fat-projects").join("demo");
    std::fs::write(project_dir.join("analysis/signals.txt"), "arch:unknown\n").expect("signals");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .current_dir(workspace_dir.path())
        .args([
            "emulate",
            "--backend",
            "qemu-direct",
            "--port",
            "8080",
            "--session-id",
            "smoke-2",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    assert!(stdout.contains("session:"));
    assert!(stdout.contains("recipe:"));

    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");
    let recipe_id = parsed.get("recipe").expect("recipe id");

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    assert!(store.session_path(session_id).exists());
    assert!(store.recipe_path(session_id, recipe_id).exists());
}

#[test]
fn fat_emulate_status_accepts_requested_session_label_alias() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(project_dir.join("analysis/signals.txt"), "arch:unknown\n").expect("signals");
    let requested_label = "smoke-alias-1";
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            requested_label,
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let canonical_session_id = parsed.get("session").expect("canonical session id");

    let status_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            requested_label,
            "--status",
        ])
        .output()
        .expect("fat emulate --status runs");

    assert!(status_output.status.success(), "{status_output:?}");
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_stdout.contains(&format!("session: {canonical_session_id}")));

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store
        .read_session(canonical_session_id)
        .expect("session record");
    assert_eq!(
        session.requested_session_id.as_deref(),
        Some(requested_label)
    );
}

#[test]
fn fat_emulate_auto_persists_service_first_selection_trace_when_service_is_viable() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}],\"processes\":[{\"pid\":77,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18080\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );
    let qemu_path = path_dir.path().join("qemu-system-arm");
    std::fs::write(
        &qemu_path,
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    )
    .expect("qemu stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&qemu_path)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&qemu_path, permissions).expect("permissions");
    }

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-auto-service-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );

    assert_eq!(selection_trace.preference, SubstratePreference::Auto);
    assert_eq!(
        selection_trace.attempts[0].substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Selected
    );
    assert_eq!(selection_trace.attempts[1].substrate, SubstrateKind::System);
    assert_eq!(
        selection_trace.attempts[2].substrate,
        SubstrateKind::Reference
    );
}

#[test]
fn fat_emulate_reference_only_policy_persists_trace_when_runtime_is_unavailable() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '29.2.1\\n'; exit 0; fi\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-reference-only-1",
            "--substrate-policy",
            "reference-only",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );

    assert_eq!(
        selection_trace.preference,
        SubstratePreference::ReferenceOnly
    );
    assert_eq!(selection_trace.attempts.len(), 1);
    assert_eq!(
        selection_trace.attempts[0].substrate,
        SubstrateKind::Reference
    );
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Selected
    );
}

#[test]
fn fat_rehosting_trace_reports_logical_selection_and_attempt_order() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}],\"processes\":[{\"pid\":78,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18080\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );
    let qemu_path = path_dir.path().join("qemu-system-arm");
    std::fs::write(
        &qemu_path,
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    )
    .expect("qemu stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&qemu_path)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&qemu_path, permissions).expect("permissions");
    }

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-trace-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let trace_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "rehosting-trace",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-trace-1",
            "--json",
        ])
        .output()
        .expect("fat rehosting-trace runs");

    assert!(trace_output.status.success(), "{trace_output:?}");
    let trace_json: serde_json::Value =
        serde_json::from_slice(&trace_output.stdout).expect("trace json");
    assert_eq!(
        trace_json
            .get("logical_substrate")
            .and_then(|value| value.as_str()),
        Some("service")
    );
    assert_eq!(
        trace_json
            .get("substrate_preference")
            .and_then(|value| value.as_str()),
        Some("auto")
    );
    assert_eq!(
        trace_json["attempts"][0]["substrate"].as_str(),
        Some("service")
    );
    assert_eq!(
        trace_json["attempts"][0]["state"].as_str(),
        Some("selected")
    );
    assert_eq!(
        trace_json["attempts"][1]["substrate"].as_str(),
        Some("system")
    );
    assert_eq!(
        trace_json["attempts"][2]["substrate"].as_str(),
        Some("reference")
    );
}

#[test]
fn fat_emulate_system_first_policy_persists_trace_when_launch_fails() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\\n'\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");

    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-system-first-1",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );

    assert_eq!(selection_trace.preference, SubstratePreference::SystemFirst);
    assert_eq!(selection_trace.attempts[0].substrate, SubstrateKind::System);
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Selected
    );
    assert_eq!(
        selection_trace.attempts[1].substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        selection_trace.attempts[2].substrate,
        SubstrateKind::Reference
    );
}

#[test]
fn explicit_pack_system_substrate_selects_system_without_cli_policy() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("system-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::write(
        &pack_path,
        r#"
id: test/system-pack
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
runtime:
  substrate: system
validators:
  - goal: shell-access
    kind: surface-ready
caveats: ["experimental fixture"]
"#,
    )
    .expect("pack file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\n'\nexec /bin/sleep 30\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
            "--backend",
            "qemu-direct",
            "--session-id",
            "pack-system-first-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting/selection"),
    );
    assert_eq!(selection_trace.preference, SubstratePreference::SystemFirst);
    assert_eq!(selection_trace.attempts[0].substrate, SubstrateKind::System);
}

#[test]
fn explicit_pack_requires_acceptance_for_manual_and_partition_limitations() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("degraded-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::write(
        &pack_path,
        r#"
id: test/degraded-pack
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
partitions:
  roles:
    - source: app
      mount: /system
      materialization: staged-copy
runtime:
  substrate: system
validators:
  - goal: operator-check
    kind: manual
"#,
    )
    .expect("pack file");
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\n",
    )
    .expect("signals");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let stderr = String::from_utf8_lossy(&emulate_output.stderr);
    assert!(stderr.contains("partition:app:/system"), "{stderr}");
    assert!(stderr.contains("validator:manual"), "{stderr}");
}

#[test]
fn explicit_pack_substrate_rejects_incompatible_explicit_backend() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("system-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::write(
        &pack_path,
        "id: test/system-pack\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: mipsel\n  signals: [\"fs:squashfs\", \"init:/sbin/preinit\"]\nruntime:\n  substrate: system\nvalidators:\n  - goal: shell-access\n    kind: surface-ready\n",
    )
    .expect("pack file");
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(project_dir.join("analysis/signals.txt"), "arch:mipsel\n").expect("signals");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
            "--backend",
            "emux",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let stderr = String::from_utf8_lossy(&emulate_output.stderr);
    assert!(
        stderr.contains("requires logical substrate system"),
        "{stderr}"
    );
}

#[test]
fn system_pack_materialize_paths_are_present_in_final_guest_root() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("materialize-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::write(
        &pack_path,
        r#"
id: test/materialize-pack
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
runtime:
  substrate: system
repairs:
  init:
    materialize_paths: ["/configs", "/configs/etc"]
validators:
  - goal: shell-access
    kind: surface-ready
"#,
    )
    .expect("pack file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nexec /bin/sleep 30\n",
    );
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\n",
    )
    .expect("signals");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
            "--backend",
            "qemu-direct",
            "--session-id",
            "pack-materialize-system-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(parsed.get("session").unwrap(), parsed.get("run").unwrap())
            .parent()
            .unwrap()
            .join("rehosting/staging"),
    );
    let guest_root = PathBuf::from(staging.staging_root);
    assert!(
        guest_root.join("configs").is_dir(),
        "{}",
        guest_root.display()
    );
    assert!(
        guest_root.join("configs/etc").is_dir(),
        "{}",
        guest_root.display()
    );
    let recipe = read_single_json_record::<RehostingRecipe>(
        &store
            .run_path(parsed.get("session").unwrap(), parsed.get("run").unwrap())
            .parent()
            .unwrap()
            .join("rehosting/recipes"),
    );
    let capability = recipe.rehosting_capability.expect("pack capability report");
    for expected in [
        "materialize:directory:/configs",
        "selected-backend:qemu-direct",
        "selected-logical-substrate:system",
    ] {
        assert!(
            capability
                .supported_actions
                .iter()
                .any(|item| item == expected),
            "missing {expected}: {capability:?}"
        );
    }
}

#[test]
fn native_system_partition_materialization_assembles_rootfs_and_app() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let rootfs_dir = tempdir().expect("rootfs dir");
    let app_dir = tempdir().expect("app dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("partition-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::create_dir_all(rootfs_dir.path().join("etc")).expect("rootfs etc");
    std::fs::write(
        rootfs_dir.path().join("etc/inittab"),
        b"::sysinit:/sbin/preinit\n",
    )
    .expect("rootfs inittab");
    std::fs::create_dir_all(app_dir.path().join("init")).expect("app init");
    std::fs::write(
        app_dir.path().join("init/app_init.sh"),
        b"#!/bin/sh\necho app\n",
    )
    .expect("app init script");
    std::fs::write(
        &pack_path,
        r#"
id: test/multi-partition
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
partitions:
  roles:
    - source: rootfs
      mount: /
      materialization: staged-copy
    - source: app
      mount: /system
      materialization: staged-copy
runtime:
  substrate: system
  network:
    interface: eth0
    mode: dhcp
    fallback_ip: 10.0.2.15
repairs:
  init:
    skip_module_loads_matching: ["tx-isp-*.ko"]
    skip_commands: ["devmem"]
validators:
  - goal: shell-access
    kind: surface-ready
  - goal: http-reply
    kind: http
    port: 80
caveats: ["synthetic multi-partition fixture"]
"#,
    )
    .expect("pack file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nexec /bin/sleep 30\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    seed_native_system_kernel_inputs(path_dir.path());
    std::fs::create_dir_all(project_dir.join("work")).expect("work dir");
    std::fs::write(
        project_dir.join("work/extraction-manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "rootfs_path": rootfs_dir.path(),
            "kernel_paths": [],
            "file_count": 2,
            "filesystem_trees": [
                {"role": "rootfs", "path": rootfs_dir.path(), "tree_kind": "rootfs"},
                {"role": "app", "path": app_dir.path(), "tree_kind": "app"}
            ]
        }))
        .expect("manifest json"),
    )
    .expect("extraction manifest");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\n",
    )
    .expect("signals");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
            "--backend",
            "qemu-direct",
            "--session-id",
            "native-partition-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting/staging"),
    );
    let recipe = read_single_json_record::<RehostingRecipe>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting/recipes"),
    );
    let capability = recipe.rehosting_capability.expect("pack capability");
    assert!(
        capability
            .supported_actions
            .iter()
            .any(|action| action == "partition:app:/system"),
        "{capability:?}"
    );
    let qemu_command_path = staging
        .generated_artifacts
        .iter()
        .find(|artifact| artifact.ends_with("boot/qemu-command.sh"))
        .expect("qemu command artifact path")
        .clone();
    let guest_root = PathBuf::from(staging.staging_root);
    assert!(guest_root.join("etc/inittab").is_file());
    assert!(guest_root.join("system/init/app_init.sh").is_file());
    assert!(guest_root.join("fat/shims/mount").is_file());
    assert!(guest_root.join("fat/shims/devmem").is_file());
    assert!(guest_root.join("fat/shims/insmod").is_file());
    let trampoline =
        std::fs::read(guest_root.join("fat/init-trampoline")).expect("MIPSEL init trampoline");
    assert_eq!(&trampoline[..4], b"\x7fELF");
    let trampoline_identity =
        std::fs::read_to_string(guest_root.join("fat/init-trampoline-identity.json"))
            .expect("trampoline identity");
    assert!(trampoline_identity
        .contains("d254a2bf2079f8729a8ee59442c752b8e70c99abee9099f45c6defb10e932b7f"));
    let preinit = std::fs::read_to_string(guest_root.join("fat/preinit.sh")).expect("preinit");
    assert!(preinit.contains("FAT_NATIVE_PREINIT_START"), "{preinit}");
    assert!(preinit.contains("udhcpc -i 'eth0'"), "{preinit}");
    let adaptation_manifest =
        std::fs::read_to_string(guest_root.join("fat/adaptation-manifest.json"))
            .expect("adaptation manifest");
    assert!(adaptation_manifest.contains("mount-shim"));
    assert!(adaptation_manifest.contains("command-shim"));
    assert!(adaptation_manifest.contains("module-filter-shim"));
    let qemu_args = std::fs::read_to_string(&qemu_command_path)
        .unwrap_or_else(|err| panic!("qemu command artifact {qemu_command_path}: {err}"));
    assert!(qemu_args.contains("e1000,netdev=fatnet0"), "{qemu_args}");
    assert!(
        qemu_args.contains("user,id=fatnet0,hostfwd=tcp:127.0.0.1:"),
        "{qemu_args}"
    );
    assert!(qemu_args.contains("-:80"), "{qemu_args}");
    assert!(!qemu_args.contains("0.0.0.0"), "{qemu_args}");
    let run = store.read_run(session_id, run_id).expect("run");
    let http_forward = run
        .active_endpoints
        .iter()
        .find(|endpoint| endpoint.target_port == Some(80))
        .expect("HTTP host forward endpoint");
    assert_eq!(http_forward.host, "127.0.0.1");
    assert_eq!(
        http_forward.uri.as_deref(),
        Some(format!("http://127.0.0.1:{}", http_forward.port).as_str())
    );
    let assembly: serde_json::Value = serde_json::from_slice(
        &std::fs::read(guest_root.join("assembly-manifest.json")).expect("assembly manifest"),
    )
    .expect("assembly manifest json");
    let partitions = assembly["partitions"].as_array().expect("partitions");
    assert_eq!(partitions.len(), 2);
    assert!(partitions.iter().any(|entry| {
        entry["source_role"] == "rootfs"
            && entry["source_path"] == rootfs_dir.path().to_string_lossy().as_ref()
            && entry["destination"] == "/"
            && entry["strategy"] == "staged-copy"
    }));
    assert!(partitions.iter().any(|entry| {
        entry["source_role"] == "app"
            && entry["source_path"] == app_dir.path().to_string_lossy().as_ref()
            && entry["destination"] == "/system"
            && entry["strategy"] == "staged-copy"
    }));

    let supervisor_pid = run.supervisor_pid.expect("native host pid");
    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("fat emulate stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");
    assert_process_eventually_exits(supervisor_pid);
}

#[test]
fn native_host_system_runner_persists_launch_artifacts_and_registered_surfaces() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\\n'\nexec /bin/sleep 30\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--port",
            "8080",
            "--session-id",
            "smoke-native-system-2",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");

    let session = store.read_session(session_id).expect("session");
    let run = store.read_run(session_id, run_id).expect("run");
    assert_eq!(session.session_id, session_id.as_str());
    assert_eq!(run.run_id, run_id.as_str());
    assert_eq!(run.backend_driver, "qemu-direct");

    let staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("staging"),
    );
    assert!(
        staging
            .generated_artifacts
            .iter()
            .any(|artifact| artifact.ends_with("boot/qemu-command.sh")),
        "system staging did not record the launch command artifact"
    );
    assert!(
        staging
            .generated_artifacts
            .iter()
            .any(|artifact| artifact.ends_with("boot/surface-manifest.json")),
        "system staging did not record the surface manifest artifact"
    );

    let artifacts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("artifacts");
    let runtime_artifacts = read_json_records::<ArtifactRecord>(&artifacts_dir);
    let launch_command_artifact = runtime_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "native-system-launch-command")
        .expect("launch command artifact");
    assert!(
        launch_command_artifact
            .path
            .ends_with("outputs/native-system-launch-command.log"),
        "unexpected launch command artifact path: {}",
        launch_command_artifact.path
    );
    let surface_manifest_artifact = runtime_artifacts
        .iter()
        .find(|artifact| artifact.subkind == "native-system-surface-manifest")
        .expect("surface manifest artifact");
    assert!(
        surface_manifest_artifact
            .path
            .ends_with("outputs/native-system-surface-manifest.json"),
        "unexpected surface manifest artifact path: {}",
        surface_manifest_artifact.path
    );

    let launch_state_path = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs")
        .join("native-system-launch-state.json");
    let launch_state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&launch_state_path).expect("launch state"))
            .expect("launch state json");
    let stdout_log_path = launch_state
        .get("stdout_log_path")
        .and_then(|value| value.as_str())
        .expect("stdout log path");
    assert!(
        std::path::Path::new(stdout_log_path).exists(),
        "expected stdout log path to exist: {stdout_log_path}"
    );
    let launch_command = std::fs::read_to_string(&launch_command_artifact.path)
        .expect("launch command artifact contents");
    assert!(
        launch_command.contains("qemu-system-mipsel"),
        "launch command did not record the native-host qemu binary: {launch_command}"
    );
    assert!(
        launch_command.contains("rootfs.ext2"),
        "launch command did not record the staged rootfs image: {launch_command}"
    );
    assert!(
        launch_command.contains("init=/fat/init-trampoline"),
        "launch command did not record the FAT preinit handoff: {launch_command}"
    );
    let surface_manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&surface_manifest_artifact.path)
            .expect("surface manifest artifact contents"),
    )
    .expect("surface manifest json");
    let surface_names: Vec<_> = surface_manifest
        .get("registered_surfaces")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|surface| surface.get("name").and_then(|value| value.as_str()))
        .collect();
    assert!(
        surface_names.contains(&"serial-console"),
        "expected serial console surface in manifest, got {surface_names:?}"
    );
    assert!(
        surface_names.contains(&"qemu-monitor"),
        "expected monitor surface in manifest, got {surface_names:?}"
    );
    assert!(
        surface_names.contains(&"gdb-server"),
        "expected debugger surface in manifest, got {surface_names:?}"
    );
    let predeclared_surface_names: Vec<_> = surface_manifest
        .get("predeclared_service_surfaces")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|surface| surface.get("name").and_then(|value| value.as_str()))
        .collect();
    assert!(
        predeclared_surface_names.contains(&"port-8080"),
        "expected predeclared service surface in manifest, got {predeclared_surface_names:?}"
    );

    assert!(
        run.active_endpoints
            .iter()
            .any(|endpoint| endpoint.name == "serial-console"
                && endpoint.kind == RuntimeEndpointKind::Shell),
        "expected serial console endpoint, got {:?}",
        run.active_endpoints
    );
    assert!(
        run.active_endpoints
            .iter()
            .any(|endpoint| endpoint.name == "qemu-monitor"
                && endpoint.kind == RuntimeEndpointKind::Monitor),
        "expected monitor endpoint, got {:?}",
        run.active_endpoints
    );
    assert!(
        run.active_endpoints
            .iter()
            .any(|endpoint| endpoint.name == "gdb-server"
                && endpoint.kind == RuntimeEndpointKind::Debugger),
        "expected gdb endpoint, got {:?}",
        run.active_endpoints
    );
    assert!(
        run.active_endpoints
            .iter()
            .any(|endpoint| endpoint.name == "port-8080"
                && endpoint.kind == RuntimeEndpointKind::PortForward),
        "expected predeclared service endpoint, got {:?}",
        run.active_endpoints
    );
}

#[test]
fn explicit_qemu_direct_system_first_overrides_launchable_service_selection() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\\n'\nexec /bin/sleep 30\n",
    );
    make_executable_with_contents(
        path_dir.path().join("qemu-mipsel"),
        "#!/bin/sh\nprintf 'service-launch\\n'\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\nservice:/bin/alphapd\nweb:alphapd\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("bin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("alphapd"),
        "#!/bin/sh\nprintf 'alphapd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "smoke-native-system-service-conflict-1",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );
    let launch_state = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs")
        .join("native-system-launch-state.json");

    assert_eq!(selection_trace.attempts[0].substrate, SubstrateKind::System);
    assert!(
        launch_state.exists(),
        "expected native system launch state at {}",
        launch_state.display()
    );
}

#[test]
fn native_host_system_runner_stop_reaps_qemu_process() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\\n'\nexec /bin/sleep 60\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "smoke-native-system-stop",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let run = store.read_run(session_id, run_id).expect("run");
    let supervisor_pid = run.supervisor_pid.expect("native host pid");
    assert_eq!(run.status, fat_core::runs::RunStatus::Running);
    assert_process_is_running(supervisor_pid);

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("fat emulate stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");

    assert_process_eventually_exits(supervisor_pid);

    let session = store.read_session(session_id).expect("session");
    let stopped_run = store.read_run(session_id, run_id).expect("stopped run");
    assert_eq!(session.status, fat_core::sessions::SessionStatus::Completed);
    assert_eq!(stopped_run.status, fat_core::runs::RunStatus::Completed);
    assert_eq!(stopped_run.supervisor_pid, None);
    assert!(stopped_run.finished_at.is_some());
    let stop_state = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs/native-system-stop-state.json");
    assert!(stop_state.is_file(), "{}", stop_state.display());
    let stop_state_text = std::fs::read_to_string(stop_state).expect("stop state");
    assert!(stop_state_text.contains("\"process_running\": false"));

    let mut unrelated = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("unrelated process");
    let unrelated_pid = unrelated.id();
    let second_stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("second stop runs");
    assert!(second_stop.status.success(), "{second_stop:?}");
    assert!(
        process_is_running(unrelated_pid),
        "idempotent stop must not signal an unrelated process"
    );
    unrelated.kill().expect("terminate unrelated process");
    unrelated.wait().expect("reap unrelated process");
}

#[test]
fn native_host_system_runner_status_refreshes_after_qemu_exit() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nexec /bin/sleep 60\n",
    );
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "native-status-refresh",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let running = store.read_run(session_id, run_id).expect("running run");
    let qemu_pid = running.supervisor_pid.expect("qemu pid");
    assert_process_is_running(qemu_pid);
    let owned_socket_paths = running
        .active_endpoints
        .iter()
        .filter_map(|endpoint| endpoint.uri.as_deref())
        .filter_map(|uri| uri.strip_prefix("unix://"))
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    let owned_sockets = owned_socket_paths
        .iter()
        .map(|path| std::os::unix::net::UnixListener::bind(path).expect("owned socket"))
        .collect::<Vec<_>>();

    let live_status = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--status",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("live status runs");
    assert!(live_status.status.success(), "{live_status:?}");
    assert_eq!(
        store.read_run(session_id, run_id).expect("live run").status,
        fat_core::runs::RunStatus::Running
    );
    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting/readiness"),
    );
    assert!(readiness
        .surfaces
        .iter()
        .all(|surface| surface.readiness == fat_core::rehosting::SurfaceReadiness::Registered));
    assert!(readiness.validated_goals.is_empty());

    Command::new("kill")
        .arg(qemu_pid.to_string())
        .status()
        .expect("terminate qemu");
    assert_process_eventually_exits(qemu_pid);
    let exited_status = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--status",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("exited status runs");
    assert!(exited_status.status.success(), "{exited_status:?}");
    let exited = store.read_run(session_id, run_id).expect("exited run");
    assert_eq!(exited.status, fat_core::runs::RunStatus::Failed);
    assert_eq!(exited.supervisor_pid, None);
    assert_eq!(
        exited.health_state,
        fat_core::runs::HealthState::Unreachable
    );
    let diagnostics = store
        .read_run_diagnostics(session_id, run_id)
        .expect("diagnostics");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.subclass.as_deref() == Some("native-system-process-exited")
    }));
    drop(owned_sockets);

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("stale native stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");
    assert!(owned_socket_paths.iter().all(|path| !path.exists()));
    assert_eq!(
        store
            .read_run(session_id, run_id)
            .expect("stopped run")
            .status,
        fat_core::runs::RunStatus::Failed,
        "cleanup must not turn a failed experiment into success"
    );
}

#[test]
fn native_system_validators_promote_only_run_scoped_serial_process_and_http_evidence() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let pack_path = firmware_dir.path().join("validator-pack.yaml");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    std::fs::write(
        &pack_path,
        r#"
id: test/native-validator-evidence
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:/sbin/preinit"]
runtime:
  substrate: system
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: FAT_NATIVE_TEST_MARKER
  - goal: boa-process
    kind: process
    name: boa
  - goal: http-reply
    kind: http
    port: 80
"#,
    )
    .expect("pack file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nserial_log=''\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    *logfile=*) serial_log=${arg##*logfile=} ;;\n  esac\ndone\n[ -n \"$serial_log\" ] && printf 'FAT_NATIVE_TEST_MARKER\\n' > \"$serial_log\"\nexec /bin/sleep 60\n",
    );
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\n",
    )
    .expect("signals");
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--pack",
            pack_path.to_str().expect("pack path"),
            "--experimental-rehosting",
            "--backend",
            "qemu-direct",
            "--session-id",
            "native-validator-evidence",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let launch_state_path = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs/native-system-launch-state.json");
    let launch_state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&launch_state_path).expect("launch state"))
            .expect("launch state json");
    let serial_log_path = PathBuf::from(
        launch_state["serial_log_path"]
            .as_str()
            .expect("serial log path"),
    );
    let serial_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < serial_deadline
        && !std::fs::read_to_string(&serial_log_path)
            .unwrap_or_default()
            .contains("FAT_NATIVE_TEST_MARKER")
    {
        std::thread::sleep(Duration::from_millis(20));
    }

    let serial_status = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--status",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("serial status runs");
    assert!(serial_status.status.success(), "{serial_status:?}");
    let readiness_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("rehosting/readiness");
    let serial_readiness = read_single_json_record::<ReadinessReport>(&readiness_dir);
    assert_eq!(serial_readiness.validated_goals, vec!["init-handoff"]);

    let run = store.read_run(session_id, run_id).expect("run");
    let session = store.read_session(session_id).expect("session");
    let http_endpoint = run
        .active_endpoints
        .iter()
        .find(|endpoint| endpoint.target_port == Some(80))
        .expect("http endpoint");
    let listener = TcpListener::bind((http_endpoint.host.as_str(), http_endpoint.port))
        .expect("host validator listener");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("http probe connection");
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).expect("http request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .expect("http response");
    });

    let process_path = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs/process-snapshot.json");
    let process_json = serde_json::to_string_pretty(&fat_core::debug::ObservedProcessSnapshot {
        session_id: session_id.clone(),
        run_id: run_id.clone(),
        backend_id: "qemu-direct".into(),
        processes: vec![fat_core::debug::ObservedProcessEntry::new(
            42,
            "/system/bin/boa -c /configs/boa.conf",
            "test-guest-observation",
        )],
    })
    .expect("process json");
    std::fs::write(&process_path, &process_json).expect("process snapshot");
    let process_artifact = ArtifactRecord::new(
        "demo",
        session.target_id.clone(),
        session_id.clone(),
        run_id.clone(),
        ArtifactKind::RuntimeCapture,
        "process-snapshot",
        "test",
        "guest observer",
        "2026-08-21T00:00:00Z",
        process_path.to_string_lossy(),
        "application/json",
        process_json.len() as u64,
        None,
        "explicit guest process observation",
        ArtifactRetentionPolicy::Session,
    )
    .with_backend_driver("qemu-direct")
    .with_substrate_kind(run.substrate_kind);
    store.write_artifact(&process_artifact).expect("artifact");

    let validated_status = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--status",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("validated status runs");
    assert!(validated_status.status.success(), "{validated_status:?}");
    server.join().expect("http server");
    let validated = read_single_json_record::<ReadinessReport>(&readiness_dir);
    for goal in ["init-handoff", "boa-process", "http-reply"] {
        assert!(
            validated.validated_goals.contains(&goal.to_string()),
            "missing {goal}: {validated:?}"
        );
    }

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("fat emulate stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");
}

#[test]
fn native_host_system_runner_failure_is_classified_for_fallback() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "smoke-native-system-fallback-1",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let _run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store.read_session(session_id).expect("session");
    let first_run_id = session.run_ids.first().expect("first run id");
    let failed_run = store
        .read_run(session_id, first_run_id)
        .expect("failed run");
    assert_eq!(failed_run.status, fat_core::runs::RunStatus::Failed);
    let diagnostics = store
        .read_run_diagnostics(session_id, first_run_id)
        .expect("first run diagnostics");
    let launch_failure = diagnostics.last().expect("launch failure diagnostic");
    assert_eq!(launch_failure.run_id, first_run_id.as_str());
    assert_eq!(launch_failure.class, DiagnosticClass::SubstrateUnavailable);
    assert_eq!(
        launch_failure.subclass.as_deref(),
        Some("native-host-system-launch")
    );
    assert!(
        launch_failure
            .summary
            .contains("failed to spawn native-host system launch"),
        "expected native-host launch failure summary, got {}",
        launch_failure.summary
    );
    assert_eq!(
        launch_failure.actionability,
        fat_core::diagnostics::DiagnosticActionability::FallbackRecommended
    );

    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, session.run_ids.last().expect("final run id"))
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );
    assert_eq!(selection_trace.preference, SubstratePreference::SystemFirst);
    assert_eq!(selection_trace.attempts[0].substrate, SubstrateKind::System);
    let project = ProjectDb::open(&project_dir)
        .expect("project db")
        .get("demo")
        .expect("project lookup")
        .expect("project record");
    assert_eq!(project.status, ProjectStatus::Error);
}

#[test]
fn fat_emulate_persists_service_staging_and_confidence_records() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}],\"processes\":[{\"pid\":79,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18080\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );
    make_executable_with_contents(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-staging-confidence-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let run_path = store.run_path(session_id, run_id);
    let run_root = run_path.parent().expect("run parent");

    let staging =
        read_single_json_record::<StagingManifest>(&run_root.join("rehosting").join("staging"));
    assert_eq!(staging.logical_substrate, "service");
    assert_eq!(staging.strategy, StagingStrategy::MutableOverlay);
    assert!(staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.contains("overlay")));

    let confidence_reports =
        read_json_records::<ConfidenceReport>(&run_root.join("rehosting").join("confidence"));
    assert!(
        !confidence_reports.is_empty(),
        "expected confidence records"
    );
    assert!(confidence_reports.iter().any(|report| {
        report.logical_substrate == Some(SubstrateKind::Service)
            && report.level == ConfidenceLevel::Medium
    }));
}

#[test]
fn fat_emulate_failed_launch_persists_blocker_and_low_confidence() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );
    make_executable_with_contents(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-blocker-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let run_path = store.run_path(session_id, run_id);
    let run_root = run_path.parent().expect("run parent");

    let blockers = read_json_records::<BlockerRecord>(&run_root.join("rehosting").join("blockers"));
    assert!(!blockers.is_empty(), "expected blocker records");
    assert!(blockers.iter().any(|blocker| {
        blocker.logical_substrate == SubstrateKind::Service
            && blocker.session_id == *session_id
            && blocker.run_id == *run_id
    }));

    let confidence_reports =
        read_json_records::<ConfidenceReport>(&run_root.join("rehosting").join("confidence"));
    assert!(confidence_reports.iter().any(|report| {
        report.logical_substrate == Some(SubstrateKind::Service)
            && report.level == ConfidenceLevel::Low
            && !report.blockers.is_empty()
    }));
}

#[test]
fn fat_emulate_auto_falls_back_from_service_to_system_within_one_session() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    make_executable_with_contents(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env_remove("FAT_FIRMAE_UPSTREAM_DIR")
        .env_remove("FAT_FIRMAE_HOST_PYTHON")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-auto-fallback-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store.read_session(session_id).expect("session");
    assert!(session.run_ids.len() >= 2, "expected fallback run chain");
    assert_eq!(
        session.run_ids.last().map(String::as_str),
        Some(run_id.as_str())
    );

    let final_run = store.read_run(session_id, run_id).expect("final run");
    assert!(matches!(
        final_run.backend_driver.as_str(),
        "firmae" | "firmadyne"
    ));

    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );
    assert_eq!(selection_trace.preference, SubstratePreference::Auto);
    assert_eq!(
        selection_trace.attempts[0].substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Failed
    );
    assert_eq!(selection_trace.attempts[1].substrate, SubstrateKind::System);
    assert_eq!(
        selection_trace.attempts[1].state,
        SubstrateAttemptState::Selected
    );
}

#[test]
fn fat_emulate_auto_falls_back_to_reference_after_service_and_system_fail() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let emux_dir = tempdir().expect("emux dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );
    make_executable_with_contents(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '29.2.1\\n'; exit 0; fi\nif [ \"$1\" = \"exec\" ]; then\n  cmd=\"$5\"\n  case \"$cmd\" in\n    */emuxps)\n      printf 'PID TTY STAT TIME COMMAND\\n'\n      printf '1 ? Ss 00:00 /sbin/init\\n'\n      printf '77 ? S 00:00 /usr/sbin/uhttpd\\n'\n      exit 0\n      ;;\n    */emuxnetstat*)\n      printf 'Active Internet connections (only servers)\\n'\n      printf 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\\n'\n      printf 'tcp        0      0 0.0.0.0:22222           0.0.0.0:*               LISTEN\\n'\n      exit 0\n      ;;\n    *ssh\\ -o\\ StrictHostKeyChecking=no*)\n      printf 'shell-helper:ready\\n'\n      printf 'shell-command:%s\\n' \"$cmd\"\n      exit 0\n      ;;\n    *127.0.0.1*55555*)\n      printf 'monitor-helper:ready\\n'\n      printf 'monitor-command:info version\\n'\n      exit 0\n      ;;\n  esac\nfi\nprintf 'docker:%s\\n' \"$*\"\nexit 0\n",
    );
    write_fake_emux_recipe(emux_dir.path());

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .env_remove("FAT_FIRMAE_UPSTREAM_DIR")
        .env_remove("FAT_FIRMAE_HOST_PYTHON")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "smoke-auto-fallback-reference-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store.read_session(session_id).expect("session");
    assert!(session.run_ids.len() >= 2, "expected fallback run chain");
    assert_eq!(
        session.run_ids.last().map(String::as_str),
        Some(run_id.as_str())
    );

    let final_run = store.read_run(session_id, run_id).expect("final run");
    assert_eq!(final_run.backend_driver, "emux");
    let supervisor_pid = final_run.supervisor_pid.expect("EmuX supervisor pid");
    assert_process_is_running(supervisor_pid);
    let emux_workspace = std::fs::read_dir(emux_dir.path().join("workspace"))
        .expect("EmuX workspace root")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("EmuX runtime workspace");
    let launcher_pid = std::fs::read_to_string(emux_workspace.join("emux-launcher.pid"))
        .expect("EmuX launcher pid")
        .trim()
        .parse::<u32>()
        .expect("numeric EmuX launcher pid");
    assert_process_is_running(launcher_pid);

    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );
    assert_eq!(selection_trace.preference, SubstratePreference::Auto);
    assert_eq!(
        selection_trace.attempts[0].substrate,
        SubstrateKind::Service
    );
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Failed
    );
    assert_eq!(selection_trace.attempts[1].substrate, SubstrateKind::System);
    assert_eq!(
        selection_trace.attempts[1].state,
        SubstrateAttemptState::Failed
    );
    assert_eq!(
        selection_trace.attempts[2].substrate,
        SubstrateKind::Reference
    );
    assert_eq!(
        selection_trace.attempts[2].state,
        SubstrateAttemptState::Selected
    );

    let run_path = store.run_path(session_id, run_id);
    let run_root = run_path.parent().expect("run parent");
    let readiness =
        read_single_json_record::<ReadinessReport>(&run_root.join("rehosting").join("readiness"));
    assert!(
        readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "reference-bootstrap"),
        "expected reference-bootstrap validation, got {:?}",
        readiness.validated_goals
    );
    assert!(
        readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "shell-access"),
        "expected shell-access validation, got {:?}",
        readiness.validated_goals
    );

    let confidence_reports =
        read_json_records::<ConfidenceReport>(&run_root.join("rehosting").join("confidence"));
    assert!(confidence_reports.iter().any(|report| {
        report.logical_substrate == Some(SubstrateKind::Reference)
            && report.level == ConfidenceLevel::High
    }));

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .args([
            "emulate",
            "--stop",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("stop reference fallback runtime");
    assert!(stop_output.status.success(), "{stop_output:?}");
    assert_process_eventually_exits(supervisor_pid);
    assert_process_eventually_exits(launcher_pid);
}

#[test]
fn fat_emulate_system_trace_records_firmadyne_selection_detail_when_requested() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );
    make_executable_with_contents(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '29.2.1\\n'; exit 0; fi\nexit 0\n",
    );
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    make_executable_with_contents(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:uhttpd\ngenerated:reference-rootfs\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmadyne",
            "--session-id",
            "smoke-system-swap-detail-1",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let selection_trace = read_single_json_record::<SelectionTrace>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("selection"),
    );

    assert_eq!(selection_trace.attempts[0].substrate, SubstrateKind::System);
    assert_eq!(
        selection_trace.attempts[0].state,
        SubstrateAttemptState::Selected
    );
    let detail = selection_trace.attempts[0]
        .detail
        .clone()
        .expect("selection detail");
    assert!(
        detail.contains("selected backend=firmadyne")
            && detail.contains("substrate=managed-linux-vm"),
        "expected explicit firmadyne selection detail, got {detail}"
    );
}

#[test]
fn fat_emulate_service_runner_executes_qemu_user_against_extracted_rootfs() {
    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}],\"processes\":[{\"pid\":77,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18080\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/uhttpd\nweb:uhttpd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-service-runner-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let run = store.read_run(session_id, run_id).expect("run");
    assert_eq!(run.backend_driver, "qemu-direct");
    assert!(
        run.active_endpoints
            .iter()
            .any(|endpoint| endpoint.name == "uhttpd"
                && endpoint.uri.as_deref() == Some("http://127.0.0.1:18080")),
        "expected persisted service endpoint, got {:?}",
        run.active_endpoints
    );

    let args = std::fs::read_to_string(&qemu_args_log).expect("qemu-user args log");
    assert!(
        args.contains("-L"),
        "expected qemu-user invocation to include a sysroot, got:\n{args}"
    );
    assert!(
        args.contains("/usr/sbin/uhttpd"),
        "expected qemu-user invocation to target uhttpd, got:\n{args}"
    );

    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert!(readiness
        .validated_goals
        .iter()
        .any(|goal| goal == "shell-access"));
    assert!(
        !readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "http-validation"),
        "expected listener/process evidence alone to leave http-validation unvalidated, got {:?}",
        readiness.validated_goals
    );

    let probe_artifact = store
        .read_run_artifacts(session_id, run_id)
        .expect("run artifacts")
        .into_iter()
        .find(|artifact| artifact.subkind == "http-probe-state")
        .expect("http probe artifact");
    let probe_state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&probe_artifact.path).expect("read probe artifact"))
            .expect("parse probe artifact");
    assert_eq!(
        probe_state
            .get("reply_received")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        probe_state
            .get("failure_mode")
            .and_then(serde_json::Value::as_str),
        Some("connect-refused")
    );

    let confidence_reports = read_json_records::<ConfidenceReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("confidence"),
    );
    assert!(confidence_reports
        .iter()
        .any(|report| report.level == ConfidenceLevel::High));

    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(outputs_dir.join("service-launch-manifest.json").exists());
    assert!(outputs_dir.join("process-snapshot.json").exists());
    assert!(outputs_dir.join("service-snapshot.json").exists());
    assert!(outputs_dir.join("network-snapshot.json").exists());
}

#[test]
fn fat_emulate_persists_process_chain_artifact_for_expected_service() {
    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user-process-chain.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"alphapd\",\"host\":\"127.0.0.1\",\"port\":18081,\"target_port\":80,\"uri\":\"http://127.0.0.1:18081\"}],\"processes\":[{\"pid\":91,\"command\":\"/usr/sbin/alphapd -f /etc/alphapd.conf\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"alphapd\",\"endpoint\":\"http://127.0.0.1:18081\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/alphapd\nweb:alphapd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("alphapd"),
        "#!/bin/sh\nprintf 'alphapd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-process-chain-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert!(
        readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "process-chain"),
        "expected explicit process-chain validation, got {:?}",
        readiness.validated_goals
    );

    let process_chain_artifact = store
        .read_run_artifacts(session_id, run_id)
        .expect("run artifacts")
        .into_iter()
        .find(|artifact| artifact.subkind == "process-chain-state")
        .expect("process chain artifact");
    let process_chain_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&process_chain_artifact.path).expect("read process chain artifact"),
    )
    .expect("parse process chain artifact");
    assert_eq!(
        process_chain_state
            .get("validated")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

#[test]
fn fat_emulate_persists_http_probe_artifact_for_service_surface() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("http listener");
    let http_port = listener.local_addr().expect("listener addr").port();
    let server = spawn_single_reply_http_server(
        listener,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
    );

    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user-http.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nprintf '%s\\n' '{{\"endpoints\":[{{\"kind\":\"service\",\"name\":\"alphapd\",\"host\":\"127.0.0.1\",\"port\":{http_port},\"target_port\":80,\"uri\":\"http://127.0.0.1:{http_port}\"}}],\"processes\":[{{\"pid\":90,\"command\":\"/usr/sbin/alphapd\",\"source_kind\":\"service-launch-manifest\"}}],\"services\":[{{\"name\":\"alphapd\",\"endpoint\":\"http://127.0.0.1:{http_port}\",\"source_kind\":\"service-launch-manifest\"}}]}}'\nexit 0\n"
        ),
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/alphapd\nweb:alphapd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("alphapd"),
        "#!/bin/sh\nprintf 'alphapd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-http-probe-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    assert!(
        server.join().expect("http server thread"),
        "expected FAT to connect to the local HTTP probe fixture"
    );

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert!(
        readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "http-validation"),
        "expected explicit http probe reply to validate http-validation, got {:?}",
        readiness.validated_goals
    );
    let probe_artifact = store
        .read_run_artifacts(session_id, run_id)
        .expect("run artifacts")
        .into_iter()
        .find(|artifact| artifact.subkind == "http-probe-state")
        .expect("http probe artifact");
    let probe_state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&probe_artifact.path).expect("read probe artifact"))
            .expect("parse probe artifact");
    assert_eq!(
        probe_artifact.kind,
        fat_core::artifacts::ArtifactKind::RuntimeState
    );
    assert_eq!(
        probe_state
            .get("reply_received")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        probe_state
            .get("status_line")
            .and_then(serde_json::Value::as_str),
        Some("HTTP/1.1 200 OK")
    );
}

#[test]
fn fat_emulate_process_chain_requires_expected_process_role() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("http listener");
    let http_port = listener.local_addr().expect("listener addr").port();
    let server = spawn_single_reply_http_server(
        listener,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
    );

    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user-process-mismatch.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nprintf '%s\\n' '{{\"endpoints\":[{{\"kind\":\"service\",\"name\":\"alphapd\",\"host\":\"127.0.0.1\",\"port\":{http_port},\"target_port\":80,\"uri\":\"http://127.0.0.1:{http_port}\"}}],\"processes\":[{{\"pid\":92,\"command\":\"/usr/sbin/httpd -f /etc/httpd.conf\",\"source_kind\":\"service-launch-manifest\"}}],\"services\":[{{\"name\":\"alphapd\",\"endpoint\":\"http://127.0.0.1:{http_port}\",\"source_kind\":\"service-launch-manifest\"}}]}}'\nexit 0\n"
        ),
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/alphapd\nweb:alphapd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("alphapd"),
        "#!/bin/sh\nprintf 'alphapd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-process-chain-negative-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    assert!(
        server.join().expect("http server thread"),
        "expected FAT to connect to the local HTTP probe fixture"
    );

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let readiness = read_single_json_record::<ReadinessReport>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("readiness"),
    );
    assert!(
        readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "http-validation"),
        "expected explicit http validation, got {:?}",
        readiness.validated_goals
    );
    assert!(
        !readiness
            .validated_goals
            .iter()
            .any(|goal| goal == "process-chain"),
        "expected mismatched process role to keep process-chain unvalidated, got {:?}",
        readiness.validated_goals
    );

    let process_chain_artifact = store
        .read_run_artifacts(session_id, run_id)
        .expect("run artifacts")
        .into_iter()
        .find(|artifact| artifact.subkind == "process-chain-state")
        .expect("process chain artifact");
    let process_chain_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&process_chain_artifact.path).expect("read process chain artifact"),
    )
    .expect("parse process chain artifact");
    assert_eq!(
        process_chain_state
            .get("validated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        process_chain_state
            .get("missing_roles")
            .and_then(serde_json::Value::as_array)
            .map(|roles| roles
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["primary-service"])
    );
}

#[test]
fn fat_emulate_repair_retry_creates_missing_device_node_and_retries_service_runner() {
    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user-repair.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprev=\"\"\nsysroot=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-L\" ]; then sysroot=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nprintf '%s\\n' \"$@\" >> \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nif [ ! -e \"$sysroot/dev/ttyS0\" ]; then\n  printf 'missing /dev/ttyS0 while bootstrapping the guest\\n' >&2\n  exit 7\nfi\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}],\"processes\":[{\"pid\":88,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18080\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/uhttpd\nweb:uhttpd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-service-repair-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store.read_session(session_id).expect("session");
    assert_eq!(session.run_ids.len(), 2, "expected one repaired retry run");
    assert_eq!(
        session.run_ids.last().map(String::as_str),
        Some(run_id.as_str())
    );

    let first_run = store
        .read_run(session_id, &session.run_ids[0])
        .expect("initial failed run");
    let repaired_run = store
        .read_run(session_id, &session.run_ids[1])
        .expect("repaired run");
    assert_eq!(first_run.status, fat_core::runs::RunStatus::Failed);
    assert!(matches!(
        repaired_run.status,
        fat_core::runs::RunStatus::Running
            | fat_core::runs::RunStatus::Completed
            | fat_core::runs::RunStatus::DegradedRunning
            | fat_core::runs::RunStatus::DegradedCompleted
    ));
    assert_eq!(
        repaired_run.derived_from_run_id.as_deref(),
        Some(first_run.run_id.as_str())
    );

    let repaired_staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("staging"),
    );
    assert!(
        PathBuf::from(repaired_staging.staging_root)
            .join("dev")
            .join("ttyS0")
            .exists(),
        "expected repaired staging root to contain /dev/ttyS0"
    );

    let repair_records = read_json_records::<fat_core::rehosting::RepairRecord>(
        &store
            .run_path(session_id, &session.run_ids[0])
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("repairs"),
    );
    assert!(repair_records
        .iter()
        .any(|record| record.action == fat_core::rehosting::RepairActionKind::CreateNode));

    let repair_materialization = read_single_json_record::<serde_json::Value>(
        &store
            .run_path(session_id, &session.run_ids[0])
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("repairs")
            .join("materializations"),
    );
    assert_eq!(
        repair_materialization
            .get("action")
            .and_then(serde_json::Value::as_str),
        Some("create-node")
    );
    assert!(repair_materialization
        .get("device_nodes")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node.get("path").and_then(serde_json::Value::as_str) == Some("/dev/ttyS0")
            })
        }));

    let args = std::fs::read_to_string(&qemu_args_log).expect("qemu-user args log");
    assert!(
        args.lines().count() >= 2,
        "expected the qemu-user launcher to run twice"
    );
}

#[test]
fn fat_emulate_repair_retry_materializes_config_patch_and_retries() {
    let path_dir = tempdir().expect("path dir");
    let qemu_args_log = path_dir.path().join("qemu-user-repair-config.args");
    make_executable_with_contents(
        path_dir.path().join("qemu-arm"),
        "#!/bin/sh\nprev=\"\"\nsysroot=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-L\" ]; then sysroot=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nprintf '%s\\n' \"$@\" >> \"$FAT_TEST_QEMU_USER_ARGS_LOG\"\nif [ ! -e \"$sysroot/etc/fat/repair-init.sh\" ]; then\n  printf 'wrong init path /sbin/init; retry with /etc/init.d/rcS and materialize /etc/fat/repair-init.sh\\n' >&2\n  exit 9\nfi\nprintf '%s\\n' '{\"endpoints\":[{\"kind\":\"service\",\"name\":\"uhttpd\",\"host\":\"127.0.0.1\",\"port\":18081,\"target_port\":80,\"uri\":\"http://127.0.0.1:18081\"}],\"processes\":[{\"pid\":89,\"command\":\"/usr/sbin/uhttpd -f\",\"source_kind\":\"service-launch-manifest\"}],\"services\":[{\"name\":\"uhttpd\",\"endpoint\":\"http://127.0.0.1:18081\",\"source_kind\":\"service-launch-manifest\"}]}'\nexit 0\n",
    );

    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\nservice:/usr/sbin/uhttpd\nweb:uhttpd\n",
    )
    .expect("signals");
    let extracted_bin_dir = project_dir.join("extracted").join("usr").join("sbin");
    std::fs::create_dir_all(&extracted_bin_dir).expect("extracted bin dir");
    make_executable_with_contents(
        extracted_bin_dir.join("uhttpd"),
        "#!/bin/sh\nprintf 'uhttpd config repair rootfs stub\\n'\nexit 0\n",
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_QEMU_USER_ARGS_LOG", &qemu_args_log)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--substrate-policy",
            "service-first",
            "--session-id",
            "smoke-service-config-repair-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let session = store.read_session(session_id).expect("session");
    assert_eq!(session.run_ids.len(), 2, "expected one repaired retry run");
    assert_eq!(
        session.run_ids.last().map(String::as_str),
        Some(run_id.as_str())
    );

    let first_run = store
        .read_run(session_id, &session.run_ids[0])
        .expect("initial failed run");
    let repaired_run = store
        .read_run(session_id, &session.run_ids[1])
        .expect("repaired run");
    assert_eq!(first_run.status, fat_core::runs::RunStatus::Failed);
    assert!(matches!(
        repaired_run.status,
        fat_core::runs::RunStatus::Running
            | fat_core::runs::RunStatus::Completed
            | fat_core::runs::RunStatus::DegradedRunning
            | fat_core::runs::RunStatus::DegradedCompleted
    ));
    assert_eq!(
        repaired_run.derived_from_run_id.as_deref(),
        Some(first_run.run_id.as_str())
    );

    let repair_records = read_json_records::<fat_core::rehosting::RepairRecord>(
        &store
            .run_path(session_id, &session.run_ids[0])
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("repairs"),
    );
    assert!(repair_records
        .iter()
        .any(|record| record.action == fat_core::rehosting::RepairActionKind::PatchConfig));

    let repair_materialization =
        read_single_json_record::<fat_core::rehosting::RepairMaterializationRecord>(
            &store
                .run_path(session_id, &session.run_ids[0])
                .parent()
                .expect("run parent")
                .join("rehosting")
                .join("repairs")
                .join("materializations"),
        );
    assert_eq!(
        repair_materialization.action,
        fat_core::rehosting::RepairActionKind::PatchConfig
    );
    assert!(repair_materialization
        .filesystem_transforms
        .iter()
        .any(|transform| {
            transform.transform_kind == "patch-config"
                && transform.source == "synth:repair-init"
                && transform.destination == "/etc/fat/repair-init.sh"
        }));

    let repaired_staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("staging"),
    );
    assert!(
        PathBuf::from(repaired_staging.staging_root)
            .join("etc")
            .join("fat")
            .join("repair-init.sh")
            .exists(),
        "expected repaired staging root to contain /etc/fat/repair-init.sh"
    );

    let args = std::fs::read_to_string(&qemu_args_log).expect("qemu-user args log");
    assert!(
        args.lines().count() >= 2,
        "expected the qemu-user launcher to run twice"
    );
}

fn parse_keyed_output(stdout: &str) -> HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn make_executable(path: PathBuf) {
    make_executable_with_contents(path, "#!/bin/sh\nexit 0\n");
}

fn make_executable_with_contents(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}

fn seed_native_system_boot_inputs(project_dir: &std::path::Path, path_dir: &std::path::Path) {
    let extracted = project_dir.join("extracted");
    std::fs::create_dir_all(extracted.join("bin")).expect("extracted bin");
    std::fs::create_dir_all(extracted.join("sbin")).expect("extracted sbin");
    std::fs::create_dir_all(extracted.join("etc")).expect("extracted etc");
    std::fs::write(extracted.join("bin/busybox"), b"busybox").expect("busybox");
    std::fs::write(extracted.join("sbin/preinit"), b"#!/bin/sh\nexit 0\n").expect("preinit");
    std::fs::write(extracted.join("etc/inittab"), b"::sysinit:/sbin/preinit\n").expect("inittab");
    seed_native_system_kernel_inputs(path_dir);
}

fn seed_native_system_kernel_inputs(path_dir: &std::path::Path) {
    std::fs::write(path_dir.join("vmlinux.mipsel.4"), b"synthetic-kernel")
        .expect("synthetic system kernel");
    let kernel_profiles = path_dir.join("profiles/kernels");
    std::fs::create_dir_all(&kernel_profiles).expect("kernel profiles");
    std::fs::write(
        kernel_profiles.join("catalog.json"),
        r#"[
  {
    "profile_id": "mipsel-test",
    "architecture": "mipsel",
    "family_hint": "linux-",
    "tier": 1,
    "image_hint": "vmlinux.mipsel.4",
    "support_tier": "test-only",
    "compatibility_note": "synthetic integration-test kernel"
  }
]"#,
    )
    .expect("synthetic kernel catalog");
    make_executable_with_contents(
        path_dir.join("mke2fs"),
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-F\" ]; then out=\"$arg\"; fi\n  prev=\"$arg\"\ndone\n[ -n \"$out\" ] || exit 64\n: > \"$out\"\nexit 0\n",
    );
    make_executable_with_contents(
        path_dir.join("debugfs"),
        "#!/bin/sh\nwhile IFS= read -r _command; do :; done\nexit 0\n",
    );
}

fn assert_process_is_running(pid: u32) {
    assert!(
        process_is_running(pid),
        "expected pid {pid} to be running before stop"
    );
}

fn assert_process_eventually_exits(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !process_is_running(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    panic!("expected pid {pid} to exit after stop");
}

fn process_is_running(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn spawn_single_reply_http_server(
    listener: TcpListener,
    response: &'static str,
) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buffer = [0u8; 1024];
                    let _ = stream.read(&mut buffer);
                    stream
                        .write_all(response.as_bytes())
                        .expect("write http response");
                    let _ = stream.flush();
                    return true;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => panic!("accept http client: {err}"),
            }
        }
        false
    })
}

fn write_fake_emux_recipe(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("files/emux/run")).expect("recipe dirs");
    std::fs::create_dir_all(root.join("files/emux/firmware/TRI227WF/kernel")).expect("device dirs");
    std::fs::create_dir_all(root.join("files/emux/firmware/DV-MIPSEL/kernel"))
        .expect("device dirs");
    std::fs::write(
        root.join("files/emux/firmware/devices"),
        "firmware/TRI227WF,qemu-system-arm,versatilepb,,,128M,zImage,TRI227WF,Trivision Camera\nfirmware/DV-MIPSEL,qemu-system-mipsel,malta,,,128M,vmlinux,DV-MIPSEL,Damn Vulnerable MIPS Router (Little Endian)\n",
    )
    .expect("devices file");
    std::fs::write(
        root.join("files/emux/firmware/TRI227WF/config"),
        "# fake emux config\nid=firmware/TRI227WF\nrootfs=rootfs\ninitcommands=\"/bin/sh\"\n",
    )
    .expect("config");
    std::fs::write(
        root.join("files/emux/firmware/DV-MIPSEL/config"),
        "# fake emux config\nid=firmware/DV-MIPSEL\nnvram=\nrootfs=rootfs-mipsel\nrandomize_va_space=0\nlegacy_va_layout=1\nmount_dev_tree=1\ninitcommands=\"/etc/rc.local;/bin/sh\"\n",
    )
    .expect("config");
    make_executable_with_contents(
        root.join("files/emux/firmware/TRI227WF/run-init"),
        "#!/bin/sh\nprintf 'userspace:%s\\n' \"$*\"\nexit 0\n",
    );
    make_executable_with_contents(
        root.join("files/emux/firmware/DV-MIPSEL/run-init"),
        "#!/bin/sh\nprintf 'userspace:%s\\n' \"$*\"\nexit 0\n",
    );
    make_executable_with_contents(
        root.join("run-emux-docker"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexport PATH=/usr/bin:/bin\nexec /bin/sh -c \"$cmd\"\n",
    );
    make_executable_with_contents(
        root.join("emux-docker-shell"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexport PATH=/usr/bin:/bin\nexec /bin/sh -c \"$cmd\"\n",
    );
    for script in [
        "launcher",
        "hostfs-emux.sh",
        "emuxps",
        "emuxmaps",
        "emuxnetstat",
        "emuxgdb",
        "monitor",
    ] {
        let contents = match script {
            "launcher" => {
                "#!/bin/sh\nworkspace_dir=${fundialog%/*}\nprintf '%s\\n' \"$$\" > \"$workspace_dir/emux-launcher.pid\"\nprintf 'launch:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nexec /bin/sleep 30\n"
            }
            "hostfs-emux.sh" => {
                "#!/bin/sh\nworkspace_dir=${fundialog%/*}\nmarker=\"$workspace_dir/emux-runtime.marker\"\n[ -e \"$marker\" ] || { printf 'missing-marker\\n' >&2; exit 42; }\nprintf 'userspace:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nexit 0\n"
            }
            "emuxps" => {
                "#!/bin/sh\nprintf 'PID TTY STAT TIME COMMAND\\n'\nprintf '1 ? Ss 00:00 /sbin/init\\n'\nprintf '77 ? S 00:00 /usr/sbin/uhttpd\\n'\n"
            }
            "emuxmaps" => {
                "#!/bin/sh\nprintf 'maps-target:%s\\n' \"$1\"\nprintf 'maps-helper:ready\\n'\n"
            }
            "emuxgdb" => {
                "#!/bin/sh\nprintf 'gdb-target:%s\\n' \"$1\"\nprintf 'gdb-helper:ready\\n'\n"
            }
            "monitor" => "#!/bin/sh\nprintf 'monitor-helper:ready\\n'\n",
            _ => "#!/bin/sh\nexit 0\n",
        };
        make_executable_with_contents(root.join("files/emux/run").join(script), contents);
    }
    std::fs::write(root.join("tun"), b"tun").expect("tun");
}

fn read_single_json_record<T>(dir: &std::path::Path) -> T
where
    T: serde::de::DeserializeOwned,
{
    let mut entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"));
    let path = entries
        .next()
        .unwrap_or_else(|| panic!("no json records found in {}", dir.display()));
    assert!(
        entries.next().is_none(),
        "expected exactly one json record in {}",
        dir.display()
    );
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn read_json_records<T>(dir: &std::path::Path) -> Vec<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
        })
        .collect()
}
