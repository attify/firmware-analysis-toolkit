use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use fat_core::rehosting::{FailureClass, RepairActionKind, RepairRecord};
use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::derive_target_id;
use tempfile::tempdir;

#[test]
fn fat_doctor_reports_managed_linux_vm_when_bundle_is_ready() {
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    make_executable(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nexit 0\n",
    );
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FirmAE [firmae]: unavailable"));
    assert!(stdout.contains("managed-linux-vm"));
    assert!(stdout.contains("Firmadyne [firmadyne]: available"));
}

#[test]
fn firmadyne_launch_requires_a_successful_initial_runtime_probe() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let stop_marker = firmware_dir.path().join("stop-marker");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'runtime absent\\n' >&2; exit 12; fi\nif [ \"$1\" = \"--stop\" ]; then printf 'stopped\\n' > \"$FAT_TEST_STOP_MARKER\"; exit 0; fi\nprintf 'launcher returned success\\n'\nexit 0\n",
    );
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
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_STOP_MARKER", &stop_marker)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmadyne",
            "--session-id",
            "firmadyne-probe-required-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session = store
        .read_session(parsed.get("session").expect("session id"))
        .expect("session");
    assert_ne!(session.status, fat_core::sessions::SessionStatus::Active);
    let run = store
        .read_run(&session.session_id, session.run_ids.last().unwrap())
        .expect("run");
    assert_ne!(run.status, fat_core::runs::RunStatus::Running);
    assert!(
        stop_marker.is_file(),
        "failed initial probe must stop the launched runtime"
    );
    assert!(
        !project_dir
            .join("work/runtime")
            .join(&session.session_id)
            .join("managed-linux-vm/firmadyne/dev")
            .exists(),
        "successful cleanup must remove the managed workspace"
    );
}

#[test]
fn firmadyne_initial_probe_cleanup_failure_is_durable_and_retriable() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let allow_stop = firmware_dir.path().join("allow-stop");
    let stop_calls = firmware_dir.path().join("stop-calls");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'runtime absent\\n' >&2; exit 12; fi\nif [ \"$1\" = \"--stop\" ]; then printf 'stop\\n' >> \"$FAT_TEST_STOP_CALLS\"; if [ -f \"$FAT_TEST_ALLOW_STOP\" ]; then exit 0; fi; printf 'cleanup failed\\n' >&2; exit 9; fi\nexit 0\n",
    );
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(created.status.success(), "{created:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");

    let launch = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(!launch.status.success(), "{launch:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&launch.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("store");
    let diagnostics = store
        .read_run_diagnostics(session_id, run_id)
        .expect("diagnostics");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.class
                == fat_core::diagnostics::DiagnosticClass::CleanupFailed),
        "cleanup failure must be durable: {diagnostics:?}"
    );
    let workspace = project_dir
        .join("work/runtime")
        .join(session_id)
        .join("managed-linux-vm/firmadyne/dev");
    assert!(
        workspace.is_dir(),
        "failed cleanup must retain retry identity"
    );

    std::fs::write(&allow_stop, b"allow").expect("allow stop");
    let retry = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("stop retry");
    assert!(retry.status.success(), "{retry:?}");
    assert!(!workspace.exists(), "retry must remove managed workspace");
    assert_eq!(
        store
            .read_run(session_id, run_id)
            .expect("completed run")
            .status,
        fat_core::runs::RunStatus::Completed
    );
    assert_eq!(
        std::fs::read_to_string(stop_calls).expect("stop calls"),
        "stop\nstop\n"
    );
}

#[test]
fn firmadyne_supervisor_spawn_failure_never_persists_running() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("image");
    make_executable(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'firmadyne-probe-ok\\n'; fi\nexit 0\n",
    );
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(created.status.success(), "{created:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env(
            "FAT_MANAGED_LINUX_VM_SUPERVISOR_EXECUTABLE",
            "/definitely/missing/fat",
        )
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(!output.status.success(), "{output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&output.stdout));
    let store = RuntimeStore::open(&project_dir).expect("store");
    let session = store
        .read_session(parsed.get("session").unwrap())
        .expect("session");
    let run = store
        .read_run(&session.session_id, session.run_ids.last().unwrap())
        .expect("run");
    assert_eq!(session.status, fat_core::sessions::SessionStatus::Degraded);
    assert_eq!(run.status, fat_core::runs::RunStatus::Failed);
}

#[test]
fn firmadyne_promotes_to_running_only_with_a_durable_supervisor_pid() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("image");
    make_executable(
        bundle_dir.path().join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'firmadyne-probe-ok\\n'; exit 0; fi\nif [ \"$1\" = \"--stop\" ]; then exit 0; fi\nexit 0\n",
    );
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(created.status.success(), "{created:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS", "10")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS", "1")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(output.status.success(), "{output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("store");
    let run = store.read_run(session_id, run_id).expect("run");
    assert_eq!(run.status, fat_core::runs::RunStatus::Running);
    assert!(run.supervisor_pid.is_some());

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("stop");
    assert!(stop.status.success(), "{stop:?}");
}

#[test]
fn firmadyne_supervisor_identity_is_persisted_before_running_promotion() {
    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/emulate_cmd.rs"),
    )
    .expect("emulate source");
    let managed_launch = source
        .split_once("fn prepare_managed_linux_vm_session(")
        .expect("managed launch function")
        .1
        .split_once("fn stop_managed_linux_vm_session(")
        .expect("managed stop boundary")
        .0;
    let pre_running_write = managed_launch
        .find("persist_managed_pre_supervisor_state(")
        .expect("durable pre-supervisor state");
    let spawn = managed_launch
        .find("spawn_managed_linux_vm_supervisor(")
        .expect("supervisor spawn");
    let running_promotion = managed_launch
        .find("persist_managed_supervised_running_state(")
        .expect("durable running promotion");

    assert!(
        pre_running_write < spawn,
        "pre-running state must precede spawn"
    );
    assert!(
        spawn < running_promotion,
        "Running must not be persisted before supervisor identity"
    );
    let supervisor = source
        .split_once("pub fn run_managed_supervisor(")
        .expect("managed supervisor")
        .1
        .split_once("fn refresh_managed_linux_vm_status(")
        .expect("managed supervisor boundary")
        .0;
    let launching_wait = supervisor
        .find("view.run.status == fat_core::runs::RunStatus::Launching")
        .expect("Launching wait state");
    let running_requirement = supervisor
        .find("view.run.status != fat_core::runs::RunStatus::Running")
        .expect("Running probe requirement");
    assert!(
        launching_wait < running_requirement,
        "supervisor must wait through Launching instead of exiting"
    );
}

#[test]
fn firmadyne_supervisor_spawn_cleanup_failure_is_durable_and_retriable() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let guest_agent = bundle_dir.path().join("guest-agent");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("image");
    make_executable(
        guest_agent.clone(),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'firmadyne-probe-ok\\n'; exit 0; fi\nif [ \"$1\" = \"--stop\" ]; then printf 'cleanup failed\\n' >&2; exit 9; fi\nexit 0\n",
    );
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(created.status.success(), "{created:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env(
            "FAT_MANAGED_LINUX_VM_SUPERVISOR_EXECUTABLE",
            "/definitely/missing/fat",
        )
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(!output.status.success(), "{output:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("store");
    let diagnostics = store
        .read_run_diagnostics(session_id, run_id)
        .expect("diagnostics");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.class
                == fat_core::diagnostics::DiagnosticClass::CleanupFailed),
        "cleanup failure must be durable: {diagnostics:?}"
    );
    assert!(
        project_dir
            .join("work/runtime")
            .join(session_id)
            .join("managed-linux-vm/firmadyne/dev")
            .exists(),
        "failed cleanup identity must remain available for retry"
    );

    make_executable(
        guest_agent,
        "#!/bin/sh\nif [ \"$1\" = \"--stop\" ]; then printf 'invoked\\n' > \"$FAT_TEST_STOP_MARKER\"; exit 0; fi\nexit 0\n",
    );
    let stop_marker = firmware_dir.path().join("stop-invoked");
    let workspace = project_dir
        .join("work/runtime")
        .join(session_id)
        .join("managed-linux-vm/firmadyne/dev");
    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_STOP_MARKER", &stop_marker)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("stop retry");
    assert!(stop.status.success(), "{stop:?}");
    assert!(
        stop_marker.is_file(),
        "managed stop command was not invoked"
    );
    assert!(!workspace.exists(), "managed workspace was not removed");
    let completed_session = store.read_session(session_id).expect("completed session");
    let completed_run = store.read_run(session_id, run_id).expect("completed run");
    assert_eq!(
        completed_session.status,
        fat_core::sessions::SessionStatus::Completed
    );
    assert_eq!(completed_run.status, fat_core::runs::RunStatus::Completed);

    std::fs::remove_file(&stop_marker).expect("remove stop marker");
    let second_stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_STOP_MARKER", &stop_marker)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("idempotent second stop");
    assert!(second_stop.status.success(), "{second_stop:?}");
    assert!(
        !stop_marker.exists(),
        "completed second stop must not invoke cleanup again"
    );
}

#[test]
fn firmadyne_failed_stop_is_nonzero_retriable_and_then_idempotent() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let guest_agent = bundle_dir.path().join("guest-agent");
    let allow_stop = firmware_dir.path().join("allow-stop");
    let stop_calls = firmware_dir.path().join("stop-calls");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("image");
    make_executable(
        guest_agent,
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'firmadyne-probe-ok\\n'; exit 0; fi\nif [ \"$1\" = \"--stop\" ]; then printf 'stop\\n' >> \"$FAT_TEST_STOP_CALLS\"; if [ -f \"$FAT_TEST_ALLOW_STOP\" ]; then exit 0; fi; printf 'cleanup failed\\n' >&2; exit 9; fi\nexit 0\n",
    );
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().unwrap(),
            "--projects-dir",
            projects_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("new");
    assert!(created.status.success(), "{created:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals");
    let launch = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS", "10")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS", "1")
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--backend",
            "firmadyne",
        ])
        .output()
        .expect("emulate");
    assert!(launch.status.success(), "{launch:?}");
    let parsed = parse_keyed_output(&String::from_utf8_lossy(&launch.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("store");
    let workspace = project_dir
        .join("work/runtime")
        .join(session_id)
        .join("managed-linux-vm/firmadyne/dev");

    let failed_stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("failed stop");
    assert!(
        !failed_stop.status.success(),
        "failed managed stop must return nonzero: {failed_stop:?}"
    );
    assert!(
        workspace.is_dir(),
        "failed stop must preserve retry identity"
    );
    assert_eq!(
        store
            .read_run(session_id, run_id)
            .expect("degraded run")
            .status,
        fat_core::runs::RunStatus::DegradedRunning
    );

    std::fs::write(&allow_stop, b"allow").expect("allow stop");
    let retry = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("stop retry");
    assert!(retry.status.success(), "{retry:?}");
    assert!(
        !workspace.exists(),
        "successful retry must remove workspace"
    );
    assert_eq!(
        store
            .read_run(session_id, run_id)
            .expect("completed run")
            .status,
        fat_core::runs::RunStatus::Completed
    );

    let idempotent_stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_TEST_ALLOW_STOP", &allow_stop)
        .env("FAT_TEST_STOP_CALLS", &stop_calls)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("idempotent stop");
    assert!(idempotent_stop.status.success(), "{idempotent_stop:?}");
    assert_eq!(
        std::fs::read_to_string(&stop_calls).expect("stop calls"),
        "stop\nstop\n",
        "idempotent stop must not invoke cleanup again"
    );
}

#[test]
fn fat_doctor_reports_native_firmae_recipe_checks_when_configured() {
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let helper_python = path_dir.path().join("firmae-host-python");
    let native_arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    };

    make_executable(
        path_dir.path().join("docker"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf '{native_arch}\\n'; exit 0; fi\nexit 1\n"
        ),
    );
    make_executable(helper_python.clone(), "#!/bin/sh\nexit 0\n");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_HOST_PYTHON", &helper_python)
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FirmAE [firmae]: available"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "firmae recipe docker-server-arch: pass ({native_arch} (native))"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("firmae recipe upstream-checkout: pass"),
        "{stdout}"
    );
    assert!(
        stdout.contains("firmae recipe host-helper-python: pass"),
        "{stdout}"
    );
    assert!(
        stdout.contains("firmae recipe docker-psql-ip: pass (host.docker.internal)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("firmae recipe upstream-brand: pass (example-brand)"),
        "{stdout}"
    );
}

/// The brand is required for the upstream launch, so doctor has to be able to
/// see it missing. Before this check existed, an operator with a complete
/// checkout and host python got a green recipe from doctor and an
/// upstream-recipe failure at BackendProvisioning — and that failure's own
/// remediation told them to run doctor.
#[test]
fn fat_doctor_reports_a_missing_firmae_upstream_brand() {
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let helper_python = path_dir.path().join("firmae-host-python");

    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(helper_python.clone(), "#!/bin/sh\nexit 0\n");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_HOST_PYTHON", &helper_python)
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .env_remove("FAT_FIRMAE_UPSTREAM_BRAND")
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("firmae recipe upstream-brand: fail (missing FAT_FIRMAE_UPSTREAM_BRAND)"),
        "{stdout}"
    );
}

#[test]
fn fat_doctor_distinguishes_installed_firmae_from_an_unreachable_docker_daemon() {
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let helper_python = path_dir.path().join("firmae-host-python");

    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nprintf 'Cannot connect to the Docker daemon at unix:///tmp/docker.sock\n' >&2\nexit 1\n",
    );
    make_executable(helper_python.clone(), "#!/bin/sh\nexit 0\n");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_HOST_PYTHON", &helper_python)
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FirmAE [firmae]: unavailable")
            && stdout.contains("Cannot connect to the Docker daemon"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Docker Native [docker-native]: unavailable")
            && stdout.contains("docker daemon is not reachable"),
        "{stdout}"
    );
    assert!(
        stdout.contains("firmae recipe docker-server-arch: fail")
            && stdout.contains("Cannot connect to the Docker daemon"),
        "{stdout}"
    );
}

#[test]
fn fat_cli_uses_upstream_firmae_launch_when_native_recipe_is_configured() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    let system_path = std::env::var("PATH").expect("system path");
    let tool_path = format!("{}:{system_path}", path_dir.path().display());

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then printf 'true\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(path_dir.path().join("ping"), "#!/bin/sh\nexit 0\n");
    make_executable(
        path_dir.path().join("nc"),
        "#!/bin/sh\nif [ \"$4\" = \"80\" ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(
        host_python_dir.path().join("python"),
        "#!/bin/sh\nprintf 'upstream launch ok\\n'\nprintf 'container:firmae-upstream-demo\\n'\nprintf 'argv:\\n%s\\n%s\\n%s\\n%s\\n' \"$0\" \"$1\" \"$2\" \"$3\"\nprintf 'artifact:scratch/1/qemu.initial.serial.log\\n'\nprintf 'artifact:scratch/1/qemu.final.serial.log\\n'\nprintf 'artifact:scratch/1/makeNetwork.log\\n'\nprintf 'artifact:scratch/1/upstream-argv.log\\n'\nmkdir -p \"$PWD/scratch/1\"\nprintf 'serial-one\\nguest-ip:192.168.0.1\\n' > \"$PWD/scratch/1/qemu.initial.serial.log\"\nprintf 'serial-two\\n' > \"$PWD/scratch/1/qemu.final.serial.log\"\nprintf 'network-one\\n' > \"$PWD/scratch/1/makeNetwork.log\"\nprintf '%s\\n%s\\n%s\\n%s\\n' \"$0\" \"$1\" \"$2\" \"$3\" > \"$PWD/scratch/1/upstream-argv.log\"\nexit 0\n",
    );

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &tool_path)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS", "50")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS", "200")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--port",
            "8080",
            "--session-id",
            "upstream-launch-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");

    assert!(stdout.contains("managed runtime outcome: booted-services-unreachable"));
    assert_eq!(parsed.get("backend").map(String::as_str), Some("firmae"));
    assert_eq!(
        parsed.get("substrate").map(String::as_str),
        Some("managed-linux-vm")
    );

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(outputs_dir
        .join("firmae-upstream-launch-stdout.log")
        .exists());
    assert!(outputs_dir
        .join("firmae-upstream-launch-stderr.log")
        .exists());
    assert!(outputs_dir
        .join("firmae-upstream-launch-command.log")
        .exists());
    assert!(outputs_dir
        .join("firmae-upstream-upstream-argv.log")
        .exists());
    assert!(outputs_dir
        .join("firmae-upstream-initial-serial.log")
        .exists());
    assert!(outputs_dir
        .join("firmae-upstream-final-serial.log")
        .exists());
    assert!(outputs_dir.join("firmae-upstream-network-log.log").exists());
    assert!(outputs_dir
        .join("firmae-upstream-observation.json")
        .exists());
    assert!(outputs_dir.join("managed-runtime-status.json").exists());
    assert!(outputs_dir.join("managed-runtime-summary.json").exists());

    let runtime_status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outputs_dir.join("managed-runtime-status.json")).expect("runtime status"),
    )
    .expect("runtime status json");
    assert_eq!(
        runtime_status.get("phase").and_then(|value| value.as_str()),
        Some("probe-unreachable")
    );
    assert_eq!(
        runtime_status
            .get("probe_outcome")
            .and_then(|value| value.as_str()),
        Some("unreachable")
    );

    let runtime_summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outputs_dir.join("managed-runtime-summary.json")).expect("runtime summary"),
    )
    .expect("runtime summary json");
    assert_eq!(
        runtime_summary
            .get("runtime_phase")
            .and_then(|value| value.as_str()),
        Some("probe-unreachable")
    );

    let command_log =
        std::fs::read_to_string(outputs_dir.join("firmae-upstream-launch-command.log"))
            .expect("command log");
    assert!(command_log.contains("docker-helper.py -ec example-brand"));
    assert!(
        command_log.contains("brand-source: FAT_FIRMAE_UPSTREAM_BRAND"),
        "the launch artifact must record where the brand came from: {command_log}"
    );

    let argv_log = std::fs::read_to_string(outputs_dir.join("firmae-upstream-upstream-argv.log"))
        .expect("argv log");
    assert!(argv_log.contains("docker-helper.py"));
    assert!(argv_log.contains("-ec"));
    assert!(argv_log.contains("example-brand"));
}

#[test]
fn fat_cli_fails_firmae_launch_when_upstream_recipe_is_missing() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env_remove("FAT_FIRMAE_UPSTREAM_DIR")
        .env_remove("FAT_FIRMAE_HOST_PYTHON")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--session-id",
            "upstream-missing-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    assert_eq!(parsed.get("run status").map(String::as_str), Some("failed"));
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let diagnostics = store
        .read_run_diagnostics(session_id, run_id)
        .expect("run diagnostics");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.subclass.as_deref() == Some("firmae-upstream-recipe-unavailable")
    }));

    let target_id = derive_target_id("demo", "demo.bin");
    let repairs = read_single_json_record::<RepairRecord>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("repairs"),
    );
    assert_eq!(repairs.project_id, "demo");
    assert_eq!(repairs.target_id, target_id);
    assert_eq!(repairs.session_id, session_id.as_str());
    assert_eq!(repairs.run_id, run_id.as_str());
    assert_eq!(repairs.failure_class, FailureClass::TargetLaunch);
    assert_eq!(repairs.action, RepairActionKind::RetryPlan);

    let attempts_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("rehosting")
        .join("attempts");
    let attempt_count = std::fs::read_dir(&attempts_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", attempts_dir.display()))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .count();
    assert_eq!(attempt_count, 1);
}

#[test]
fn fat_cli_records_upstream_firmae_observation_after_launch() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    make_executable(
        host_python_dir.path().join("python"),
        "#!/bin/sh\nprintf 'upstream launch ok\\n'\nprintf 'container:firmae-upstream-1\\n'\nprintf 'artifact:scratch/1/qemu.initial.serial.log\\n'\nprintf 'artifact:scratch/1/qemu.final.serial.log\\n'\nprintf 'artifact:scratch/1/makeNetwork.log\\n'\n/bin/mkdir -p \"$PWD/scratch/1\"\nprintf 'serial-one\\n' > \"$PWD/scratch/1/qemu.initial.serial.log\"\nprintf 'serial-two\\n' > \"$PWD/scratch/1/qemu.final.serial.log\"\nprintf 'guest-ip:192.168.0.1\\n' > \"$PWD/scratch/1/makeNetwork.log\"\nexit 0\n",
    );
    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = inspect ] && [ \"$2\" = -f ] && [ \"$3\" = '{{.State.Running}}' ] && [ \"$4\" = 'firmae-upstream-1' ]; then printf 'true\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(
        path_dir.path().join("ping"),
        "#!/bin/sh\nif [ \"$5\" = '192.168.0.1' ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(path_dir.path().join("nc"), "#!/bin/sh\nexit 1\n");

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_value = format!(
        "{}:{}",
        path_dir.path().display(),
        std::env::var("PATH").expect("PATH available")
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS", "50")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS", "200")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--port",
            "8080",
            "--session-id",
            "upstream-observation-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");

    assert!(stdout.contains("managed runtime phase: probe-unreachable"));
    assert!(stdout.contains("managed runtime outcome: booted-services-unreachable"));

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    let observation_path = outputs_dir.join("firmae-upstream-observation.json");
    assert!(observation_path.exists());
    assert!(outputs_dir.join("managed-runtime-status.json").exists());
    assert!(outputs_dir.join("managed-runtime-summary.json").exists());

    let observation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&observation_path).expect("observation"))
            .expect("observation json");
    assert_eq!(
        observation
            .get("container_name")
            .and_then(|value| value.as_str()),
        Some("firmae-upstream-1")
    );
    assert_eq!(
        observation
            .get("container_running")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        observation
            .get("guest_reachable")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        observation
            .get("port_80_reachable")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        observation
            .get("port_31337_reachable")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        observation
            .get("port_31338_reachable")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let runtime_status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outputs_dir.join("managed-runtime-status.json")).expect("runtime status"),
    )
    .expect("runtime status json");
    assert_eq!(
        runtime_status.get("phase").and_then(|value| value.as_str()),
        Some("probe-unreachable")
    );
    assert_eq!(
        runtime_status
            .get("runtime_outcome")
            .and_then(|value| value.as_str()),
        Some("booted-services-unreachable")
    );

    let runtime_summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outputs_dir.join("managed-runtime-summary.json")).expect("runtime summary"),
    )
    .expect("runtime summary json");
    assert_eq!(
        runtime_summary
            .get("runtime_phase")
            .and_then(|value| value.as_str()),
        Some("probe-unreachable")
    );
    assert_eq!(
        runtime_summary
            .get("runtime_outcome")
            .and_then(|value| value.as_str()),
        Some("booted-services-unreachable")
    );
}

#[test]
fn fat_cli_rejects_exit_zero_firmae_launch_without_a_running_container() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(upstream_dir.path().join("database/schema"), b"-- schema\n").expect("schema");
    std::fs::write(
        upstream_dir.path().join("core/Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    make_executable(
        host_python_dir.path().join("python"),
        "#!/bin/sh\nprintf 'container failed to connect\n' >&2\nexit 0\n",
    );
    make_executable(path_dir.path().join("docker"), "#!/bin/sh\nexit 1\n");

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");
    let path_value = format!(
        "{}:{}",
        path_dir.path().display(),
        std::env::var("PATH").expect("PATH available")
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--session-id",
            "upstream-no-container-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(
        !emulate_output.status.success(),
        "an unobserved runtime must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&emulate_output.stdout),
        String::from_utf8_lossy(&emulate_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    assert!(stdout.contains("run status: failed"), "{stdout}");
    assert!(!stdout.contains("run status: running"), "{stdout}");

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            "upstream-no-container-1",
            "--stop",
        ])
        .output()
        .expect("fat emulate --stop runs");
    assert!(
        stop_output.status.success(),
        "stopping an already failed absent runtime must be idempotent: {stop_output:?}"
    );
}

#[test]
fn fat_cli_exposes_upstream_firmae_observation_surfaces_after_launch() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    make_executable(
        host_python_dir.path().join("python"),
        "#!/bin/sh\nprintf 'upstream launch ok\\n'\nprintf 'container:firmae-upstream-2\\n'\nprintf 'artifact:scratch/2/qemu.initial.serial.log\\n'\nprintf 'artifact:scratch/2/qemu.final.serial.log\\n'\nprintf 'artifact:scratch/2/makeNetwork.log\\n'\n/bin/mkdir -p \"$PWD/scratch/2\"\nprintf 'serial-one\\n' > \"$PWD/scratch/2/qemu.initial.serial.log\"\nprintf 'serial-two\\n' > \"$PWD/scratch/2/qemu.final.serial.log\"\nprintf 'guest-ip:192.168.0.1\\n' > \"$PWD/scratch/2/makeNetwork.log\"\nexit 0\n",
    );
    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = inspect ] && [ \"$2\" = -f ] && [ \"$3\" = '{{.State.Running}}' ] && [ \"$4\" = 'firmae-upstream-2' ]; then printf 'true\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(
        path_dir.path().join("ping"),
        "#!/bin/sh\nif [ \"$5\" = '192.168.0.1' ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(
        path_dir.path().join("nc"),
        "#!/bin/sh\nif [ \"$4\" = '192.168.0.1' ] && [ \"$5\" = '80' ]; then exit 0; fi\nexit 1\n",
    );

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_value = format!(
        "{}:{}",
        path_dir.path().display(),
        std::env::var("PATH").expect("PATH available")
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_INTERVAL_MS", "50")
        .env("FAT_MANAGED_LINUX_VM_SUPERVISOR_MAX_TICKS", "200")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--port",
            "8080",
            "--session-id",
            "upstream-surface-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id");

    assert_eq!(
        parsed.get("active endpoints").map(String::as_str),
        Some("2")
    );
    assert!(
        stdout.contains("health state: booted-services-reachable"),
        "{stdout}"
    );
    assert!(
        stdout.contains("managed runtime outcome: booted-services-reachable"),
        "{stdout}"
    );
    assert!(
        stdout.contains("endpoint port-80: http://192.168.0.1:80"),
        "{stdout}"
    );
    assert!(
        stdout.contains("endpoint port-8080: 127.0.0.1:8080"),
        "{stdout}"
    );

    let debug_surfaces_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .args([
            "debug",
            "surfaces",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
        ])
        .output()
        .expect("fat debug surfaces runs");

    assert!(
        debug_surfaces_output.status.success(),
        "{debug_surfaces_output:?}"
    );
    let debug_surfaces_stdout = String::from_utf8_lossy(&debug_surfaces_output.stdout);
    assert!(
        debug_surfaces_stdout.contains("surface count: 2"),
        "{debug_surfaces_stdout}"
    );
    assert!(
        debug_surfaces_stdout
            .contains("surface port-80 [service] state=validated: http://192.168.0.1:80"),
        "{debug_surfaces_stdout}"
    );
    assert!(
        debug_surfaces_stdout
            .contains("surface port-8080 [forwarded-port] state=validated: 127.0.0.1:8080"),
        "{debug_surfaces_stdout}"
    );
}

#[test]
fn fat_cli_routes_firmae_stop_through_upstream_control() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    make_executable(
        host_python_dir.path().join("python"),
        "#!/bin/sh\nprintf 'upstream launch ok\\n'\nprintf 'container:firmae-upstream-stop-1\\n'\nprintf 'artifact:scratch/1/qemu.initial.serial.log\\n'\nprintf 'artifact:scratch/1/qemu.final.serial.log\\n'\nprintf 'artifact:scratch/1/makeNetwork.log\\n'\n/bin/mkdir -p \"$PWD/scratch/1\"\nprintf 'serial-one\\n' > \"$PWD/scratch/1/qemu.initial.serial.log\"\nprintf 'serial-two\\n' > \"$PWD/scratch/1/qemu.final.serial.log\"\nprintf 'guest-ip:192.168.0.1\\n' > \"$PWD/scratch/1/makeNetwork.log\"\nexit 0\n",
    );
    make_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = inspect ] && [ \"$2\" = -f ] && [ \"$3\" = '{{.State.Running}}' ] && [ \"$4\" = 'firmae-upstream-stop-1' ]; then printf 'true\\n'; exit 0; fi\nif [ \"$1\" = stop ] && [ \"$2\" = 'firmae-upstream-stop-1' ]; then printf 'firmae-upstream-stop-1\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(
        path_dir.path().join("ping"),
        "#!/bin/sh\nif [ \"$5\" = '192.168.0.1' ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(path_dir.path().join("nc"), "#!/bin/sh\nexit 1\n");

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_value = format!(
        "{}:{}",
        path_dir.path().display(),
        std::env::var("PATH").expect("PATH available")
    );
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--session-id",
            "upstream-stop-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let emulate_stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&emulate_stdout);
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let mut failed_run = store.read_run(session_id, run_id).expect("run");
    failed_run.status = fat_core::runs::RunStatus::Failed;
    store.write_run(&failed_run).expect("failed run state");

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_BRAND", "example-brand")
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("fat emulate --stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");
    let stop_stdout = String::from_utf8_lossy(&stop_output.stdout);
    assert!(
        stop_stdout.contains("run status: completed"),
        "{stop_stdout}"
    );

    let second_stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path_value)
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().unwrap(),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("second stop");
    assert!(second_stop.status.success(), "{second_stop:?}");

    let outputs_dir = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(outputs_dir
        .join("firmae-upstream-stop-command.log")
        .exists());
    assert!(outputs_dir.join("firmae-upstream-stop-stdout.log").exists());
    assert!(outputs_dir.join("firmae-upstream-stop-stderr.log").exists());

    let stop_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(outputs_dir.join("managed-linux-vm-stop-state.json")).expect("stop state"),
    )
    .expect("stop state json");
    assert_eq!(
        stop_state
            .get("result_contract")
            .and_then(|value| value.as_str()),
        Some("firmae-upstream-container-stop-v1")
    );
    assert_eq!(
        stop_state
            .get("result_contract_verified")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        stop_state
            .get("workspace_removed")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}

/// FAT used to pass a single hard-coded vendor brand to upstream FirmAE for
/// every firmware, and persisted that invented value as run evidence. The
/// brand is now an explicit operator input: absent or malformed, the launch
/// fails before any container is created.
#[test]
fn fat_cli_fails_firmae_launch_when_the_upstream_brand_is_not_supplied() {
    assert_brand_input_rejected(None, "upstream-brand-missing-1");
}

#[test]
fn fat_cli_fails_firmae_launch_when_the_upstream_brand_is_malformed() {
    assert_brand_input_rejected(Some("--exec"), "upstream-brand-malformed-1");
}

/// Runs a firmae launch whose only defect is the brand input, and proves the
/// run failed with the upstream-recipe diagnostic and produced no launch
/// artifacts — the failure must precede the side effect, not follow it.
fn assert_brand_input_rejected(brand: Option<&str>, session_id: &str) {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    let host_python_dir = tempdir().expect("host python dir");
    let firmware_path = firmware_dir.path().join("demo.bin");

    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    make_executable(host_python_dir.path().join("python"), "#!/bin/sh\nexit 0\n");

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
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            host_python_dir.path().join("python"),
        );
    match brand {
        Some(value) => command.env("FAT_FIRMAE_UPSTREAM_BRAND", value),
        None => command.env_remove("FAT_FIRMAE_UPSTREAM_BRAND"),
    };
    let emulate_output = command
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "firmae",
            "--session-id",
            session_id,
        ])
        .output()
        .expect("fat emulate runs");

    assert!(!emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&stdout);
    assert_eq!(parsed.get("run status").map(String::as_str), Some("failed"));

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let resolved_session = parsed.get("session").expect("session id");
    let resolved_run = parsed.get("run").expect("run id");
    let diagnostics = store
        .read_run_diagnostics(resolved_session, resolved_run)
        .expect("run diagnostics");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.subclass.as_deref() == Some("firmae-upstream-recipe-unavailable")
        }),
        "{diagnostics:?}"
    );

    let outputs_dir = store
        .run_path(resolved_session, resolved_run)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(
        !outputs_dir
            .join("firmae-upstream-launch-command.log")
            .exists(),
        "the upstream launch must not run before the brand input is validated"
    );

    // No brand may be invented from firmware evidence when the input is absent.
    assert!(
        !stdout.contains("tp-link"),
        "a vendor brand must never be defaulted: {stdout}"
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

fn make_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}
