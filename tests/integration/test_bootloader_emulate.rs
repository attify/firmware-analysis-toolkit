use fat_bootloader::bootplan::BootExecutionResult;
use fat_bootloader::{materialize_workspace, prepare_launch, stop_tmux_session};
use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tempfile::{tempdir, TempDir};

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write test file");
}

/// Owns a materialized bootloader project for the lifetime of one test.
///
/// `fat bootloader emulate` starts QEMU inside a *detached* tmux session that
/// deliberately outlives the process that launched it, so dropping only the
/// tempdir would leave the session and its fake-QEMU child running on the
/// developer's machine. Teardown lives in `Drop` so it also runs while a
/// failing test unwinds, and it stops the session before the tempdir the
/// session was launched from is removed.
struct BootloaderProject {
    project_dir: PathBuf,
    _tempdir: TempDir,
}

impl Deref for BootloaderProject {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.project_dir
    }
}

impl AsRef<Path> for BootloaderProject {
    fn as_ref(&self) -> &Path {
        &self.project_dir
    }
}

impl Drop for BootloaderProject {
    fn drop(&mut self) {
        // Cleanup must never mask the assertion that failed, so this does not
        // panic — but staying silent would hide a live session and the fixture
        // it holds open, so a failure is reported.
        if let Err(error) = stop_tmux_session(&self.project_dir) {
            eprintln!(
                "warning: failed to stop the bootloader session for {}: {error}",
                self.project_dir.display()
            );
        }
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn prepared_bootloader_project() -> BootloaderProject {
    let tempdir = tempdir().expect("tempdir");
    let project_dir = tempdir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2024.01".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "sig_check".into(),
                value: "yes".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );

    materialize_workspace(&project_dir, "consumer-iot-camera").expect("materialize workspace");
    BootloaderProject {
        project_dir,
        _tempdir: tempdir,
    }
}

fn prepared_true_mode_bootloader_project() -> BootloaderProject {
    let tempdir = tempdir().expect("tempdir");
    let project_dir = tempdir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2019.07 ARM".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "sig_check".into(),
                value: "yes".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("u-boot.bin"),
        b"U-Boot 2019.07\0ARM\0bootdelay=3\0",
    );
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );

    materialize_workspace(&project_dir, "consumer-iot-camera").expect("materialize workspace");
    BootloaderProject {
        project_dir,
        _tempdir: tempdir,
    }
}

#[test]
fn bootloader_emulate_writes_launch_metadata() {
    let project = prepared_bootloader_project();
    prepare_launch(&project).unwrap();

    let launch = std::fs::read_to_string(project.join("bootloader/qemu/launch.json")).unwrap();
    assert!(launch.contains("qemu-system"));
    assert!(launch.contains("u-boot"));
    assert!(launch.contains("tmux_session"));
    assert!(launch.contains("attach_command"));
    assert!(launch.contains("mon:stdio"));
    assert!(launch.contains("loader,file="));
    assert!(launch.contains("rootfs.img"));
}

#[test]
fn bootloader_emulate_uses_unique_tmux_sessions_per_project_path() {
    let project_a = prepared_bootloader_project();
    let project_b = prepared_bootloader_project();

    let launch_a = prepare_launch(&project_a).unwrap();
    let launch_b = prepare_launch(&project_b).unwrap();

    assert_ne!(launch_a.project_dir, launch_b.project_dir);
    assert_ne!(launch_a.tmux_session, launch_b.tmux_session);
}

#[test]
fn bootloader_emulate_stabilizes_tmux_session_across_canonical_project_paths() {
    let project = prepared_true_mode_bootloader_project();
    let canonical_project = std::fs::canonicalize(&project).expect("canonical project");

    let launch_raw = prepare_launch(&project).expect("prepare launch from raw path");
    let launch_canonical =
        prepare_launch(&canonical_project).expect("prepare launch from canonical path");

    assert_eq!(launch_raw.tmux_session, launch_canonical.tmux_session);
}

#[test]
fn bootloader_emulate_restarts_stale_tmux_sessions() {
    let project = prepared_bootloader_project();
    let launch = prepare_launch(&project).unwrap();
    let fake_dir = tempdir().expect("fake runtime dir");
    let fake_qemu = fake_dir.path().join("qemu-system-arm");
    let fake_uboot = fake_dir.path().join("u-boot.bin");
    write_file(&fake_qemu, b"#!/bin/sh\nsleep 30\n");
    write_file(&fake_uboot, b"U-Boot test asset\n");
    let mut perms = std::fs::metadata(&fake_qemu)
        .expect("fake qemu metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_qemu, perms).expect("chmod fake qemu");

    let _ = Command::new("tmux")
        .args(["kill-session", "-t", &launch.tmux_session])
        .status();
    Command::new("tmux")
        .args(["new-session", "-d", "-s", &launch.tmux_session, "cat"])
        .status()
        .expect("create stale tmux session");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
        ])
        .env("FAT_BOOTLOADER_UBOOT_ASSET", &fake_uboot)
        .env("FAT_BOOTLOADER_QEMU_BINARY", &fake_qemu)
        .output()
        .expect("relaunch bootloader session");
    assert!(output.status.success(), "{output:?}");
    let pane_command = Command::new("tmux")
        .args([
            "display-message",
            "-p",
            "-t",
            &launch.tmux_session,
            "#{pane_start_command}",
        ])
        .output()
        .expect("inspect tmux pane");

    let pane_command = String::from_utf8_lossy(&pane_command.stdout);
    let expected_qemu = fake_qemu
        .file_name()
        .and_then(|name| name.to_str())
        .expect("selected QEMU binary name");
    assert!(
        pane_command.contains(expected_qemu),
        "restarted tmux pane should run {expected_qemu}, got {pane_command:?}"
    );
}

#[test]
fn bootloader_emulate_reuses_a_healthy_tmux_session() {
    let project = prepared_bootloader_project();
    let fake_dir = tempdir().expect("fake runtime dir");
    let quoted_dir = fake_dir.path().join("quoted\"runtime");
    let fake_qemu = quoted_dir.join("qemu-system-arm");
    let fake_uboot = quoted_dir.join("u-boot.bin");
    write_file(&fake_qemu, b"#!/bin/sh\nsleep 30\n");
    write_file(&fake_uboot, b"U-Boot test asset\n");
    let mut perms = std::fs::metadata(&fake_qemu)
        .expect("fake qemu metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_qemu, perms).expect("chmod fake qemu");

    let launch = prepare_launch(&project).expect("prepare launch identity");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_fat"))
            .args([
                "bootloader",
                "emulate",
                project.to_str().expect("project path"),
            ])
            .env("FAT_BOOTLOADER_UBOOT_ASSET", &fake_uboot)
            .env("FAT_BOOTLOADER_QEMU_BINARY", &fake_qemu)
            .output()
            .expect("run bootloader emulate")
    };
    let pane_pid = || {
        let output = Command::new("tmux")
            .args([
                "display-message",
                "-p",
                "-t",
                &launch.tmux_session,
                "#{pane_pid}",
            ])
            .output()
            .expect("inspect tmux pane pid");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };

    let first = run();
    assert!(first.status.success(), "{first:?}");
    let first_pid = pane_pid();
    let second = run();
    assert!(second.status.success(), "{second:?}");
    let second_pid = pane_pid();
    assert_eq!(
        second_pid, first_pid,
        "a healthy tmux session must be reused rather than restarted"
    );
}

/// Build a fake QEMU that stays alive, so the launched tmux session is a real
/// long-running session that `stop` has to terminate rather than one that has
/// already exited on its own.
fn long_running_fake_qemu(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let fake_qemu = dir.join("qemu-system-arm");
    let fake_uboot = dir.join("u-boot.bin");
    write_file(&fake_qemu, b"#!/bin/sh\nsleep 300\n");
    write_file(&fake_uboot, b"U-Boot test asset\n");
    let mut perms = std::fs::metadata(&fake_qemu)
        .expect("fake qemu metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_qemu, perms).expect("chmod fake qemu");
    (fake_qemu, fake_uboot)
}

fn tmux_session_is_live(session: &str) -> bool {
    Command::new("tmux")
        .args(["has-session", "-t", session])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn tmux_sessions_with_prefix(prefix: &str) -> Vec<String> {
    let Ok(output) = Command::new("tmux")
        .args(["list-sessions", "-F", "#{session_name}"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with(prefix))
        .map(str::to_string)
        .collect()
}

/// Kills a bare tmux session on drop, so a decoy outlives neither the test nor
/// a failure part-way through it.
struct TmuxSessionGuard(String);

impl Drop for TmuxSessionGuard {
    fn drop(&mut self) {
        let _ = Command::new("tmux")
            .args(["kill-session", "-t", &self.0])
            .status();
    }
}

/// Kills every session under a test-owned prefix on drop. The sweep tests run
/// their sessions under a private prefix, which the project guards (which use
/// the default prefix) would not clean up.
struct TmuxPrefixGuard(String);

impl Drop for TmuxPrefixGuard {
    fn drop(&mut self) {
        for session in tmux_sessions_with_prefix(&self.0) {
            let _ = Command::new("tmux")
                .args(["kill-session", "-t", &session])
                .status();
        }
    }
}

/// A prefix private to this test process. `stop --all` is host-wide by design,
/// so a test must namespace its sessions or it would reap the sessions of any
/// test running concurrently in another binary.
fn private_session_prefix(tag: &str) -> String {
    format!("fat-{tag}-{}-", std::process::id())
}

#[test]
fn bootloader_stop_terminates_a_running_session() {
    let project = prepared_bootloader_project();
    let fake_dir = tempdir().expect("fake runtime dir");
    let (fake_qemu, fake_uboot) = long_running_fake_qemu(fake_dir.path());
    let launch = prepare_launch(&project).expect("prepare launch identity");

    let emulate = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
        ])
        .env("FAT_BOOTLOADER_UBOOT_ASSET", &fake_uboot)
        .env("FAT_BOOTLOADER_QEMU_BINARY", &fake_qemu)
        .output()
        .expect("launch bootloader session");
    assert!(emulate.status.success(), "{emulate:?}");
    assert!(
        tmux_session_is_live(&launch.tmux_session),
        "expected a live tmux session before stopping"
    );

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "stop",
            project.to_str().expect("project path"),
        ])
        .output()
        .expect("stop bootloader session");

    assert!(stop.status.success(), "{stop:?}");
    let stdout = String::from_utf8_lossy(&stop.stdout);
    assert!(stdout.contains("stopped: true"), "{stdout}");
    assert!(stdout.contains(&launch.tmux_session), "{stdout}");
    assert!(
        !tmux_session_is_live(&launch.tmux_session),
        "tmux session {} should be gone after stop",
        launch.tmux_session
    );

    let recorded = std::fs::read_to_string(project.join("bootloader/qemu/launch.json"))
        .expect("read launch record");
    assert!(
        recorded.contains("\"launched\": false"),
        "stop should clear the launched flag:\n{recorded}"
    );
}

#[test]
fn bootloader_stop_all_sweeps_managed_sessions_and_spares_others() {
    let prefix = private_session_prefix("sweep");
    let _prefix_guard = TmuxPrefixGuard(prefix.clone());
    let project_a = prepared_bootloader_project();
    let project_b = prepared_bootloader_project();
    let fake_dir = tempdir().expect("fake runtime dir");
    let (fake_qemu, fake_uboot) = long_running_fake_qemu(fake_dir.path());

    // A session that is not FAT-managed. The sweep must leave it alone.
    let decoy = format!("sweep-decoy-{}", std::process::id());
    Command::new("tmux")
        .args(["new-session", "-d", "-s", &decoy, "cat"])
        .status()
        .expect("create decoy session");
    let _decoy_guard = TmuxSessionGuard(decoy.clone());

    for project in [&project_a, &project_b] {
        let emulate = Command::new(env!("CARGO_BIN_EXE_fat"))
            .args([
                "bootloader",
                "emulate",
                project.to_str().expect("project path"),
            ])
            .env("FAT_BOOTLOADER_UBOOT_ASSET", &fake_uboot)
            .env("FAT_BOOTLOADER_QEMU_BINARY", &fake_qemu)
            .env("FAT_BOOTLOADER_TMUX_PREFIX", &prefix)
            .output()
            .expect("launch bootloader session");
        assert!(emulate.status.success(), "{emulate:?}");
    }
    assert_eq!(
        tmux_sessions_with_prefix(&prefix).len(),
        2,
        "expected two managed sessions before the sweep"
    );

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bootloader", "stop", "--all"])
        .env("FAT_BOOTLOADER_TMUX_PREFIX", &prefix)
        .output()
        .expect("sweep bootloader sessions");

    assert!(stop.status.success(), "{stop:?}");
    let stdout = String::from_utf8_lossy(&stop.stdout);
    assert!(stdout.contains("stopped: 2"), "{stdout}");
    assert!(
        tmux_sessions_with_prefix(&prefix).is_empty(),
        "sweep should stop every managed session"
    );
    assert!(
        tmux_session_is_live(&decoy),
        "sweep must not touch sessions outside the FAT prefix"
    );
}

#[test]
fn bootloader_stop_all_reports_when_nothing_is_running() {
    let prefix = private_session_prefix("sweep-empty");

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bootloader", "stop", "--all"])
        .env("FAT_BOOTLOADER_TMUX_PREFIX", &prefix)
        .output()
        .expect("sweep bootloader sessions");

    assert!(stop.status.success(), "{stop:?}");
    let stdout = String::from_utf8_lossy(&stop.stdout);
    assert!(stdout.contains("stopped: 0"), "{stdout}");
    assert!(
        stdout.contains("no FAT-managed bootloader sessions were running"),
        "{stdout}"
    );
}

#[test]
fn bootloader_stop_requires_a_project_or_all() {
    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["bootloader", "stop"])
        .output()
        .expect("run bootloader stop without arguments");

    assert!(!stop.status.success(), "{stop:?}");
    let stderr = String::from_utf8_lossy(&stop.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("Usage"),
        "{stderr}"
    );
}

#[test]
fn bootloader_stop_reports_when_no_session_is_running() {
    let project = prepared_bootloader_project();
    let launch = prepare_launch(&project).expect("prepare launch identity");
    let _ = Command::new("tmux")
        .args(["kill-session", "-t", &launch.tmux_session])
        .status();

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "stop",
            project.to_str().expect("project path"),
        ])
        .output()
        .expect("stop bootloader session");

    assert!(stop.status.success(), "{stop:?}");
    let stdout = String::from_utf8_lossy(&stop.stdout);
    assert!(stdout.contains("stopped: false"), "{stdout}");
    assert!(stdout.contains("no live bootloader session"), "{stdout}");
}

/// Launch a bootloader session for `project` using a fake long-running QEMU.
fn launch_bootloader_session(project: &Path, fake_qemu: &Path, fake_uboot: &Path) {
    let emulate = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
        ])
        .env("FAT_BOOTLOADER_UBOOT_ASSET", fake_uboot)
        .env("FAT_BOOTLOADER_QEMU_BINARY", fake_qemu)
        .output()
        .expect("launch bootloader session");
    assert!(emulate.status.success(), "{emulate:?}");
}

fn emulate_list(project: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--project"])
        .arg(project)
        .arg("--list")
        .output()
        .expect("fat emulate --list runs");
    assert!(
        output.status.success(),
        "expected success, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn emulate_list_shows_live_bootloader_sessions_and_drops_them_once_stopped() {
    let project = prepared_bootloader_project();
    let fake_dir = tempdir().expect("fake runtime dir");
    let (fake_qemu, fake_uboot) = long_running_fake_qemu(fake_dir.path());
    let launch = prepare_launch(&project).expect("prepare launch identity");

    launch_bootloader_session(&project, &fake_qemu, &fake_uboot);

    let listed = emulate_list(&project);
    assert!(listed.contains(&launch.tmux_session), "got:\n{listed}");
    assert!(listed.contains("bootloader-tmux"), "got:\n{listed}");
    assert!(listed.contains("live"), "got:\n{listed}");

    let stop = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "stop",
            project.to_str().expect("project path"),
        ])
        .output()
        .expect("stop bootloader session");
    assert!(stop.status.success(), "{stop:?}");

    // Stopping clears the launch record, so the row is gone rather than stale.
    let listed = emulate_list(&project);
    assert!(!listed.contains(&launch.tmux_session), "got:\n{listed}");
    assert!(listed.contains("no active emulations"), "got:\n{listed}");
}

#[test]
fn emulate_list_reports_a_bootloader_session_that_died_as_stale() {
    let project = prepared_bootloader_project();
    let fake_dir = tempdir().expect("fake runtime dir");
    let (fake_qemu, fake_uboot) = long_running_fake_qemu(fake_dir.path());
    let launch = prepare_launch(&project).expect("prepare launch identity");

    launch_bootloader_session(&project, &fake_qemu, &fake_uboot);
    // Kill the session behind FAT's back: the launch record still claims a
    // launched session, which is exactly the state a user needs to see.
    Command::new("tmux")
        .args(["kill-session", "-t", &launch.tmux_session])
        .status()
        .expect("kill session outside FAT");

    let listed = emulate_list(&project);
    assert!(listed.contains(&launch.tmux_session), "got:\n{listed}");
    assert!(listed.contains("stale"), "got:\n{listed}");
}

#[test]
fn bootloader_emulate_prefers_vendor_bootloader_binary_in_true_mode() {
    let project = prepared_true_mode_bootloader_project();
    prepare_launch(&project).unwrap();

    let launch = std::fs::read_to_string(project.join("bootloader/qemu/launch.json")).unwrap();
    assert!(launch.contains("storage/bootloader/u-boot.bin"));
    assert!(!launch.contains("bundled u-boot asset"));
}

#[test]
fn bootloader_emulate_rejects_incoherent_true_mode_root_mapping() {
    let project = prepared_true_mode_bootloader_project();
    let launch = prepare_launch(&project).unwrap();

    assert!(!launch.launchable);
    assert!(launch
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("root device"));
}

#[test]
fn bootloader_emulate_loads_dtb_artifact_when_present() {
    let project = prepared_true_mode_bootloader_project();
    write_file(
        &project.join("extracted").join("board.dtb"),
        &[
            0xd0, 0x0d, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x3c, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    materialize_workspace(&project, "consumer-iot-camera").expect("rematerialize workspace");

    let launch = prepare_launch(&project).expect("prepare launch");

    assert!(launch
        .qemu_args
        .iter()
        .any(|arg| arg.contains("loader,file=") && arg.contains("/dtb/")));
}

#[test]
fn bootloader_emulate_resolves_profile_qemu_binary_from_path() {
    let _guard = env_lock().lock().expect("env lock");
    let project = prepared_true_mode_bootloader_project();
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let fake_qemu = fake_bin_dir.path().join("qemu-system-arm");
    std::fs::write(&fake_qemu, b"#!/bin/sh\nexit 0\n").expect("write fake qemu");
    let mut perms = std::fs::metadata(&fake_qemu)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_qemu, perms).expect("chmod");

    let old_path = std::env::var_os("PATH");
    let mut new_path = fake_bin_dir.path().as_os_str().to_os_string();
    if let Some(old) = &old_path {
        new_path.push(":");
        new_path.push(old);
    }

    unsafe {
        std::env::set_var("PATH", &new_path);
    }

    let launch = prepare_launch(&project).expect("prepare launch");

    match old_path {
        Some(value) => unsafe { std::env::set_var("PATH", value) },
        None => unsafe { std::env::remove_var("PATH") },
    }

    assert_eq!(launch.qemu_binary, fake_qemu.display().to_string());
}

#[test]
fn bootloader_status_reports_launch_and_last_execution_result() {
    let project = prepared_true_mode_bootloader_project();
    let launch = prepare_launch(&project).expect("prepare launch");
    std::fs::create_dir_all(project.join("bootloader").join("qemu")).expect("qemu dir");
    std::fs::write(
        project
            .join("bootloader")
            .join("qemu")
            .join("execution-result.json"),
        serde_json::to_vec_pretty(&BootExecutionResult {
            stage: "kernel_handoff_attempted".into(),
            result: "unknown".into(),
            observed_output: vec!["Starting kernel ...".into()],
            error: None,
        })
        .expect("execution result"),
    )
    .expect("write execution result");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "bootloader",
            "status",
            project.to_str().expect("project path"),
        ])
        .output()
        .expect("bootloader status");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("launchable:"));
    assert!(
        stdout.contains(&launch.tmux_session),
        "expected tmux session `{}` in stdout:\n{}",
        launch.tmux_session,
        stdout
    );
    assert!(stdout.contains("attach:"));
    assert!(stdout.contains("last execution: kernel_handoff_attempted (unknown)"));
}
