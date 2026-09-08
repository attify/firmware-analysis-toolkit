use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::tempdir;

fn now_stamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    format!("unix-ms:{millis}")
}

fn write_session(project_dir: &Path, session_id: &str, updated_at: &str) {
    let session_dir = project_dir.join("sessions").join(session_id);
    fs::create_dir_all(session_dir.join("runs")).expect("create session dir");
    fs::write(
        session_dir.join("session.json"),
        format!(
            r#"{{
  "session_id": "{session_id}",
  "project_id": "proj-test",
  "target_id": "tgt-test",
  "goal": "gc check",
  "strategy_family": "manual",
  "status": "active",
  "progress": "partial",
  "run_ids": [],
  "created_at": "{updated_at}",
  "updated_at": "{updated_at}",
  "origin": "manual"
}}"#
        ),
    )
    .expect("write session record");
}

fn write_run(project_dir: &Path, session_id: &str, run_id: &str, pid: &str) {
    write_run_with_backend(project_dir, session_id, run_id, pid, "qemu-system-mipsel");
}

fn write_run_with_backend(
    project_dir: &Path,
    session_id: &str,
    run_id: &str,
    pid: &str,
    backend: &str,
) {
    let run_dir = project_dir
        .join("sessions")
        .join(session_id)
        .join("runs")
        .join(run_id);
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::write(
        run_dir.join("run.json"),
        format!(
            r#"{{
  "run_id": "{run_id}",
  "session_id": "{session_id}",
  "recipe_id": "rcp-1",
  "backend_driver": "{backend}",
  "substrate_kind": "native-host",
  "status": "running",
  "sequence_in_session": 1,
  "derived_from_run_id": null,
  "origin": "manual",
  "started_at": "2026-08-23T10:00:00Z",
  "finished_at": null,
  "active_endpoints": [],
  "goal_progress_delta": {{"from":"not-started","to":"partial"}},
  "supervision_mode": "background-supervisor",
  "health_state": "healthy",
  "last_health_check_at": null,
  "supervisor_pid": {pid},
  "last_heartbeat_at": null,
  "supervision_lease_expires_at": null
}}"#
        ),
    )
    .expect("write run record");
}

fn read_run_status(project_dir: &Path, session_id: &str, run_id: &str) -> String {
    let path = project_dir
        .join("sessions")
        .join(session_id)
        .join("runs")
        .join(run_id)
        .join("run.json");
    let text = fs::read_to_string(path).expect("read run record");
    let value: serde_json::Value = serde_json::from_str(&text).expect("run record parses");
    value["status"].as_str().expect("status string").to_string()
}

fn run_gc(project_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--project"])
        .arg(project_dir)
        .arg("--gc")
        .output()
        .expect("fat emulate --gc runs")
}

#[test]
fn gc_marks_a_session_whose_process_is_gone_as_stale() {
    let dir = tempdir().expect("tempdir");
    write_session(dir.path(), "sess-dead", &now_stamp());
    write_run(dir.path(), "sess-dead", "run-dead", "999999");

    let output = run_gc(dir.path());
    assert!(
        output.status.success(),
        "expected success, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("marked stale"), "got:\n{stdout}");
    assert!(stdout.contains("run-dead"), "got:\n{stdout}");

    assert_eq!(
        read_run_status(dir.path(), "sess-dead", "run-dead"),
        "degraded-running"
    );
}

#[test]
fn gc_leaves_a_live_process_it_may_not_signal_alone() {
    // pid 1 exists on every unix host and is not ours to signal. Probing it
    // with kill(2) returns a permission error, which means *alive* — a
    // liveness check that reads that as dead would sweep a running session.
    let dir = tempdir().expect("tempdir");
    write_session(dir.path(), "sess-perm", &now_stamp());
    write_run(dir.path(), "sess-perm", "run-perm", "1");

    let output = run_gc(dir.path());
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("marked stale"),
        "a process we may not signal must not be swept as stale, got:\n{stdout}"
    );
    assert_eq!(
        read_run_status(dir.path(), "sess-perm", "run-perm"),
        "running",
        "the record should be left exactly as it was"
    );
}

#[test]
fn gc_leaves_a_session_with_no_recorded_pid_alone() {
    let dir = tempdir().expect("tempdir");
    write_session(dir.path(), "sess-nopid", &now_stamp());
    write_run(dir.path(), "sess-nopid", "run-nopid", "null");

    let output = run_gc(dir.path());
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Without a pid there is nothing to decide liveness against, so the sweep
    // has no basis to act.
    assert!(stdout.contains("nothing to clean up"), "got:\n{stdout}");
    assert_eq!(
        read_run_status(dir.path(), "sess-nopid", "run-nopid"),
        "running"
    );
}

/// Start a supervisor stand-in: a live process leading its own group, whose
/// corpse is reaped the moment it dies.
///
/// Both properties matter. The recorded `supervisor_pid` is signalled as a
/// group, so it has to be a group leader. And a signalled child that nobody
/// reaps stays a zombie, which still answers `kill(pgid, 0)` — the stop would
/// then wait out its whole grace and escalate. In production init does this
/// reaping, because the sweep runs in a different process than the launcher.
fn spawn_reaped_group_leader() -> u32 {
    let mut command = Command::new("sleep");
    command.arg("120");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("spawn stand-in supervisor");
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    pid
}

fn is_running(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn stale_stamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        .saturating_sub(60_000);
    format!("unix-ms:{millis}")
}

#[test]
fn gc_stops_an_idle_session_through_the_real_stop_path() {
    // `qemu-direct` is the backend a native-host launch actually records. The
    // sweep used to match on backend names that never included it and reported
    // "does not support gc stop"; it now goes through the same stop the CLI
    // performs, so the runtime is really torn down.
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("fw.bin");
    fs::write(&firmware, vec![0u8; 4096]).expect("write firmware");
    let projects = dir.path().join("projects");
    let created = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg("new")
        .arg(&firmware)
        .arg("--projects-dir")
        .arg(&projects)
        .output()
        .expect("fat new runs");
    assert!(
        created.status.success(),
        "fat new failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );
    // The stop path reads project metadata, so the sweep needs a real project.
    let project = projects.join("fw");

    let pid = spawn_reaped_group_leader();
    write_session(&project, "sess-idle", &stale_stamp());
    write_run_with_backend(
        &project,
        "sess-idle",
        "run-idle",
        &pid.to_string(),
        "qemu-direct",
    );
    fs::create_dir_all(project.join("profiles")).expect("profiles dir");
    fs::write(
        project.join("profiles/emulation.toml"),
        "[lifecycle]\nidle_timeout_secs = 1\n",
    )
    .expect("write config");

    let output = run_gc(&project);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("gc: stopped"), "got:\n{stdout}");
    assert!(stdout.contains("sess-idle"), "got:\n{stdout}");
    assert!(
        !stdout.contains("does not support gc stop"),
        "every backend the CLI can stop should be sweepable, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("stop-failed"),
        "the stop should succeed, got:\n{stdout}"
    );
    assert!(
        !is_running(pid),
        "the idle runtime should have been stopped"
    );

    // Safety net if an assertion above fails before the sweep reaps it.
    let _ = Command::new("kill")
        .args(["-9", &format!("-{pid}")])
        .stderr(std::process::Stdio::null())
        .status();
}
