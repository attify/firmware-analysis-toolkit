use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::tempdir;

/// A process group this test owns, standing in for a live emulation supervisor.
/// Never a real system pid: the caps path only counts, but a fixture that could
/// be handed to a stop path must never name something we do not own.
struct LiveGroup(Child);

impl LiveGroup {
    fn spawn() -> Self {
        let mut command = Command::new("sleep");
        command.arg("120");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        LiveGroup(command.spawn().expect("spawn stand-in supervisor"))
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for LiveGroup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn now_stamp() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    format!("unix-ms:{millis}")
}

fn write_live_session(project_dir: &Path, session_id: &str, pid: u32) {
    let session_dir = project_dir.join("sessions").join(session_id);
    let run_dir = session_dir.join("runs").join("run-1");
    fs::create_dir_all(&run_dir).expect("create run dir");
    let stamp = now_stamp();
    fs::write(
        session_dir.join("session.json"),
        format!(
            r#"{{
  "session_id": "{session_id}",
  "project_id": "proj-test",
  "target_id": "tgt-test",
  "goal": "caps check",
  "strategy_family": "manual",
  "status": "active",
  "progress": "partial",
  "run_ids": [],
  "created_at": "{stamp}",
  "updated_at": "{stamp}",
  "origin": "manual"
}}"#
        ),
    )
    .expect("write session record");
    fs::write(
        run_dir.join("run.json"),
        format!(
            r#"{{
  "run_id": "run-1",
  "session_id": "{session_id}",
  "recipe_id": "rcp-1",
  "backend_driver": "qemu-system-mipsel",
  "substrate_kind": "native-host",
  "status": "running",
  "sequence_in_session": 1,
  "derived_from_run_id": null,
  "origin": "manual",
  "started_at": "2026-08-24T10:00:00Z",
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

/// Written in the documented `[lifecycle]` table form.
fn write_config(project_dir: &Path, body: &str) {
    let profiles = project_dir.join("profiles");
    fs::create_dir_all(&profiles).expect("create profiles dir");
    fs::write(
        profiles.join("emulation.toml"),
        format!("[lifecycle]\n{body}\n"),
    )
    .expect("write emulation.toml");
}

fn launch(project_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--project"])
        .arg(project_dir)
        .output()
        .expect("fat emulate runs")
}

#[test]
fn a_launch_past_the_concurrency_cap_is_refused() {
    let dir = tempdir().expect("tempdir");
    let live = LiveGroup::spawn();
    write_live_session(dir.path(), "sess-live", live.pid());
    write_config(dir.path(), "max_concurrent = 1");

    let output = launch(dir.path());

    assert!(!output.status.success(), "the launch should be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("max_concurrent"), "got:\n{stderr}");
    assert!(stderr.contains("1 emulation session(s)"), "got:\n{stderr}");
    // Refused before the project database is opened, so nothing was created.
    assert!(!dir.path().join(".fat.db").exists());
}

#[test]
fn caps_are_off_by_default() {
    let dir = tempdir().expect("tempdir");
    let live = LiveGroup::spawn();
    write_live_session(dir.path(), "sess-live", live.pid());
    // No config at all: an unconfigured project must not gain a limit.

    let output = launch(dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The launch still fails — this fixture has no firmware — but it must get
    // past the caps to do so.
    assert!(
        !stderr.contains("refusing to launch"),
        "caps should not fire without configuration, got:\n{stderr}"
    );
}

#[test]
fn a_stale_session_does_not_consume_the_concurrency_cap() {
    let dir = tempdir().expect("tempdir");
    // A record that claims to be running but whose process is gone is not a
    // live session, and must not block the next launch.
    write_live_session(dir.path(), "sess-dead", 999_999);
    write_config(dir.path(), "max_concurrent = 1");

    let output = launch(dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("max_concurrent"),
        "a stale record should not hold a slot, got:\n{stderr}"
    );
}
