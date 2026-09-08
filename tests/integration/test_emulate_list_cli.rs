use std::fs;
use std::path::Path;
use std::process::{Child, Command};

use tempfile::tempdir;

/// A process this test owns, used as a stand-in supervisor pid.
struct LiveProcess(Child);

impl LiveProcess {
    fn spawn() -> Self {
        let child = Command::new("sleep")
            .arg("120")
            .spawn()
            .expect("spawn a live stand-in supervisor");
        LiveProcess(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for LiveProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_session(project_dir: &Path, session_id: &str) {
    let session_dir = project_dir.join("sessions").join(session_id);
    fs::create_dir_all(session_dir.join("runs")).expect("create session dir");
    fs::write(
        session_dir.join("session.json"),
        format!(
            r#"{{
  "session_id": "{session_id}",
  "project_id": "proj-test",
  "target_id": "tgt-test",
  "goal": "list check",
  "strategy_family": "manual",
  "status": "active",
  "progress": "partial",
  "run_ids": [],
  "created_at": "2026-08-23T10:00:00Z",
  "updated_at": "2026-08-23T10:05:00Z",
  "origin": "manual"
}}"#
        ),
    )
    .expect("write session record");
}

fn write_run(project_dir: &Path, session_id: &str, run_id: &str, status: &str, pid: &str) {
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
  "backend_driver": "qemu-system-mipsel",
  "substrate_kind": "native-host",
  "status": "{status}",
  "sequence_in_session": 1,
  "derived_from_run_id": null,
  "origin": "manual",
  "started_at": "2026-08-23T10:00:00Z",
  "finished_at": null,
  "active_endpoints": [
    {{"kind":"port-forward","name":"http","host":"127.0.0.1","port":8080,"target_port":80,"uri":null}}
  ],
  "goal_progress_delta": {{"from":"not-started","to":"partial"}},
  "supervision_mode": "background-supervisor",
  "health_state": "healthy",
  "last_health_check_at": null,
  "supervisor_pid": {pid},
  "last_heartbeat_at": "2026-08-23T10:05:00Z",
  "supervision_lease_expires_at": null
}}"#
        ),
    )
    .expect("write run record");
}

/// A project with one live run, one run whose supervisor is gone, and one
/// finished run that must not be listed.
fn fixture_project(project_dir: &Path, live_pid: u32) {
    write_session(project_dir, "sess-live");
    write_run(
        project_dir,
        "sess-live",
        "run-live",
        "running",
        &live_pid.to_string(),
    );

    write_session(project_dir, "sess-stale");
    write_run(project_dir, "sess-stale", "run-stale", "running", "999999");

    write_session(project_dir, "sess-done");
    write_run(project_dir, "sess-done", "run-done", "completed", "null");
}

fn fat() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fat"))
}

#[test]
fn emulate_list_reports_live_and_stale_sessions() {
    let dir = tempdir().expect("tempdir");
    let live = LiveProcess::spawn();
    fixture_project(dir.path(), live.pid());

    let output = fat()
        .args(["emulate", "--project"])
        .arg(dir.path())
        .arg("--list")
        .output()
        .expect("fat emulate --list runs");

    assert!(
        output.status.success(),
        "expected success, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("sess-live"), "got:\n{stdout}");
    assert!(stdout.contains("sess-stale"), "got:\n{stdout}");
    // Completed runs are history, not active emulations.
    assert!(!stdout.contains("sess-done"), "got:\n{stdout}");
    assert!(stdout.contains("1 live, 1 stale"), "got:\n{stdout}");
    // Full names, not clipped ones.
    assert!(stdout.contains("qemu-system-mipsel"), "got:\n{stdout}");
}

#[test]
fn emulate_list_json_uses_on_disk_status_names_and_process_state() {
    let dir = tempdir().expect("tempdir");
    let live = LiveProcess::spawn();
    fixture_project(dir.path(), live.pid());

    let output = fat()
        .args(["emulate", "--project"])
        .arg(dir.path())
        .args(["--list", "--list-json"])
        .output()
        .expect("fat emulate --list --list-json runs");

    assert!(
        output.status.success(),
        "expected success, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON parses");

    assert_eq!(report["live_count"], 1);
    assert_eq!(report["stale_count"], 1);

    let entries = report["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2, "got:\n{stdout}");

    let live_entry = entries
        .iter()
        .find(|entry| entry["session_id"] == "sess-live")
        .expect("live entry present");
    // Kebab-case, matching how the status is stored on disk.
    assert_eq!(live_entry["status"], "running");
    assert_eq!(live_entry["state"], "live");
    assert!(
        live_entry["rss_kb"].as_u64().unwrap_or(0) > 0,
        "expected measured RSS, got:\n{stdout}"
    );

    let stale_entry = entries
        .iter()
        .find(|entry| entry["session_id"] == "sess-stale")
        .expect("stale entry present");
    assert_eq!(stale_entry["state"], "stale");
    assert!(stale_entry["rss_kb"].is_null(), "got:\n{stdout}");
}

#[test]
fn emulate_list_does_not_create_a_project_layout() {
    let dir = tempdir().expect("tempdir");

    let output = fat()
        .args(["emulate", "--project"])
        .arg(dir.path())
        .arg("--list")
        .output()
        .expect("fat emulate --list runs");

    assert!(
        output.status.success(),
        "expected success, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("no active emulations"),
        "got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Listing is a read: it must not materialize a project in a directory that
    // is not one.
    assert!(!dir.path().join("project.json").exists());
    assert!(!dir.path().join("sessions").exists());
    assert!(!dir.path().join("benchmark").exists());
}

#[test]
fn emulate_list_subcommand_form_matches_the_flag() {
    let dir = tempdir().expect("tempdir");
    let live = LiveProcess::spawn();
    fixture_project(dir.path(), live.pid());

    let flag = fat()
        .args(["emulate", "--project"])
        .arg(dir.path())
        .arg("--list")
        .output()
        .expect("fat emulate --list runs");
    let subcommand = fat()
        .args(["emulate", "list", "--project"])
        .arg(dir.path())
        .output()
        .expect("fat emulate list runs");

    assert!(subcommand.status.success());
    // Resource columns move between the two runs, so compare the identity of
    // the rows rather than the measured numbers.
    assert_eq!(
        row_identities(&String::from_utf8_lossy(&subcommand.stdout)),
        row_identities(&String::from_utf8_lossy(&flag.stdout))
    );
}

/// The `SESSION ID`, `BACKEND`, `STATUS`, and `STATE` columns of each row.
fn row_identities(table: &str) -> Vec<Vec<String>> {
    table
        .lines()
        .filter(|line| line.starts_with("sess-"))
        .map(|line| {
            line.split_whitespace()
                .take(4)
                .map(str::to_string)
                .collect()
        })
        .collect()
}

#[test]
fn emulate_list_conflicts_with_lifecycle_flags() {
    let dir = tempdir().expect("tempdir");

    for conflicting in ["--stop", "--status"] {
        let output = fat()
            .args(["emulate", "--project"])
            .arg(dir.path())
            .args(["--list", conflicting])
            .output()
            .expect("fat emulate runs");

        assert!(
            !output.status.success(),
            "expected --list {conflicting} to be rejected"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot be used with"), "got:\n{stderr}");
    }
}

#[test]
fn emulate_list_json_requires_list() {
    let dir = tempdir().expect("tempdir");

    let output = fat()
        .args(["emulate", "--project"])
        .arg(dir.path())
        .arg("--list-json")
        .output()
        .expect("fat emulate runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--list"), "got:\n{stderr}");
}
