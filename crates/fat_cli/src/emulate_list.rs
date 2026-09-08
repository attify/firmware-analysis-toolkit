//! `fat emulate list` — a docker-ps-style view of the emulation sessions a
//! project has on record, joined against live process state.
//!
//! Resource numbers are measured over the supervisor's whole process group, not
//! just the supervisor pid: the supervisor is a thin wrapper and the emulator it
//! launches is the process that actually holds the memory.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::process::Command;

use fat_core::runs::RunStatus;
use fat_core::runtime_store::RuntimeStore;
use serde::Serialize;

/// Run statuses that claim the run is still live. Records outside this set are
/// finished history and are not listed.
const LIVE_STATUSES: [RunStatus; 3] = [
    RunStatus::Launching,
    RunStatus::Running,
    RunStatus::DegradedRunning,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessState {
    /// The record claims the run is live and the supervisor process is alive.
    Live,
    /// The record claims the run is live but the supervisor process is gone.
    Stale,
    /// The record claims the run is live but never recorded a supervisor pid,
    /// so liveness cannot be decided.
    Unknown,
}

impl ProcessState {
    fn label(self) -> &'static str {
        match self {
            ProcessState::Live => "live",
            ProcessState::Stale => "stale",
            ProcessState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EmulationListEntry {
    pub session_id: String,
    pub run_id: String,
    pub backend: String,
    /// Serialized in the same kebab-case form the record uses on disk, so the
    /// JSON view round-trips back into [`RunStatus`].
    pub status: RunStatus,
    pub updated_at: String,
    pub supervisor_pid: Option<u32>,
    /// Process group the supervisor leads; resource numbers are summed over it.
    pub process_group_id: Option<u32>,
    pub state: ProcessState,
    /// Resident set size summed over every process in the supervisor's group.
    pub rss_kb: Option<u64>,
    /// CPU percent summed over the group. This is `ps`'s lifetime average per
    /// process, not an instantaneous sample.
    pub cpu_percent: Option<f64>,
    /// Number of processes in the supervisor's group.
    pub process_count: usize,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmulationListReport {
    pub entries: Vec<EmulationListEntry>,
    pub live_count: usize,
    pub stale_count: usize,
    pub unknown_count: usize,
    /// Summed over distinct process groups: two runs supervised by the same
    /// group contribute their memory once, not twice.
    pub total_rss_kb: u64,
}

/// A run whose record claims it is live, paired with the verdict on its
/// supervisor process.
///
/// This is the single definition of "what the store currently claims is
/// running". `fat emulate list` and the `--gc` sweep both read it, so the two
/// cannot drift apart on which statuses count as live or on how liveness is
/// decided.
#[derive(Debug, Clone)]
pub struct LiveRun {
    pub session: fat_core::sessions::SessionRecord,
    pub run: fat_core::runs::RunRecord,
    pub state: ProcessState,
}

pub fn collect_live_runs(store: &RuntimeStore) -> io::Result<Vec<LiveRun>> {
    let mut live_runs = Vec::new();
    for session in store.read_sessions()? {
        for run in store.read_runs(&session.session_id)? {
            if !LIVE_STATUSES.contains(&run.status) {
                continue;
            }
            let state = process_state_for(run.supervisor_pid);
            live_runs.push(LiveRun {
                session: session.clone(),
                run,
                state,
            });
        }
    }
    Ok(live_runs)
}

/// Classify a recorded supervisor pid.
///
/// Goes through [`crate::emulate_cmd::process_is_running`], which treats a
/// permission error as alive: a process we may not signal still exists, and
/// calling it dead would strand a running emulation behind a `stale` label.
pub fn process_state_for(pid: Option<u32>) -> ProcessState {
    match pid {
        None => ProcessState::Unknown,
        Some(pid) if crate::emulate_cmd::process_is_running(pid) => ProcessState::Live,
        Some(_) => ProcessState::Stale,
    }
}

pub fn collect_emulation_list(project_dir: &Path) -> io::Result<EmulationListReport> {
    // Read-only open: listing must never materialize a project layout for a
    // path the user mistyped.
    let store = RuntimeStore::open_read_only(project_dir)?;
    let processes = capture_process_table();

    let mut entries = collect_live_runs(&store)?
        .iter()
        .map(|live_run| build_entry(live_run, &processes))
        .collect::<Vec<_>>();
    entries.extend(bootloader_entry(project_dir, &processes));
    entries.sort_by(|left, right| {
        left.session_id
            .cmp(&right.session_id)
            .then_with(|| left.run_id.cmp(&right.run_id))
    });

    Ok(summarize(entries))
}

fn build_entry(live_run: &LiveRun, processes: &ProcessTable) -> EmulationListEntry {
    let LiveRun {
        session,
        run,
        state,
    } = live_run;
    let (session_id, updated_at, state) = (&session.session_id, &session.updated_at, *state);
    let pid = run.supervisor_pid;

    let group = match (state, pid) {
        (ProcessState::Live, Some(pid)) => processes.group_of(pid),
        _ => None,
    };
    let usage = group.and_then(|group_id| processes.group_usage(group_id));

    EmulationListEntry {
        session_id: session_id.to_string(),
        run_id: run.run_id.clone(),
        backend: run.backend_driver.clone(),
        status: run.status,
        updated_at: updated_at.to_string(),
        supervisor_pid: pid,
        process_group_id: group,
        state,
        rss_kb: usage.map(|usage| usage.rss_kb),
        cpu_percent: usage.map(|usage| usage.cpu_percent),
        process_count: usage.map(|usage| usage.process_count).unwrap_or(0),
        endpoints: run
            .active_endpoints
            .iter()
            .map(|endpoint| match endpoint.uri.as_deref() {
                Some(uri) => uri.to_string(),
                None => format!("{}:{}", endpoint.host, endpoint.port),
            })
            .collect(),
    }
}

/// Backend label for bootloader sessions. They are not runtime-store runs, so
/// they carry no backend driver of their own, but the column must say what the
/// row is and `fat bootloader stop` is what acts on it.
const BOOTLOADER_BACKEND: &str = "bootloader-tmux";

/// The project's bootloader session, if it has one worth listing.
///
/// `fat bootloader emulate` runs QEMU in a detached tmux session and records
/// nothing in the runtime store, so these sessions were invisible here even
/// though they hold real memory and keep running until stopped. Liveness comes
/// from tmux rather than a stored pid, and the pane pid lets the row reuse the
/// same process-group accounting as every other entry.
///
/// Returns `None` when the project never launched one. A record claiming a
/// launch whose session is gone is still listed, as `stale` — that is the state
/// a user needs to see to know a cleanup is pending.
fn bootloader_entry(project_dir: &Path, processes: &ProcessTable) -> Option<EmulationListEntry> {
    let status = fat_bootloader::inspect_tmux_session(project_dir).ok()?;
    if !status.live && !status.recorded_launched {
        return None;
    }

    let state = if status.live {
        ProcessState::Live
    } else {
        ProcessState::Stale
    };
    let group = status.pane_pid.and_then(|pid| processes.group_of(pid));
    let usage = group.and_then(|group_id| processes.group_usage(group_id));

    Some(EmulationListEntry {
        session_id: status.tmux_session,
        // tmux sessions have no run history: the session is the run.
        run_id: String::new(),
        backend: BOOTLOADER_BACKEND.to_string(),
        status: RunStatus::Running,
        updated_at: String::new(),
        supervisor_pid: status.pane_pid,
        process_group_id: group,
        state,
        rss_kb: usage.map(|usage| usage.rss_kb),
        cpu_percent: usage.map(|usage| usage.cpu_percent),
        process_count: usage.map(|usage| usage.process_count).unwrap_or(0),
        // The console is a tmux attach, not a network endpoint.
        endpoints: Vec::new(),
    })
}

fn summarize(entries: Vec<EmulationListEntry>) -> EmulationListReport {
    let live_count = entries
        .iter()
        .filter(|entry| entry.state == ProcessState::Live)
        .count();
    let stale_count = entries
        .iter()
        .filter(|entry| entry.state == ProcessState::Stale)
        .count();
    let unknown_count = entries
        .iter()
        .filter(|entry| entry.state == ProcessState::Unknown)
        .count();

    // Count each process group once: several runs can share one supervisor.
    let mut counted = HashSet::new();
    let mut total_rss_kb = 0;
    for entry in &entries {
        let Some(rss_kb) = entry.rss_kb else {
            continue;
        };
        let key = entry.process_group_id.or(entry.supervisor_pid);
        if key.is_some_and(|key| !counted.insert(key)) {
            continue;
        }
        total_rss_kb += rss_kb;
    }

    EmulationListReport {
        entries,
        live_count,
        stale_count,
        unknown_count,
        total_rss_kb,
    }
}

/// Render the docker-ps-style table. Columns are sized to their content so
/// real backend driver and status names are not clipped.
pub fn render_emulation_table(report: &EmulationListReport) -> String {
    if report.entries.is_empty() {
        return "no active emulations\n".to_string();
    }

    let header = [
        "SESSION ID",
        "BACKEND",
        "STATUS",
        "STATE",
        "PID",
        "PROCS",
        "RSS",
        "CPU%",
        "ENDPOINTS",
    ];
    let mut rows = vec![header
        .iter()
        .map(|cell| cell.to_string())
        .collect::<Vec<_>>()];
    for entry in &report.entries {
        rows.push(vec![
            truncate(&entry.session_id, 44),
            truncate(&entry.backend, 28),
            status_label(entry.status),
            entry.state.label().to_string(),
            entry
                .supervisor_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            match entry.process_count {
                0 => "-".to_string(),
                count => count.to_string(),
            },
            entry
                .rss_kb
                .map(format_rss)
                .unwrap_or_else(|| "-".to_string()),
            entry
                .cpu_percent
                .map(|cpu| format!("{cpu:.1}"))
                .unwrap_or_else(|| "-".to_string()),
            if entry.endpoints.is_empty() {
                "-".to_string()
            } else {
                entry.endpoints.join(" ")
            },
        ]);
    }

    let column_count = header.len();
    let mut widths = vec![0usize; column_count];
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    for row in &rows {
        let mut line = String::new();
        for (index, cell) in row.iter().enumerate() {
            if index + 1 == column_count {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}  ", width = widths[index]));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&format!(
        "{} session(s): {} live, {} stale",
        report.entries.len(),
        report.live_count,
        report.stale_count
    ));
    if report.unknown_count > 0 {
        out.push_str(&format!(", {} unknown", report.unknown_count));
    }
    out.push_str(&format!(
        " — total RSS {} across live process groups\n",
        format_rss(report.total_rss_kb)
    ));
    if report.stale_count > 0 {
        out.push_str("stale rows are recorded as live but their supervisor process is gone\n");
    }
    out
}

fn status_label(status: RunStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{status:?}"))
}

fn format_rss(rss_kb: u64) -> String {
    let megabytes = rss_kb as f64 / 1024.0;
    if megabytes >= 1024.0 {
        format!("{:.1}GB", megabytes / 1024.0)
    } else {
        format!("{megabytes:.1}MB")
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    format!(
        "{}…",
        value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>()
    )
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct GroupUsage {
    rss_kb: u64,
    cpu_percent: f64,
    process_count: usize,
}

#[derive(Debug, Default, Clone)]
struct ProcessTable {
    /// pid → process group id.
    groups: HashMap<u32, u32>,
    /// process group id → usage summed over its members.
    usage: HashMap<u32, GroupUsage>,
}

impl ProcessTable {
    fn group_of(&self, pid: u32) -> Option<u32> {
        self.groups.get(&pid).copied()
    }

    fn group_usage(&self, process_group_id: u32) -> Option<GroupUsage> {
        self.usage.get(&process_group_id).copied()
    }
}

/// Parse `pid pgid rss %cpu` rows and fold them into per-group totals.
fn parse_ps_snapshot(text: &str) -> ProcessTable {
    let mut table = ProcessTable::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [pid, process_group_id, rss_kb, cpu_percent] = fields[..] else {
            continue;
        };
        let (Ok(pid), Ok(process_group_id)) = (pid.parse::<u32>(), process_group_id.parse::<u32>())
        else {
            continue;
        };
        let rss_kb = rss_kb.parse::<u64>().unwrap_or(0);
        let cpu_percent = cpu_percent.parse::<f64>().unwrap_or(0.0);

        table.groups.insert(pid, process_group_id);
        let entry = table.usage.entry(process_group_id).or_insert(GroupUsage {
            rss_kb: 0,
            cpu_percent: 0.0,
            process_count: 0,
        });
        entry.rss_kb += rss_kb;
        entry.cpu_percent += cpu_percent;
        entry.process_count += 1;
    }
    table
}

#[cfg(unix)]
fn capture_process_table() -> ProcessTable {
    let output = Command::new("ps")
        .args(["-axo", "pid=,pgid=,rss=,%cpu="])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            parse_ps_snapshot(&String::from_utf8_lossy(&output.stdout))
        }
        _ => ProcessTable::default(),
    }
}

#[cfg(not(unix))]
fn capture_process_table() -> ProcessTable {
    ProcessTable::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        session_id: &str,
        state: ProcessState,
        pid: Option<u32>,
        group: Option<u32>,
        rss_kb: Option<u64>,
    ) -> EmulationListEntry {
        EmulationListEntry {
            session_id: session_id.to_string(),
            run_id: format!("run-{session_id}"),
            backend: "qemu-system-mipsel".to_string(),
            status: RunStatus::Running,
            updated_at: "2026-08-23T10:05:00Z".to_string(),
            supervisor_pid: pid,
            process_group_id: group,
            state,
            rss_kb,
            cpu_percent: rss_kb.map(|_| 12.5),
            process_count: rss_kb.map(|_| 3).unwrap_or(0),
            endpoints: vec!["127.0.0.1:8080".to_string()],
        }
    }

    #[test]
    fn group_usage_sums_every_member_of_the_process_group() {
        // A 2MB supervisor whose emulator child holds 256MB: the group total is
        // what matters, the supervisor's own RSS is noise.
        let table = parse_ps_snapshot(
            "  100   100    2304   0.7\n  101   100  262144  91.2\n  200   200    1024   0.0\n",
        );

        assert_eq!(table.group_of(100), Some(100));
        assert_eq!(table.group_of(101), Some(100));
        let usage = table.group_usage(100).expect("group 100 present");
        assert_eq!(usage.rss_kb, 264_448);
        assert_eq!(usage.process_count, 2);
        assert!((usage.cpu_percent - 91.9).abs() < 0.001);
    }

    #[test]
    fn ps_rows_that_do_not_parse_are_skipped() {
        let table = parse_ps_snapshot("garbage\n  1\n  a b c d\n  7   7   64   1.0\n");
        assert_eq!(table.groups.len(), 1);
        assert_eq!(table.group_usage(7).map(|usage| usage.rss_kb), Some(64));
    }

    #[test]
    fn total_rss_counts_a_shared_process_group_once() {
        let report = summarize(vec![
            entry(
                "sess-a",
                ProcessState::Live,
                Some(100),
                Some(100),
                Some(2048),
            ),
            entry(
                "sess-b",
                ProcessState::Live,
                Some(101),
                Some(100),
                Some(2048),
            ),
            entry(
                "sess-c",
                ProcessState::Live,
                Some(300),
                Some(300),
                Some(1024),
            ),
        ]);

        assert_eq!(report.total_rss_kb, 3072);
        assert_eq!(report.live_count, 3);
    }

    #[test]
    fn stale_entries_are_labelled_and_counted_separately() {
        let report = summarize(vec![
            entry(
                "sess-live",
                ProcessState::Live,
                Some(100),
                Some(100),
                Some(4096),
            ),
            entry("sess-dead", ProcessState::Stale, Some(999999), None, None),
            entry("sess-nopid", ProcessState::Unknown, None, None, None),
        ]);
        let table = render_emulation_table(&report);

        assert_eq!(report.live_count, 1);
        assert_eq!(report.stale_count, 1);
        assert_eq!(report.unknown_count, 1);
        assert_eq!(report.total_rss_kb, 4096);
        assert!(table.contains("stale"), "got:\n{table}");
        assert!(table.contains("unknown"), "got:\n{table}");
        assert!(
            table.contains("3 session(s): 1 live, 1 stale, 1 unknown"),
            "got:\n{table}"
        );
        assert!(
            table.contains("supervisor process is gone"),
            "got:\n{table}"
        );
    }

    #[test]
    fn full_backend_and_status_names_survive_rendering() {
        let mut degraded = entry(
            "sess-a",
            ProcessState::Live,
            Some(100),
            Some(100),
            Some(2048),
        );
        degraded.status = RunStatus::DegradedRunning;
        let table = render_emulation_table(&summarize(vec![degraded]));

        assert!(table.contains("qemu-system-mipsel"), "got:\n{table}");
        assert!(table.contains("degraded-running"), "got:\n{table}");
        assert!(!table.contains('…'), "got:\n{table}");
    }

    #[test]
    fn status_labels_match_the_on_disk_serialization() {
        assert_eq!(status_label(RunStatus::Running), "running");
        assert_eq!(status_label(RunStatus::DegradedRunning), "degraded-running");
        assert_eq!(status_label(RunStatus::Launching), "launching");
    }

    #[test]
    fn empty_report_says_so() {
        assert_eq!(
            render_emulation_table(&summarize(Vec::new())),
            "no active emulations\n"
        );
    }

    #[test]
    fn rss_formatting_switches_to_gigabytes() {
        assert_eq!(format_rss(2048), "2.0MB");
        assert_eq!(format_rss(2 * 1024 * 1024), "2.0GB");
    }
}
