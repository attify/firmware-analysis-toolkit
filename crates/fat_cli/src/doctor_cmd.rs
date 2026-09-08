use std::error::Error;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fat_backend::model::{
    BackendCheckRecord, BackendHealthSummary, CommandProbe, PathCommandProbe,
};
use std::collections::HashMap;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// An external tool FAT can shell out to, grouped by the workflow that needs it.
struct ExternalTool {
    /// Executable name(s) probed on `PATH`; the first one found wins.
    names: &'static [&'static str],
    purpose: &'static str,
    /// `true` if a core workflow cannot run without it.
    required: bool,
    /// `true` if the tool's `--version` should be probed. Version text is only
    /// worth the extra process spawn where FAT either reports it or checks it.
    version_probed: bool,
}

const EXTERNAL_TOOLS: &[ExternalTool] = &[
    ExternalTool {
        names: &["binwalk"],
        purpose: "firmware extraction (fat extract)",
        required: false,
        version_probed: true,
    },
    ExternalTool {
        names: &["unblob"],
        purpose: "firmware extraction, alternative engine",
        required: false,
        version_probed: true,
    },
    ExternalTool {
        names: &["debugfs"],
        purpose: "ext filesystem extraction and ext2 permission repair",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["rabin2", "r2"],
        purpose: "radare2 binary triage (fat r2-triage, taint resolve)",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["joern", "c2cpg"],
        purpose: "Joern CPG for taint proof (fat taint)",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["qemu-system-arm", "qemu-system-mips", "qemu-system-mipsel"],
        purpose: "system-mode emulation (fat emulate)",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["docker"],
        purpose: "containerized emulation backends (FirmAE/EMUX)",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["python3"],
        purpose: "angr taint and discovery runners",
        required: false,
        version_probed: false,
    },
    ExternalTool {
        names: &["gdb-multiarch", "gdb"],
        purpose: "remote debugging (fat debug gdb)",
        required: false,
        version_probed: true,
    },
];

#[derive(serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ToolState {
    Usable {
        name: String,
        path: String,
        version: Option<String>,
    },
    Unusable {
        name: String,
        path: String,
        error: String,
    },
    Missing,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct ToolFinding {
    label: String,
    purpose: String,
    /// Overrides the generic `— {purpose}` note when the tool is absent
    /// (ghidra points at GHIDRA_HOME instead).
    missing_note: Option<String>,
    extraction_engine: bool,
    required: bool,
    /// Known-defect note for the discovered version. Advisory only: the tool
    /// is still usable, but a specific release misbehaves for a FAT workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory: Option<String>,
    state: ToolState,
}

/// GDB releases with defects that break `fat debug gdb`.
///
/// 15.2 segfaults parsing a remote uClibc library list when the sysroot is
/// `target:` — the shape EMUX's `emuxgdb` uses — because a `<library>` element
/// without the `lmid` attribute is dereferenced unconditionally.
/// FAT invokes EMUX's helper rather than building that command line itself, so
/// it cannot pass a different sysroot; warning at doctor time is the honest
/// remedy.
fn gdb_version_advisory(version: &str) -> Option<String> {
    let numeric = version.split_whitespace().find_map(|token| {
        let token = token.trim_start_matches(|c: char| !c.is_ascii_digit());
        let mut parts = token.split('.');
        let major: u32 = parts.next()?.parse().ok()?;
        let minor: u32 = parts
            .next()?
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse()
            .ok()?;
        Some((major, minor))
    })?;
    (numeric == (15, 2)).then(|| {
        "GDB 15.2 segfaults parsing remote uClibc library lists (fat debug gdb \
         against EMUX targets); prefer 15.1 or >= 16.1"
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// Probe every external tool, plus ghidra, which is located via GHIDRA_HOME
/// (or /opt/ghidra) rather than a PATH binary. Probing is separated from
/// rendering so the same findings feed the plain and panel layouts.
fn probe_external_tools() -> Vec<ToolFinding> {
    let probe = PathCommandProbe;
    let mut findings = Vec::new();
    for tool in EXTERNAL_TOOLS {
        let found = tool
            .names
            .iter()
            .find_map(|name| probe.command_path(name).map(|path| (*name, path)))
            .or_else(|| {
                (tool.names == ["debugfs"])
                    .then(|| {
                        [
                            "/opt/homebrew/opt/e2fsprogs/sbin/debugfs",
                            "/usr/local/opt/e2fsprogs/sbin/debugfs",
                        ]
                        .into_iter()
                        .map(PathBuf::from)
                        .find(|path| path.is_file())
                        .map(|path| ("debugfs", path))
                    })
                    .flatten()
            });
        let extraction_engine = tool.names == ["binwalk"] || tool.names == ["unblob"];
        let mut advisory = None;
        let state = match found {
            Some((name, path)) if tool.version_probed => match program_version(&path) {
                Ok(version) => {
                    if name.starts_with("gdb") {
                        advisory = gdb_version_advisory(&version);
                    }
                    ToolState::Usable {
                        name: name.to_string(),
                        path: path.display().to_string(),
                        version: Some(version),
                    }
                }
                Err(error) => ToolState::Unusable {
                    name: name.to_string(),
                    path: path.display().to_string(),
                    error,
                },
            },
            Some((name, path)) => ToolState::Usable {
                name: name.to_string(),
                path: path.display().to_string(),
                version: None,
            },
            None => ToolState::Missing,
        };
        findings.push(ToolFinding {
            label: tool.names.join(" | "),
            purpose: tool.purpose.to_string(),
            missing_note: None,
            extraction_engine,
            required: tool.required,
            advisory,
            state,
        });
    }

    let ghidra = std::env::var_os("GHIDRA_HOME")
        .map(PathBuf::from)
        .filter(|home| home.join("support/analyzeHeadless").exists())
        .or_else(|| {
            let default = PathBuf::from("/opt/ghidra");
            default
                .join("support/analyzeHeadless")
                .exists()
                .then_some(default)
        });
    findings.push(ToolFinding {
        label: "ghidra".to_string(),
        purpose: "decompilation (fat decompile / taint normalize)".to_string(),
        missing_note: Some(
            "set GHIDRA_HOME; decompilation (fat decompile / taint normalize)".to_string(),
        ),
        extraction_engine: false,
        required: false,
        advisory: None,
        state: match ghidra {
            Some(home) => ToolState::Usable {
                name: "ghidra".to_string(),
                path: home.display().to_string(),
                version: None,
            },
            None => ToolState::Missing,
        },
    });
    findings
}

/// Plain `-` bullet rendering; byte-identical to the historical output so
/// scripts and piped output keep parsing the same shape.
fn print_plain_tools(palette: &crate::style::Palette, findings: &[ToolFinding]) {
    println!();
    println!("{}", palette.heading("External Tools"));
    for tool in findings {
        match &tool.state {
            ToolState::Usable {
                name,
                path,
                version: Some(version),
            } => println!(
                "{} {} {} {}",
                palette.bullet("-"),
                palette.good(format!("{name} found")),
                palette.muted(path),
                palette.muted(format!("— {version}; {}", tool.purpose)),
            ),
            ToolState::Usable { name, path, .. } => println!(
                "{} {} {} {}",
                palette.bullet("-"),
                palette.good(format!("{name} found")),
                palette.muted(path),
                palette.muted(format!("— {}", tool.purpose)),
            ),
            ToolState::Unusable { name, path, error } => println!(
                "{} {} {} {}",
                palette.bullet("-"),
                palette.bad(format!("{name} unusable")),
                palette.muted(path),
                palette.muted(format!("— {error}; {}", tool.purpose)),
            ),
            ToolState::Missing if tool.required => println!(
                "{} {} {}",
                palette.bullet("-"),
                palette.bad(format!("{} MISSING (required)", tool.label)),
                palette.muted(format!("— {}", tool.purpose)),
            ),
            ToolState::Missing => println!(
                "{} {} {}",
                palette.bullet("-"),
                palette.warn(format!("{} not found (optional)", tool.label)),
                palette.muted(format!(
                    "— {}",
                    tool.missing_note.as_deref().unwrap_or(&tool.purpose)
                )),
            ),
        }
        if let Some(advisory) = &tool.advisory {
            println!(
                "{}   {}",
                palette.bullet(" "),
                palette.warn(format!("warning: {advisory}")),
            );
        }
    }
}

fn tool_panel_line(tool: &ToolFinding, palette: &crate::style::Palette) -> String {
    let line = tool_panel_state_line(tool, palette);
    match &tool.advisory {
        Some(advisory) => format!(
            "{line}\n    {}",
            palette.warn(format!("warning: {advisory}"))
        ),
        None => line,
    }
}

fn tool_panel_state_line(tool: &ToolFinding, palette: &crate::style::Palette) -> String {
    match &tool.state {
        ToolState::Usable {
            name,
            path,
            version,
        } => {
            // Some tools echo their own name in `--version` output; the name
            // is already shown, so drop the redundant echo in the panel only.
            let version = version
                .as_deref()
                .map(|v| {
                    let v = v
                        .strip_prefix(name.as_str())
                        .map(str::trim_start)
                        .unwrap_or(v);
                    format!(" {v}")
                })
                .unwrap_or_default();
            format!(
                "{} {}{}  {}",
                palette.dot_ok(),
                name,
                version,
                palette.muted(format!("{} — {}", path, tool.purpose)),
            )
        }
        ToolState::Unusable { name, path, error } => format!(
            "{} {} unusable  {}",
            palette.dot_bad(),
            name,
            palette.muted(format!("{} — {error}; {}", path, tool.purpose)),
        ),
        ToolState::Missing if tool.required => format!(
            "{} {} MISSING (required)  {}",
            palette.dot_bad(),
            tool.label,
            palette.muted(format!("— {}", tool.purpose)),
        ),
        ToolState::Missing => format!(
            "{} {} not found (optional)  {}",
            palette.dot_warn(),
            tool.label,
            palette.muted(format!(
                "— {}",
                tool.missing_note.as_deref().unwrap_or(&tool.purpose)
            )),
        ),
    }
}

pub(crate) fn program_version(program: &std::path::Path) -> Result<String, String> {
    program_version_in(program, None)
}

/// Probe a tool's version, optionally from a chosen working directory.
///
/// A `--version` run is expected to print and exit, but FAT cannot assume the
/// binary on PATH is well behaved, and it inherits FAT's own working directory
/// by default. Callers that have a directory of their own should name it, so a
/// misbehaving probe writes there instead of into whatever directory the user
/// happened to run `fat` from.
pub(crate) fn program_version_in(
    program: &std::path::Path,
    working_dir: Option<&std::path::Path>,
) -> Result<String, String> {
    const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
    const MAX_VERSION_OUTPUT_BYTES: usize = 32 * 1024;
    let mut command = Command::new(program);
    command
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let remaining = Arc::new(AtomicUsize::new(MAX_VERSION_OUTPUT_BYTES));
    let truncated = Arc::new(AtomicBool::new(false));
    let (capture_sender, capture_receiver) = mpsc::sync_channel(8);
    spawn_capture_reader(
        child
            .stdout
            .take()
            .ok_or("version probe stdout unavailable")?,
        CaptureStream::Stdout,
        capture_sender.clone(),
        Arc::clone(&remaining),
        Arc::clone(&truncated),
    );
    spawn_capture_reader(
        child
            .stderr
            .take()
            .ok_or("version probe stderr unavailable")?,
        CaptureStream::Stderr,
        capture_sender,
        Arc::clone(&remaining),
        Arc::clone(&truncated),
    );
    let started = Instant::now();
    let deadline = started + VERSION_PROBE_TIMEOUT;
    let mut capture = CapturedOutput::default();
    let status = loop {
        capture.drain(&capture_receiver);
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                kill_probe_tree(&mut child);
                let _ = child.wait();
                capture.drain(&capture_receiver);
                return Err(format!(
                    "--version timed out after 2 seconds{}",
                    if truncated.load(Ordering::SeqCst) {
                        "; output truncated"
                    } else {
                        ""
                    }
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                kill_probe_tree(&mut child);
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    };
    // Best-effort cleanup for descendants that remain in the probe's process
    // group. Capture completion is bounded independently of descendant EOF.
    kill_probe_tree(&mut child);
    let failure_capture_deadline = Instant::now() + Duration::from_millis(100);
    loop {
        capture.drain(&capture_receiver);
        if capture.done_streams == 2
            || truncated.load(Ordering::SeqCst)
            || (status.success() && capture.has_nonempty_output())
            || (!status.success() && Instant::now() >= failure_capture_deadline)
            || Instant::now() >= deadline
        {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    capture.drain(&capture_receiver);
    drop(capture_receiver);
    let truncated = truncated.load(Ordering::SeqCst);
    if !status.success() {
        return Err(format!(
            "--version exited with {status}{}",
            if truncated { "; output truncated" } else { "" }
        ));
    }
    let stdout = String::from_utf8_lossy(&capture.stdout);
    let stderr = String::from_utf8_lossy(&capture.stderr);
    stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .map(|line| {
            if truncated {
                format!("{line} [output truncated]")
            } else {
                line.to_string()
            }
        })
        .ok_or_else(|| "--version produced no output".to_string())
}

#[derive(Clone, Copy)]
enum CaptureStream {
    Stdout,
    Stderr,
}

enum CaptureMessage {
    Data(CaptureStream, Vec<u8>),
    Done,
}

#[derive(Default)]
struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    done_streams: usize,
}

impl CapturedOutput {
    fn drain(&mut self, receiver: &Receiver<CaptureMessage>) {
        while let Ok(message) = receiver.try_recv() {
            match message {
                CaptureMessage::Data(CaptureStream::Stdout, bytes) => {
                    self.stdout.extend_from_slice(&bytes);
                }
                CaptureMessage::Data(CaptureStream::Stderr, bytes) => {
                    self.stderr.extend_from_slice(&bytes);
                }
                CaptureMessage::Done => self.done_streams += 1,
            }
        }
    }

    fn has_nonempty_output(&self) -> bool {
        self.stdout
            .iter()
            .chain(&self.stderr)
            .any(|byte| !byte.is_ascii_whitespace())
    }
}

fn spawn_capture_reader<R>(
    mut reader: R,
    stream: CaptureStream,
    sender: SyncSender<CaptureMessage>,
    remaining: Arc<AtomicUsize>,
    truncated: Arc<AtomicBool>,
) where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            if remaining.load(Ordering::SeqCst) == 0 {
                truncated.store(true, Ordering::SeqCst);
                break;
            }
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            };
            let retained = reserve_capture_budget(&remaining, read);
            if retained > 0
                && sender
                    .send(CaptureMessage::Data(stream, buffer[..retained].to_vec()))
                    .is_err()
            {
                return;
            }
            if retained < read || remaining.load(Ordering::SeqCst) == 0 {
                truncated.store(true, Ordering::SeqCst);
                break;
            }
        }
        drop(reader);
        let _ = sender.send(CaptureMessage::Done);
    });
}

fn reserve_capture_budget(remaining: &AtomicUsize, requested: usize) -> usize {
    let mut available = remaining.load(Ordering::SeqCst);
    loop {
        if available == 0 {
            return 0;
        }
        let retained = requested.min(available);
        match remaining.compare_exchange_weak(
            available,
            available - retained,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return retained,
            Err(actual) => available = actual,
        }
    }
}

fn kill_probe_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
}

/// Tally check types for one backend, e.g. `bundle · 4× recipe · 6× command`.
fn check_type_tally(checks: &[BackendCheckRecord]) -> String {
    let mut order: Vec<String> = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for check in checks {
        if !counts.contains_key(&check.check_type) {
            order.push(check.check_type.clone());
        }
        *counts.entry(check.check_type.clone()).or_default() += 1;
    }
    order
        .iter()
        .map(|check_type| match counts[check_type] {
            1 => check_type.clone(),
            n => format!("{n}× {check_type}"),
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Label a failed check without repeating itself: when the detail already
/// mentions the subject, the detail alone carries the information.
fn failed_check_label(check: &BackendCheckRecord) -> String {
    let subject = check.subject.trim();
    let detail = check.detail.trim();
    if detail.is_empty() {
        subject.to_string()
    } else if detail
        .to_ascii_lowercase()
        .contains(&subject.to_ascii_lowercase())
    {
        detail.to_string()
    } else {
        format!("{subject} ({detail})")
    }
}

/// Strip the `Display [id]: available via ` / `unavailable (...)` framing from
/// a stable summary so the panel does not repeat the backend name or the
/// verdict already carried by the status glyph.
fn backend_detail(summary: &BackendHealthSummary) -> String {
    let raw = summary.stable_summary.trim();
    let rest = match raw.split_once("]: ") {
        Some((_, rest)) => rest.trim(),
        None => return raw.to_string(),
    };
    let (unavailable, rest) = match rest.strip_prefix("available via ") {
        Some(detail) => (false, detail.trim()),
        None => match rest.strip_prefix("unavailable") {
            Some(detail) => (true, detail.trim()),
            None => (false, rest),
        },
    };
    // `unavailable (...)` wraps its detail in parens — unwrap before the
    // display-name echo check so a detail like `(EMUX recipe …)` matches.
    let mut detail = if unavailable {
        let inner = rest.strip_prefix('(').unwrap_or(rest);
        let inner = inner.strip_suffix(')').unwrap_or(inner);
        inner.trim()
    } else {
        rest
    };
    // Drop a leading echo of the display name inside the detail.
    if let Some(stripped) = detail.get(summary.display_name.len()..) {
        if detail
            .to_ascii_lowercase()
            .starts_with(&summary.display_name.to_ascii_lowercase())
        {
            detail = stripped
                .trim_start()
                .trim_start_matches(['-', '—', ':', ','])
                .trim();
        }
    }
    if detail.is_empty() {
        raw.to_string()
    } else {
        detail.to_string()
    }
}

pub fn run(strict: bool, json: bool) -> DynResult<()> {
    let report = fat_emulate::preflight::doctor_report();
    let palette = crate::style::Palette::stdout();
    let tool_findings = probe_external_tools();
    let kernel_dir = check_system_kernel_dir();
    let version = version_check();
    let data_dir = check_data_dir();
    let kernel_dir_hint = kernel_dir_remediation_hint();
    let extraction_engine_available = tool_findings
        .iter()
        .any(|tool| tool.extraction_engine && matches!(tool.state, ToolState::Usable { .. }));

    let available: Vec<_> = report
        .backend_summaries
        .iter()
        .filter(|summary| summary.is_available)
        .collect();
    let unavailable: Vec<_> = report
        .backend_summaries
        .iter()
        .filter(|summary| !summary.is_available)
        .collect();
    let checks: Vec<(&str, &BackendCheckRecord)> = report
        .backend_summaries
        .iter()
        .flat_map(|summary| {
            summary
                .checks
                .iter()
                .map(move |check| (summary.backend_id.as_str(), check))
        })
        .collect();

    if json {
        let payload = DoctorJson {
            report: &report,
            tools: &tool_findings,
            system_kernel_dir: KernelDirCheck {
                status: kernel_dir,
                hint: kernel_dir_hint,
            },
            version,
            data_dir,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else if palette.enabled() {
        let mut lines = vec![palette.heading("Host")];
        lines.push(format!(
            "{} {} · {}   {}",
            palette.dot_ok(),
            report.host_os,
            report.host_arch,
            palette.muted("host healthy"),
        ));

        lines.push(String::new());
        lines.push(palette.heading("Tools"));
        for tool in &tool_findings {
            lines.push(tool_panel_line(tool, &palette));
        }

        if !report.backend_summaries.is_empty() {
            lines.push(String::new());
            lines.push(palette.heading("Backends"));
            for summary in report
                .backend_summaries
                .iter()
                .filter(|summary| summary.is_available)
            {
                lines.push(format!(
                    "{} {}  {}",
                    palette.dot_ok(),
                    palette.good(&summary.display_name),
                    palette.muted(backend_detail(summary)),
                ));
            }
            for summary in report
                .backend_summaries
                .iter()
                .filter(|summary| !summary.is_available)
            {
                lines.push(format!(
                    "{} {}  {}",
                    palette.dot_bad(),
                    palette.bad(&summary.display_name),
                    palette.muted(backend_detail(summary)),
                ));
            }
        }

        if !checks.is_empty() {
            lines.push(String::new());
            lines.push(palette.heading("Checks"));
            // One grouped line per backend instead of repeating the backend id
            // and the pass/fail word on every check.
            for summary in &report.backend_summaries {
                if summary.checks.is_empty() {
                    continue;
                }
                let total = summary.checks.len();
                let failed: Vec<&BackendCheckRecord> = summary
                    .checks
                    .iter()
                    .filter(|check| !check.passed)
                    .collect();
                let (glyph, name) = if failed.is_empty() {
                    (
                        palette.check_glyph(true),
                        palette.good(&summary.display_name),
                    )
                } else {
                    (
                        palette.check_glyph(false),
                        palette.bad(&summary.display_name),
                    )
                };
                if failed.is_empty() {
                    lines.push(format!(
                        "{glyph} {name}  {}",
                        palette.muted(check_type_tally(&summary.checks)),
                    ));
                } else {
                    let failed_labels: Vec<String> = failed
                        .iter()
                        .map(|check| failed_check_label(check))
                        .collect();
                    lines.push(format!(
                        "{glyph} {name}  {}/{} — {}",
                        total - failed.len(),
                        total,
                        failed_labels.join(", "),
                    ));
                }
            }
        }

        lines.extend(environment_lines(
            &palette,
            &kernel_dir,
            &version,
            &data_dir,
            kernel_dir_hint.as_deref(),
        ));

        if !report.diagnostics.is_empty() {
            lines.push(String::new());
            lines.push(palette.heading("Diagnostics"));
            for diagnostic in &report.diagnostics {
                lines.push(format!(
                    "{} {} {}",
                    palette.dot_warn(),
                    palette.warn(&diagnostic.summary),
                    palette.muted(format!("[{}]", diagnostic.diagnostic_id)),
                ));
            }
        }

        let missing_tools = tool_findings
            .iter()
            .filter(|tool| !matches!(tool.state, ToolState::Usable { .. }))
            .count();
        lines.push(verdict_line(
            &palette,
            &checks,
            unavailable.len(),
            missing_tools,
        ));

        println!("{}", palette.panel("fat doctor", &lines));
        println!("{}", palette.muted("next: fat preflight <project>"));
    } else {
        println!("{}", palette.heading("Host Health"));
        println!("{}", palette.kv("host os", &report.host_os));
        println!("{}", palette.kv("host arch", &report.host_arch));

        print_plain_tools(&palette, &tool_findings);
        println!();
        println!("{}", palette.heading("Available Backends"));
        if available.is_empty() {
            println!("{} {}", palette.bullet("-"), palette.muted("none"));
        } else {
            for summary in &available {
                println!(
                    "{} {}",
                    palette.bullet("-"),
                    palette.good(&summary.stable_summary)
                );
            }
        }

        println!();
        println!("{}", palette.heading("Unavailable Backends"));
        if unavailable.is_empty() {
            println!("{} {}", palette.bullet("-"), palette.muted("none"));
        } else {
            for summary in &unavailable {
                println!(
                    "{} {}",
                    palette.bullet("-"),
                    palette.warn(&summary.stable_summary)
                );
            }
        }

        if !checks.is_empty() {
            println!();
            println!("{}", palette.heading("Backend Checks"));
            for (backend_id, check) in &checks {
                let verdict = if check.passed {
                    palette.good("pass")
                } else {
                    palette.bad("fail")
                };
                println!(
                    "{} {} {} {}: {} ({})",
                    palette.bullet("-"),
                    palette.code(backend_id),
                    palette.info(&check.check_type),
                    check.subject,
                    verdict,
                    check.detail
                );
            }
        }

        println!();
        for line in environment_lines(
            &palette,
            &kernel_dir,
            &version,
            &data_dir,
            kernel_dir_hint.as_deref(),
        ) {
            println!("{line}");
        }

        if !report.diagnostics.is_empty() {
            println!();
            println!("{}", palette.heading("Diagnostics"));
            for diagnostic in &report.diagnostics {
                println!(
                    "{} {} {}",
                    palette.bullet("-"),
                    palette.warn(&diagnostic.summary),
                    palette.muted(format!("[{}]", diagnostic.diagnostic_id))
                );
            }
        }
    }

    if strict && !extraction_engine_available {
        return Err(
            "strict host readiness failed: no usable extraction engine found; install or repair binwalk or unblob".into(),
        );
    }
    Ok(())
}

fn verdict_line(
    palette: &crate::style::Palette,
    checks: &[(&str, &BackendCheckRecord)],
    unavailable_backends: usize,
    missing_tools: usize,
) -> String {
    let total = checks.len();
    let passed = checks.iter().filter(|(_, check)| check.passed).count();
    let mut line = if total == 0 {
        format!(
            "{} {}",
            palette.dot_ok(),
            palette.muted("no backend checks to run")
        )
    } else {
        let all_passed = passed == total;
        let summary = if all_passed {
            palette.good(format!("{passed} of {total} checks pass"))
        } else {
            palette.bad(format!("{passed} of {total} checks pass"))
        };
        format!("{} {}", palette.check_glyph(all_passed), summary)
    };

    let mut extras = Vec::new();
    if unavailable_backends > 0 {
        extras.push(plural_count(unavailable_backends, "unavailable backend"));
    }
    if missing_tools > 0 {
        extras.push(plural_count(missing_tools, "missing tool"));
    }
    if !extras.is_empty() {
        line.push_str(&format!(
            "  {}",
            palette.muted(format!("— {}", extras.join(", ")))
        ));
    }
    line
}

fn plural_count(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Verdict of comparing the build-time version with the git checkout the
/// binary appears to have been built from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum VersionCheckStatus {
    /// No checkout identity was discoverable; nothing to compare against.
    Skipped,
    /// The checkout's described tag matches the build-time version.
    Ok,
    /// The checkout describes a different release than the running binary.
    Mismatch { described: String },
}

#[derive(serde::Serialize)]
struct VersionCheck {
    build_version: &'static str,
    #[serde(flatten)]
    status: VersionCheckStatus,
}

/// Verdict of the `FAT_SYSTEM_KERNEL_DIR` doctor check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum KernelDirStatus {
    /// The variable is unset; informational only — system-mode emulation
    /// refuses to launch later without it.
    Unset,
    /// The configured directory exists and the kernel catalog loaded.
    Ok { path: String, profiles: usize },
    /// The configured directory does not exist.
    Missing { path: String },
    /// The directory exists but the kernel catalog failed to load.
    Unloadable { path: String, error: String },
}

#[derive(serde::Serialize)]
struct KernelDirCheck {
    #[serde(flatten)]
    status: KernelDirStatus,
    hint: Option<String>,
}

/// Verdict of the data-dir doctor check: where FAT stores profiles and
/// per-project data, and whether that location accepts writes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DataDirStatus {
    /// FAT_DATA_DIR is set explicitly. Reported even when unusable, so a
    /// misconfiguration is visible instead of silently falling back to the
    /// discovered root.
    EnvSet { path: String, writable: bool },
    /// No FAT_DATA_DIR; the data root was discovered relative to the binary.
    Discovered { path: String, writable: bool },
    /// Neither an explicit variable nor a discoverable data root.
    Unavailable,
}

/// Probe the effective data root: an explicit FAT_DATA_DIR wins and is
/// reported as-is (even when broken); otherwise fall back to the same
/// discovery `fat emulate` uses.
fn check_data_dir() -> DataDirStatus {
    let env_value = std::env::var("FAT_DATA_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    classify_data_dir(env_value, crate::emulate_cmd::resolve_data_root())
}

/// Classify a data-dir probe: an explicit variable is reported even when
/// broken (so a misconfiguration is visible instead of silently falling back
/// to the discovered root), a discovered root reports writability, and
/// nothing discoverable is a failure.
fn classify_data_dir(
    env_value: Option<String>,
    discovered: Option<std::path::PathBuf>,
) -> DataDirStatus {
    if let Some(data) = env_value {
        let path = std::path::PathBuf::from(data);
        let writable = is_writable_dir(&path);
        return DataDirStatus::EnvSet {
            path: path.display().to_string(),
            writable,
        };
    }
    match discovered {
        Some(path) => {
            let writable = is_writable_dir(&path);
            DataDirStatus::Discovered {
                path: path.display().to_string(),
                writable,
            }
        }
        None => DataDirStatus::Unavailable,
    }
}

/// A directory counts as writable only if a probe file can be created and
/// removed inside it — permission bits alone do not decide it.
fn is_writable_dir(path: &std::path::Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let probe = path.join(".fat-doctor-write-probe");
    std::fs::write(&probe, b"").is_ok() && std::fs::remove_file(&probe).is_ok()
}

/// The full doctor output as one machine-readable object: the host report,
/// per-tool findings, and the environment checks.
#[derive(serde::Serialize)]
struct DoctorJson<'a> {
    #[serde(flatten)]
    report: &'a fat_emulate::preflight::DoctorReport,
    tools: &'a [ToolFinding],
    system_kernel_dir: KernelDirCheck,
    version: VersionCheck,
    data_dir: DataDirStatus,
}

/// Build the version-mismatch check for the running binary.
fn version_check() -> VersionCheck {
    let build_version = env!("CARGO_PKG_VERSION");
    VersionCheck {
        build_version,
        status: classify_version_match(build_version, describe_checkout().as_deref()),
    }
}

/// Ask git for a human-readable identity (`git describe --tags --always`) of
/// the checkout the binary may have been built from: the directory holding
/// the executable first (a cargo `target/` build lives inside its checkout),
/// then the working directory. `None` when git is unavailable, the directory
/// is not a checkout, or git fails.
fn describe_checkout() -> Option<String> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd);
    }
    candidates.iter().find_map(|dir| {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["describe", "--tags", "--always"])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    })
}

/// Compare a build-time package version against `git describe --tags
/// --always` output. A checkout with no reachable tags describes as a bare
/// commit hash, which carries no version information, so it is skipped
/// rather than flagged as a mismatch.
fn classify_version_match(build_version: &str, described: Option<&str>) -> VersionCheckStatus {
    let Some(described) = described.map(str::trim).filter(|d| !d.is_empty()) else {
        return VersionCheckStatus::Skipped;
    };
    if is_bare_commit_hash(described) {
        return VersionCheckStatus::Skipped;
    }
    // Both `v2.0.0-alpha.1` and `v2.0.0-alpha.1-3-g717913a` name the version.
    if described.contains(build_version) {
        VersionCheckStatus::Ok
    } else {
        VersionCheckStatus::Mismatch {
            described: described.to_string(),
        }
    }
}

/// A bare `git describe --always` fallback: nothing but 7-40 hex digits.
fn is_bare_commit_hash(described: &str) -> bool {
    (7..=40).contains(&described.len()) && described.chars().all(|c| c.is_ascii_hexdigit())
}

/// Probe `FAT_SYSTEM_KERNEL_DIR` and the kernel catalog for the doctor check.
fn check_system_kernel_dir() -> KernelDirStatus {
    let configured = std::env::var(fat_emulate::kernel_catalog::SYSTEM_KERNEL_DIR_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(path) = configured else {
        return KernelDirStatus::Unset;
    };
    let dir_exists = std::path::Path::new(&path).is_dir();
    let catalog = if dir_exists {
        fat_emulate::kernel_catalog::load_embedded_kernel_catalog().map(|profiles| profiles.len())
    } else {
        Ok(0)
    };
    classify_kernel_dir(Some(path), dir_exists, catalog)
}

/// Classify a kernel-dir probe: unset is informational, a missing directory
/// and an unloadable catalog are failures, and a loaded catalog is healthy.
fn classify_kernel_dir(
    configured: Option<String>,
    dir_exists: bool,
    catalog: Result<usize, String>,
) -> KernelDirStatus {
    let Some(path) = configured else {
        return KernelDirStatus::Unset;
    };
    if !dir_exists {
        return KernelDirStatus::Missing { path };
    }
    match catalog {
        Ok(profiles) => KernelDirStatus::Ok { path, profiles },
        Err(error) => KernelDirStatus::Unloadable { path, error },
    }
}

/// Path of the asset verification helper when the checkout provides it. The
/// helper is only pointed at, never executed here.
fn kernel_dir_remediation_hint() -> Option<String> {
    const SCRIPT: &str = "scripts/verify-external-assets.py";
    let from_cwd = std::env::current_dir().ok().map(|dir| dir.join(SCRIPT));
    let from_exe = std::env::current_exe().ok().and_then(|exe| {
        exe.ancestors().skip(1).find_map(|dir| {
            let candidate = dir.join(SCRIPT);
            candidate.is_file().then_some(candidate)
        })
    });
    from_cwd
        .into_iter()
        .chain(from_exe)
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.display().to_string())
}

/// Human-readable lines for the doctor environment checks: the kernel-dir
/// probe and the binary-vs-checkout version comparison.
fn environment_lines(
    palette: &crate::style::Palette,
    kernel_dir: &KernelDirStatus,
    version: &VersionCheck,
    data_dir: &DataDirStatus,
    hint: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![palette.heading("Environment")];
    match &version.status {
        VersionCheckStatus::Skipped => {}
        VersionCheckStatus::Ok => lines.push(format!(
            "{} fat {}  {}",
            palette.dot_ok(),
            version.build_version,
            palette.muted("checkout tag matches")
        )),
        VersionCheckStatus::Mismatch { described } => lines.push(format!(
            "{} {}  {}",
            palette.dot_warn(),
            palette.warn(format!("fat {}", version.build_version)),
            palette.muted(format!(
                "checkout is {described} — rebuild the binary or reinstall fat"
            ))
        )),
    }
    let hint_note = hint.map(|hint| format!("; see {hint}")).unwrap_or_default();
    match kernel_dir {
        KernelDirStatus::Unset => lines.push(format!(
            "{} {}  {}",
            palette.dot_muted(),
            palette.code("FAT_SYSTEM_KERNEL_DIR"),
            palette.muted(format!(
                "unset — system-mode emulation will refuse until it is configured{hint_note}"
            )),
        )),
        KernelDirStatus::Ok { path, profiles } => lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            palette.code(path),
            palette.muted(format!("kernel catalog loaded ({profiles} profiles)")),
        )),
        KernelDirStatus::Missing { path } => lines.push(format!(
            "{} {}  {}",
            palette.dot_bad(),
            palette.code(path),
            palette.muted(format!(
                "directory does not exist — set FAT_SYSTEM_KERNEL_DIR to the directory holding the system-mode kernel images{hint_note}"
            )),
        )),
        KernelDirStatus::Unloadable { path, error } => lines.push(format!(
            "{} {}  {}",
            palette.dot_bad(),
            palette.code(path),
            palette.muted(format!(
                "kernel catalog failed to load: {error}{hint_note}"
            )),
        )),
    }
    match data_dir {
        DataDirStatus::EnvSet {
            path,
            writable: true,
        } => lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            palette.code(path),
            palette.muted("FAT_DATA_DIR set and writable"),
        )),
        DataDirStatus::EnvSet {
            path,
            writable: false,
        } => lines.push(format!(
            "{} {}  {}",
            palette.dot_bad(),
            palette.code(path),
            palette.muted("FAT_DATA_DIR is set but not a writable directory — fix or unset it"),
        )),
        DataDirStatus::Discovered {
            path,
            writable: true,
        } => lines.push(format!(
            "{} {}  {}",
            palette.dot_ok(),
            palette.code(path),
            palette.muted("data root discovered and writable"),
        )),
        DataDirStatus::Discovered {
            path,
            writable: false,
        } => lines.push(format!(
            "{} {}  {}",
            palette.dot_bad(),
            palette.code(path),
            palette.muted("data root is not writable — set FAT_DATA_DIR to a writable directory"),
        )),
        DataDirStatus::Unavailable => lines.push(format!(
            "{} {}  {}",
            palette.dot_bad(),
            palette.code("FAT_DATA_DIR"),
            palette.muted("no data root discovered — set FAT_DATA_DIR to a writable directory"),
        )),
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdb_15_2_is_flagged_and_neighbouring_releases_are_not() {
        // The real shape of `gdb --version` first lines.
        assert!(gdb_version_advisory("GNU gdb (Debian 15.2-1) 15.2").is_some());
        assert!(gdb_version_advisory("GNU gdb 15.2").is_some());
        // Adjacent releases are fine; 15.10 must not be read as 15.1.
        assert!(gdb_version_advisory("GNU gdb (GDB) 15.1").is_none());
        assert!(gdb_version_advisory("GNU gdb (GDB) 16.1").is_none());
        assert!(gdb_version_advisory("GNU gdb (GDB) 15.20").is_none());
        assert!(gdb_version_advisory("GNU gdb (GDB) 14.2").is_none());
    }

    #[test]
    fn gdb_advisory_ignores_unparseable_version_text() {
        assert!(gdb_version_advisory("").is_none());
        assert!(gdb_version_advisory("not a version").is_none());
        assert!(gdb_version_advisory("gdb 15").is_none());
    }

    #[test]
    fn only_version_probed_tools_declare_a_version_probe() {
        // Probing costs a process spawn per tool; keep the set deliberate.
        let probed: Vec<&str> = EXTERNAL_TOOLS
            .iter()
            .filter(|tool| tool.version_probed)
            .map(|tool| tool.names[0])
            .collect();
        assert_eq!(probed, vec!["binwalk", "unblob", "gdb-multiarch"]);
    }

    #[test]
    fn version_check_skips_when_no_checkout_is_described() {
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", None),
            VersionCheckStatus::Skipped
        );
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", Some("  ")),
            VersionCheckStatus::Skipped
        );
    }

    #[test]
    fn version_check_skips_bare_commit_hash_describe_output() {
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", Some("717913a")),
            VersionCheckStatus::Skipped
        );
    }

    #[test]
    fn version_check_matches_a_tag_named_after_the_build_version() {
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", Some("v2.0.0-alpha.1")),
            VersionCheckStatus::Ok
        );
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", Some("v2.0.0-alpha.1-3-g717913a")),
            VersionCheckStatus::Ok
        );
    }

    #[test]
    fn version_check_flags_a_checkout_describing_a_different_release() {
        assert_eq!(
            classify_version_match("2.0.0-alpha.1", Some("v1.9.0")),
            VersionCheckStatus::Mismatch {
                described: "v1.9.0".to_string()
            }
        );
    }

    #[test]
    fn kernel_dir_check_classifies_unset_as_informational() {
        assert_eq!(
            classify_kernel_dir(None, false, Ok(0)),
            KernelDirStatus::Unset
        );
    }

    #[test]
    fn kernel_dir_check_classifies_a_missing_directory() {
        assert_eq!(
            classify_kernel_dir(Some("/does/not/exist".to_string()), false, Ok(4)),
            KernelDirStatus::Missing {
                path: "/does/not/exist".to_string()
            }
        );
    }

    #[test]
    fn kernel_dir_check_classifies_an_unloadable_catalog() {
        assert_eq!(
            classify_kernel_dir(
                Some("/kernels".to_string()),
                true,
                Err("parse kernel catalog: bad json".to_string())
            ),
            KernelDirStatus::Unloadable {
                path: "/kernels".to_string(),
                error: "parse kernel catalog: bad json".to_string()
            }
        );
    }

    #[test]
    fn kernel_dir_check_classifies_a_loaded_catalog() {
        assert_eq!(
            classify_kernel_dir(Some("/kernels".to_string()), true, Ok(4)),
            KernelDirStatus::Ok {
                path: "/kernels".to_string(),
                profiles: 4
            }
        );
    }

    #[test]
    fn data_dir_probe_reports_writable_and_unwritable_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(is_writable_dir(dir.path()));
        assert!(!is_writable_dir(&dir.path().join("missing")));
    }

    #[test]
    fn data_dir_check_reports_an_explicit_broken_variable_instead_of_falling_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        // An env var pointing at a file (not a directory) must surface as a
        // broken EnvSet rather than silently discovering a healthy root.
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"").expect("write probe file");
        assert_eq!(
            classify_data_dir(
                Some(file.display().to_string()),
                Some(dir.path().to_path_buf())
            ),
            DataDirStatus::EnvSet {
                path: file.display().to_string(),
                writable: false
            }
        );
    }

    #[test]
    fn data_dir_check_classifies_a_discovered_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            classify_data_dir(None, Some(dir.path().to_path_buf())),
            DataDirStatus::Discovered {
                path: dir.path().display().to_string(),
                writable: true
            }
        );
    }

    #[test]
    fn data_dir_check_classifies_no_root_as_unavailable() {
        assert_eq!(classify_data_dir(None, None), DataDirStatus::Unavailable);
    }
}
