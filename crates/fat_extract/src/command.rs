use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    Succeeded,
    Failed,
    TimedOut,
}

impl CommandOutcome {
    pub fn succeeded(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub fn timed_out(self) -> bool {
        matches!(self, Self::TimedOut)
    }
}

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Run an external extractor with its output streaming into `log_path` and an
/// optional deadline.
///
/// The child appends straight into the log file, so `tail -f` shows a long
/// extraction as it happens and a full pipe can never wedge it. `on_tick` is
/// called on every poll while the child runs; pacing the reports it produces is
/// the caller's business.
pub fn run_logged_command<I>(
    program: &str,
    args: I,
    current_dir: &Path,
    log_path: &Path,
    timeout: Option<Duration>,
    on_tick: &mut dyn FnMut(Duration),
) -> io::Result<CommandOutcome>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    let rendered_args = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(log_path, format!("$ {program} {rendered_args}\n"))?;

    let mut command = Command::new(program);
    command
        .args(&args)
        .current_dir(current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(append_handle(log_path)?))
        .stderr(Stdio::from(append_handle(log_path)?));
    // Extractors spawn helpers; the whole group has to be reachable for a kill.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            append_line(log_path, &format!("failed to run {program}: {err}"))?;
            return Ok(CommandOutcome::Failed);
        }
    };
    let process_group_id = child.id();

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait()? {
            Some(status) => break (Some(status), false),
            None => {
                if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                    terminate_process_group(&mut child, process_group_id);
                    break (child.try_wait()?, true);
                }
                on_tick(started.elapsed());
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    };

    if timed_out {
        // A remaining retry deadline can be fractional (for example 7.999s
        // of an 8s budget). Round up rather than claiming it expired a second
        // early or reporting a positive subsecond timeout as zero seconds.
        let seconds = timeout
            .map(|timeout| {
                timeout
                    .as_secs()
                    .saturating_add(u64::from(timeout.subsec_nanos() != 0))
            })
            .unwrap_or_default();
        append_line(
            log_path,
            &format!("timeout after {seconds}s; process group {process_group_id} killed"),
        )?;
        append_line(log_path, "exit=-1")?;
        return Ok(CommandOutcome::TimedOut);
    }

    let code = status.and_then(|status| status.code()).unwrap_or(-1);
    append_line(log_path, &format!("exit={code}"))?;
    Ok(if status.is_some_and(|status| status.success()) {
        CommandOutcome::Succeeded
    } else {
        CommandOutcome::Failed
    })
}

/// Whether a program is runnable from PATH.
pub fn command_available(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn append_handle(log_path: &Path) -> io::Result<fs::File> {
    fs::File::options().append(true).open(log_path)
}

fn append_line(log_path: &Path, line: &str) -> io::Result<()> {
    writeln!(append_handle(log_path)?, "{line}")
}

/// SIGTERM the whole group, then SIGKILL whatever survives. Killing only the
/// direct child would leave binwalk's and unblob's helpers running.
fn terminate_process_group(child: &mut Child, process_group_id: u32) {
    for signal in [terminate_signal(), kill_signal()] {
        let _ = signal_process_group(process_group_id, signal);
        for _ in 0..40 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn signal_process_group(process_group_id: u32, signal: i32) -> io::Result<()> {
    let process_group_id = i32::try_from(process_group_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process group id overflow"))?;
    if unsafe { libc::kill(-process_group_id, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_process_group(_process_group_id: u32, _signal: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process-group signaling is unavailable",
    ))
}

#[cfg(unix)]
const fn terminate_signal() -> i32 {
    libc::SIGTERM
}

#[cfg(not(unix))]
const fn terminate_signal() -> i32 {
    15
}

#[cfg(unix)]
const fn kill_signal() -> i32 {
    libc::SIGKILL
}

#[cfg(not(unix))]
const fn kill_signal() -> i32 {
    9
}
