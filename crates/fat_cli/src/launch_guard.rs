//! Cleanup guard for the window between spawning a backend process and
//! recording its pid.
//!
//! `fat emulate` spawns the emulator, then writes the run record that carries
//! its pid. Interrupted in between, it would leave a process that nothing on
//! disk names: `fat emulate list` cannot show it and `fat emulate --stop`
//! cannot find it. While armed, an interrupt terminates the spawned process
//! before exiting, and a failure to persist the record terminates it directly.
//!
//! The guard covers only that window. Once the pid is durable the emulator is
//! meant to outlive the CLI, so it is disarmed and a later Ctrl-C leaves the
//! running emulation alone.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Pid armed for cleanup, or 0 when no launch is in flight.
static GUARDED_PID: AtomicU32 = AtomicU32::new(0);
/// Whether the armed pid leads its own process group.
static GUARDED_LEADS_GROUP: AtomicBool = AtomicBool::new(false);

/// Arm a child that leads its own process group — one spawned with
/// `process_group(0)`. The whole group is signalled, so anything the child
/// spawned goes with it.
pub fn arm_process_group(pid: u32) {
    arm(pid, true);
}

/// Arm a child that shares this process's group. Only that pid is signalled:
/// signalling the group would take down the CLI itself and its siblings.
pub fn arm_process(pid: u32) {
    arm(pid, false);
}

/// Close the window. The spawned process is now named by a durable record and
/// is expected to outlive this command.
pub fn disarm() {
    GUARDED_PID.store(0, Ordering::SeqCst);
}

/// Terminate the armed process and close the window, for failures that happen
/// after the spawn but before the pid reaches disk.
pub fn terminate_and_disarm() {
    if let Some(target) = guarded_target() {
        send_terminate(target);
    }
    disarm();
}

/// The `kill(2)` target for the armed process: negative for a process group,
/// positive for a single pid, `None` when nothing is armed.
fn guarded_target() -> Option<i32> {
    let pid = i32::try_from(GUARDED_PID.load(Ordering::SeqCst)).ok()?;
    if pid == 0 {
        return None;
    }
    if GUARDED_LEADS_GROUP.load(Ordering::SeqCst) {
        Some(-pid)
    } else {
        Some(pid)
    }
}

fn arm(pid: u32, leads_group: bool) {
    // A pid that does not fit in i32 could never be a valid kill(2) target.
    if i32::try_from(pid).is_err() {
        return;
    }
    install_handlers();
    GUARDED_LEADS_GROUP.store(leads_group, Ordering::SeqCst);
    GUARDED_PID.store(pid, Ordering::SeqCst);
}

#[cfg(unix)]
/// Deliberately a bare `kill`, not [`crate::emulate_cmd`]'s terminate helpers.
/// This runs inside a signal handler, where only async-signal-safe calls are
/// allowed: the helpers there allocate error strings and sleep between
/// escalation rounds, neither of which is safe here.
fn send_terminate(target: i32) {
    unsafe { libc::kill(target, libc::SIGTERM) };
}

#[cfg(not(unix))]
fn send_terminate(_target: i32) {}

#[cfg(unix)]
fn install_handlers() {
    use std::sync::Once;

    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            unsafe { libc::signal(signal, handle_interrupt as *const () as libc::sighandler_t) };
        }
    });
}

#[cfg(not(unix))]
fn install_handlers() {}

/// Everything here is async-signal-safe: two atomic loads, `kill`, `signal`,
/// `raise`. Re-raising with the default disposition preserves the conventional
/// `128 + signal` exit status instead of reporting a clean exit.
#[cfg(unix)]
extern "C" fn handle_interrupt(signal: i32) {
    if let Some(target) = guarded_target() {
        send_terminate(target);
    }
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    /// The guard is process-global state, so guard tests run one at a time.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        disarm();
        guard
    }

    fn spawn_group_leader() -> std::process::Child {
        let mut command = Command::new("sleep");
        command.arg("60");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().expect("spawn a stand-in emulator")
    }

    fn is_running(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn a_group_leader_is_signalled_as_a_whole_group() {
        let _lock = lock();
        arm_process_group(4242);
        assert_eq!(guarded_target(), Some(-4242));
        disarm();
    }

    #[test]
    fn a_shared_group_child_is_signalled_by_pid_alone() {
        let _lock = lock();
        // Signalling -pid here would reach the CLI's own process group.
        arm_process(4242);
        assert_eq!(guarded_target(), Some(4242));
        disarm();
    }

    #[test]
    fn disarming_leaves_nothing_to_signal() {
        let _lock = lock();
        arm_process_group(4242);
        disarm();
        assert_eq!(guarded_target(), None);
    }

    #[test]
    fn terminate_and_disarm_kills_the_spawned_process() {
        let _lock = lock();
        let mut child = spawn_group_leader();
        let pid = child.id();
        assert!(is_running(pid), "stand-in emulator should be running");

        arm_process_group(pid);
        terminate_and_disarm();

        let deadline = Instant::now() + Duration::from_secs(5);
        while is_running(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.wait();
        assert!(!is_running(pid), "guarded process should have been reaped");
        assert_eq!(guarded_target(), None, "guard should be closed afterwards");
    }
}
