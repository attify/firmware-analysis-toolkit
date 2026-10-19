//! Userspace GDB attachment through a temporary, owned QEMU SSH forward.

use crate::debug_cmd::DynResult;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Clone, Args)]
pub struct ProcessArgs {
    #[arg(long)]
    project: PathBuf,
    #[arg(long)]
    session_id: Option<String>,
    /// Guest PID to attach (not a host PID).
    #[arg(long, value_parser=clap::value_parser!(u32).range(2..))]
    pid: u32,
    /// Guest SSH account with ptrace permission and an explicitly provisioned key.
    #[arg(long)]
    user: String,
    #[arg(long)]
    identity_file: PathBuf,
    /// Absolute guest path to a compatible, already provisioned gdbserver.
    #[arg(long)]
    gdbserver: String,
    /// Matching extracted rootfs for symbols; omitting it reads files from the guest.
    #[arg(long)]
    sysroot: Option<PathBuf>,
    /// GDB command after identity/thread inspection; repeat for multiple commands.
    #[arg(long)]
    command: Vec<String>,
    /// Overall debugger deadline, including symbol transfer and breakpoint waits.
    #[arg(long, default_value_t=120, value_parser=clap::value_parser!(u64).range(1..=600))]
    timeout: u64,
    #[arg(long)]
    json: bool,
}
pub fn run(args: ProcessArgs) -> DynResult<()> {
    #[cfg(unix)]
    {
        unix::run(args)
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        Err("BMC process debugging currently requires a Unix host with SSH and GDB".into())
    }
}
#[cfg(unix)]
mod unix {
    use super::*;
    use crate::debug_cmd::{
        find_gdb_binary, load_context, runtime_monitor_command, write_runtime_json_artifact,
        DebugContext,
    };
    use fat_core::artifacts::ArtifactKind;
    use fat_core::runs::RunStatus;
    use serde::Serialize;
    use serde_json::json;
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub(super) fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
    fn gdb_quote(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
    pub(super) fn sysroot_value(path: &str) -> String {
        path.to_string()
    }
    pub(super) fn validate_guest(path: &str, user: &str, pid: u32) -> DynResult<()> {
        if pid < 2
            || !path.starts_with('/')
            || path.len() > 1024
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
            || user.is_empty()
            || !user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("use a guest PID greater than one, a simple SSH username and an absolute gdbserver path without shell syntax".into());
        }
        Ok(())
    }
    pub(super) fn process_start(stat: &str) -> Option<&str> {
        stat.rsplit_once(") ")?.1.split_whitespace().nth(19)
    }
    pub(super) fn has_forward(text: &str, nic: u8, port: u16) -> bool {
        let mut matching = false;
        for line in text.lines() {
            if line.starts_with("Hub ") {
                matching = line.ends_with(&format!("(bmc{nic}):"));
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if matching
                && fields.len() >= 6
                && fields[0] == "TCP[HOST_FORWARD]"
                && fields[2] == "127.0.0.1"
                && fields[3] == port.to_string()
                && fields[5] == "22"
            {
                return true;
            }
        }
        false
    }
    struct Forward<'a> {
        context: &'a DebugContext,
        nic: u8,
        port: u16,
        closed: bool,
    }
    impl Forward<'_> {
        fn close(&mut self) -> bool {
            if self.closed {
                return true;
            }
            let _ = runtime_monitor_command(
                self.context,
                &format!("hostfwd_remove bmc{} tcp:127.0.0.1:{}", self.nic, self.port),
            );
            self.closed = runtime_monitor_command(self.context, "info usernet")
                .is_ok_and(|s| !has_forward(&s, self.nic, self.port));
            self.closed
        }
    }
    impl Drop for Forward<'_> {
        fn drop(&mut self) {
            if !self.close() {
                eprintln!("BMC debug cleanup failed: could not confirm removal of bmc{} SSH forward 127.0.0.1:{}; inspect this runtime or stop it with fat emulate stop", self.nic, self.port);
            }
        }
    }
    struct ProcessGroup(std::process::Child);
    impl Drop for ProcessGroup {
        fn drop(&mut self) {
            // This group contains only the helper we spawned and its descendants.
            // Cover I/O errors as well as normal exit and deadline termination.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
    #[derive(Debug, Serialize)]
    pub(super) struct Output {
        pub success: bool,
        pub timed_out: bool,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        output_limit_exceeded: bool,
    }
    pub(super) fn bounded(cmd: &mut Command, timeout: Duration) -> DynResult<Output> {
        let out = tempfile::NamedTempFile::new()?;
        let err = tempfile::NamedTempFile::new()?;
        cmd.stdin(Stdio::null())
            .stdout(out.reopen()?)
            .stderr(err.reopen()?)
            .process_group(0);
        let mut group = ProcessGroup(cmd.spawn()?);
        let child = &mut group.0;
        let start = Instant::now();
        let mut timed_out = false;
        let mut output_limit = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            output_limit = out.as_file().metadata()?.len() > 8 * 1024 * 1024
                || err.as_file().metadata()?.len() > 8 * 1024 * 1024;
            timed_out = start.elapsed() >= timeout;
            if timed_out || output_limit {
                // The group contains only this debugger/SSH helper and its children.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        drop(group);
        // A short-lived helper can exceed the budget and exit between polls.
        output_limit |= out.as_file().metadata()?.len() > 8 * 1024 * 1024
            || err.as_file().metadata()?.len() > 8 * 1024 * 1024;
        let read = |file: &tempfile::NamedTempFile| -> DynResult<String> {
            let mut b = vec![];
            file.reopen()?.take(8 * 1024 * 1024).read_to_end(&mut b)?;
            Ok(String::from_utf8_lossy(&b).into_owned())
        };
        Ok(Output {
            success: status.success() && !timed_out && !output_limit,
            timed_out,
            exit_code: status.code(),
            stdout: read(&out)?,
            stderr: read(&err)?,
            output_limit_exceeded: output_limit,
        })
    }
    fn identity(ssh: &[String], pid: u32) -> DynResult<Output> {
        let command=format!("cat /proc/{pid}/stat && readlink /proc/{pid}/exe && (if command -v sha256sum >/dev/null 2>&1; then sha256sum /proc/{pid}/exe; else openssl dgst -sha256 /proc/{pid}/exe; fi) && cat /proc/{pid}/maps");
        bounded(
            Command::new("ssh").args(ssh).arg(command),
            Duration::from_secs(15),
        )
    }
    pub(super) fn run(args: ProcessArgs) -> DynResult<()> {
        validate_guest(&args.gdbserver, &args.user, args.pid)?;
        let key = fs::canonicalize(&args.identity_file)?;
        if !key.is_file() {
            return Err("identity-file must be a file".into());
        }
        let sysroot = args.sysroot.as_ref().map(fs::canonicalize).transpose()?;
        if sysroot.as_ref().is_some_and(|p| !p.is_dir()) {
            return Err("sysroot must be a directory".into());
        }
        if [Some(&key), sysroot.as_ref()]
            .into_iter()
            .flatten()
            .any(|p| p.to_string_lossy().contains(['\r', '\n']))
        {
            return Err("paths must not contain newlines".into());
        }
        let gdb = find_gdb_binary().ok_or("GDB is unavailable")?;
        let context = load_context(&args.project, args.session_id.as_deref())?;
        if context.view.run.status != RunStatus::Running
            || context.view.run.backend_driver != "qemu-direct"
        {
            return Err("requires a running native BMC session".into());
        }
        let config = crate::emulate_cmd::load_rehosting_recipe_record(
            &context.store,
            &context.view.session.session_id,
            &context.view.run.run_id,
        )?
        .and_then(|r| r.bmc_boot)
        .ok_or("selected runtime is not a BMC profile")?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let nic = config.management_nic;
        // A read error can occur after QEMU applies a mutation. Arm cleanup first.
        if has_forward(
            &runtime_monitor_command(&context, "info usernet")?,
            nic,
            port,
        ) {
            return Err("allocated port already belongs to a QEMU forward".into());
        }
        let mut forward = Forward {
            context: &context,
            nic,
            port,
            closed: false,
        };
        // Only the selected QEMU runtime receives this temporary SSH forward.
        let added = runtime_monitor_command(
            &context,
            &format!("hostfwd_add bmc{nic} tcp:127.0.0.1:{port}-:22"),
        )?;
        if added.contains("Could not") || added.contains("Error") {
            return Err("QEMU rejected the temporary SSH forwarding rule".into());
        }
        if !has_forward(
            &runtime_monitor_command(&context, "info usernet")?,
            nic,
            port,
        ) {
            return Err("QEMU did not install the SSH forwarding rule".into());
        }
        let known_hosts = tempfile::NamedTempFile::new()?;
        let ssh = vec![
            "-F".into(),
            "/dev/null".into(),
            "-T".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "ConnectTimeout=5".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            format!(
                "UserKnownHostsFile={}",
                gdb_quote(&known_hosts.path().display().to_string())
            ),
            "-i".into(),
            key.display().to_string(),
            "-p".into(),
            port.to_string(),
            format!("{}@127.0.0.1", args.user),
        ];
        let before = identity(&ssh, args.pid)?;
        if !before.success {
            return Err(format!(
                "guest process identity/SSH failed: {}",
                before.stderr.trim()
            )
            .into());
        }
        let start_before = before
            .stdout
            .lines()
            .next()
            .and_then(process_start)
            .ok_or("guest process identity is malformed")?
            .to_string();
        let remote = format!("{} --once --attach - {}", quote(&args.gdbserver), args.pid);
        let pipe = std::iter::once("ssh".to_string())
            .chain(ssh.iter().cloned())
            .chain([remote])
            .map(|s| quote(&s))
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = Command::new(gdb);
        command
            .args([
                "-q",
                "-nx",
                "-nh",
                "--batch",
                "-iex",
                "set auto-load off",
                "-iex",
                "set debuginfod enabled off",
                "-ex",
                "set pagination off",
                "-ex",
                "set print frame-arguments none",
                "-ex",
            ])
            .arg(format!(
                "set sysroot {}",
                sysroot.as_ref().map_or("target:".into(), |p| sysroot_value(
                    &p.display().to_string()
                ))
            ))
            .arg("-ex")
            .arg(format!("target remote | {pipe}"))
            .args(["-ex", "info inferiors", "-ex", "info threads"]);
        if args.command.is_empty() {
            command.args(["-ex", "bt 8"]);
        }
        for c in &args.command {
            command.arg("-ex").arg(c);
        }
        command.args(["-ex", "detach"]);
        let debug = bounded(&mut command, Duration::from_secs(args.timeout));
        let after = identity(&ssh, args.pid);
        let removed = forward.close();
        let after = after?;
        let debug = debug?;
        let same_process = after.success
            && after.stdout.lines().next().and_then(process_start) == Some(start_before.as_str())
            && before.stdout.lines().nth(1) == after.stdout.lines().nth(1)
            && before.stdout.lines().nth(2) == after.stdout.lines().nth(2);
        let resumed = after
            .stdout
            .lines()
            .next()
            .and_then(|s| s.rsplit_once(") "))
            .and_then(|(_, s)| s.split_whitespace().next())
            .is_some_and(|s| s != "t" && s != "T" && s != "Z");
        let detached = debug.stdout.contains(" detached]");
        let passed = debug.success && same_process && resumed && detached && removed;
        let report = json!({"schema_version":"bmc-process/v1","session_id":context.view.session.session_id,"run_id":context.view.run.run_id,"guest_pid":args.pid,"guest_user":args.user,"gdbserver":args.gdbserver,"sysroot":sysroot,"commands":args.command,"ssh_forward_port":port,"ssh_host_key_policy":"accept-new on temporary forward owned by this QEMU runtime","before":before,"debugger":debug,"after":after,"same_process":same_process,"process_resumed":resumed,"detach_observed":detached,"forward_removed":removed,"passed":passed});
        let text = serde_json::to_string_pretty(&report)?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        write_runtime_json_artifact(
            &context.store,
            &context.project,
            &context.view.session.session_id,
            &context.view.run.run_id,
            ArtifactKind::RuntimeDebug,
            &format!("bmc-process-{stamp}"),
            "fat debug process",
            "guest process GDB attachment",
            "debug",
            &context.view.run.backend_driver,
            context.view.run.substrate_kind,
            &text,
        )?;
        if args.json {
            println!("{text}");
        } else {
            print!("{}", debug.stdout);
            eprint!("{}", debug.stderr);
            println!(
                "same process: {same_process}; resumed: {resumed}; SSH forward removed: {removed}"
            );
        }
        if passed {
            Ok(())
        } else {
            Err("process debug did not complete with the same resumed process and removed forward; inspect the runtime artifact".into())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::*;
    #[test]
    fn gdb_sysroot_is_a_literal_path_not_a_quoted_shell_argument() {
        assert_eq!(sysroot_value("/tmp/root fs"), "/tmp/root fs");
    }
    #[test]
    fn process_identity_rejects_reused_pid() {
        let a = "161 (bmcweb) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 100 0";
        assert_eq!(process_start(a), Some("100"));
        assert_ne!(process_start(a), process_start(&a.replace("100", "200")));
        assert_eq!(process_start("161 (name with ) spaces) S 1"), None);
    }
    #[test]
    fn monitor_forward_requires_matching_nic_and_destination() {
        let text = "Hub -1 (bmc1):\n  TCP[HOST_FORWARD] 21 127.0.0.1 43210 10.0.3.15 22 0 0\n";
        assert!(has_forward(text, 1, 43210));
        assert!(!has_forward(text, 0, 43210));
        assert!(!has_forward(text, 1, 43211));
        assert!(!has_forward(&text.replace(" 22 ", " 443 "), 1, 43210));
    }
    #[test]
    fn quoting_preserves_shell_metacharacters_without_execution() {
        let value = "/tmp/key's $(touch /tmp/unwanted)";
        let result = std::process::Command::new("sh")
            .args(["-c", &format!("printf '%s' {}", quote(value))])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(result.stdout).unwrap(), value);
        assert!(validate_guest("/tmp/gdbserver", "sysadmin", 5).is_ok());
        for path in ["gdbserver", "/tmp/gdb\ncommand", "/tmp/gdb;reboot"] {
            assert!(validate_guest(path, "root", 5).is_err());
        }
        assert!(validate_guest("/tmp/gdbserver", "-oProxyCommand=x", 5).is_err());
    }
    #[test]
    fn batch_deadline_stops_the_debugger_process_group() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "sleep 30 & wait"]);
        let result = bounded(&mut cmd, std::time::Duration::from_millis(100)).unwrap();
        assert!(result.timed_out);
        assert!(!result.success);
    }
    #[test]
    fn oversized_output_is_not_reported_as_complete_after_fast_exit() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "dd if=/dev/zero bs=1048576 count=9 2>/dev/null"]);
        let result = bounded(&mut cmd, std::time::Duration::from_secs(5)).unwrap();
        assert!(!result.success);
        let report = serde_json::to_value(result).unwrap();
        assert_eq!(report["output_limit_exceeded"], true);
        assert_eq!(report["stdout"].as_str().unwrap().len(), 8 * 1024 * 1024);
    }
}
