use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use fat_core::runtime_store::RuntimeStore;
use fat_core::staging::StagingManifest;
use tempfile::tempdir;

fn serial_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(unix)]
struct EscapedChildGuard {
    pid_file: PathBuf,
}

#[cfg(unix)]
impl EscapedChildGuard {
    fn new(pid_file: PathBuf) -> Self {
        Self { pid_file }
    }
}

#[cfg(unix)]
impl Drop for EscapedChildGuard {
    fn drop(&mut self) {
        let Ok(pid) = std::fs::read_to_string(&self.pid_file) else {
            return;
        };
        let Ok(pid) = pid.trim().parse::<i32>() else {
            return;
        };
        if pid <= 1 {
            return;
        }

        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        while Instant::now() < deadline {
            let still_exists = unsafe { libc::kill(pid, 0) } == 0;
            if !still_exists {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

struct NativeSessionGuard {
    project_dir: PathBuf,
    runtime_env_dir: PathBuf,
    session_id: &'static str,
    active: bool,
}

impl NativeSessionGuard {
    fn new(project_dir: PathBuf, runtime_env_dir: PathBuf, session_id: &'static str) -> Self {
        Self {
            project_dir,
            runtime_env_dir,
            session_id,
            active: true,
        }
    }

    fn stop(&mut self) -> Output {
        let output = self.try_stop_output().expect("fat emulate --stop runs");
        if output.status.success() {
            self.active = false;
        }
        output
    }

    fn try_stop_output(&self) -> std::io::Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_fat"))
            .env("PATH", &self.runtime_env_dir)
            .env("FAT_DATA_DIR", &self.runtime_env_dir)
            .env("FAT_SYSTEM_KERNEL_DIR", &self.runtime_env_dir)
            .args([
                "emulate",
                "--project",
                self.project_dir.to_str().expect("project path"),
                "--session-id",
                self.session_id,
                "--stop",
            ])
            .output()
    }
}

impl Drop for NativeSessionGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.try_stop_output();
        }
    }
}

#[test]
fn fat_doctor_strict_times_out_hanging_extraction_engines() {
    let _serial = serial_guard();
    let path_dir = tempdir().expect("tempdir");
    make_executable_with_contents(
        path_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/sleep 30\n",
    );
    make_executable_with_contents(path_dir.path().join("unblob"), "#!/bin/sh\n/bin/sleep 30\n");
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["doctor", "--strict"])
        .output()
        .expect("fat doctor runs");

    assert!(!output.status.success(), "{output:?}");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "probe did not time out"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("timed out"));
}

#[cfg(unix)]
#[test]
fn fat_doctor_reaps_background_children_that_inherit_probe_output() {
    let _serial = serial_guard();
    // The behaviour under test is that doctor does not block on output pipes it
    // handed to a probe's background child: if it did, every attempt would take
    // the child's full 10 seconds. A single slow attempt on a host running many
    // test binaries at once says nothing about that, so retry rather than
    // reporting a busy machine as a defect.
    const ATTEMPTS: usize = 5;
    for attempt in 1..=ATTEMPTS {
        let path_dir = tempdir().expect("tempdir");
        let forks = "#!/bin/sh\n/bin/sleep 10 &\necho extractor-1.0\nexit 0\n";
        make_executable_with_contents(path_dir.path().join("binwalk"), forks);
        make_executable_with_contents(path_dir.path().join("unblob"), forks);
        let started = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .env("PATH", path_dir.path())
            .args(["doctor", "--strict"])
            .output()
            .expect("fat doctor runs");
        let elapsed = started.elapsed();

        if !output.status.success() {
            // A loaded host can push the probe's `echo` past doctor's two-second
            // --version deadline, which marks every extraction engine unusable
            // and fails --strict. That is the same busy-machine condition the
            // retry exists to absorb, so spend an attempt on it rather than
            // reporting it as the pipe-blocking defect under test.
            assert!(
                attempt < ATTEMPTS,
                "fat doctor --strict did not succeed on any of {ATTEMPTS} attempts: {output:?}"
            );
            continue;
        }
        if elapsed < Duration::from_secs(5) {
            return;
        }
        assert!(
            attempt < ATTEMPTS,
            "probe readers waited for inherited output pipes: {ATTEMPTS} attempts each took \
             at least 5s (last was {elapsed:?})"
        );
    }
}

#[cfg(unix)]
#[test]
fn fat_doctor_does_not_wait_for_setsid_descendant_output_eof() {
    let _serial = serial_guard();
    let Some(python) = find_python() else {
        return;
    };
    let path_dir = tempdir().expect("tempdir");
    let marker = path_dir.path().join("setsid-ready");
    let pid_file = path_dir.path().join("setsid-child.pid");
    let escaping_probe = format!(
        "#!/bin/sh\n'{}' -c 'import os,sys,time;\nwith open(sys.argv[2], \"w\") as pid_file:\n pid_file.write(str(os.getpid()))\nos.setsid(); open(sys.argv[1], \"w\").close(); time.sleep(6)' '{}' '{}' &\nwhile [ ! -f '{}' ]; do :; done\nexit 1\n",
        python.display(),
        marker.display(),
        pid_file.display(),
        marker.display(),
    );
    make_executable_with_contents(path_dir.path().join("binwalk"), &escaping_probe);
    make_executable_with_contents(path_dir.path().join("unblob"), "#!/bin/sh\nexit 1\n");
    let escaped_child = EscapedChildGuard::new(pid_file);
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["doctor", "--strict"])
        .output()
        .expect("fat doctor runs");

    assert!(!output.status.success(), "{output:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "doctor waited for an escaped descendant to close inherited output"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("binwalk unusable"));
    drop(escaped_child);
}

#[cfg(unix)]
#[test]
fn fat_doctor_uses_no_temp_disk_for_escaped_output_flood() {
    let _serial = serial_guard();
    let Some(python) = find_python() else {
        return;
    };
    // Pay the interpreter's cold-start cost once, before anything is timed, so
    // the first attempt is not also the one warming the page cache.
    let _ = Command::new(&python).args(["-c", "pass"]).output();

    // `fat doctor` kills a probe's whole process group after VERSION_PROBE_TIMEOUT
    // (two seconds). The scenario under test only exists once the probe's
    // escaping child is flooding inside that window, so the marker is a
    // precondition -- proof the scenario was set up -- not the behaviour being
    // checked. On a busy host, retry only after the escaped child from the
    // previous attempt has been terminated.
    const ATTEMPTS: usize = 5;
    for attempt in 1..=ATTEMPTS {
        let path_dir = tempdir().expect("tempdir");
        let marker = path_dir.path().join("setsid-flood-ready");
        let pid_file = path_dir.path().join("setsid-flood-child.pid");
        let escaping_probe = format!(
            "#!/bin/sh\n'{}' -c 'import os,sys,time;\nwith open(sys.argv[2], \"w\") as pid_file:\n pid_file.write(str(os.getpid()))\nos.setsid(); open(sys.argv[1], \"w\").close();\ntry:\n while True: os.write(1, b\"x\" * 8192)\nexcept BrokenPipeError:\n time.sleep(6)' '{}' '{}' &\nwhile [ ! -f '{}' ]; do :; done\nexit 1\n",
            python.display(),
            marker.display(),
            pid_file.display(),
            marker.display(),
        );
        make_executable_with_contents(path_dir.path().join("binwalk"), &escaping_probe);
        make_executable_with_contents(path_dir.path().join("unblob"), "#!/bin/sh\nexit 1\n");
        let escaped_child = EscapedChildGuard::new(pid_file);
        let started = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .env("PATH", path_dir.path())
            .env("TMPDIR", path_dir.path().join("missing-temp-root"))
            .args(["doctor", "--strict"])
            .output()
            .expect("fat doctor runs");

        if !marker.is_file() {
            drop(escaped_child);
            assert!(
                attempt < ATTEMPTS,
                "the probe never started inside doctor's two-second deadline \
                 across {ATTEMPTS} attempts, so the flood scenario was never exercised"
            );
            continue;
        }

        assert!(!output.status.success(), "{output:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "doctor exceeded its escaped-writer deadline"
        );
        assert!(
            output.stdout.len() < 128 * 1024,
            "doctor output was unbounded"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("output truncated"));
        drop(escaped_child);
        return;
    }
}

#[test]
fn native_host_system_runner_dispatches_through_fat_owned_launcher() {
    let _serial = serial_guard();
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let path_dir = tempdir().expect("path dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"mips firmware-bytes").expect("firmware file");
    make_executable_with_contents(
        path_dir.path().join("qemu-system-mipsel"),
        "#!/bin/sh\nprintf 'native-system-launch\\n'\nexec /bin/sleep 30\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
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
    seed_native_system_boot_inputs(&project_dir, path_dir.path());
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:/sbin/preinit\nnvram:present\n",
    )
    .expect("signals file");
    let mut native_session = NativeSessionGuard::new(
        project_dir.clone(),
        path_dir.path().to_path_buf(),
        "smoke-native-system-1",
    );

    let started_at = Instant::now();
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_DATA_DIR", path_dir.path())
        .env("FAT_SYSTEM_KERNEL_DIR", path_dir.path())
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "smoke-native-system-1",
            "--substrate-policy",
            "system-first",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    assert!(
        started_at.elapsed() < Duration::from_secs(5),
        "expected native-host system dispatch to return quickly, got {:?}",
        started_at.elapsed()
    );

    let parsed = parse_keyed_output(&String::from_utf8_lossy(&emulate_output.stdout));
    let session_id = parsed.get("session").expect("session id");
    let run_id = parsed.get("run").expect("run id");
    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    #[cfg(unix)]
    let supervisor_pid = store
        .read_run(session_id, run_id)
        .expect("run record")
        .supervisor_pid
        .expect("native-host supervisor pid");
    let staging = read_single_json_record::<StagingManifest>(
        &store
            .run_path(session_id, run_id)
            .parent()
            .expect("run parent")
            .join("rehosting")
            .join("staging"),
    );
    let launch_state = store
        .run_path(session_id, run_id)
        .parent()
        .expect("run parent")
        .join("outputs")
        .join("native-system-launch-state.json");
    assert!(
        launch_state.exists(),
        "expected {} to exist",
        launch_state.display()
    );
    let launch_state_text = std::fs::read_to_string(&launch_state).expect("launch state");
    assert!(
        launch_state_text.contains("qemu-system-mipsel"),
        "launch state did not record the native-host qemu binary: {launch_state_text}"
    );
    assert!(
        launch_state_text.contains("rootfs.ext2"),
        "launch state did not record the staged rootfs image: {launch_state_text}"
    );
    assert!(
        launch_state_text.contains("init=/fat/init-trampoline"),
        "launch state did not record the FAT preinit boot args: {launch_state_text}"
    );
    assert!(
        staging
            .generated_artifacts
            .iter()
            .any(|artifact| artifact.ends_with("boot/qemu-command.sh")),
        "system staging did not record the boot-time launch artifacts"
    );
    assert!(
        staging
            .generated_artifacts
            .iter()
            .any(|artifact| artifact.ends_with("boot/rootfs.ext2")),
        "system staging did not record the staged rootfs image"
    );

    let stop_output = native_session.stop();
    assert!(stop_output.status.success(), "{stop_output:?}");
    #[cfg(unix)]
    assert_process_eventually_exits(supervisor_pid);
}

#[cfg(unix)]
fn assert_process_eventually_exits(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("native-host supervisor process {pid} remained after fat emulate --stop");
}

#[cfg(unix)]
fn find_python() -> Option<PathBuf> {
    [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn make_executable_with_contents(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
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

fn seed_native_system_boot_inputs(project_dir: &std::path::Path, path_dir: &std::path::Path) {
    let extracted = project_dir.join("extracted");
    std::fs::create_dir_all(extracted.join("bin")).expect("extracted bin");
    std::fs::create_dir_all(extracted.join("sbin")).expect("extracted sbin");
    std::fs::create_dir_all(extracted.join("etc")).expect("extracted etc");
    std::fs::write(extracted.join("bin/busybox"), b"busybox").expect("busybox");
    std::fs::write(extracted.join("sbin/preinit"), b"#!/bin/sh\nexit 0\n").expect("preinit");
    std::fs::write(extracted.join("etc/inittab"), b"::sysinit:/sbin/preinit\n").expect("inittab");
    seed_native_system_kernel_inputs(path_dir);
}

fn seed_native_system_kernel_inputs(path_dir: &std::path::Path) {
    std::fs::write(path_dir.join("vmlinux.mipsel.4"), b"synthetic-kernel")
        .expect("synthetic system kernel");
    let kernel_profiles = path_dir.join("profiles/kernels");
    std::fs::create_dir_all(&kernel_profiles).expect("kernel profiles");
    std::fs::write(
        kernel_profiles.join("catalog.json"),
        r#"[
  {
    "profile_id": "mipsel-test",
    "architecture": "mipsel",
    "family_hint": "linux-",
    "tier": 1,
    "image_hint": "vmlinux.mipsel.4",
    "support_tier": "test-only",
    "compatibility_note": "synthetic integration-test kernel"
  }
]"#,
    )
    .expect("synthetic kernel catalog");
    make_executable_with_contents(
        path_dir.join("mke2fs"),
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-F\" ]; then out=\"$arg\"; fi\n  prev=\"$arg\"\ndone\n[ -n \"$out\" ] || exit 64\n: > \"$out\"\nexit 0\n",
    );
    make_executable_with_contents(
        path_dir.join("debugfs"),
        "#!/bin/sh\nwhile IFS= read -r _command; do :; done\nexit 0\n",
    );
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
