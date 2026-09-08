use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fat_core::runs::{RuntimeEndpoint, RuntimeEndpointKind};
use fat_emulate::system_launch::{launch_native_system, launch_native_system_with};
use fat_emulate::system_runner::SystemLaunchSpec;

fn make_executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write fake qemu");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod");
}

#[test]
fn launch_native_system_invokes_expected_command_and_preserves_output() {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!("fat-system-launch-{unique_suffix}"));
    let fake_qemu = temp_root.join("qemu-system-mipsel");
    let launch_root = temp_root.join("boot");
    fs::create_dir_all(&temp_root).expect("temp root");
    fs::create_dir_all(&launch_root).expect("boot dir");

    make_executable(
        &fake_qemu,
        "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then printf 'QEMU emulator version 11.0.2\\n'; exit 0; fi\nprintf 'stdout-line\\n'\nprintf 'stderr-line\\n' >&2\nsleep 5\n",
    );

    let spec = SystemLaunchSpec {
        kernel_profile_id: Some("mipsel-router-tier1".to_string()),
        machine: "malta".to_string(),
        qemu_binary: fake_qemu.display().to_string(),
        required_qemu_version: Some("11.0.2".to_string()),
        args: vec![
            "-M".to_string(),
            "malta".to_string(),
            "-nographic".to_string(),
            "-serial".to_string(),
            "unix:/tmp/fake-serial.sock,server,nowait".to_string(),
            "-monitor".to_string(),
            "unix:/tmp/fake-monitor.sock,server,nowait".to_string(),
            "-gdb".to_string(),
            "tcp:127.0.0.1:1234".to_string(),
            "-kernel".to_string(),
            "/tmp/vmlinux.mipsel.4".to_string(),
            "-drive".to_string(),
            "file=/tmp/rootfs.ext2,format=raw".to_string(),
            "-append".to_string(),
            "root=/dev/sda rw console=ttyS0 init=/fat/preinit.sh".to_string(),
            "-m".to_string(),
            "256".to_string(),
            "-no-reboot".to_string(),
            "--kernel-profile".to_string(),
            "mipsel-router-tier1".to_string(),
        ],
        kernel_path: "/tmp/vmlinux.mipsel.4".to_string(),
        rootfs_image: "/tmp/rootfs.ext2".to_string(),
        preinit_path: "/tmp/guest-root/fat/preinit.sh".to_string(),
        boot_args: "root=/dev/sda rw console=ttyS0 init=/fat/preinit.sh".to_string(),
        serial_log: launch_root.join("serial.log").display().to_string(),
        serial_socket: launch_root.join("serial.sock").display().to_string(),
        monitor_socket: launch_root.join("monitor.sock").display().to_string(),
        gdb_address: "127.0.0.1:1234".to_string(),
        boot_artifacts: vec![
            launch_root.join("qemu-command.sh").display().to_string(),
            launch_root
                .join("surface-manifest.json")
                .display()
                .to_string(),
        ],
        registered_surfaces: vec![RuntimeEndpoint::new(
            RuntimeEndpointKind::Shell,
            "serial-console",
            "127.0.0.1",
            10022,
        )],
        host_forwards: vec![],
        instrumentation: None,
    };

    let result = launch_native_system(&spec).expect("launch result");
    let process_id = result.process_id.expect("process id");
    let group_is_alive = Command::new("kill")
        .args(["-0", &format!("-{process_id}")])
        .status()
        .expect("probe launched process group");
    assert!(
        group_is_alive.success(),
        "launch must return while the child process group is still running"
    );

    assert_eq!(result.command[0], fake_qemu.display().to_string());
    assert_eq!(
        result.command,
        vec![
            fake_qemu.display().to_string(),
            "-M".to_string(),
            "malta".to_string(),
            "-nographic".to_string(),
            "-serial".to_string(),
            "unix:/tmp/fake-serial.sock,server,nowait".to_string(),
            "-monitor".to_string(),
            "unix:/tmp/fake-monitor.sock,server,nowait".to_string(),
            "-gdb".to_string(),
            "tcp:127.0.0.1:1234".to_string(),
            "-kernel".to_string(),
            "/tmp/vmlinux.mipsel.4".to_string(),
            "-drive".to_string(),
            "file=/tmp/rootfs.ext2,format=raw".to_string(),
            "-append".to_string(),
            "root=/dev/sda rw console=ttyS0 init=/fat/preinit.sh".to_string(),
            "-m".to_string(),
            "256".to_string(),
            "-no-reboot".to_string(),
            "--kernel-profile".to_string(),
            "mipsel-router-tier1".to_string(),
        ]
    );
    assert!(result.stdout.len() <= "stdout-line\n".len());
    assert!(result.stderr.len() <= "stderr-line\n".len());
    assert!(Path::new(&result.stdout_log_path).exists());
    assert!(Path::new(&result.stderr_log_path).exists());
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let stdout_log = fs::read_to_string(&result.stdout_log_path).expect("stdout log");
        let stderr_log = fs::read_to_string(&result.stderr_log_path).expect("stderr log");
        if stdout_log == "stdout-line\n" && stderr_log == "stderr-line\n" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "capture files never received launch output"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(result.registered_surfaces.len(), 1);
    assert_eq!(
        result.registered_surfaces[0].kind,
        RuntimeEndpointKind::Shell
    );
    assert_eq!(result.exit_code, None);

    let _ = Command::new("kill")
        .args(["-TERM", &format!("-{process_id}")])
        .status();
}

#[test]
fn launch_native_system_refuses_a_managed_machine_version_mismatch() {
    let temp_root = tempfile::tempdir().expect("temp root");
    let fake_qemu = temp_root.path().join("qemu-system-mipsel");
    let launch_root = temp_root.path().join("boot");
    fs::create_dir_all(&launch_root).expect("boot dir");
    make_executable(
        &fake_qemu,
        "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then printf 'QEMU emulator version 11.0.20\\n'; exit 0; fi\nprintf launched > launched.marker\nsleep 5\n",
    );
    let spec = SystemLaunchSpec {
        kernel_profile_id: Some("fat-mipsle".to_string()),
        machine: "malta".to_string(),
        qemu_binary: fake_qemu.display().to_string(),
        required_qemu_version: Some("11.0.2".to_string()),
        args: vec!["-M".to_string(), "malta".to_string()],
        kernel_path: "/tmp/vmlinux".to_string(),
        rootfs_image: "/tmp/rootfs.ext2".to_string(),
        preinit_path: "/tmp/preinit.sh".to_string(),
        boot_args: "root=/dev/sda".to_string(),
        serial_log: launch_root.join("serial.log").display().to_string(),
        serial_socket: launch_root.join("serial.sock").display().to_string(),
        monitor_socket: launch_root.join("monitor.sock").display().to_string(),
        gdb_address: "127.0.0.1:1234".to_string(),
        boot_artifacts: vec![],
        registered_surfaces: vec![],
        host_forwards: vec![],
        instrumentation: None,
    };

    let error = launch_native_system(&spec).expect_err("version mismatch must fail closed");
    assert!(error.summary.contains("requires QEMU 11.0.2"));
    assert!(error
        .summary
        .contains("observed QEMU emulator version 11.0.20"));
    assert!(!launch_root.join("launched.marker").exists());
}

/// A spec whose "qemu" just sleeps, for exercising the spawn path itself.
fn sleeping_spec(root: &Path) -> SystemLaunchSpec {
    let fake_qemu = root.join("qemu-system-sleep");
    fs::create_dir_all(root).expect("temp root");
    make_executable(&fake_qemu, "#!/bin/sh\nsleep 60\n");

    SystemLaunchSpec {
        kernel_profile_id: None,
        machine: "malta".to_string(),
        qemu_binary: fake_qemu.display().to_string(),
        required_qemu_version: None,
        args: vec![],
        kernel_path: String::new(),
        rootfs_image: String::new(),
        preinit_path: String::new(),
        boot_args: String::new(),
        serial_log: root.join("serial.log").display().to_string(),
        serial_socket: root.join("serial.sock").display().to_string(),
        monitor_socket: root.join("monitor.sock").display().to_string(),
        gdb_address: "127.0.0.1:1234".to_string(),
        boot_artifacts: vec![],
        registered_surfaces: vec![],
        host_forwards: vec![],
        instrumentation: None,
    }
}

#[test]
fn launch_native_system_hands_the_pid_over_before_returning() {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!("fat-spawn-hook-{unique_suffix}"));
    let spec = sleeping_spec(&temp_root);

    let mut spawned = None;
    let result = launch_native_system_with(&spec, |pid| spawned = Some(pid)).expect("launch");

    let observed = spawned.expect("on_spawn must run for a child that stays up");
    assert_eq!(
        Some(observed),
        result.process_id,
        "the pid handed to the caller must be the one that gets recorded"
    );
    // The child leads its own group, so cleanup can signal the group and take
    // anything it spawned along with it.
    let group_alive = Command::new("kill")
        .args(["-0", &format!("-{observed}")])
        .status()
        .expect("probe process group");
    assert!(
        group_alive.success(),
        "spawned group should still be running"
    );

    let _ = Command::new("kill")
        .args(["-TERM", &format!("-{observed}")])
        .status();
    let _ = fs::remove_dir_all(&temp_root);
}
