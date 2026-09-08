use fat_bootloader::{materialize_workspace, stop_tmux_session};
use fat_core::bootloader::{BootEnvVariable, BootValueSource, BootloaderSnapshot};
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::{tempdir, TempDir};

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write test file");
}

/// Owns a materialized bootloader project for the lifetime of one test.
///
/// `fat bootloader emulate --assist` starts QEMU inside a *detached* tmux
/// session that deliberately outlives the process that launched it, and these
/// tests point it at a fake QEMU that loops forever. Dropping only the tempdir
/// would therefore leave both the session and its child running on the
/// developer's machine. Teardown lives in `Drop` so it also runs while a
/// failing test unwinds, and it stops the session before the tempdir the
/// session was launched from is removed.
struct BootloaderProject {
    project_dir: PathBuf,
    _tempdir: TempDir,
}

impl Deref for BootloaderProject {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.project_dir
    }
}

impl AsRef<Path> for BootloaderProject {
    fn as_ref(&self) -> &Path {
        &self.project_dir
    }
}

impl Drop for BootloaderProject {
    fn drop(&mut self) {
        // Cleanup must never mask the assertion that failed, so this does not
        // panic — but staying silent would hide a live session and the fixture
        // it holds open, so a failure is reported.
        if let Err(error) = stop_tmux_session(&self.project_dir) {
            eprintln!(
                "warning: failed to stop the bootloader session for {}: {error}",
                self.project_dir.display()
            );
        }
    }
}

fn prepared_real_boot_project() -> BootloaderProject {
    let tempdir = tempdir().expect("tempdir");
    let project_dir = tempdir.path().join("camera-demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");

    let snapshot = BootloaderSnapshot {
        family: Some("u-boot".into()),
        version_hint: Some("U-Boot 2024.01".into()),
        env_variables: vec![
            BootEnvVariable {
                key: "bootcmd".into(),
                value: "bootm ${loadaddr}".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "bootargs".into(),
                value: "console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw".into(),
                source: BootValueSource::Imported,
            },
            BootEnvVariable {
                key: "loadaddr".into(),
                value: "0x80008000".into(),
                source: BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    std::fs::write(
        project_dir.join("analysis").join("bootloader.json"),
        serde_json::to_vec_pretty(&snapshot).expect("bootloader json"),
    )
    .expect("write snapshot");
    write_file(
        &project_dir.join("extracted").join("uImage"),
        &[0x27, 0x05, 0x19, 0x56, b'r', b'e', b'a', b'l'],
    );
    write_file(
        &project_dir.join("extracted").join("rootfs.img"),
        b"hsqsroot",
    );

    materialize_workspace(&project_dir, "consumer-iot-camera").expect("materialize workspace");
    BootloaderProject {
        project_dir,
        _tempdir: tempdir,
    }
}

#[test]
fn bootloader_emulate_assist_writes_sent_command_log() {
    let project = prepared_real_boot_project();
    let qemu_script = project.join("test-qemu.sh");
    std::fs::write(
        &qemu_script,
        b"#!/bin/sh\nprintf 'BK-IoT => \\n'\nwhile IFS= read -r line; do printf '%s\\n' \"$line\"; done\n",
    )
    .expect("write qemu script");
    let mut permissions = std::fs::metadata(&qemu_script)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&qemu_script, permissions).expect("chmod script");
    let asset = project.join("u-boot-test.bin");
    std::fs::write(&asset, b"real-asset").expect("write asset");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_BOOTLOADER_QEMU_BINARY", &qemu_script)
        .env("FAT_BOOTLOADER_QEMU_MACHINE", "virt")
        .env("FAT_BOOTLOADER_UBOOT_ASSET", &asset)
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
            "--assist",
        ])
        .output()
        .expect("assist boot");

    assert!(output.status.success(), "assist failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("assist log:"));
    assert!(stdout.contains("execution stage:"));
    assert!(project
        .join("bootloader")
        .join("qemu")
        .join("assist.log")
        .is_file());
}

#[test]
fn bootloader_emulate_assist_waits_for_delayed_kernel_output() {
    let project = prepared_real_boot_project();
    let qemu_script = project.join("test-qemu-delayed.sh");
    std::fs::write(
        &qemu_script,
        b"#!/bin/sh\nprintf 'BK-IoT => \\n'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\"\n  case \"$line\" in\n    *bootm*)\n      sleep 1\n      printf 'Linux version 5.10.0\\n'\n      ;;\n  esac\ndone\n",
    )
    .expect("write qemu script");
    let mut permissions = std::fs::metadata(&qemu_script)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&qemu_script, permissions).expect("chmod script");
    let asset = project.join("u-boot-test.bin");
    std::fs::write(&asset, b"real-asset").expect("write asset");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_BOOTLOADER_QEMU_BINARY", &qemu_script)
        .env("FAT_BOOTLOADER_QEMU_MACHINE", "virt")
        .env("FAT_BOOTLOADER_UBOOT_ASSET", &asset)
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
            "--assist",
        ])
        .output()
        .expect("assist boot");

    assert!(output.status.success(), "assist failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("execution stage: kernel_banner_seen"));
    assert!(stdout.contains("execution result: observed"));
}

#[test]
fn bootloader_emulate_assist_interrupts_after_autoboot_countdown() {
    let project = prepared_real_boot_project();
    let qemu_script = project.join("test-qemu-countdown.sh");
    std::fs::write(
        &qemu_script,
        b"#!/bin/sh\nprintf 'U-Boot 2024.01\\n'\nsleep 1\nprintf 'Hit any key to stop autoboot:  2\\n'\nIFS= read -r _line\nprintf 'BK-IoT => \\n'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\"\n  case \"$line\" in\n    *bootm*|*bootz*|*booti*)\n      printf 'Linux version 6.1.0\\n'\n      ;;\n  esac\ndone\n",
    )
    .expect("write qemu script");
    let mut permissions = std::fs::metadata(&qemu_script)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&qemu_script, permissions).expect("chmod script");
    let asset = project.join("u-boot-test.bin");
    std::fs::write(&asset, b"real-asset").expect("write asset");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_BOOTLOADER_QEMU_BINARY", &qemu_script)
        .env("FAT_BOOTLOADER_QEMU_MACHINE", "virt")
        .env("FAT_BOOTLOADER_UBOOT_ASSET", &asset)
        .args([
            "bootloader",
            "emulate",
            project.to_str().expect("project path"),
            "--assist",
        ])
        .output()
        .expect("assist boot");

    assert!(output.status.success(), "assist failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("execution stage: kernel_banner_seen"),
        "{stdout}"
    );
    assert!(stdout.contains("execution result: observed"), "{stdout}");
}
