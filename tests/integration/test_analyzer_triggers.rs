use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use fat_core::runtime_store::RuntimeStore;
use fat_core::targets::derive_target_id;
use tempfile::tempdir;

/// The same firmware must classify the same way whichever engine happened to
/// win, which was not true while signals were scraped out of extractor logs.
#[test]
fn signals_do_not_depend_on_which_engine_extracted_the_firmware() {
    let binwalk_signals = signals_for_engine(Engine::Binwalk);
    let unblob_signals = signals_for_engine(Engine::Unblob);

    assert!(binwalk_signals.contains("fs:squashfs"), "{binwalk_signals}");
    assert!(
        binwalk_signals.contains("init:busybox"),
        "{binwalk_signals}"
    );
    assert_eq!(
        binwalk_signals, unblob_signals,
        "identical trees must yield identical signals regardless of engine"
    );
}

#[derive(Clone, Copy)]
enum Engine {
    Binwalk,
    Unblob,
}

/// Extract the same content through one engine and return `signals.txt`.
///
/// Both stubs lay down an identical tree; only the directory naming differs —
/// binwalk's `squashfs-root` versus unblob's `<offset>.<handler>_extract`.
fn signals_for_engine(engine: Engine) -> String {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("shared.bin");
    fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");

    let populate = r#"
mkdir -p "$r/bin" "$r/usr/sbin" "$r/etc" "$r/www/cgi-bin"
touch "$r/bin/busybox" "$r/usr/sbin/httpd" "$r/etc/nvram.conf" "$r/www/cgi-bin/login"
"#;
    match engine {
        Engine::Binwalk => {
            write_script(
                &fake_bin_dir.path().join("binwalk"),
                &format!("#!/bin/sh\nr=_shared.bin.extracted/squashfs-root\n{populate}exit 0\n"),
            );
            write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 1\n");
        }
        Engine::Unblob => {
            write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 1\n");
            write_script(
                &fake_bin_dir.path().join("unblob"),
                &format!(
                    r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "unblob 25.5.26"; exit 0; fi
while [ $# -gt 0 ]; do case "$1" in -e) out="$2"; shift 2 ;; *) shift ;; esac; done
r="$out/0-1048576.squashfs_v4_le_extract"
{populate}exit 0
"#
                ),
            );
        }
    }
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("shared");
    let extract = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["extract", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat extract runs");
    assert!(extract.status.success(), "{extract:?}");

    let analyze = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze.status.success(), "{analyze:?}");

    // Provenance is reported next to each signal, so the reader can tell a
    // parsed header from a name in the tree.
    let stdout = String::from_utf8_lossy(&analyze.stdout);
    assert!(
        stdout.contains("(tree-name)"),
        "analyze output records signal provenance: {stdout}"
    );

    fs::read_to_string(project_dir.join("analysis").join("signals.txt")).expect("signals")
}

#[test]
fn cli_triggers_persist_static_and_runtime_analyzer_findings() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _demo.bin.extracted
touch _demo.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract"
  mkdir -p "$extract_dir"
  touch "$extract_dir/image.squashfs_v4_le"
fi
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  dest="$2"
  mkdir -p "$dest/bin"
  touch "$dest/bin/busybox"
  touch "$dest/bin/httpd"
fi
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("qemu-system-arm"),
        r#"#!/bin/sh
printf 'uhttpd 0.0.0.0:80\nsshd 0.0.0.0:22\n'
exit 0
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
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
    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["extract", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat extract runs");
    assert!(extract_output.status.success(), "{extract_output:?}");

    let analyze_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze_output.status.success(), "{analyze_output:?}");

    // The reported finding count must come from the analyzer engine, not from a
    // hardcoded zero, and the persisted summary must agree with stdout.
    let analyze_stdout = String::from_utf8_lossy(&analyze_output.stdout);
    let reported_findings = parse_keyed_output(&analyze_stdout)
        .get("findings")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("findings count on stdout");
    assert!(
        reported_findings > 0,
        "analyzers produced findings for this fixture: {analyze_stdout}"
    );
    let summary = fs::read_to_string(project_dir.join("analysis").join("summary.txt"))
        .expect("analysis summary");
    assert_eq!(
        summary,
        analyze_stdout.as_ref(),
        "summary.txt must be a faithful record of what stdout reported"
    );

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "qemu-direct",
            "--session-id",
            "phase2-trigger-1",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(
        !emulate_output.status.success(),
        "a failed launch must return non-zero: {emulate_output:?}"
    );
    assert!(
        String::from_utf8_lossy(&emulate_output.stderr)
            .contains("emulation launch failed after exhausting allowed attempts"),
        "{emulate_output:?}"
    );
    let emulate_stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let parsed = parse_keyed_output(&emulate_stdout);
    let session_id = parsed.get("session").expect("session id");

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            session_id,
            "--stop",
        ])
        .output()
        .expect("fat emulate --stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");

    let store = RuntimeStore::open(&project_dir).expect("runtime store");
    let target_findings = store
        .read_target_findings(&derive_target_id("demo", "demo.bin"))
        .expect("target findings");
    assert!(target_findings
        .iter()
        .any(|finding| { finding.plugin_id.as_deref() == Some("web-surface-static") }));

    let session = store.read_session(session_id).expect("session record");
    let run_id = session.run_ids.last().expect("run id");
    let run = store.read_run(session_id, run_id).expect("run record");
    assert_eq!(run.run_id, *run_id);
    assert_eq!(run.status, fat_core::runs::RunStatus::Failed);
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

fn write_script(path: &PathBuf, script: &str) {
    fs::write(path, script).expect("script written");

    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("permissions");
}

#[test]
fn analyze_summary_lists_binaries_with_architecture_and_caps_long_lists() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("many.bin");
    fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");

    // Twelve discoverable binaries: two past the cap, so the tail collapses.
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
i=1
while [ $i -le 12 ]; do
  mkdir -p "_many.bin.extracted/squashfs-root/opt/app$i/bin"
  dd if=/dev/zero of="_many.bin.extracted/squashfs-root/opt/app$i/bin/busybox" bs=1024 count=8 2>/dev/null
  i=$((i + 1))
done
mkdir -p _many.bin.extracted/squashfs-root/bin
ln -s ../opt/app1/bin/busybox _many.bin.extracted/squashfs-root/bin/busybox
exit 0
"#,
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    // Architecture is derived from file(1) output, so the stub decides it.
    write_script(
        &fake_bin_dir.path().join("file"),
        "#!/bin/sh\nprintf '%s: ELF 32-bit LSB executable, ARM, EABI5 version 1\\n' \"$1\"\n",
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("many");
    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["extract", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat extract runs");
    assert!(extract_output.status.success(), "{extract_output:?}");

    // The rootfs summary reports substance, not just counts.
    let extract_stdout = String::from_utf8_lossy(&extract_output.stdout);
    let rootfs_line = extract_stdout
        .lines()
        .find(|line| line.starts_with("rootfs: "))
        .expect("rootfs line");
    assert!(
        rootfs_line.contains("KB, squashfs)") || rootfs_line.contains("MB, squashfs)"),
        "rootfs line must carry size and filesystem kind: {rootfs_line}"
    );
    assert!(
        extract_stdout.contains("top-level: bin opt"),
        "{extract_stdout}"
    );

    let analyze_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", &path)
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .output()
        .expect("fat analyze runs");
    assert!(analyze_output.status.success(), "{analyze_output:?}");

    let analyze_stdout = String::from_utf8_lossy(&analyze_output.stdout);
    assert!(analyze_stdout.contains("binaries: 12"), "{analyze_stdout}");
    let listed = analyze_stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("- "))
        .count();
    assert_eq!(listed, 10, "list caps at ten entries: {analyze_stdout}");
    assert!(
        analyze_stdout.contains("... and 2 more"),
        "{analyze_stdout}"
    );
    assert!(
        analyze_stdout.contains("/bin/busybox (armel, 8.0 KB)"),
        "each entry carries architecture and size: {analyze_stdout}"
    );

    let summary = fs::read_to_string(project_dir.join("analysis").join("summary.txt"))
        .expect("analysis summary");
    assert_eq!(summary, analyze_stdout.as_ref());
}
