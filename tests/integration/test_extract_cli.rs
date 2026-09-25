use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use fat_core::database::ProjectDb;
use fat_core::project::ProjectStatus;
use fat_package::unitree_upk::{self, PAYLOAD_TYPE_TAR};
use flate2::write::GzEncoder;
use flate2::Compression;
use tempfile::tempdir;

#[path = "../support/firmware_formats.rs"]
mod firmware_formats;

#[test]
fn fat_extract_uses_native_gzip_and_cramfs_without_external_engines() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("moxa-like.rom");
    let binwalk_marker = workspace.path().join("binwalk-ran");
    let unblob_marker = workspace.path().join("unblob-ran");

    let mut firmware = vec![0u8; 0x100];
    firmware.extend_from_slice(&firmware_formats::named_gzip_member());
    firmware.resize(0x400, 0);
    firmware.extend_from_slice(
        &firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Big).image,
    );
    fs::write(&firmware_path, firmware).expect("firmware");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        &format!("#!/bin/sh\ntouch '{}'\nexit 91\n", binwalk_marker.display()),
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        &format!("#!/bin/sh\ntouch '{}'\nexit 92\n", unblob_marker.display()),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    assert!(!binwalk_marker.exists(), "binwalk must not run");
    assert!(!unblob_marker.exists(), "unblob must not run");
    let project_dir = only_project_dir(workspace.path());
    let native = project_dir.join("work/extractions/native");
    assert_eq!(
        fs::read(native.join("kernel/vmlinux.64")).expect("kernel"),
        b"kernel-payload-for-fat"
    );
    assert!(native.join("cramfs-root/bin/busybox").is_file());
    assert!(native.join("cramfs-root/init").is_symlink());
    assert_ne!(
        fs::metadata(native.join("cramfs-root/bin/busybox"))
            .expect("busybox metadata")
            .permissions()
            .mode()
            & 0o111,
        0,
        "native extraction must preserve executable mode bits"
    );
    assert!(native.join("cramfs-root/etc/inittab").is_file());
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert!(
        manifest["rootfs_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("native/cramfs-root")),
        "{manifest:?}"
    );
    assert!(manifest["file_count"].as_u64().unwrap_or(0) > 0);
    let filesystem_trees = manifest["filesystem_trees"]
        .as_array()
        .expect("filesystem trees");
    assert_eq!(filesystem_trees.len(), 1, "{manifest:?}");
    assert_eq!(filesystem_trees[0]["role"], "rootfs");
    assert!(filesystem_trees[0]["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("native/cramfs-root")));
    let kernel_paths = manifest["kernel_paths"].as_array().expect("kernel paths");
    assert_eq!(kernel_paths.len(), 1, "{manifest:?}");
    assert!(
        kernel_paths[0]
            .as_str()
            .is_some_and(|path| path.ends_with("native/kernel/vmlinux.64")),
        "{manifest:?}"
    );
    assert_eq!(project_status(&project_dir), ProjectStatus::Extracted);
}

#[test]
fn fat_extract_preserves_native_kernel_evidence_when_external_fallback_fails() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("kernel-only.rom");
    let mut firmware = vec![0u8; 0x40];
    firmware.extend_from_slice(&firmware_formats::named_gzip_member());
    fs::write(&firmware_path, firmware).expect("firmware");
    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 91\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 92\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "{output:?}");
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert_eq!(
        fs::read(project_dir.join("work/extractions/native/kernel/vmlinux.64"))
            .expect("preserved kernel"),
        b"kernel-payload-for-fat"
    );
    assert!(!project_dir.join("work/extraction-manifest.json").exists());
}

#[test]
fn fat_extract_raw_firmware_auto_creates_default_project() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("raw-auto.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
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
  mkdir -p "$dest/bin" "$dest/sbin" "$dest/etc"
  touch "$dest/bin/busybox"
  touch "$dest/sbin/init"
  touch "$dest/etc/inittab"
fi
exit 0
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("project:"), "{stdout}");
    let project_dir = workspace.path().join(".fat-projects").join("raw-auto");
    assert!(project_dir.join("project.json").exists());
    assert!(project_dir
        .join("extracted")
        .join("bin")
        .join("busybox")
        .exists());
}

#[test]
fn fat_extract_does_not_dispatch_structured_utpk_prefix_to_decryptor() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("structured-prefix.bin");
    let mut bytes = b"UTPK\n".to_vec();
    for index in 0..256 {
        bytes.extend_from_slice(
            format!("field_{index:04}=plain-text-value-{index:04}\n").as_bytes(),
        );
    }
    fs::write(&firmware_path, bytes).expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/mkdir -p recovered\n/usr/bin/touch recovered/plain.txt\nexit 0\n",
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(
        output.status.success(),
        "structured UTPK prefix must use generic extraction\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("container: Unitree UTPK"), "{stdout}");
    assert!(only_project_dir(workspace.path())
        .join("work/extractions/binwalk/recovered/plain.txt")
        .is_file());
}

#[test]
fn fat_extract_allows_high_entropy_gzip_to_reach_generic_extraction() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("kernel.bin.gz");

    let mut state: u32 = 0xCAFE_BABE;
    let mut uncompressed = Vec::with_capacity(128 * 1024);
    for _ in 0..(128 * 1024) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        uncompressed.push((state & 0xff) as u8);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&uncompressed).expect("compress payload");
    let gzip = encoder.finish().expect("finish gzip");
    assert!(gzip.len() > 64 * 1024, "fixture must fill the probe");
    fs::write(&firmware_path, gzip).expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/mkdir -p recovered\n/usr/bin/touch recovered/kernel\nexit 0\n",
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(
        output.status.success(),
        "valid gzip must reach generic extraction\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(only_project_dir(workspace.path())
        .join("work/extractions/binwalk/recovered/kernel")
        .is_file());
}

#[test]
fn fat_extract_allows_opaque_unknown_to_reach_generic_extraction() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("opaque-unknown.bin");
    let mut state: u32 = 0xCAFE_BABE;
    let mut bytes = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push((state & 0xff) as u8);
    }
    fs::write(&firmware_path, bytes).expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/mkdir -p recovered\n/usr/bin/touch recovered/payload.bin\nexit 0\n",
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("no supported container handler"),
        "{stderr}"
    );
    assert!(!stderr.contains("decrypt first"), "{stderr}");
    let project_dir = only_project_dir(workspace.path());
    assert!(project_dir
        .join("work/extractions/binwalk/recovered/payload.bin")
        .is_file());
    assert_eq!(project_status(&project_dir), ProjectStatus::Extracted);
}

#[test]
fn fat_extract_understands_unblob_layout_and_records_its_version() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("unblob-only.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 1\n");
    // unblob's real layout: <offset>-<offset>.<handler>_extract holding the
    // tree, with none of the anchors content sniffing looks for.
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "unblob 25.5.26"; exit 0; fi
out=""
opts=""
while [ $# -gt 0 ]; do
  case "$1" in
    -e) out="$2"; shift 2 ;;
    --processes|--depth) opts="$opts $1=$2"; shift 2 ;;
    *) shift ;;
  esac
done
tree="$out/0-1048576.squashfs_v4_le_extract"
mkdir -p "$tree/bin" "$tree/www"
/usr/bin/touch "$tree/bin/busybox" "$tree/www/index.html"
printf 'opt%s\n' "$opts" > "$out/../unblob-options.txt"
exit 0
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            firmware_path.to_str().expect("firmware path"),
            "--unblob-processes",
            "3",
            "--unblob-depth",
            "5",
        ])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("engine: unblob"), "{stdout}");
    assert!(
        stdout.contains("0-1048576.squashfs_v4_le_extract"),
        "the unblob tree is identified as the rootfs: {stdout}"
    );
    assert!(!stdout.contains("rootfs: not found"), "{stdout}");

    let project_dir = only_project_dir(workspace.path());

    // Tuning reaches the tool only because it was asked for.
    let forwarded = fs::read_to_string(project_dir.join("work/extractions/unblob-options.txt"))
        .expect("unblob options");
    assert!(forwarded.contains("--processes=3"), "{forwarded}");
    assert!(forwarded.contains("--depth=5"), "{forwarded}");

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert_eq!(manifest["engine"].as_str(), Some("unblob"), "{manifest:?}");
    assert_eq!(
        manifest["engine_version"].as_str(),
        Some("unblob 25.5.26"),
        "the manifest pins the version that produced the tree: {manifest:?}"
    );
    let recorded_args = manifest["engine_args"]
        .as_array()
        .expect("engine args")
        .iter()
        .filter_map(|arg| arg.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(recorded_args.contains("--processes 3"), "{recorded_args}");
    assert!(
        manifest["rootfs_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("0-1048576.squashfs_v4_le_extract")),
        "{manifest:?}"
    );
    assert!(
        manifest["filesystem_trees"][0]["role"] == "squashfs",
        "trees are labelled by the handler that produced them: {manifest:?}"
    );
}

#[test]
fn fat_extract_auto_and_all_continue_past_carved_images() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("suppressed.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _suppressed.bin.extracted
touch _suppressed.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract/squashfs-root/bin"
  mkdir -p "$extract_dir"
  /usr/bin/touch "$extract_dir/busybox"
fi
exit 0
"#,
    );
    // No working unsquashfs, so the carved image stays opaque.
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        "#!/bin/sh\nexit 1\n",
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let auto = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");
    assert!(auto.status.success(), "{auto:?}");
    let auto_stdout = String::from_utf8_lossy(&auto.stdout);
    assert!(
        auto_stdout.contains("- unblob: succeeded (carved a rootfs)"),
        "{auto_stdout}"
    );
    assert!(!auto_stdout.contains("rootfs: not found"), "{auto_stdout}");

    let project_dir = only_project_dir(workspace.path());
    let forced = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            project_dir.to_str().expect("project dir"),
            "--force",
            "--extractor",
            "all",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat extract --extractor all runs");
    assert!(forced.status.success(), "{forced:?}");
    let forced_stdout = String::from_utf8_lossy(&forced.stdout);
    assert!(
        forced_stdout.contains("- unblob: succeeded (carved a rootfs)"),
        "{forced_stdout}"
    );
    assert!(forced_stdout.contains("engine: unblob"), "{forced_stdout}");
    assert!(
        !forced_stdout.contains("rootfs: not found"),
        "the suppressed engine recovers the rootfs: {forced_stdout}"
    );

    let single = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            project_dir.to_str().expect("project dir"),
            "--force",
            "--extractor",
            "unblob",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat extract --extractor unblob runs");
    assert!(single.status.success(), "{single:?}");
    let single_stdout = String::from_utf8_lossy(&single.stdout);
    assert!(
        single_stdout.contains("- binwalk: skipped (--extractor unblob selected instead)"),
        "{single_stdout}"
    );

    let rejected = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            project_dir.to_str().expect("project dir"),
            "--extractor",
            "magic",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat extract rejects unknown engines");
    assert!(!rejected.status.success(), "{rejected:?}");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("unsupported extractor: magic"),
        "{rejected:?}"
    );
}

#[test]
fn fat_extract_streams_extractor_output_into_a_live_log() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("slow-log.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    // The stub prints, then blocks until the test releases it, so the log is
    // inspected at a point where the extractor is definitely still running —
    // no sleep-and-hope timing.
    let release_marker = workspace.path().join("release-binwalk");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        &format!(
            r#"#!/bin/sh
echo "DECIMAL HEXADECIMAL DESCRIPTION"
while [ ! -f '{}' ]; do sleep 0.1; done
mkdir -p _slow-log.bin.extracted/squashfs-root/bin
/usr/bin/touch _slow-log.bin.extracted/squashfs-root/bin/busybox
echo "carve complete"
exit 0
"#,
            release_marker.display()
        ),
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("fat extract starts");

    // Poll for the streamed first line while the extractor is blocked.
    let log_path = workspace
        .path()
        .join(".fat-projects/slow-log/work/binwalk.log");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut streamed = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(&log_path) {
            if contents.contains("DECIMAL HEXADECIMAL DESCRIPTION") {
                streamed = contents;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let still_running = child.try_wait().expect("child state").is_none();
    // Release the stub before asserting so a failure cannot leave it blocked.
    fs::write(&release_marker, b"go").expect("release marker");

    assert!(
        streamed.contains("DECIMAL HEXADECIMAL DESCRIPTION"),
        "log must receive extractor output during the run, got: {streamed:?}"
    );
    assert!(
        still_running,
        "the extractor should still have been running when the log was inspected"
    );
    assert!(
        streamed.starts_with("$ binwalk -e "),
        "log keeps its command header: {streamed:?}"
    );
    assert!(
        !streamed.contains("exit="),
        "exit status is a trailer, not written before the child finishes: {streamed:?}"
    );

    let status = child.wait().expect("fat extract finishes");
    assert!(status.success(), "{status:?}");
    let final_log = fs::read_to_string(&log_path).expect("binwalk log");
    assert!(final_log.contains("carve complete"), "{final_log}");
    assert!(final_log.trim_end().ends_with("exit=0"), "{final_log}");
}

#[test]
fn fat_extract_kills_a_wedged_extractor_and_falls_through_to_the_next() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("wedged.bin");
    fs::write(&firmware_path, b"firmware-bytes-with-no-native-regions").expect("firmware file");

    // binwalk wedges and leaves a helper behind, the shape both extractors take
    // on malformed images. The helper must die with the process group.
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
sleep 600 &
echo "helper-pid=$!"
wait
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract/squashfs-root/bin"
  mkdir -p "$extract_dir"
  /usr/bin/touch "$extract_dir/busybox"
fi
exit 0
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    // Long enough that the fast unblob stub is never the one that trips the
    // deadline, even with the rest of the suite running in parallel.
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            firmware_path.to_str().expect("firmware path"),
            "--extract-timeout",
            "8",
        ])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");

    // The timeout must not fail the run: the chain continues to unblob.
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("- binwalk: failed (timed out; see work/binwalk.log)"),
        "{stdout}"
    );
    assert!(stdout.contains("engine: unblob"), "{stdout}");

    let project_dir = only_project_dir(workspace.path());
    let binwalk_log =
        fs::read_to_string(project_dir.join("work/binwalk.log")).expect("binwalk log");
    assert!(binwalk_log.contains("timeout after 8s"), "{binwalk_log}");
    assert!(binwalk_log.contains("killed"), "{binwalk_log}");

    let helper_pid = binwalk_log
        .lines()
        .find_map(|line| line.trim().strip_prefix("helper-pid="))
        .expect("stub reported its helper pid")
        .to_string();
    let helper_alive = Command::new("ps")
        .args(["-p", &helper_pid])
        .output()
        .expect("ps runs")
        .status
        .success();
    assert!(
        !helper_alive,
        "timeout must kill the extractor's whole process group, but helper {helper_pid} survived"
    );
}

#[test]
fn fat_extract_reports_the_winning_engine_and_skip_reasons() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("provenance.bin");
    fs::write(&firmware_path, b"firmware-bytes-with-no-native-regions").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _provenance.bin.extracted
touch _provenance.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        "#!/bin/sh\necho 'fallback attempted' >&2\nexit 9\n",
    );
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  dest="$2"
  mkdir -p "$dest/bin"
  touch "$dest/bin/busybox"
fi
exit 0
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("engine: binwalk"), "{stdout}");
    assert!(
        stdout.contains("- native: skipped (no supported regions in the image)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("- unblob: failed (see work/unblob.log)"),
        "{stdout}"
    );

    let project_dir = only_project_dir(workspace.path());
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert_eq!(manifest["engine"].as_str(), Some("binwalk"), "{manifest:?}");

    // A cached re-run answers "what extracted this?" without re-running anything.
    let rerun = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", &path)
        .output()
        .expect("fat extract re-runs");
    assert!(rerun.status.success(), "{rerun:?}");
    let rerun_stdout = String::from_utf8_lossy(&rerun.stdout);
    assert!(
        rerun_stdout.contains("status: already extracted"),
        "{rerun_stdout}"
    );
    assert!(rerun_stdout.contains("engine: binwalk"), "{rerun_stdout}");
    assert!(
        rerun_stdout.contains("- unblob: failed (see work/unblob.log)"),
        "{rerun_stdout}"
    );
}

#[test]
fn fat_extract_attributes_a_native_extraction_to_the_native_engine() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("native-win.rom");

    let mut firmware = vec![0u8; 0x100];
    firmware.extend_from_slice(&firmware_formats::named_gzip_member());
    firmware.resize(0x400, 0);
    firmware.extend_from_slice(
        &firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Big).image,
    );
    fs::write(&firmware_path, firmware).expect("firmware");
    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 91\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 92\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("engine: native"), "{stdout}");
    assert!(
        stdout.contains("- binwalk: skipped (native extraction recovered a rootfs)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("- unblob: skipped (native extraction recovered a rootfs)"),
        "{stdout}"
    );
}

#[test]
fn fat_extract_runs_every_engine_in_its_own_extraction_dir() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("engine-cwd.bin");
    fs::write(&firmware_path, b"firmware-bytes-with-no-native-regions").expect("firmware file");

    // Both stubs drop a file relative to their working directory; that side
    // effect must land inside the engine's own extraction dir.
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/usr/bin/touch stray-binwalk-artifact\nexit 1\n",
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
/usr/bin/touch stray-unblob-artifact
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract"
  mkdir -p "$extract_dir"
  /usr/bin/touch "$extract_dir/payload.bin"
fi
exit 0
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");
    let project_dir = only_project_dir(workspace.path());
    let extraction_root = project_dir.join("work/extractions");
    assert!(
        extraction_root
            .join("binwalk/stray-binwalk-artifact")
            .is_file(),
        "binwalk must run with its own extraction dir as cwd"
    );
    assert!(
        extraction_root
            .join("unblob/stray-unblob-artifact")
            .is_file(),
        "unblob must run with its own extraction dir as cwd"
    );

    // FAT owns the directories in the project root; loose files there mean an
    // extractor wrote relative to a cwd it should not have had.
    let unexpected: Vec<String> = fs::read_dir(&project_dir)
        .expect("project dir")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !matches!(name.as_str(), ".fat.db" | "project.json"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "extractors must not write into the project root: {unexpected:?}"
    );

    // Nothing FAT runs — including the version probe that pins the engine into
    // the manifest — may write into the directory the user invoked it from.
    let mut caller_entries: Vec<String> = fs::read_dir(workspace.path())
        .expect("caller dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    caller_entries.sort();
    assert_eq!(
        caller_entries,
        vec![".fat-projects".to_string(), "engine-cwd.bin".to_string()],
        "fat extract must leave the caller's working directory alone"
    );
}

#[test]
fn fat_extract_raw_firmware_reuses_existing_manifest_without_overwrite() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("raw-repeat.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
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
fi
exit 0
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let first_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("first fat extract runs");
    assert!(first_output.status.success(), "{first_output:?}");

    let project_dir = workspace.path().join(".fat-projects").join("raw-repeat");
    let hand_edited_file = project_dir
        .join("work")
        .join("extractions")
        .join("hand-edited.txt");
    fs::write(&hand_edited_file, "keep me").expect("hand-edited marker");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\necho binwalk should not rerun >&2\nexit 91\n",
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        "#!/bin/sh\necho unblob should not rerun >&2\nexit 92\n",
    );

    let second_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("second fat extract runs");

    assert!(
        second_output.status.success(),
        "second extract should reuse the existing manifest\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second_output.stdout),
        String::from_utf8_lossy(&second_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&second_output.stdout);
    assert!(stdout.contains("status: already extracted"), "{stdout}");
    assert!(
        stdout.contains("use --force to re-run extraction"),
        "{stdout}"
    );
    assert!(
        hand_edited_file.exists(),
        "second run should not clobber work/extractions"
    );
}

#[test]
fn fat_extract_reuses_valid_manifest_before_probing_changed_input() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("cached.bin");
    fs::write(&firmware_path, b"structured firmware").expect("firmware file");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/mkdir -p recovered\n/usr/bin/touch recovered/file\nexit 0\n",
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let first = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("first extract runs");
    assert!(first.status.success(), "{first:?}");

    let project_dir = only_project_dir(workspace.path());
    let copied_input = project_dir.join("input/cached.bin");
    let mut state: u32 = 0xCAFE_BABE;
    let mut opaque = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        opaque.push((state & 0xff) as u8);
    }
    fs::write(copied_input, opaque).expect("replace project input");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\necho binwalk should not rerun >&2\nexit 91\n",
    );

    let second = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("second extract runs");
    assert!(
        second.status.success(),
        "manifest reuse must precede container probing\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("status: already extracted"),
        "{}",
        String::from_utf8_lossy(&second.stdout)
    );
}

#[test]
fn fat_extract_recovers_rootfs_with_unsquashfs_fallback() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
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
fi
exit 0
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("demo");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    let rootfs_path = manifest["rootfs_path"].as_str().expect("rootfs path");
    assert!(rootfs_path.contains("squashfs-root"), "{manifest:?}");
    assert!(project_dir
        .join("work")
        .join("extractions")
        .join("unblob")
        .join("demo.bin_extract")
        .join("squashfs-root")
        .join("bin")
        .join("busybox")
        .exists());
}

#[test]
fn fat_extract_recovers_ext_rootfs_with_debugfs_fallback() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("rootfs.img");
    let mut firmware = vec![0u8; 0x440];
    firmware[0x438..0x43a].copy_from_slice(&0xef53u16.to_le_bytes());
    fs::write(&firmware_path, firmware).expect("ext fixture");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    write_script(
        &fake_bin_dir.path().join("debugfs"),
        r#"#!/bin/sh
if [ "$1" != "-R" ] || [ "$2" != "rdump / debugfs-root" ]; then
  echo "unexpected debugfs arguments: $*" >&2
  exit 9
fi
if [ ! -d debugfs-root ]; then
  echo "debugfs destination must exist before rdump" >&2
  exit 8
fi
mkdir -p debugfs-root/bin debugfs-root/sbin debugfs-root/etc
touch debugfs-root/bin/busybox debugfs-root/sbin/init debugfs-root/etc/inittab
exit 0
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let project_dir = workspace.path().join(".fat-projects").join("rootfs");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert!(
        manifest["rootfs_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("debugfs-root")),
        "{manifest:?}"
    );
    assert_eq!(manifest["filesystem_trees"][0]["role"], "rootfs");
    assert!(manifest["filesystem_trees"][0]["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("debugfs-root")));
    assert!(project_dir.join("extracted/bin/busybox").exists());

    let fallback_log =
        fs::read_to_string(project_dir.join("work/rootfs-fallback.log")).expect("fallback log");
    assert!(
        fallback_log.contains("debugfs -R rdump / debugfs-root"),
        "{fallback_log}"
    );
}

#[test]
fn fat_extract_does_not_run_debugfs_for_non_ext_blob() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("opaque.bin");
    let debugfs_marker = workspace.path().join("debugfs-invoked");
    fs::write(&firmware_path, vec![0u8; 0x440]).expect("raw fixture");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");
    write_script(
        &fake_bin_dir.path().join("debugfs"),
        "#!/bin/sh\ntouch \"$DEBUGFS_MARKER\"\nexit 0\n",
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", path)
        .env("DEBUGFS_MARKER", &debugfs_marker)
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "a zero-evidence non-ext extraction must fail: {output:?}"
    );
    assert!(
        !debugfs_marker.exists(),
        "debugfs must not run for a non-ext blob"
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extraction-manifest.json").exists());
}

#[test]
fn fat_extract_accepts_unsquashfs_output_with_nonzero_warning_exit() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("warn.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
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
  mkdir -p "$dest/etc"
  touch "$dest/etc/banner"
fi
exit 2
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("warn");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    assert!(manifest["rootfs_path"].is_string(), "{manifest:?}");
}

#[test]
fn fat_extract_does_not_accept_empty_rootfs_fallback_output() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("empty.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
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
  mkdir -p "$dest"
fi
exit 0
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("empty");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    assert!(manifest["rootfs_path"].is_null(), "{manifest:?}");
}

#[test]
fn fat_extract_continues_when_only_filesystem_images_were_carved() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("skip.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _skip.bin.extracted
touch _skip.bin.extracted/image.squashfs_v4_le
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
echo "fallback attempted" >&2
exit 9
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unsquashfs"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  dest="$2"
  mkdir -p "$dest/bin"
  touch "$dest/bin/busybox"
fi
exit 0
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("skip");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let unblob_log =
        fs::read_to_string(project_dir.join("work").join("unblob.log")).expect("unblob log");
    assert!(unblob_log.contains("exit=9"), "{unblob_log}");
}

#[test]
fn fat_extract_continues_when_only_boot_artifacts_were_carved() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("coherent.cpio");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
mkdir -p _coherent.cpio.extracted
touch _coherent.cpio.extracted/u-boot.bin
touch _coherent.cpio.extracted/zImage
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
echo "fallback attempted" >&2
exit 9
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("coherent");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    let kernels = manifest["kernel_paths"].as_array().expect("kernel paths");
    assert_eq!(kernels.len(), 1, "{manifest:?}");
    assert!(
        kernels[0].as_str().expect("kernel path").contains("zImage"),
        "{manifest:?}"
    );

    let unblob_log =
        fs::read_to_string(project_dir.join("work").join("unblob.log")).expect("unblob log");
    assert!(unblob_log.contains("exit=9"), "{unblob_log}");
}

#[test]
fn fat_extract_accepts_relative_project_paths() {
    let workspace_dir = tempdir().expect("workspace dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("relative.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
firmware="$2"
if [ ! -f "$firmware" ]; then
  echo "missing firmware: $firmware" >&2
  exit 7
fi
mkdir -p "extractions/$(basename "$firmware").extracted/jffs2-root/bin"
touch "extractions/$(basename "$firmware").extracted/jffs2-root/bin/busybox"
touch "extractions/$(basename "$firmware").extracted/decompressed.bin"
exit 0
"#,
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  if [ ! -f "$firmware" ]; then
    echo "missing firmware: $firmware" >&2
    exit 7
  fi
  echo "unblob should not run when binwalk already recovered a rootfs" >&2
  exit 9
fi
exit 0
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .current_dir(workspace_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--name",
            "relative",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let extract_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .current_dir(workspace_dir.path())
        .args(["extract", ".fat-projects/relative"])
        .env("PATH", &path)
        .output()
        .expect("fat extract runs");

    assert!(extract_output.status.success(), "{extract_output:?}");

    let project_dir = workspace_dir.path().join(".fat-projects").join("relative");
    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    let rootfs_path = manifest["rootfs_path"].as_str().expect("rootfs path");
    assert!(rootfs_path.contains("jffs2-root"), "{manifest:?}");

    let unblob_log =
        fs::read_to_string(project_dir.join("work").join("unblob.log")).expect("unblob log");
    assert!(
        unblob_log.contains("skipped unblob because binwalk already recovered a rootfs"),
        "{unblob_log}"
    );
}

#[test]
fn fat_extract_promotes_nested_rootfs_tree_without_rootfs_name() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = firmware_dir.path().join("nested.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(
        &fake_bin_dir.path().join("unblob"),
        r#"#!/bin/sh
if [ "$1" = "-e" ]; then
  out="$2"
  firmware="$3"
  extract_dir="$out/$(basename "$firmware")_extract"
  root="$extract_dir/blob_extract/lzma.uncompressed_extract"
  mkdir -p "$root/sbin" "$root/etc" "$root/bin"
  touch "$root/sbin/init"
  touch "$root/etc/inittab"
  touch "$root/bin/busybox"
fi
exit 0
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(output.status.success(), "{output:?}");

    let project_dir = projects_dir.path().join("nested");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", project_dir.to_str().expect("project dir")])
        .env("PATH", path)
        .output()
        .expect("fat extract runs");

    assert!(output.status.success(), "{output:?}");

    let manifest_path = project_dir.join("work").join("extraction-manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest file")).unwrap();
    let rootfs_path = manifest["rootfs_path"].as_str().expect("rootfs path");
    assert!(
        rootfs_path.contains("lzma.uncompressed_extract"),
        "{manifest:?}"
    );
    let extracted_root = project_dir.join("extracted");
    assert!(extracted_root.join("bin").join("busybox").exists());
    assert_eq!(
        fs::read_link(&extracted_root)
            .expect("extracted symlink")
            .to_string_lossy(),
        rootfs_path
    );
}

#[test]
fn fat_extract_fails_without_any_available_extraction_engine() {
    let workspace = tempdir().expect("workspace");
    let empty_path = tempdir().expect("empty PATH");
    let firmware_path = workspace.path().join("missing-tools.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", empty_path.path())
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "missing extraction engines must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("install the missing tools"),
        "missing engines should retain installation advice: {output:?}"
    );
    let project_dir = only_project_dir(workspace.path());
    assert!(
        !project_dir.join("work/extraction-manifest.json").exists(),
        "failed extraction must not persist a success manifest"
    );
}

#[test]
fn fat_extract_fails_when_every_extraction_engine_exits_nonzero() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("failed-tools.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\necho binwalk failed >&2\nexit 41\n",
    );
    write_script(
        &fake_bin_dir.path().join("unblob"),
        "#!/bin/sh\necho unblob failed >&2\nexit 42\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "non-zero extraction engines must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("install the missing tools"),
        "installed engines that fail should direct users to their logs: {output:?}"
    );
    let project_dir = only_project_dir(workspace.path());
    assert!(
        !project_dir.join("work/extraction-manifest.json").exists(),
        "failed extraction must not persist a success manifest"
    );
}

#[test]
fn fat_extract_reports_binwalk_retry_exhaustion_without_missing_tool_advice() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("zero-scan.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\nprintf 'incomplete\\n' > partial.txt\nprintf 'Analyzed 0 files for 85 file signatures (187 magic patterns) in 5.0 milliseconds\\n'\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            firmware_path.to_str().expect("firmware path"),
            "--extractor",
            "binwalk",
        ])
        .current_dir(workspace.path())
        // unblob is absent but was not selected, so it must not trigger advice.
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("firmware extraction failed:"), "{stderr}");
    assert!(
        stderr.contains("binwalk: Binwalk analyzed zero files in all 3 attempts"),
        "the terminal error must report why the installed engine failed: {stderr}"
    );
    assert!(stderr.contains("work/binwalk.log"), "{stderr}");
    assert!(stderr.contains("work/unblob.log"), "{stderr}");
    assert!(!stderr.contains("install the missing tools"), "{stderr}");
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extraction-manifest.json").exists());
    assert!(!project_dir.join("work/extractions").exists());
    for attempt in 1..=3 {
        let archived = project_dir.join(format!("work/binwalk.attempt-{attempt}"));
        assert_eq!(
            fs::read_to_string(archived.join("partial.txt")).expect("preserved output"),
            "incomplete\n"
        );
        assert!(project_dir
            .join(format!("work/binwalk.attempt-{attempt}.log"))
            .is_file());
    }
}

#[test]
fn fat_extract_rejects_zero_exit_engines_that_recover_no_evidence() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("empty-success.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "zero-evidence extraction must fail: {output:?}"
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extraction-manifest.json").exists());
    assert!(!project_dir.join("work/extractions").exists());
}

#[test]
fn fat_extract_zero_file_error_includes_repetitive_envelope_measurements() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("repetitive.bin");
    fs::write(&firmware_path, b"0123456789ABCDEF".repeat(512)).expect("firmware file");
    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for evidence in [
        "classification: repetitive-payload",
        "ecb_assessment: not-indicated",
    ] {
        assert!(stderr.contains(evidence), "missing {evidence}:\n{stderr}");
    }
    assert!(!stderr.contains("decrypt first"), "{stderr}");
}

#[test]
fn fat_extract_zero_file_error_includes_plaintext_header_measurement() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("header-and-opaque.bin");
    let mut bytes = vec![0_u8; 32];
    let mut state: u32 = 0xCAFE_BABE;
    for _ in 0..8192 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push((state & 0xff) as u8);
    }
    fs::write(&firmware_path, bytes).expect("firmware file");
    write_script(&fake_bin_dir.path().join("binwalk"), "#!/bin/sh\nexit 0\n");
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 0\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware_path.to_str().expect("firmware path")])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for evidence in [
        "classification: opaque-wrapper-likely",
        "ecb_assessment: ecb-unlikely",
        "likely_plaintext_header_len: 0x20",
    ] {
        assert!(stderr.contains(evidence), "missing {evidence}:\n{stderr}");
    }
    assert!(!stderr.contains("decrypt first"), "{stderr}");
}

fn write_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod");
}

/// Build a small tar mirroring a Unitree module package layout.
fn build_demo_module_tar() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let files: &[(&str, &[u8], u32)] = &[
            (
                "network_manager_demo/module.json",
                b"{\"name\":\"network_manager\"}",
                0o644,
            ),
            (
                "network_manager_demo/upper_bluetooth/btgatt-server",
                b"\x7fELF fake bluetooth binary payload",
                0o755,
            ),
        ];
        for (path, data, mode) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(*mode);
            builder
                .append_data(&mut header, *path, *data)
                .expect("append tar entry");
        }
        builder.finish().expect("finish tar");
    }
    buf
}

/// Build a tar that writes one valid file before encountering a traversal path.
/// The malformed path is injected after `tar::Builder` creates a valid archive,
/// because the builder correctly refuses to create unsafe paths itself.
fn build_partially_unsafe_module_tar() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        for (path, data) in [
            ("safe.txt", &b"written first"[..]),
            ("second.txt", &b"must be rejected"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, path, data)
                .expect("append tar entry");
        }
        builder.finish().expect("finish tar");
    }

    // Each small file occupies one 512-byte header and one 512-byte data block,
    // so the second header starts at 1024.
    let header = &mut buf[1024..1536];
    header[..100].fill(0);
    header[..13].copy_from_slice(b"../escape.txt");
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum_field = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_field.as_bytes());
    buf
}

fn build_gnu_sparse_module_tar() -> Vec<u8> {
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        let data = b"sparse-content";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "sparse.bin", &data[..])
            .expect("append sparse candidate");
        builder.finish().expect("finish tar");
    }
    let header = &mut tar[..512];
    header[156] = b'S';
    refresh_tar_checksum(header);
    tar
}

fn build_pax_module_tar() -> Vec<u8> {
    let mut tar = build_gnu_sparse_module_tar();
    tar[156] = b'x';
    refresh_tar_checksum(&mut tar[..512]);
    tar
}

fn build_many_entry_module_tar(entry_count: usize) -> Vec<u8> {
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        for index in 0..entry_count {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, format!("entry-{index}"), &b""[..])
                .expect("append entry");
        }
        builder.finish().expect("finish tar");
    }
    tar
}

fn refresh_tar_checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum_field = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_field.as_bytes());
}

/// The single project directory auto-created under `<workspace>/.fat-projects`.
fn only_project_dir(workspace: &std::path::Path) -> std::path::PathBuf {
    let mut entries: Vec<_> = fs::read_dir(workspace.join(".fat-projects"))
        .expect("read .fat-projects")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one project: {entries:?}"
    );
    entries.pop().unwrap()
}

fn project_status(project_dir: &std::path::Path) -> ProjectStatus {
    let project_name = project_dir.file_name().unwrap().to_string_lossy();
    ProjectDb::open(project_dir)
        .expect("project db")
        .get(&project_name)
        .expect("project lookup")
        .expect("project record")
        .status
}

#[test]
fn fat_extract_decrypts_and_unpacks_unitree_upk() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "network_manager_demo", &tar_bytes)
        .expect("encode supported UTPK");
    let upk_path = workspace.path().join("network_manager_demo.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("files: 0"),
        "must not report zero files:\n{stdout}"
    );
    assert!(
        stdout.contains("decryption: completed"),
        "fresh UTPK extraction must say that decryption ran:\n{stdout}"
    );

    let project_dir = only_project_dir(workspace.path());
    let upk_dir = project_dir.join("work/extractions/unitree-upk");
    assert!(
        upk_dir.join("network_manager_demo.tar").exists(),
        "decoded tar artifact should be written"
    );
    let unpacked = upk_dir.join("unpacked/network_manager_demo");
    assert!(
        unpacked.join("module.json").exists(),
        "module.json unpacked"
    );
    assert!(
        unpacked.join("upper_bluetooth/btgatt-server").exists(),
        "nested btgatt-server unpacked"
    );
    assert_ne!(
        fs::metadata(unpacked.join("upper_bluetooth/btgatt-server"))
            .expect("btgatt-server metadata")
            .permissions()
            .mode()
            & 0o111,
        0,
        "executable mode from the firmware archive must be preserved"
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("manifest"),
    )
    .expect("manifest json");
    assert!(
        manifest["file_count"].as_u64().unwrap_or(0) > 0,
        "manifest file_count should be positive: {manifest:?}"
    );

    // Second run without --force reuses the nonzero manifest.
    let reuse = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract reuse runs");
    assert!(reuse.status.success(), "{reuse:?}");
    let reuse_stdout = String::from_utf8_lossy(&reuse.stdout);
    assert!(
        reuse_stdout.contains("status: already extracted"),
        "{reuse_stdout}"
    );
    assert!(
        reuse_stdout.contains("container: Unitree UTPK")
            && reuse_stdout.contains("decryption: already completed (cached)"),
        "cached UTPK extraction must be distinguished from a fresh decrypt:\n{reuse_stdout}"
    );
    assert!(
        !reuse_stdout.contains("files: 0"),
        "reuse must keep nonzero files:\n{reuse_stdout}"
    );
}

#[test]
fn fat_extract_refreshes_legacy_empty_utpk_manifest_without_force() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "network_manager_demo", &tar_bytes)
        .expect("encode supported UTPK");
    let upk_path = workspace.path().join("network_manager_demo.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let initial = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("initial fat extract runs");
    assert!(initial.status.success(), "{initial:?}");

    // Reproduce a project created by FAT before UTPK extraction support: the
    // project and manifest exist, but the generated extraction tree is empty.
    let project_dir = only_project_dir(workspace.path());
    let extraction_root = project_dir.join("work/extractions");
    fs::remove_dir_all(&extraction_root).expect("remove modern extraction tree");
    fs::create_dir_all(&extraction_root).expect("create legacy empty extraction tree");
    fs::write(
        project_dir.join("work/extraction-manifest.json"),
        br#"{
  "rootfs_path": null,
  "kernel_paths": [],
  "file_count": 0
}"#,
    )
    .expect("write legacy zero-file manifest");

    let refresh = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract refresh runs");
    assert!(
        refresh.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&refresh.stdout),
        String::from_utf8_lossy(&refresh.stderr)
    );
    let stdout = String::from_utf8_lossy(&refresh.stdout);
    assert!(
        stdout.contains("stale empty UTPK extraction detected; refreshing"),
        "the automatic refresh must be visible to the user:\n{stdout}"
    );
    assert!(
        !stdout.contains("status: already extracted"),
        "legacy zero-file state must not short-circuit extraction:\n{stdout}"
    );
    assert!(
        !stdout.contains("files: 0"),
        "refreshed extraction must contain files:\n{stdout}"
    );

    let unpacked = extraction_root.join("unitree-upk/unpacked/network_manager_demo");
    assert!(unpacked.join("module.json").is_file());
    assert!(unpacked.join("upper_bluetooth/btgatt-server").is_file());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(project_dir.join("work/extraction-manifest.json")).expect("refreshed manifest"),
    )
    .expect("manifest json");
    assert!(
        manifest["file_count"].as_u64().unwrap_or(0) > 0,
        "refreshed manifest must record files: {manifest:?}"
    );

    // Once refreshed, the same ordinary command should reuse the valid state.
    let reuse = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract reuse runs");
    assert!(reuse.status.success(), "{reuse:?}");
    let reuse_stdout = String::from_utf8_lossy(&reuse.stdout);
    assert!(
        reuse_stdout.contains("status: already extracted"),
        "{reuse_stdout}"
    );
    assert!(!reuse_stdout.contains("files: 0"), "{reuse_stdout}");
}

#[test]
fn fat_extract_does_not_reuse_manifest_while_project_is_extracting() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "refresh", &tar_bytes).unwrap();
    let upk_path = workspace.path().join("refresh.upk");
    fs::write(&upk_path, &upk).unwrap();
    let first = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(first.status.success(), "{first:?}");

    let project_dir = only_project_dir(workspace.path());
    let db = ProjectDb::open(&project_dir).unwrap();
    let mut project = db.get("refresh").unwrap().unwrap();
    project.status = ProjectStatus::Extracting;
    db.save(&project).unwrap();

    let retry = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(retry.status.success(), "{retry:?}");
    let stdout = String::from_utf8_lossy(&retry.stdout);
    assert!(!stdout.contains("status: already extracted"), "{stdout}");
    assert!(stdout.contains("decryption: completed"), "{stdout}");
    assert_eq!(project_status(&project_dir), ProjectStatus::Extracted);
}

#[test]
fn fat_extract_marks_error_when_cached_manifest_is_malformed() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "malformed", &tar_bytes).unwrap();
    let upk_path = workspace.path().join("malformed.upk");
    fs::write(&upk_path, &upk).unwrap();
    let first = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(first.status.success(), "{first:?}");

    let project_dir = only_project_dir(workspace.path());
    fs::write(
        project_dir.join("work/extraction-manifest.json"),
        b"{invalid",
    )
    .unwrap();
    let db = ProjectDb::open(&project_dir).unwrap();
    let mut project = db.get("malformed").unwrap().unwrap();
    project.status = ProjectStatus::Extracting;
    db.save(&project).unwrap();

    let retry = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(!retry.status.success(), "{retry:?}");
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
}

#[cfg(unix)]
#[test]
fn fat_extract_marks_error_when_stale_cleanup_fails_before_extraction() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "early-cleanup", &tar_bytes).unwrap();
    let upk_path = workspace.path().join("early-cleanup.upk");
    fs::write(&upk_path, &upk).unwrap();
    let first = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(first.status.success(), "{first:?}");

    let project_dir = only_project_dir(workspace.path());
    let db = ProjectDb::open(&project_dir).unwrap();
    let mut project = db.get("early-cleanup").unwrap().unwrap();
    project.status = ProjectStatus::Extracting;
    db.save(&project).unwrap();
    let work = project_dir.join("work");
    let mut permissions = fs::metadata(&work).unwrap().permissions();
    permissions.set_mode(0o555);
    fs::set_permissions(&work, permissions).unwrap();

    let retry = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap()])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    let mut permissions = fs::metadata(&work).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&work, permissions).unwrap();

    assert!(!retry.status.success(), "{retry:?}");
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
}

#[test]
fn fat_extract_supports_non_sample_specific_utpk_seed() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    // 0xa4 is the effective seed byte from a real non-network-manager module.
    // The generic generator must support it without a seed/key lookup entry.
    let upk = unitree_upk::encode(0xa4, PAYLOAD_TYPE_TAR, "generic_seed", &tar_bytes)
        .expect("generic seed must encode");
    let upk_path = workspace.path().join("generic-seed.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("files: 0"),
        "generic-seed extraction must contain files:\n{stdout}"
    );
    let project_dir = only_project_dir(workspace.path());
    let unpacked = project_dir.join("work/extractions/unitree-upk/unpacked/network_manager_demo");
    assert!(unpacked.join("module.json").is_file());
    assert!(unpacked.join("upper_bluetooth/btgatt-server").is_file());
}

#[test]
fn fat_extract_corrupt_utpk_fails_with_validation_error() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_demo_module_tar();
    let mut upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "demo", &tar_bytes).expect("encode");
    // Corrupt a ciphertext byte so the payload MD5 no longer matches.
    let last = upk.len() - 1;
    upk[last] ^= 0xff;
    let upk_path = workspace.path().join("corrupt.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "corrupt UTPK must exit nonzero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed validation"),
        "expected validation error, got:\n{stderr}"
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extraction-manifest.json").exists());
}

#[test]
fn fat_extract_unsafe_utpk_tar_leaves_no_partial_generated_tree() {
    let workspace = tempdir().expect("workspace");
    let tar_bytes = build_partially_unsafe_module_tar();
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "unsafe", &tar_bytes)
        .expect("encode supported UTPK");
    let upk_path = workspace.path().join("unsafe.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(!output.status.success(), "unsafe tar must exit nonzero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing unsafe tar entry path"),
        "expected traversal rejection, got:\n{stderr}"
    );

    let project_dir = only_project_dir(workspace.path());
    assert!(
        !project_dir.join("work/extractions/unitree-upk").exists(),
        "failed extraction must not leave a decoded tar or partially unpacked files"
    );
}

#[test]
fn fat_extract_rejects_gnu_sparse_utpk_entries_without_partial_output() {
    let workspace = tempdir().expect("workspace");
    let upk = unitree_upk::encode(
        0x1c,
        PAYLOAD_TYPE_TAR,
        "sparse",
        &build_gnu_sparse_module_tar(),
    )
    .expect("encode UTPK");
    let upk_path = workspace.path().join("sparse.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "GNU sparse must be rejected: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("GNU sparse"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extractions").exists());
}

#[test]
fn fat_extract_rejects_utpk_tar_with_excessive_entry_count() {
    let workspace = tempdir().expect("workspace");
    let upk = unitree_upk::encode(
        0x1c,
        PAYLOAD_TYPE_TAR,
        "too-many",
        &build_many_entry_module_tar(4_097),
    )
    .expect("encode UTPK");
    let upk_path = workspace.path().join("too-many.upk");
    fs::write(&upk_path, &upk).expect("write upk");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .expect("fat extract runs");

    assert!(
        !output.status.success(),
        "entry flood must be rejected: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("too many tar entries"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extractions").exists());
}

#[test]
fn fat_extract_rejects_pax_utpk_tar_without_partial_output() {
    let workspace = tempdir().expect("workspace");
    let upk = unitree_upk::encode(0x1c, PAYLOAD_TYPE_TAR, "pax", &build_pax_module_tar())
        .expect("encode UTPK");
    let upk_path = workspace.path().join("pax.upk");
    fs::write(&upk_path, upk).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported PAX"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
    assert!(!project_dir.join("work/extractions").exists());
}

#[test]
fn fat_extract_rejects_non_tar_utpk_payload_before_decryption() {
    let workspace = tempdir().expect("workspace");
    let upk = unitree_upk::encode(0x1c, 0x7f, "unsupported", &build_demo_module_tar()).unwrap();
    let upk_path = workspace.path().join("unsupported.upk");
    fs::write(&upk_path, upk).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported UTPK payload type"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn fat_extract_surfaces_cleanup_failure_instead_of_hiding_stale_state() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware = workspace.path().join("cleanup.bin");
    fs::write(&firmware, b"firmware").unwrap();
    write_script(
        &fake_bin_dir.path().join("binwalk"),
        "#!/bin/sh\n/bin/mkdir recovered\n/usr/bin/touch recovered/evidence.bin\n/bin/chmod 0555 ../..\nexit 0\n",
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 1\n");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", firmware.to_str().unwrap()])
        .current_dir(workspace.path())
        .env("PATH", fake_bin_dir.path())
        .output()
        .unwrap();
    let project_dir = only_project_dir(workspace.path());
    let work = project_dir.join("work");
    let mut permissions = fs::metadata(&work).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&work, permissions).unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to clean stale extraction state"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
}

#[test]
fn fat_extract_rejects_oversized_declared_utpk_before_payload_read() {
    let workspace = tempdir().expect("workspace");
    let mut state: u32 = 0x1234_5678;
    let mut bytes = Vec::with_capacity(unitree_upk::HEADER_LEN + 8_196);
    for _ in 0..unitree_upk::HEADER_LEN + 8_196 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push((state & 0xff) as u8);
    }
    bytes[..4].copy_from_slice(&unitree_upk::UTPK_MAGIC);
    bytes[0x10..0x18].copy_from_slice(&(256_u64 * 1024 * 1024 + 8).to_le_bytes());
    bytes[0x18] = PAYLOAD_TYPE_TAR;
    bytes[unitree_upk::HEADER_LEN..unitree_upk::HEADER_LEN + unitree_upk::TEA_MARKER.len()]
        .copy_from_slice(&unitree_upk::TEA_MARKER);
    let upk_path = workspace.path().join("declared-oversized.upk");
    fs::write(&upk_path, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["extract", upk_path.to_str().unwrap(), "--force"])
        .current_dir(workspace.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("decrypted tar exceeds maximum size"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let project_dir = only_project_dir(workspace.path());
    assert_eq!(project_status(&project_dir), ProjectStatus::Error);
}

#[test]
fn fat_extract_and_analyze_emit_parseable_json() {
    let workspace = tempdir().expect("workspace");
    let fake_bin_dir = tempdir().expect("fake bin dir");
    let firmware_path = workspace.path().join("json-demo.bin");
    fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_script(
        &fake_bin_dir.path().join("binwalk"),
        r#"#!/bin/sh
r=_json-demo.bin.extracted/squashfs-root
mkdir -p "$r/bin" "$r/etc"
touch "$r/bin/busybox" "$r/etc/inittab"
exit 0
"#,
    );
    write_script(&fake_bin_dir.path().join("unblob"), "#!/bin/sh\nexit 1\n");
    let path = format!(
        "{}:{}",
        fake_bin_dir.path().display(),
        std::env::var("PATH").expect("PATH")
    );

    let extract = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            firmware_path.to_str().expect("firmware path"),
            "--json",
        ])
        .current_dir(workspace.path())
        .env("PATH", &path)
        .output()
        .expect("fat extract --json runs");
    assert!(extract.status.success(), "{extract:?}");

    // Nothing but the payload may reach stdout, or a pipeline cannot parse it.
    let report: serde_json::Value =
        serde_json::from_slice(&extract.stdout).expect("extract JSON parses");
    assert_eq!(report["schema"], "fat.extract.v1");
    assert_eq!(report["status"], "extracted");
    assert_eq!(report["engine"], "binwalk");
    assert!(report["file_count"].as_u64().is_some_and(|count| count > 0));
    assert!(report["rootfs"]["path"].as_str().is_some());
    assert_eq!(report["rootfs"]["filesystem"], "squashfs");
    // binwalk recovered a rootfs, so the skip decision is reported too.
    assert!(report["engines"]
        .as_array()
        .expect("engines")
        .iter()
        .any(|engine| engine["engine"] == "unblob"
            && engine["status"] == "skipped"
            && engine["detail"] == "binwalk already recovered a rootfs"));

    let project_dir = only_project_dir(workspace.path());

    // A cached re-run reports the same shape rather than a bare status line.
    let cached = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            project_dir.to_str().expect("project dir"),
            "--json",
        ])
        .env("PATH", &path)
        .output()
        .expect("cached fat extract --json runs");
    assert!(cached.status.success(), "{cached:?}");
    let cached_report: serde_json::Value =
        serde_json::from_slice(&cached.stdout).expect("cached extract JSON parses");
    assert_eq!(cached_report["status"], "already-extracted");
    assert_eq!(cached_report["engine"], "binwalk");

    let analyze = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "analyze",
            project_dir.to_str().expect("project dir"),
            "--json",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat analyze --json runs");
    assert!(analyze.status.success(), "{analyze:?}");
    let analysis: serde_json::Value =
        serde_json::from_slice(&analyze.stdout).expect("analyze JSON parses");
    assert_eq!(analysis["schema"], "fat.analyze.v1");
    assert!(analysis["findings"].as_u64().is_some());
    let signals = analysis["signals"].as_array().expect("signals");
    assert!(signals
        .iter()
        .any(|signal| signal["signal"] == "init:busybox" && signal["provenance"] == "tree-name"));

    let preflight = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "preflight",
            project_dir.to_str().expect("project dir"),
            "--json",
        ])
        .env("PATH", &path)
        .output()
        .expect("fat preflight --json runs");
    assert!(preflight.status.success(), "{preflight:?}");
    let readiness: serde_json::Value =
        serde_json::from_slice(&preflight.stdout).expect("preflight JSON parses");
    assert_eq!(readiness["schema"], "fat.preflight.v1");
    assert!(readiness["family"]["family_id"].as_str().is_some());
    assert!(!readiness["backends"]
        .as_array()
        .expect("backends")
        .is_empty());

    // Default output is unchanged by the flag existing.
    let text = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["analyze", project_dir.to_str().expect("project dir")])
        .env("PATH", &path)
        .output()
        .expect("fat analyze runs");
    assert!(text.status.success(), "{text:?}");
    let text_stdout = String::from_utf8_lossy(&text.stdout);
    assert!(text_stdout.starts_with("project: "), "{text_stdout}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&text_stdout).is_err(),
        "text mode must stay human output: {text_stdout}"
    );
}

#[test]
fn native_extract_recurses_through_containers_and_records_lineage() {
    let workspace = tempdir().unwrap();
    let image = firmware_formats::cramfs_fixture(firmware_formats::FixtureEndian::Big).image;
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(image.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "payload", image.as_slice())
        .unwrap();
    let input = workspace.path().join("nested.bin");
    fs::write(&input, archive.into_inner().unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            input.to_str().unwrap(),
            "--extractor",
            "native",
            "--json",
        ])
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["recovery_status"], "rootfs_recovered");
    assert_eq!(json["artifacts"][0]["format"], "tar");
    assert_eq!(json["artifacts"][1]["format"], "cramfs");
    assert_eq!(json["artifacts"][1]["parent"], 0);
    assert_eq!(json["engine"], "native");
}

#[test]
fn native_selection_does_not_run_external_rootfs_fallback() {
    let workspace = tempdir().unwrap();
    let tools = tempdir().unwrap();
    let marker = workspace.path().join("external-ran");
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "rootfs.squashfs", &b"data"[..])
        .unwrap();
    let input = workspace.path().join("native-only.tar");
    fs::write(&input, archive.into_inner().unwrap()).unwrap();
    let script = format!("#!/bin/sh\n/usr/bin/touch '{}'\nexit 1\n", marker.display());
    for name in ["sasquatch", "unsquashfs"] {
        write_script(&tools.path().join(name), &script);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "extract",
            input.to_str().unwrap(),
            "--extractor",
            "native",
            "--json",
        ])
        .current_dir(workspace.path())
        .env("PATH", tools.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!marker.exists());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["recovery_status"], "files_only");
    assert!(json["rootfs"].is_null());
}
