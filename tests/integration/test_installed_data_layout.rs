use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn write(path: &Path, contents: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn installed_fat() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let prefix = temp.path().join("prefix");
    let binary = prefix.join("bin/fat");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_fat"), &binary).expect("copy fat binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
    }
    let data = prefix.join("share/fat");
    let unrelated = temp.path().join("unrelated/current-directory");
    fs::create_dir_all(&unrelated).unwrap();
    (temp, binary, data)
}

fn run(binary: &Path, cwd: &Path, args: &[&str]) -> Output {
    run_with_packs(binary, cwd, args, None)
}

fn run_with_packs(binary: &Path, cwd: &Path, args: &[&str], packs: Option<&Path>) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(cwd)
        .env_remove("FAT_DATA_DIR");
    match packs {
        Some(dir) => command.env("FAT_REHOSTING_PACKS", dir),
        None => command.env_remove("FAT_REHOSTING_PACKS"),
    };
    command.output().expect("copied fat binary runs")
}

#[test]
fn copied_binary_discovers_rehosting_packs_from_an_explicit_source() {
    let (temp, binary, data) = installed_fat();

    const PACK: &str = r#"id: acme/router
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  signals: ["fs:squashfs", "init:busybox"]
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: rcS
"#;

    // The same pack in two places: the installed data directory, which FAT no
    // longer searches, and an operator-chosen directory, which it does.
    write(&data.join("profiles/rehosting/acme/router.yaml"), PACK);
    let chosen = temp.path().join("operator-packs");
    write(&chosen.join("router.yaml"), PACK);

    let project = temp.path().join("project");
    write(
        &project.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    );
    let unrelated = temp.path().join("unrelated/current-directory");
    let args = &["rehost", "match", project.to_str().unwrap(), "--json"];

    // Installed, run from an unrelated directory, with an explicit source.
    let output = run_with_packs(&binary, &unrelated, args, Some(&chosen));
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows[0]["id"], "acme/router");
    assert!(rows[0]["path"]
        .as_str()
        .unwrap()
        .starts_with(chosen.to_str().unwrap()));

    // Without that source, the copy sitting in the installed data directory is
    // inert: FAT ships no packs and no longer searches its own data tree.
    let output = run_with_packs(&binary, &unrelated, args, None);
    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        rows.as_array().map(Vec::is_empty).unwrap_or(true),
        "an installed data directory must not be an implicit pack source: {rows}"
    );
}

#[test]
fn copied_binary_loads_bootloader_profiles_from_sibling_share() {
    let (temp, binary, data) = installed_fat();
    write(
        &data.join("profiles/bootloader/consumer-iot-camera.json"),
        include_str!("../../profiles/bootloader/consumer-iot-camera.json"),
    );
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let unrelated = temp.path().join("unrelated/current-directory");

    let output = run(
        &binary,
        &unrelated,
        &[
            "bootloader",
            "new",
            project.to_str().unwrap(),
            "--profile",
            "consumer-iot-camera",
        ],
    );

    assert!(
        !output.status.success(),
        "empty project should lack boot artifacts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("runtime resource"), "{stderr}");
    assert!(
        !stderr.contains("unsupported bootloader profile"),
        "{stderr}"
    );
}

#[test]
fn copied_binary_doctor_discovers_custom_data_through_sibling_share() {
    let (temp, binary, data) = installed_fat();
    let custom = temp.path().join("custom data");
    fs::create_dir_all(custom.join("profiles")).unwrap();
    fs::create_dir_all(data.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&custom, &data).unwrap();
    #[cfg(windows)]
    {
        // Windows may require elevation for directory symlinks. The ordinary
        // sibling layout still exercises the shared discovery path there.
        fs::create_dir_all(data.join("profiles")).unwrap();
    }
    let unrelated = temp.path().join("unrelated/current-directory");
    let output = run(&binary, &unrelated, &["doctor", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data_dir"]["status"], "discovered", "{value}");
    assert_eq!(value["data_dir"]["path"], data.to_str().unwrap());
}

#[test]
fn copied_binary_writes_android_handoff_using_sibling_share_scripts() {
    let (temp, binary, data) = installed_fat();
    for script in ["adb_icc_runner.py", "webview_runner.py", "native_runner.py"] {
        write(
            &data.join("scripts/discovery/android").join(script),
            "#!/usr/bin/env python3\n",
        );
    }
    let apk = temp.path().join("base.apk");
    let file = fs::File::create(&apk).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    use std::io::Write as _;
    zip.start_file("AndroidManifest.xml", options).unwrap();
    zip.write_all(b"<manifest package=\"com.example.app\"><application /></manifest>")
        .unwrap();
    zip.start_file("classes.dex", options).unwrap();
    zip.write_all(b"dex").unwrap();
    zip.finish().unwrap();
    let manifest = temp.path().join("runtime.json");
    let semantic = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/android/semantic/router-mini.json");
    let unrelated = temp.path().join("unrelated/current-directory");

    let output = run(
        &binary,
        &unrelated,
        &[
            "android",
            "discover",
            "--apk",
            apk.to_str().unwrap(),
            "--semantic-bundle",
            semantic.to_str().unwrap(),
            "--family",
            "remote-router-gadget",
            "--runtime-manifest-out",
            manifest.to_str().unwrap(),
            "--json",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    let command = value["lanes"][0]["launcher_command"].as_array().unwrap();
    assert!(command.iter().filter_map(|item| item.as_str()).any(|item| {
        item == data
            .join("scripts/discovery/android/adb_icc_runner.py")
            .to_str()
            .unwrap()
    }));
}
