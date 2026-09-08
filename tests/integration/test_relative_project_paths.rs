use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::tempdir;

/// `fat emulate --project ./relative/path` must resolve the project directory to
/// an absolute path before any launch specification is built. Native-system
/// launches set the QEMU child working directory to the run directory, so a
/// project-relative file argument that the parent could open resolves to a
/// different (non-existent) path in the child.
#[test]
fn emulate_relative_project_records_absolute_paths() {
    let workspace = tempdir().expect("workspace");
    let projects_dir = workspace.path().join("projects");
    let path_dir = tempdir().expect("path dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::create_dir_all(&projects_dir).expect("projects dir");
    std::fs::write(&firmware_path, b"arm firmware-bytes").expect("firmware file");
    make_executable(
        path_dir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'launch failed\\n' >&2\nexit 7\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\n",
    )
    .expect("signals file");

    // Invoke from the project parent with a relative --project, the exact shape
    // that produced unresolvable child paths.
    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .current_dir(&projects_dir)
        .args([
            "emulate",
            "--project",
            "./demo",
            "--backend",
            "qemu-direct",
            "--session-id",
            "relative-project-1",
        ])
        .output()
        .expect("fat emulate runs");

    // The stub QEMU always fails; what matters is which paths were generated.
    assert!(!emulate_output.status.success(), "{emulate_output:?}");

    let recorded_paths = recorded_filesystem_paths(&project_dir.join("sessions"));
    assert!(
        !recorded_paths.is_empty(),
        "expected the run to record at least one filesystem path"
    );
    let relative_paths: Vec<&String> = recorded_paths
        .iter()
        .filter(|path| !Path::new(path).is_absolute())
        .collect();
    assert!(
        relative_paths.is_empty(),
        "launch paths must be absolute so the QEMU child can resolve them from its own cwd: {relative_paths:?}"
    );
}

/// Collect every JSON string value that looks like a generated filesystem path
/// (staging roots, rootfs images, capture files) from the recorded run tree.
fn recorded_filesystem_paths(sessions_dir: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    for record in json_records(sessions_dir) {
        collect_path_like_strings(&record, &mut paths);
    }
    paths.sort();
    paths.dedup();
    paths
}

fn json_records(dir: &Path) -> Vec<serde_json::Value> {
    let mut records = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return records;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            records.extend(json_records(&path));
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    records.push(value);
                }
            }
        }
    }
    records
}

fn collect_path_like_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            // Only project-tree paths are FAT-generated launch arguments; ids and
            // free-form diagnostic text are not.
            if text.contains("/demo/work/") || text.starts_with("./demo") {
                out.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_path_like_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_path_like_strings(item, out);
            }
        }
        _ => {}
    }
}

fn make_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}
