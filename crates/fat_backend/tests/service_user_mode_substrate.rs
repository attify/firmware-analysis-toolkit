use std::fs;
use std::path::PathBuf;

use fat_backend::service_user_mode::{ServiceUserModeManager, ServiceUserModeRequest};
use fat_core::diagnostics::{DiagnosticClass, DiagnosticPhase};
use fat_core::rehosting_recipe::RecipeFilesystemTransform;

#[test]
fn service_user_mode_launch_times_out_and_is_classified() {
    let tempdir = make_temp_dir("service-user-timeout");
    let input_root = tempdir.path().join("input-root");
    let source_root = tempdir.path().join("source-root");
    let staging_root = tempdir.path().join("staging-root");
    fs::create_dir_all(input_root.join("usr/sbin")).expect("input root");
    make_executable(input_root.join("usr/sbin/uhttpd"), "#!/bin/sh\nexit 0\n");
    make_executable(tempdir.path().join("qemu-arm"), "#!/bin/sh\nsleep 5\n");

    let manager = ServiceUserModeManager::new();
    let prepared = manager
        .prepare(ServiceUserModeRequest::new(
            "demo",
            "target-demo",
            "armel",
            tempdir.path().join("qemu-arm"),
            input_root,
            source_root,
            staging_root,
            "/usr/sbin/uhttpd",
        ))
        .expect("prepared");

    let previous = std::env::var_os("FAT_SERVICE_USER_MODE_TIMEOUT_SECS");
    std::env::set_var("FAT_SERVICE_USER_MODE_TIMEOUT_SECS", "1");
    let diagnostic = manager
        .launch(&prepared)
        .expect_err("launch should time out");
    restore_env("FAT_SERVICE_USER_MODE_TIMEOUT_SECS", previous);

    assert_eq!(diagnostic.phase, DiagnosticPhase::Launch);
    assert_eq!(diagnostic.class, DiagnosticClass::LaunchFailed);
    assert!(diagnostic.summary.contains("timed out"));
}

#[test]
fn service_user_mode_prepare_rejects_symlink_targets_that_escape_rootfs() {
    let tempdir = make_temp_dir("service-user-symlink-escape");
    let input_root = tempdir.path().join("input-root");
    let source_root = tempdir.path().join("source-root");
    let staging_root = tempdir.path().join("staging-root");
    fs::create_dir_all(input_root.join("usr/sbin")).expect("input root");
    fs::create_dir_all(input_root.join("etc")).expect("etc root");
    make_executable(input_root.join("usr/sbin/uhttpd"), "#!/bin/sh\nexit 0\n");
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "../../../../etc/shadow",
        input_root.join("etc").join("bad-link"),
    )
    .expect("bad symlink");
    #[cfg(not(unix))]
    fs::write(input_root.join("etc").join("bad-link"), b"shadow").expect("fallback bad link");
    make_executable(tempdir.path().join("qemu-arm"), "#!/bin/sh\nexit 0\n");

    let manager = ServiceUserModeManager::new();
    let diagnostic = manager
        .prepare(ServiceUserModeRequest::new(
            "demo",
            "target-demo",
            "armel",
            tempdir.path().join("qemu-arm"),
            input_root,
            source_root,
            staging_root,
            "/usr/sbin/uhttpd",
        ))
        .expect_err("escaping symlink should fail");

    assert_eq!(diagnostic.phase, DiagnosticPhase::Preparation);
    assert_eq!(diagnostic.class, DiagnosticClass::PreparationFailed);
    assert!(diagnostic.summary.contains("symlink"));
    assert!(diagnostic.summary.contains("escape"));
}

#[test]
fn service_user_mode_materializes_declared_directories_as_directories() {
    let tempdir = make_temp_dir("service-user-materialize-directory");
    let input_root = tempdir.path().join("input-root");
    let source_root = tempdir.path().join("source-root");
    let staging_root = tempdir.path().join("staging-root");
    fs::create_dir_all(input_root.join("usr/sbin")).unwrap();
    make_executable(input_root.join("usr/sbin/uhttpd"), "#!/bin/sh\nexit 0\n");
    make_executable(tempdir.path().join("qemu-arm"), "#!/bin/sh\nexit 0\n");

    let manager = ServiceUserModeManager::new();
    manager
        .prepare(
            ServiceUserModeRequest::new(
                "demo",
                "target-demo",
                "armel",
                tempdir.path().join("qemu-arm"),
                input_root,
                source_root,
                staging_root.clone(),
                "/usr/sbin/uhttpd",
            )
            .with_filesystem_transforms(vec![RecipeFilesystemTransform::directory(
                "materialize",
                "/configs",
            )]),
        )
        .expect("prepared");

    assert!(staging_root.join("configs").is_dir());
}

fn make_temp_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("tempdir")
}

fn make_executable(path: PathBuf, contents: &str) {
    fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("permissions");
    }
}

fn restore_env(key: &str, value: Option<std::ffi::OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}
