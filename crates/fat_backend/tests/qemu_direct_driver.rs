use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fat_backend::qemu_direct::{QemuDirectDriver, QemuDirectRequest};
use fat_backend::{BackendSubstrateKind, BackendSubstrateStatus};
use fat_core::diagnostics::{DiagnosticClass, DiagnosticPhase};
use fat_core::runs::{RuntimeEndpointKind, SubstrateKind};

#[test]
fn qemu_direct_prepares_narrow_working_set_with_stable_endpoint_metadata() {
    let tempdir = make_temp_dir("qemu-direct-prep");
    let qemu_binary = make_executable(
        tempdir.path().join("qemu-system-arm"),
        "#!/bin/sh\nexit 0\n",
    );
    let docker_binary = make_executable(tempdir.path().join("docker"), "#!/bin/sh\nexit 0\n");

    let driver = QemuDirectDriver::new();
    let request = QemuDirectRequest::new(
        "project-1",
        "target-1",
        "linux-router-arm",
        "boot-web-ui",
        "armel",
        qemu_binary,
        docker_binary,
        tempdir.path().join("work"),
    );

    let prepared = driver.prepare(request).expect("prepared");

    assert_eq!(prepared.request.family_id, "linux-router-arm");
    assert_eq!(prepared.request.architecture, "armel");
    assert_eq!(prepared.request.goal, "boot-web-ui");
    assert!(prepared
        .placements
        .iter()
        .any(|placement| placement.substrate == BackendSubstrateKind::NativeHost));
    let native_host = prepared
        .placement(BackendSubstrateKind::NativeHost)
        .expect("native-host placement");
    assert!(
        prepared
            .placement(BackendSubstrateKind::DockerEngine)
            .is_none(),
        "the incomplete mutable-image Docker placement must be disabled for the public alpha"
    );

    assert!(native_host
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Shell));
    assert!(native_host
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Debugger));
    assert!(native_host
        .launch_command
        .first()
        .map(|path| path == &prepared.request.qemu_binary)
        .unwrap_or(false));
    assert_eq!(
        endpoint_ports(&native_host.endpoints),
        vec![10022, 10023, 10024]
    );
    assert_eq!(native_host.substrate_kind(), SubstrateKind::NativeHost);
    assert_eq!(
        native_host.substrate_contract().health.status,
        BackendSubstrateStatus::Healthy
    );
}

#[test]
fn qemu_direct_launch_failure_is_classified_with_shared_diagnostics() {
    let tempdir = make_temp_dir("qemu-direct-launch");
    let qemu_binary = make_executable(
        tempdir.path().join("qemu-system-arm"),
        "#!/bin/sh\nprintf 'boom\\n' >&2\nexit 7\n",
    );
    let docker_binary = make_executable(tempdir.path().join("docker"), "#!/bin/sh\nexit 0\n");

    let driver = QemuDirectDriver::new();
    let request = QemuDirectRequest::new(
        "project-2",
        "target-2",
        "linux-router-arm",
        "boot-web-ui",
        "armel",
        qemu_binary,
        docker_binary,
        tempdir.path().join("work"),
    );

    let prepared = driver.prepare(request).expect("prepared");
    let result = driver.launch(&prepared, BackendSubstrateKind::NativeHost);

    let diagnostic = result.expect_err("launch should fail");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Launch);
    assert_eq!(diagnostic.class, DiagnosticClass::LaunchFailed);
    assert!(diagnostic.summary.contains("qemu-direct"));
}

#[test]
fn qemu_direct_can_prepare_native_host_without_docker() {
    let tempdir = make_temp_dir("qemu-direct-native-only");
    let qemu_binary = make_executable(
        tempdir.path().join("qemu-system-arm"),
        "#!/bin/sh\nexit 0\n",
    );

    let driver = QemuDirectDriver::new();
    let request = QemuDirectRequest::new(
        "project-3",
        "target-3",
        "linux-router-arm",
        "boot-web-ui",
        "armel",
        qemu_binary,
        tempdir.path().join("missing-docker"),
        tempdir.path().join("work"),
    );

    let prepared = driver.prepare(request).expect("prepared");

    assert!(prepared
        .placement(BackendSubstrateKind::NativeHost)
        .is_some());
    assert!(prepared
        .placement(BackendSubstrateKind::DockerEngine)
        .is_none());
}

fn endpoint_ports(endpoints: &[fat_core::runs::RuntimeEndpoint]) -> Vec<u16> {
    endpoints.iter().map(|endpoint| endpoint.port).collect()
}

fn make_executable(path: PathBuf, content: &str) -> PathBuf {
    fs::write(&path, content).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("permissions");
    }

    path
}

fn make_temp_dir(prefix: &str) -> TempDir {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved forward")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "fat-backend-{prefix}-{}-{unique_suffix}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp dir");

    TempDir { path }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}
