use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fat_backend::managed_linux_vm::{
    ManagedLinuxVmManager, ManagedLinuxVmRequest, ManagedLinuxVmRuntimeOutcome,
    ManagedLinuxVmRuntimePhase, ManagedLinuxVmStopResultContract,
    ManagedLinuxVmUpstreamLaunchResult, ManagedLinuxVmUpstreamObservationRequest,
    ManagedLinuxVmUpstreamStopRequest,
};
use fat_backend::CommandProbe;
use fat_backend::{BackendSubstrateKind, BackendSubstrateStatus};
use fat_core::diagnostics::{DiagnosticClass, DiagnosticPhase};
use fat_core::runs::RuntimeEndpointKind;
use fat_core::services::managed_runtime_summary_from_runtime_status_json;

#[test]
fn managed_linux_vm_prepares_bundle_backed_workspace() {
    let tempdir = make_temp_dir("managed-linux-vm");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir.clone(),
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");

    assert_eq!(prepared.contract.kind, BackendSubstrateKind::ManagedLinuxVm);
    assert_eq!(
        prepared.contract.health.status,
        BackendSubstrateStatus::Healthy
    );
    assert!(prepared.workspace_dir.exists());
    assert_eq!(prepared.bundle.bundle_version, "v1");
}

#[test]
fn managed_linux_vm_reports_missing_bundle_inputs_as_unavailable() {
    let tempdir = make_temp_dir("managed-linux-vm-missing");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");

    let manager = ManagedLinuxVmManager::new();
    let err = manager
        .prepare(ManagedLinuxVmRequest::new(
            "managed-linux-vm",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect_err("missing bundle should fail");

    assert_eq!(err.contract.kind, BackendSubstrateKind::ManagedLinuxVm);
    assert_eq!(
        err.contract.health.status,
        BackendSubstrateStatus::Unavailable
    );
    assert!(err.contract.health.detail.contains("base-image.qcow2"));
}

#[test]
fn managed_linux_vm_prepares_upstream_firmae_without_bundle_stubs() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-prepare");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir.clone(),
            tempdir.path().join("workspace"),
        ))
        .expect("upstream prepare should not require bundle stubs");

    assert_eq!(prepared.contract.kind, BackendSubstrateKind::ManagedLinuxVm);
    assert_eq!(
        prepared.contract.health.status,
        BackendSubstrateStatus::Healthy
    );
    assert_eq!(
        prepared.bundle.base_image,
        bundle_dir.join("base-image.qcow2")
    );
    assert_eq!(prepared.bundle.guest_agent, bundle_dir.join("guest-agent"));
    assert!(prepared.workspace_dir.exists());
}

#[test]
fn managed_linux_vm_launches_guest_agent_and_emits_endpoints() {
    let tempdir = make_temp_dir("managed-linux-vm-launch");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(
            ManagedLinuxVmRequest::new(
                "firmae",
                "v1",
                bundle_dir.clone(),
                tempdir.path().join("workspace"),
            )
            .with_mapped_ports(vec![8080]),
        )
        .expect("prepared");
    let launched = manager.launch(&prepared).expect("launched");

    assert_eq!(launched.substrate, BackendSubstrateKind::ManagedLinuxVm);
    assert!(launched.stdout.contains("managed-vm launch ok"));
    assert!(launched
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Shell));
    assert!(launched
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Debugger));
    assert!(launched
        .endpoints
        .iter()
        .any(|endpoint| endpoint.kind == RuntimeEndpointKind::Monitor));
    assert_eq!(launched.endpoints.len(), 3);
}

#[test]
fn managed_linux_vm_launch_uses_backend_manifest_endpoints_when_provided() {
    let tempdir = make_temp_dir("managed-linux-vm-launch-manifest");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\ncat <<'EOF'\n{\"endpoints\":[{\"kind\":\"shell\",\"name\":\"shell\",\"host\":\"127.0.0.1\",\"port\":2202,\"target_port\":22,\"uri\":\"ssh://127.0.0.1:2202\"},{\"kind\":\"service\",\"name\":\"web-admin\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}]}\nEOF\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(
            ManagedLinuxVmRequest::new(
                "firmae",
                "v1",
                bundle_dir.clone(),
                tempdir.path().join("workspace"),
            )
            .with_mapped_ports(vec![8080]),
        )
        .expect("prepared");
    let launched = manager.launch(&prepared).expect("launched");

    assert_eq!(launched.endpoints.len(), 2);
    assert_eq!(launched.endpoints[0].kind, RuntimeEndpointKind::Shell);
    assert_eq!(launched.endpoints[0].port, 2202);
    assert_eq!(launched.endpoints[1].kind, RuntimeEndpointKind::Service);
    assert_eq!(launched.endpoints[1].name, "web-admin");
    assert_eq!(launched.endpoints[1].port, 18080);
}

#[test]
fn managed_linux_vm_launch_failure_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-launch-fail");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nprintf 'vm failed\\n' >&2\nexit 9\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let diagnostic = manager.launch(&prepared).expect_err("launch should fail");

    assert_eq!(diagnostic.phase, DiagnosticPhase::Launch);
    assert_eq!(diagnostic.class, DiagnosticClass::LaunchFailed);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-launch-failed")
    );
    assert!(diagnostic.summary.contains("managed-linux-vm"));
}

#[test]
fn managed_linux_vm_invalid_launch_manifest_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-launch-manifest-invalid");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nprintf '{\"endpoints\":['\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let diagnostic = manager
        .launch(&prepared)
        .expect_err("invalid manifest should fail");

    assert_eq!(diagnostic.phase, DiagnosticPhase::Launch);
    assert_eq!(diagnostic.class, DiagnosticClass::LaunchFailed);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-launch-manifest-invalid")
    );
    assert!(diagnostic.summary.contains("launch manifest"));
}

#[test]
fn managed_linux_vm_firmae_launch_manifest_requires_shell_endpoint() {
    let tempdir = make_temp_dir("managed-linux-vm-firmae-manifest-shell");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\ncat <<'EOF'\n{\"endpoints\":[{\"kind\":\"service\",\"name\":\"web-admin\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}]}\nEOF\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let diagnostic = manager
        .launch(&prepared)
        .expect_err("FirmAE manifest should require a shell endpoint");

    assert_eq!(diagnostic.phase, DiagnosticPhase::Launch);
    assert_eq!(diagnostic.class, DiagnosticClass::LaunchFailed);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-launch-manifest-invalid")
    );
    assert!(diagnostic.summary.contains("shell endpoint"));
}

#[test]
fn managed_linux_vm_generic_manifest_can_omit_shell_endpoint() {
    let tempdir = make_temp_dir("managed-linux-vm-generic-manifest-no-shell");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\ncat <<'EOF'\n{\"endpoints\":[{\"kind\":\"service\",\"name\":\"web-admin\",\"host\":\"127.0.0.1\",\"port\":18080,\"target_port\":80,\"uri\":\"http://127.0.0.1:18080\"}]}\nEOF\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "managed-linux-vm",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let launched = manager
        .launch(&prepared)
        .expect("generic launch should succeed");

    assert_eq!(launched.endpoints.len(), 1);
    assert_eq!(launched.endpoints[0].kind, RuntimeEndpointKind::Service);
    assert_eq!(launched.endpoints[0].name, "web-admin");
}

#[test]
fn managed_linux_vm_launches_upstream_firmae_and_captures_declared_artifacts() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-launch");
    let bundle_dir = tempdir.path().join("bundle");
    let upstream_dir = tempdir.path().join("upstream");
    let upstream_dir_for_assertions = upstream_dir.clone();
    let host_python = tempdir.path().join("python");
    let firmware_path = tempdir.path().join("firmware.bin.dec");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&upstream_dir).expect("upstream dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    fs::write(
        upstream_dir.join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    fs::write(upstream_dir.join("download.sh"), b"#!/bin/sh\n").expect("download");
    fs::create_dir_all(upstream_dir.join("database")).expect("database dir");
    fs::write(upstream_dir.join("database").join("schema"), b"-- schema\n").expect("schema");
    fs::create_dir_all(upstream_dir.join("core")).expect("core dir");
    fs::write(
        upstream_dir.join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    fs::write(&firmware_path, b"firmware").expect("firmware file");
    make_executable(
        host_python.clone(),
        "#!/bin/sh\nprintf 'upstream launch ok\\n'\nprintf 'artifact:scratch/1/qemu.initial.serial.log\\n'\nprintf 'artifact:scratch/1/qemu.final.serial.log\\n'\nprintf '%s\\n' \"$PWD\" > \"$PWD/cwd.txt\"\nprintf '%s\\n' \"$0\" \"$1\" \"$2\" \"$3\" \"$4\" > \"$PWD/args.txt\"\nmkdir -p \"$PWD/scratch/1\"\nprintf 'serial-one\\n' > \"$PWD/scratch/1/qemu.initial.serial.log\"\nprintf 'serial-two\\n' > \"$PWD/scratch/1/qemu.final.serial.log\"\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");

    let upstream_launch = manager
        .launch_firmae_upstream(
            &prepared,
            &fat_backend::managed_linux_vm::ManagedLinuxVmUpstreamLaunchRequest::new(
                upstream_dir.clone(),
                host_python,
                firmware_path,
                "example-brand",
            ),
        )
        .expect("upstream launch");

    assert!(upstream_launch.stdout.contains("upstream launch ok"));
    assert!(upstream_launch
        .declared_artifact_paths
        .iter()
        .any(|path| path.ends_with("qemu.initial.serial.log")));
    assert!(upstream_launch
        .declared_artifact_paths
        .iter()
        .any(|path| path.ends_with("qemu.final.serial.log")));
    assert!(upstream_launch.stdout.contains("artifact:"));
    let cwd = fs::read_to_string(upstream_dir_for_assertions.join("cwd.txt")).expect("cwd");
    let cwd = PathBuf::from(cwd.trim());
    let expected_upstream_dir =
        fs::canonicalize(&upstream_dir_for_assertions).expect("canonical upstream dir");
    let cwd = fs::canonicalize(&cwd).expect("canonical cwd");
    assert_eq!(cwd, expected_upstream_dir);
    let args = fs::read_to_string(upstream_dir_for_assertions.join("args.txt")).expect("args");
    let expected_helper = tempdir.path().join("python").to_string_lossy().into_owned();
    assert!(args.contains(&expected_helper), "{args}");
    assert!(args.contains("docker-helper.py"), "{args}");
    assert!(args.contains("-ec"), "{args}");
    assert!(args.contains("example-brand"), "{args}");
    assert!(args.contains("firmware.bin.dec"), "{args}");
    assert!(upstream_launch
        .declared_artifact_paths
        .iter()
        .all(|path| fs::canonicalize(path)
            .expect("canonical artifact path")
            .starts_with(&expected_upstream_dir)));
}

#[test]
fn managed_linux_vm_observes_upstream_guest_reachable_but_services_unreachable() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-observe-unreachable");
    let bundle_dir = tempdir.path().join("bundle");
    let upstream_dir = tempdir.path().join("upstream");
    let tools_dir = tempdir.path().join("tools");
    let scratch_dir = upstream_dir.join("scratch").join("1");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&tools_dir).expect("tools dir");
    fs::create_dir_all(&scratch_dir).expect("scratch dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    fs::write(scratch_dir.join("qemu.initial.serial.log"), b"booting\n").expect("initial serial");
    fs::write(
        scratch_dir.join("qemu.final.serial.log"),
        b"guest-ip:192.168.0.1\n",
    )
    .expect("final serial");
    fs::write(
        scratch_dir.join("makeNetwork.log"),
        b"guest-ip:192.168.0.1\n",
    )
    .expect("network log");
    make_executable(
        tools_dir.join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then printf 'true\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(
        tools_dir.join("ping"),
        "#!/bin/sh\nif [ \"$5\" = \"192.168.0.1\" ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(tools_dir.join("nc"), "#!/bin/sh\nexit 1\n");

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let launch_result = ManagedLinuxVmUpstreamLaunchResult {
        exit_code: Some(0),
        stdout: "upstream launch ok\ncontainer:docker0_demo-camera\nartifact:scratch/1/qemu.initial.serial.log\nartifact:scratch/1/qemu.final.serial.log\nartifact:scratch/1/makeNetwork.log\n".to_string(),
        stderr: String::new(),
        container_name: Some("docker0_demo-camera".to_string()),
        declared_artifact_paths: vec![
            scratch_dir.join("qemu.initial.serial.log"),
            scratch_dir.join("qemu.final.serial.log"),
            scratch_dir.join("makeNetwork.log"),
        ],
    };
    let command_probe = StaticCommandProbe::new([
        ("docker", tools_dir.join("docker")),
        ("ping", tools_dir.join("ping")),
        ("nc", tools_dir.join("nc")),
    ]);

    let observation = manager
        .observe_firmae_upstream(
            &prepared,
            &launch_result,
            &ManagedLinuxVmUpstreamObservationRequest::new(upstream_dir, None),
            &command_probe,
        )
        .expect("observation");

    assert!(observation.container_running);
    assert!(observation.scratch_artifacts_present);
    assert_eq!(observation.guest_ip.as_deref(), Some("192.168.0.1"));
    assert!(observation.guest_reachable);
    assert!(!observation.port_80_reachable);
    assert!(!observation.port_31337_reachable);
    assert!(!observation.port_31338_reachable);
    assert_eq!(
        observation.runtime_status.phase,
        ManagedLinuxVmRuntimePhase::ProbeUnreachable
    );
    assert_eq!(
        observation.runtime_status.runtime_outcome,
        Some(ManagedLinuxVmRuntimeOutcome::BootedServicesUnreachable)
    );
}

#[test]
fn managed_linux_vm_observes_upstream_known_service_reachability() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-observe-service");
    let bundle_dir = tempdir.path().join("bundle");
    let upstream_dir = tempdir.path().join("upstream");
    let tools_dir = tempdir.path().join("tools");
    let scratch_dir = upstream_dir.join("scratch").join("1");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&tools_dir).expect("tools dir");
    fs::create_dir_all(&scratch_dir).expect("scratch dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    fs::write(
        scratch_dir.join("qemu.final.serial.log"),
        b"guest-ip:192.168.0.1\n",
    )
    .expect("final serial");
    fs::write(
        scratch_dir.join("makeNetwork.log"),
        b"guest-ip:192.168.0.1\n",
    )
    .expect("network log");
    make_executable(
        tools_dir.join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"inspect\" ]; then printf 'true\\n'; exit 0; fi\nexit 1\n",
    );
    make_executable(
        tools_dir.join("ping"),
        "#!/bin/sh\nif [ \"$5\" = \"192.168.0.1\" ]; then exit 0; fi\nexit 1\n",
    );
    make_executable(
        tools_dir.join("nc"),
        "#!/bin/sh\nlast=''\nfor arg in \"$@\"; do last=\"$arg\"; done\nif [ \"$last\" = \"80\" ]; then exit 0; fi\nexit 1\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let launch_result = ManagedLinuxVmUpstreamLaunchResult {
        exit_code: Some(0),
        stdout: "upstream launch ok\ncontainer:docker0_demo-camera\nartifact:scratch/1/qemu.final.serial.log\nartifact:scratch/1/makeNetwork.log\n".to_string(),
        stderr: String::new(),
        container_name: Some("docker0_demo-camera".to_string()),
        declared_artifact_paths: vec![
            scratch_dir.join("qemu.final.serial.log"),
            scratch_dir.join("makeNetwork.log"),
        ],
    };
    let command_probe = StaticCommandProbe::new([
        ("docker", tools_dir.join("docker")),
        ("ping", tools_dir.join("ping")),
        ("nc", tools_dir.join("nc")),
    ]);

    let observation = manager
        .observe_firmae_upstream(
            &prepared,
            &launch_result,
            &ManagedLinuxVmUpstreamObservationRequest::new(upstream_dir, None),
            &command_probe,
        )
        .expect("observation");

    assert!(observation.container_running);
    assert!(observation.guest_reachable);
    assert!(observation.port_80_reachable);
    assert!(!observation.port_31337_reachable);
    assert!(!observation.port_31338_reachable);
    assert!(observation.runtime_status.endpoints.iter().any(|endpoint| {
        endpoint.kind == RuntimeEndpointKind::Service
            && endpoint.name == "port-80"
            && endpoint.port == 80
    }));
    assert_eq!(
        observation.runtime_status.phase,
        ManagedLinuxVmRuntimePhase::ProbeHealthy
    );
    assert_eq!(
        observation.runtime_status.runtime_outcome,
        Some(ManagedLinuxVmRuntimeOutcome::BootedServicesReachable)
    );

    let summary = managed_runtime_summary_from_runtime_status_json(
        &serde_json::json!({
            "runtime_status": observation.runtime_status.clone()
        })
        .to_string(),
    )
    .expect("summary");
    assert_eq!(summary.services.len(), 1);
    assert_eq!(
        summary.services[0].display_label(),
        "port-80 http://192.168.0.1:80"
    );
}

#[test]
fn managed_linux_vm_firmae_upstream_stop_stops_declared_container() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-stop");
    let bundle_dir = tempdir.path().join("bundle");
    let tools_dir = tempdir.path().join("tools");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&tools_dir).expect("tools dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    make_executable(
        tools_dir.join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"stop\" ] && [ \"$2\" = \"firmae-upstream-demo\" ]; then printf 'firmae-upstream-demo\\n'; exit 0; fi\nexit 1\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let command_probe = StaticCommandProbe::new([("docker", tools_dir.join("docker"))]);

    let stopped = manager
        .stop_firmae_upstream(
            &prepared,
            &ManagedLinuxVmUpstreamStopRequest::new("firmae-upstream-demo"),
            &command_probe,
        )
        .expect("stopped");

    assert_eq!(stopped.container_name, "firmae-upstream-demo");
    assert!(stopped.stdout.contains("firmae-upstream-demo"));
    assert!(!prepared.workspace_dir.exists());
    let stop_state = prepared.upstream_stop_state(
        stopped.exit_code,
        true,
        true,
        &stopped.stdout,
        &stopped.stderr,
    );
    assert_eq!(
        stop_state.result_contract,
        ManagedLinuxVmStopResultContract::FirmaeUpstreamContainerStopV1
    );
    assert!(stop_state.result_contract_verified);
}

#[test]
fn managed_linux_vm_firmae_upstream_stop_contract_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-stop-contract-invalid");
    let bundle_dir = tempdir.path().join("bundle");
    let tools_dir = tempdir.path().join("tools");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&tools_dir).expect("tools dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    make_executable(
        tools_dir.join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"stop\" ]; then printf 'stopped\\n'; exit 0; fi\nexit 1\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let command_probe = StaticCommandProbe::new([("docker", tools_dir.join("docker"))]);

    let stop_error = manager
        .stop_firmae_upstream(
            &prepared,
            &ManagedLinuxVmUpstreamStopRequest::new("firmae-upstream-demo"),
            &command_probe,
        )
        .expect_err("contract should fail");

    assert_eq!(stop_error.diagnostic.phase, DiagnosticPhase::Cleanup);
    assert_eq!(stop_error.diagnostic.class, DiagnosticClass::CleanupFailed);
    assert_eq!(
        stop_error.diagnostic.subclass.as_deref(),
        Some("firmae-upstream-stop-contract-invalid")
    );
}

#[test]
fn managed_linux_vm_firmae_upstream_stop_failure_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-upstream-stop-fail");
    let bundle_dir = tempdir.path().join("bundle");
    let tools_dir = tempdir.path().join("tools");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::create_dir_all(&tools_dir).expect("tools dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    fs::write(bundle_dir.join("guest-agent"), b"agent").expect("guest agent");
    make_executable(
        tools_dir.join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"stop\" ]; then printf 'stop failed\\n' >&2; exit 9; fi\nexit 1\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    let command_probe = StaticCommandProbe::new([("docker", tools_dir.join("docker"))]);

    let stop_error = manager
        .stop_firmae_upstream(
            &prepared,
            &ManagedLinuxVmUpstreamStopRequest::new("firmae-upstream-demo"),
            &command_probe,
        )
        .expect_err("stop should fail");

    assert_eq!(stop_error.diagnostic.phase, DiagnosticPhase::Cleanup);
    assert_eq!(stop_error.diagnostic.class, DiagnosticClass::CleanupFailed);
    assert_eq!(
        stop_error.diagnostic.subclass.as_deref(),
        Some("firmae-upstream-stop-failed")
    );
    assert!(stop_error.diagnostic.summary.contains("upstream stop"));
}

#[test]
fn managed_linux_vm_stop_invokes_guest_agent_control_path() {
    let tempdir = make_temp_dir("managed-linux-vm-stop");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--stop\" ]; then printf 'managed-vm stopped\\nfirmae-stop-ok\\n'; exit 0; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let stopped = manager.stop(&prepared).expect("stopped");

    assert!(stopped.stdout.contains("managed-vm stopped"));
    assert!(stopped.stdout.contains("firmae-stop-ok"));
}

#[test]
fn managed_linux_vm_stop_success_contract_is_classified_for_firmae() {
    let tempdir = make_temp_dir("managed-linux-vm-stop-contract-invalid");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--stop\" ]; then printf 'managed-vm stopped\\n'; exit 0; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let stop_error = manager
        .stop(&prepared)
        .expect_err("stop contract should fail");
    let diagnostic = stop_error.diagnostic;

    assert_eq!(diagnostic.phase, DiagnosticPhase::Cleanup);
    assert_eq!(diagnostic.class, DiagnosticClass::CleanupFailed);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-stop-contract-invalid")
    );
    assert!(diagnostic.summary.contains("stop success contract"));
}

#[test]
fn managed_linux_vm_stop_failure_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-stop-fail");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--stop\" ]; then printf 'stop failed\\n' >&2; exit 11; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let stop_error = manager.stop(&prepared).expect_err("stop should fail");
    let diagnostic = stop_error.diagnostic;

    assert_eq!(diagnostic.phase, DiagnosticPhase::Cleanup);
    assert_eq!(diagnostic.class, DiagnosticClass::CleanupFailed);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-stop-failed")
    );
    assert!(diagnostic.summary.contains("managed-linux-vm"));
}

#[test]
fn managed_linux_vm_probe_reports_healthy_guest() {
    let tempdir = make_temp_dir("managed-linux-vm-probe");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'managed-vm healthy\\nfirmae-probe-ok\\n'; exit 0; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let probe = manager.probe(&prepared).expect("probe ok");

    assert!(probe.stdout.contains("managed-vm healthy"));
    assert!(probe.stdout.contains("firmae-probe-ok"));
}

#[test]
fn managed_linux_vm_probe_failure_is_classified() {
    let tempdir = make_temp_dir("managed-linux-vm-probe-fail");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'managed-vm missing\\n' >&2; exit 12; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let probe_error = manager.probe(&prepared).expect_err("probe should fail");
    let diagnostic = probe_error.diagnostic;

    assert_eq!(diagnostic.phase, DiagnosticPhase::Observation);
    assert_eq!(diagnostic.class, DiagnosticClass::GuestUnreachable);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-probe-failed")
    );
    assert!(diagnostic.summary.contains("managed-linux-vm"));
}

#[test]
fn managed_linux_vm_probe_success_contract_is_classified_for_firmae() {
    let tempdir = make_temp_dir("managed-linux-vm-probe-contract-invalid");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then printf 'managed-vm healthy\\n'; exit 0; fi\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(ManagedLinuxVmRequest::new(
            "firmae",
            "v1",
            bundle_dir,
            tempdir.path().join("workspace"),
        ))
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    let probe_error = manager
        .probe(&prepared)
        .expect_err("probe contract should fail");
    let diagnostic = probe_error.diagnostic;

    assert_eq!(diagnostic.phase, DiagnosticPhase::Observation);
    assert_eq!(diagnostic.class, DiagnosticClass::GuestUnreachable);
    assert_eq!(
        diagnostic.subclass.as_deref(),
        Some("firmae-managed-probe-contract-invalid")
    );
    assert!(diagnostic.summary.contains("probe success contract"));
}

#[test]
fn managed_linux_vm_firmae_uses_backend_owned_control_contract_args() {
    let tempdir = make_temp_dir("managed-linux-vm-firmae-contract");
    let bundle_dir = tempdir.path().join("bundle");
    fs::create_dir_all(&bundle_dir).expect("bundle dir");
    fs::write(bundle_dir.join("base-image.qcow2"), b"image").expect("base image");
    make_executable(
        bundle_dir.join("guest-agent"),
        "#!/bin/sh\nif [ \"$1\" = \"--stop\" ]; then printf '%s\\n' \"$@\" > \"$PWD/../stop-args.txt\"; printf 'managed-vm stopped\\nfirmae-stop-ok\\n'; exit 0; fi\nif [ \"$1\" = \"--probe\" ]; then printf '%s\\n' \"$@\" > \"$PWD/probe-args.txt\"; printf 'managed-vm healthy\\nfirmae-probe-ok\\n'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$PWD/launch-args.txt\"\nprintf 'managed-vm launch ok\\n'\nexit 0\n",
    );

    let manager = ManagedLinuxVmManager::new();
    let prepared = manager
        .prepare(
            ManagedLinuxVmRequest::new(
                "firmae",
                "v1",
                bundle_dir,
                tempdir.path().join("workspace"),
            )
            .with_mapped_ports(vec![8080]),
        )
        .expect("prepared");
    manager.launch(&prepared).expect("launched");
    manager.probe(&prepared).expect("probe ok");

    let launch_args =
        fs::read_to_string(prepared.workspace_dir.join("launch-args.txt")).expect("launch args");
    let probe_args =
        fs::read_to_string(prepared.workspace_dir.join("probe-args.txt")).expect("probe args");
    assert!(launch_args.contains("--control-contract"));
    assert!(launch_args.contains("firmae-legacy-wrapper-v1"));
    assert!(launch_args.contains("--firmae-action"));
    assert!(launch_args.contains("launch"));
    assert!(launch_args.contains("--port"));
    assert!(probe_args.contains("--control-contract"));
    assert!(probe_args.contains("firmae-legacy-wrapper-v1"));
    assert!(probe_args.contains("--firmae-action"));
    assert!(probe_args.contains("probe"));

    manager.stop(&prepared).expect("stop ok");
    let stop_args = fs::read_to_string(
        tempdir
            .path()
            .join("workspace")
            .join("managed-linux-vm")
            .join("firmae")
            .join("stop-args.txt"),
    )
    .expect("stop args");
    assert!(stop_args.contains("--control-contract"));
    assert!(stop_args.contains("firmae-legacy-wrapper-v1"));
    assert!(stop_args.contains("--firmae-action"));
    assert!(stop_args.contains("stop"));
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

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

struct StaticCommandProbe {
    commands: HashMap<String, PathBuf>,
}

impl StaticCommandProbe {
    fn new<const N: usize>(entries: [(&str, PathBuf); N]) -> Self {
        Self {
            commands: entries
                .into_iter()
                .map(|(name, path)| (name.to_string(), path))
                .collect(),
        }
    }
}

impl CommandProbe for StaticCommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf> {
        self.commands.get(command).cloned()
    }
}
