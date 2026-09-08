use std::path::Path;

use fat_core::readiness::ConfidenceLevel;
use fat_core::rehosting_policy::SubstratePreference;
use fat_core::rehosting_recipe::{RecipeFilesystemTransform, RecipeNetworkConfig, RecipeValidator};
use fat_core::runs::RuntimeEndpointKind;
use fat_core::staging::StagingStrategy;
use fat_emulate::plan::{create_emulation_bundle_from_request, EmulationBundleRequest};
use fat_emulate::reference_runner::build_reference_runner_blueprint;
use fat_emulate::service_runner::build_service_runner_blueprint;
use fat_emulate::strategy::EmulationAutomationMode;
use fat_emulate::system_runner::build_system_runner_blueprint;

#[test]
fn service_runner_blueprint_uses_mutable_overlay_staging() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-service", vec![8080])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "web:uhttpd".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_substrate_preference(SubstratePreference::Auto)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_service_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    assert_eq!(blueprint.staging.strategy, StagingStrategy::MutableOverlay);
    assert_eq!(blueprint.initial_confidence.level, ConfidenceLevel::Medium);
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.contains("overlay")));
}

#[test]
fn service_runner_staging_manifest_records_repair_generated_artifacts() {
    let mut plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-service-repair", vec![8080])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "web:uhttpd".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_substrate_preference(SubstratePreference::Auto)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");
    plan.rehosting_recipe
        .filesystem_transforms
        .push(RecipeFilesystemTransform::new(
            "patch-config",
            "synth:repair-init",
            "/etc/fat/repair-init.sh",
        ));

    let blueprint = build_service_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));

    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("overlay-root/etc/fat/repair-init.sh")));
    assert!(blueprint.staging.mutations.iter().any(|mutation| {
        mutation.mutation_kind == "patch-config"
            && mutation.source.as_deref() == Some("synth:repair-init")
            && mutation
                .destination
                .ends_with("overlay-root/etc/fat/repair-init.sh")
    }));
}

#[test]
fn system_runner_blueprint_uses_copy_on_write_images() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:busybox".to_string(),
            ])
            .with_host_capabilities(vec!["managed-linux-vm".to_string()])
            .with_requested_backend("firmae")
            .with_requested_substrate("managed-linux-vm")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    assert_eq!(
        blueprint.staging.strategy,
        StagingStrategy::CopyOnWriteImage
    );
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.contains("disk")));
}

#[test]
fn system_runner_plan_preserves_pack_network_configuration() {
    let mut plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-network", Vec::new())
            .with_target_evidence(vec![
                "arch:mipsel".to_string(),
                "fs:squashfs".to_string(),
                "init:busybox".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");
    plan.rehosting_recipe.network = Some(RecipeNetworkConfig {
        interface: Some("eth0".into()),
        mode: Some("dhcp".into()),
        fallback_ip: Some("10.0.2.15".into()),
    });

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    let entry = blueprint
        .network_seed
        .iter()
        .find(|entry| entry.interface_name == "eth0")
        .expect("pack network entry");

    assert_eq!(entry.mode.as_deref(), Some("dhcp"));
    assert_eq!(entry.fallback_ip.as_deref(), Some("10.0.2.15"));
}

#[test]
fn native_system_networking_uses_loopback_forwards_and_deduplicates_guest_ports() {
    let mut plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-forward", Vec::new())
            .with_target_evidence(vec![
                "arch:mipsel".to_string(),
                "fs:squashfs".to_string(),
                "init:busybox".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");
    plan.rehosting_recipe.validators = vec![
        RecipeValidator::new("http-reply", "http").with_port(80),
        RecipeValidator::new("http-listener", "listener").with_port(80),
    ];

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-forward"));
    let netdev = blueprint
        .launch
        .args
        .windows(2)
        .find(|pair| pair[0] == "-netdev")
        .map(|pair| pair[1].as_str())
        .expect("netdev args");

    assert!(blueprint
        .launch
        .args
        .windows(2)
        .any(|pair| pair == ["-device", "e1000,netdev=fatnet0"]));
    assert!(
        netdev.starts_with("user,id=fatnet0,hostfwd=tcp:127.0.0.1:"),
        "{netdev}"
    );
    assert!(netdev.ends_with("-:80"), "{netdev}");
    assert_eq!(netdev.matches("hostfwd=").count(), 1, "{netdev}");
    assert!(!netdev.contains("0.0.0.0"), "{netdev}");
    let endpoint = blueprint
        .launch
        .registered_surfaces
        .iter()
        .find(|surface| surface.target_port == Some(80))
        .expect("HTTP forward surface");
    assert_eq!(endpoint.kind, RuntimeEndpointKind::PortForward);
    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(
        endpoint.uri.as_deref(),
        Some(format!("http://127.0.0.1:{}", endpoint.port).as_str())
    );
}

#[test]
fn system_runner_staging_manifest_records_launch_artifacts() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-launch-artifacts", vec![80])
            .with_target_evidence(vec![
                "arch:mipsel".to_string(),
                "fs:squashfs".to_string(),
                "init:/sbin/preinit".to_string(),
                "web:alphapd".to_string(),
                "nvram:present".to_string(),
            ])
            .with_host_capabilities(vec!["native-host".to_string()])
            .with_requested_backend("qemu-direct")
            .with_requested_substrate("native-host")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));

    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("boot/qemu-command.sh")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("boot/rootfs.ext2")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("guest-root/fat/preinit.sh")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("boot/surface-manifest.json")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.starts_with("/tmp/fat-") && artifact.ends_with("-monitor.sock")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.starts_with("/tmp/fat-") && artifact.ends_with("-serial.sock")));
    assert!(blueprint.launch.monitor_socket.len() < 104);
    assert!(blueprint.launch.serial_socket.len() < 104);
}

#[test]
fn reference_runner_blueprint_marks_reference_workspace_and_caveats() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-reference", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "generated:reference-rootfs".to_string(),
            ])
            .with_host_capabilities(vec!["docker-engine".to_string()])
            .with_substrate_preference(SubstratePreference::ReferenceOnly)
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_reference_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    assert_eq!(
        blueprint.staging.strategy,
        StagingStrategy::ReferenceWorkspace
    );
    assert!(blueprint
        .initial_confidence
        .fidelity_caveats
        .iter()
        .any(|caveat| caveat.contains("reference")));
}

#[test]
fn system_runner_blueprint_honors_pack_qemu_machine_override() {
    let build = || {
        create_emulation_bundle_from_request(
            EmulationBundleRequest::new("sess-machine", Vec::new())
                .with_target_evidence(vec![
                    "arch:armel".to_string(),
                    "fs:squashfs".to_string(),
                    "init:busybox".to_string(),
                ])
                .with_host_capabilities(vec!["managed-linux-vm".to_string()])
                .with_requested_backend("firmae")
                .with_requested_substrate("managed-linux-vm")
                .with_automation_mode(EmulationAutomationMode::AutoSafe),
        )
        .expect("plan")
    };

    // Baseline: machine is derived from the architecture.
    let baseline = build_system_runner_blueprint(&build(), Path::new("/tmp/fat-staging"));
    assert_ne!(baseline.launch.machine, "versatilepb");

    // With a pack override the recipe's qemu_machine wins and reaches the argv.
    let mut plan = build();
    plan.rehosting_recipe.qemu_machine = Some("versatilepb".to_string());
    let overridden = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    assert_eq!(overridden.launch.machine, "versatilepb");
    let machine_flag = overridden
        .launch
        .args
        .windows(2)
        .any(|pair| pair[0] == "-M" && pair[1] == "versatilepb");
    assert!(
        machine_flag,
        "expected `-M versatilepb` in qemu args, got {:?}",
        overridden.launch.args
    );
}

#[test]
fn system_runner_blueprint_captures_serial_to_a_durable_logfile() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-serial", Vec::new())
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:busybox".to_string(),
            ])
            .with_host_capabilities(vec!["managed-linux-vm".to_string()])
            .with_requested_backend("firmae")
            .with_requested_substrate("managed-linux-vm")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    // The serial chardev carries a logfile= pointing at the launch serial.log,
    // and the -serial flag references that chardev.
    assert!(
        blueprint
            .launch
            .args
            .iter()
            .any(|arg| arg.starts_with("socket,id=fatserial,")
                && arg.contains("logfile=")
                && arg.contains("serial.log")),
        "expected a serial chardev with a durable logfile, got {:?}",
        blueprint.launch.args
    );
    assert!(blueprint
        .launch
        .args
        .windows(2)
        .any(|pair| pair[0] == "-serial" && pair[1] == "chardev:fatserial"));
}
