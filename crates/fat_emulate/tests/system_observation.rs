use std::path::Path;

use fat_core::rehosting_recipe::RecipeValidator;
use fat_core::runs::RuntimeEndpointKind;
use fat_emulate::plan::{create_emulation_bundle_from_request, EmulationBundleRequest};
use fat_emulate::strategy::EmulationAutomationMode;
use fat_emulate::system_runner::build_system_runner_blueprint;

#[test]
fn system_runner_blueprint_emits_seed_artifacts_for_kernel_nvram_network_and_init_rotation() {
    let plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-seeds", vec![80])
            .with_target_evidence(vec![
                "arch:armel".to_string(),
                "fs:squashfs".to_string(),
                "init:/sbin/preinit".to_string(),
                "init:/etc/init.d/rcS".to_string(),
                "web:uhttpd".to_string(),
                "iface:br0".to_string(),
                "bridge:br-lan".to_string(),
                "nvram-default:lan_ifname=br0".to_string(),
                "nvram-default:http_passwd=admin".to_string(),
            ])
            .with_host_capabilities(vec!["managed-linux-vm".to_string()])
            .with_requested_backend("firmadyne")
            .with_requested_substrate("managed-linux-vm")
            .with_automation_mode(EmulationAutomationMode::AutoSafe),
    )
    .expect("plan");

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));

    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("kernel-profile.json")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("nvram-seed.json")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("network-seed.json")));
    assert!(blueprint
        .staging
        .generated_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("init-plan.json")));
}

#[test]
fn system_runner_blueprint_exposes_native_host_launch_metadata() {
    let mut plan = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-launch", vec![80])
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
    plan.rehosting_recipe.validators =
        vec![RecipeValidator::new("http-reply", "http").with_port(80)];

    let blueprint = build_system_runner_blueprint(&plan, Path::new("/tmp/fat-staging"));
    let launch = blueprint.launch;

    assert_eq!(launch.qemu_binary, "qemu-system-mipsel");
    assert_eq!(launch.machine, "malta");
    assert_eq!(
        launch.kernel_profile_id.as_deref(),
        Some("mipsel-router-tier1")
    );
    let kernel_path = launch.kernel_path.as_str();
    assert!(
        kernel_path.ends_with("vmlinux.mipsel.4"),
        "unexpected kernel path: {kernel_path}"
    );
    assert!(
        launch.rootfs_image.ends_with("boot/rootfs.ext2"),
        "unexpected rootfs image path: {}",
        launch.rootfs_image
    );
    assert!(
        launch.preinit_path.ends_with("guest-root/fat/preinit.sh"),
        "unexpected preinit path: {}",
        launch.preinit_path
    );
    assert!(
        launch.boot_args.contains("root=/dev/sda rw"),
        "expected root device in boot args: {}",
        launch.boot_args
    );
    assert!(
        launch.boot_args.contains("init=/fat/init-trampoline"),
        "expected FAT preinit in boot args: {}",
        launch.boot_args
    );
    assert!(launch.gdb_address.starts_with("127.0.0.1:"));
    assert!(launch.args.iter().any(|arg| arg == "malta"));
    assert!(launch.args.iter().any(|arg| arg == "-kernel"));
    assert!(launch.args.iter().any(|arg| arg == kernel_path));
    assert!(launch
        .args
        .iter()
        .any(|arg| arg.contains("file=") && arg.contains("rootfs.ext2")));
    assert!(launch.args.iter().any(|arg| arg == "-append"));
    assert!(launch.args.iter().any(|arg| arg == &launch.boot_args));
    assert!(launch
        .args
        .iter()
        .any(|arg| arg == &format!("tcp:{}", launch.gdb_address)));
    assert!(launch
        .boot_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("kernel-profile.json")));
    assert!(launch
        .boot_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("qemu-command.sh")));
    assert!(launch
        .boot_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("boot/rootfs.ext2")));
    assert!(launch
        .boot_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("guest-root/fat/preinit.sh")));
    assert!(launch
        .boot_artifacts
        .iter()
        .any(|artifact| artifact.ends_with("surface-manifest.json")));
    assert!(launch.registered_surfaces.iter().any(|surface| {
        surface.kind == RuntimeEndpointKind::Shell && surface.name == "serial-console"
    }));
    assert!(launch
        .registered_surfaces
        .iter()
        .any(|surface| surface.kind == RuntimeEndpointKind::Monitor));
    assert!(launch.registered_surfaces.iter().any(|surface| {
        surface.kind == RuntimeEndpointKind::PortForward
            && surface.host == "127.0.0.1"
            && surface.target_port == Some(80)
            && surface.uri.as_deref() == Some(format!("http://127.0.0.1:{}", surface.port).as_str())
    }));
    let debugger_surface = launch
        .registered_surfaces
        .iter()
        .find(|surface| surface.kind == RuntimeEndpointKind::Debugger)
        .expect("debugger surface");
    let expected_gdb_uri = format!("tcp://{}", launch.gdb_address);
    assert_eq!(debugger_surface.name, "gdb-server");
    assert_eq!(
        debugger_surface.uri.as_deref(),
        Some(expected_gdb_uri.as_str())
    );
}

#[test]
fn system_runner_blueprint_allocates_distinct_gdb_ports_per_run() {
    let plan_one = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-launch-a", vec![80])
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
    .expect("plan one");
    let plan_two = create_emulation_bundle_from_request(
        EmulationBundleRequest::new("sess-system-launch-b", vec![80])
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
    .expect("plan two");

    let blueprint_one = build_system_runner_blueprint(&plan_one, Path::new("/tmp/fat-staging-one"));
    let blueprint_two = build_system_runner_blueprint(&plan_two, Path::new("/tmp/fat-staging-two"));
    let gdb_one = blueprint_one
        .launch
        .registered_surfaces
        .iter()
        .find(|surface| surface.kind == RuntimeEndpointKind::Debugger)
        .expect("gdb surface one");
    let gdb_two = blueprint_two
        .launch
        .registered_surfaces
        .iter()
        .find(|surface| surface.kind == RuntimeEndpointKind::Debugger)
        .expect("gdb surface two");

    assert_ne!(
        blueprint_one.launch.gdb_address, blueprint_two.launch.gdb_address,
        "native-host system runs should not share a fixed gdb address"
    );
    assert_ne!(
        gdb_one.port, gdb_two.port,
        "native-host system runs should not share a fixed gdb port"
    );
}
