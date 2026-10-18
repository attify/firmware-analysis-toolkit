//! Native ASPEED boot using a private snapshot flash and explicit profile assets.
use crate::plan::EmulationPlan;
use crate::readiness_engine::build_initial_confidence;
use crate::system_runner::{
    system_socket_path, SystemHostForward, SystemInitPlan, SystemLaunchSpec, SystemRunnerBlueprint,
};
use fat_core::bmc_boot::BmcBootConfig;
use fat_core::runs::{RuntimeEndpoint, RuntimeEndpointKind};
use fat_core::staging::{StagingManifest, StagingStrategy};
use std::path::Path;

pub fn build_bmc_blueprint(
    plan: &EmulationPlan,
    root: &Path,
    config: &BmcBootConfig,
) -> Result<SystemRunnerBlueprint, String> {
    let path = |name: &str| root.join(name).display().to_string();
    let serial_socket = system_socket_path(root, "serial");
    let monitor_socket = system_socket_path(root, "monitor");
    // Hold both listeners until distinct ports have been selected. Errors are
    // propagated before staging/launch instead of falling back to occupied ports.
    let (gdb_port, https_port) = allocate_ports()?;
    let gdb_address = format!("127.0.0.1:{gdb_port}");
    let serial_log = path("serial.log");
    let flash = path("flash.bin");
    // Each MAC uses a distinct subnet, preventing duplicate DHCP addresses and routes.
    let mut args = vec![
        "-M".into(),
        config.machine.clone(),
        "-drive".into(),
        format!("file={},format=raw,if=mtd", qemu_value(&flash)),
        "-snapshot".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        format!("unix:{monitor_socket},server=on,wait=off"),
        "-chardev".into(),
        format!(
            "socket,id=console,path={serial_socket},server=on,wait=off,logfile={}",
            qemu_value(&serial_log)
        ),
        "-serial".into(),
        "chardev:console".into(),
        "-gdb".into(),
        format!("tcp:{gdb_address}"),
        "-d".into(),
        "unimp,guest_errors".into(),
        "-D".into(),
        path("qemu-devices.log"),
    ];
    for index in 0..config.nic_count {
        let mut nic = format!("user,id=bmc{index},restrict=on,net=10.0.{}.0/24", index + 2);
        if index == config.management_nic {
            nic.push_str(&format!(",hostfwd=tcp:127.0.0.1:{https_port}-:443"));
        }
        args.extend(["-nic".into(), nic]);
    }
    let mut artifacts = vec![
        flash.clone(),
        path("bmc-boot-manifest.json"),
        serial_log.clone(),
        path("qemu-devices.log"),
    ];
    let mut kernel_path = String::new();
    let mut boot_args = String::new();
    let mut caveats = plan.rehosting_recipe.fidelity_caveats.clone();
    if let Some(vendor) = &config.vendor_kernel {
        kernel_path = path("kernel.bin");
        boot_args = vendor.boot_args.clone();
        args.extend([
            "-kernel".into(),
            kernel_path.clone(),
            "-dtb".into(),
            path("boot.dtb"),
            "-append".into(),
            boot_args.clone(),
        ]);
        artifacts.extend([kernel_path.clone(), path("original.dtb"), path("boot.dtb")]);
        if vendor.initrd_node.is_some() {
            args.extend(["-initrd".into(), path("initrd.bin")]);
            artifacts.push(path("initrd.bin"));
        }
        caveats.push(format!(
            "vendor-kernel mode bypasses SPL/U-Boot; disabled DTB nodes: {}",
            vendor.disable_nodes.join(", ")
        ));
    }
    let endpoints = vec![
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Shell,
            "serial-console",
            "127.0.0.1",
            10022,
        )
        .with_uri(format!("unix://{serial_socket}")),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Monitor,
            "qemu-monitor",
            "127.0.0.1",
            10023,
        )
        .with_uri(format!("unix://{monitor_socket}")),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::Debugger,
            "gdb-server",
            "127.0.0.1",
            gdb_port,
        )
        .with_uri(format!("tcp://{gdb_address}")),
        RuntimeEndpoint::new(
            RuntimeEndpointKind::PortForward,
            "bmc-redfish",
            "127.0.0.1",
            https_port,
        )
        .with_target_port(443)
        .with_uri(format!("https://127.0.0.1:{https_port}/redfish/v1/")),
    ];
    let staging = StagingManifest::new(
        &plan.target_model.project_id,
        &plan.target_model.target_id,
        &plan.session.session_id,
        &plan.run.record.run_id,
        "system",
        StagingStrategy::CopyOnWriteImage,
        "project/input",
        root.display().to_string(),
    )
    .with_generated_artifacts(artifacts.clone());
    Ok(SystemRunnerBlueprint {
        kernel_profile: None,
        nvram_seed: vec![],
        network_seed: vec![],
        init_plan: SystemInitPlan {
            selected_init: None,
            alternate_inits: vec![],
        },
        initial_confidence: build_initial_confidence(
            &plan.target_model.project_id,
            &plan.target_model.target_id,
            &plan.session.session_id,
            &plan.run.record.run_id,
            plan.rehosting_recipe.selected_substrate,
            caveats.clone(),
            vec!["redfish-service".into()],
        ),
        fidelity_caveats: caveats,
        staging,
        launch: SystemLaunchSpec {
            kernel_profile_id: None,
            machine: config.machine.clone(),
            qemu_binary: "qemu-system-arm".into(),
            required_qemu_version: None,
            args,
            kernel_path,
            rootfs_image: flash,
            preinit_path: String::new(),
            boot_args,
            serial_log,
            serial_socket,
            monitor_socket,
            gdb_address,
            boot_artifacts: artifacts,
            registered_surfaces: endpoints,
            host_forwards: vec![SystemHostForward {
                protocol: "tcp".into(),
                host_address: "127.0.0.1".into(),
                host_port: https_port,
                guest_port: 443,
                validator_kind: "http".into(),
            }],
            instrumentation: None,
        },
    })
}

fn allocate_ports() -> Result<(u16, u16), String> {
    use std::net::TcpListener;
    let bind = || {
        TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("cannot allocate BMC loopback port: {e}"))
    };
    let gdb = bind()?;
    let https = bind()?;
    Ok((
        gdb.local_addr().map_err(|e| e.to_string())?.port(),
        https.local_addr().map_err(|e| e.to_string())?.port(),
    ))
}

fn qemu_value(value: &str) -> String {
    value.replace(',', ",,")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fat_core::bmc_boot::BmcVendorKernel;
    #[test]
    fn bmc_flash_and_vendor_modes_preserve_distinct_contracts() {
        let mut plan = EmulationPlan::new("bmc", "qemu-direct", vec![]).unwrap();
        let mut config = BmcBootConfig {
            machine: "ast2600-evb,fmc-model=mx66u51235f".into(),
            flash_offset: 165,
            flash_size: 64 * 1024 * 1024,
            source_sha256: "b".repeat(64),
            nic_count: 4,
            management_nic: 0,
            vendor_kernel: None,
        };
        plan.rehosting_recipe.bmc_boot = Some(config.clone());
        let flash = build_bmc_blueprint(
            &plan,
            Path::new("/tmp/bmc,paths"),
            plan.rehosting_recipe.bmc_boot.as_ref().unwrap(),
        )
        .unwrap();
        assert!(flash.launch.args.contains(&"-snapshot".into()));
        assert!(!flash.launch.args.contains(&"-kernel".into()));
        assert!(flash.nvram_seed.is_empty());
        assert!(flash
            .launch
            .args
            .iter()
            .any(|v| v.contains("/tmp/bmc,,paths/flash.bin")));
        let networks: Vec<_> = flash
            .launch
            .args
            .windows(2)
            .filter(|p| p[0] == "-nic")
            .map(|p| &p[1])
            .collect();
        assert_eq!(networks.len(), 4);
        for (i, net) in networks.iter().enumerate() {
            assert!(net.contains(&format!("net=10.0.{}.0/24", i + 2)));
            assert!(net.contains("restrict=on"));
            assert_eq!(net.contains("hostfwd=tcp:127.0.0.1:"), i == 0);
        }
        config.vendor_kernel = Some(BmcVendorKernel {
            fit_offset: 1,
            kernel_node: "kernel@1".into(),
            dtb_node: "fdt@board".into(),
            initrd_node: Some("ramdisk@1".into()),
            boot_args: "root=/dev/mtdblock2".into(),
            disable_nodes: vec!["/ahb/hace".into()],
        });
        plan.rehosting_recipe.bmc_boot = Some(config);
        let vendor = build_bmc_blueprint(
            &plan,
            Path::new("/tmp/bmc"),
            plan.rehosting_recipe.bmc_boot.as_ref().unwrap(),
        )
        .unwrap();
        assert!(vendor.launch.args.contains(&"-kernel".into()));
        assert!(vendor.launch.args.contains(&"-dtb".into()));
        assert!(vendor.launch.args.contains(&"-initrd".into()));
        assert!(vendor
            .fidelity_caveats
            .iter()
            .any(|c| c.contains("bypasses SPL/U-Boot")));
        assert!(vendor.launch.preinit_path.is_empty());
    }
}
