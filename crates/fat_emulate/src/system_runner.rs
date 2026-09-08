use std::net::TcpListener;
use std::path::Path;

use fat_core::ids::stable_prefixed_id;
use fat_core::readiness::ConfidenceReport;
use fat_core::rehosting_recipe::InstrumentationConfig;
use fat_core::runs::{RuntimeEndpoint, RuntimeEndpointKind};
use fat_core::staging::{StagingManifest, StagingMutation};
use fat_core::target_model::{
    TargetModelInitCandidate, TargetModelNetworkHypothesis, TargetModelNvramFact,
};
use serde::{Deserialize, Serialize};

use crate::kernel_catalog::{
    host_qemu_version, load_machine_profile_for_host, select_kernel_profile, KernelMachineProfile,
    KernelProfile,
};
use crate::plan::EmulationPlan;
use crate::readiness_engine::build_initial_confidence;
use crate::staging_builder::{append_recipe_repair_materialization, system_staging_manifest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemNvramSeedEntry {
    pub key: String,
    pub resolution_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemNetworkSeedEntry {
    pub interface_name: String,
    pub role: String,
    pub mode: Option<String>,
    pub fallback_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemInitPlan {
    pub selected_init: Option<String>,
    pub alternate_inits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRunnerPlan {
    pub kernel_profile: Option<KernelProfile>,
    pub nvram_seed: Vec<SystemNvramSeedEntry>,
    pub network_seed: Vec<SystemNetworkSeedEntry>,
    pub init_plan: SystemInitPlan,
    pub fidelity_caveats: Vec<String>,
    pub staging_manifest: StagingManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRunnerBlueprint {
    pub kernel_profile: Option<KernelProfile>,
    pub nvram_seed: Vec<SystemNvramSeedEntry>,
    pub network_seed: Vec<SystemNetworkSeedEntry>,
    pub init_plan: SystemInitPlan,
    pub fidelity_caveats: Vec<String>,
    pub staging: StagingManifest,
    pub initial_confidence: ConfidenceReport,
    pub launch: SystemLaunchSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemLaunchSpec {
    pub kernel_profile_id: Option<String>,
    pub machine: String,
    pub qemu_binary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_qemu_version: Option<String>,
    pub args: Vec<String>,
    pub kernel_path: String,
    pub rootfs_image: String,
    pub preinit_path: String,
    pub boot_args: String,
    pub serial_log: String,
    pub serial_socket: String,
    pub monitor_socket: String,
    pub gdb_address: String,
    pub boot_artifacts: Vec<String>,
    pub registered_surfaces: Vec<RuntimeEndpoint>,
    pub host_forwards: Vec<SystemHostForward>,
    /// Typed TCG plugin instrumentation config. When set, the launcher
    /// appends `-plugin <plugin_path>,hook=...,log=...` to the QEMU command.
    pub instrumentation: Option<InstrumentationConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemHostForward {
    pub protocol: String,
    pub host_address: String,
    pub host_port: u16,
    pub guest_port: u16,
    pub validator_kind: String,
}

pub fn build_system_runner_plan(
    project_id: &str,
    target_id: &str,
    source_root: &str,
    staging_root: &str,
    plan: &EmulationPlan,
) -> SystemRunnerPlan {
    let kernel_profile = select_kernel_profile(&plan.target_model);
    let nvram_seed = system_nvram_seed(&plan.target_model.nvram_facts);
    let mut network_seed = system_network_seed(&plan.target_model.network_hypotheses);
    if let Some(network) = &plan.rehosting_recipe.network {
        if let Some(interface_name) = network.interface.as_deref() {
            if let Some(existing) = network_seed
                .iter_mut()
                .find(|entry| entry.interface_name == interface_name)
            {
                existing.mode = network.mode.clone();
                existing.fallback_ip = network.fallback_ip.clone();
            } else {
                network_seed.push(SystemNetworkSeedEntry {
                    interface_name: interface_name.to_string(),
                    role: "rehosting-pack".into(),
                    mode: network.mode.clone(),
                    fallback_ip: network.fallback_ip.clone(),
                });
            }
        }
    }
    let init_plan = system_init_plan(&plan.target_model.init_candidates);
    let mut fidelity_caveats = plan.rehosting_recipe.fidelity_caveats.clone();
    fidelity_caveats.push("system runner requires kernel/board compatibility".to_string());
    if nvram_seed
        .iter()
        .any(|entry| entry.resolution_state != "observed" && entry.resolution_state != "overridden")
    {
        fidelity_caveats
            .push("system runner is using synthesized or unresolved NVRAM state".to_string());
    }
    let mut staging_manifest = system_staging_manifest(
        project_id,
        target_id,
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
        source_root,
        staging_root,
    );
    append_recipe_repair_materialization(
        &mut staging_manifest,
        staging_root,
        &plan.rehosting_recipe,
    );
    let launch_root = system_boot_root(Path::new(staging_root));
    let kernel_artifact = runner_plan_kernel_artifact(kernel_profile.as_ref(), &launch_root);
    let rootfs_image = launch_root.join("rootfs.ext2");
    let preinit_path = Path::new(staging_root).join("fat").join("preinit.sh");
    let assembly_manifest = Path::new(staging_root).join("assembly-manifest.json");
    let adaptation_manifest = Path::new(staging_root)
        .join("fat")
        .join("adaptation-manifest.json");
    let serial_socket = system_socket_path(&launch_root, "serial");
    let monitor_socket = system_socket_path(&launch_root, "monitor");
    staging_manifest.generated_artifacts.extend([
        format!("{staging_root}/kernel-profile.json"),
        format!("{staging_root}/kernel-identity.json"),
        format!("{staging_root}/nvram-seed.json"),
        format!("{staging_root}/network-seed.json"),
        format!("{staging_root}/init-plan.json"),
        kernel_artifact.display().to_string(),
        rootfs_image.display().to_string(),
        preinit_path.display().to_string(),
        assembly_manifest.display().to_string(),
        adaptation_manifest.display().to_string(),
        serial_socket.clone(),
        monitor_socket.clone(),
    ]);
    if plan.target_model.architecture.as_deref() == Some("mipsel") {
        staging_manifest.generated_artifacts.extend([
            format!("{staging_root}/fat/init-trampoline"),
            format!("{staging_root}/fat/init-trampoline-identity.json"),
        ]);
    }
    staging_manifest.mutations.extend([
        StagingMutation::new(
            "seed-kernel-profile",
            None::<String>,
            format!("{staging_root}/kernel-profile.json"),
        )
        .with_detail("materialize selected kernel profile for the system runner"),
        StagingMutation::new(
            "seed-nvram",
            None::<String>,
            format!("{staging_root}/nvram-seed.json"),
        )
        .with_detail("materialize synthesized NVRAM defaults for the first boot attempt"),
        StagingMutation::new(
            "seed-network",
            None::<String>,
            format!("{staging_root}/network-seed.json"),
        )
        .with_detail("materialize inferred network topology for the first boot attempt"),
        StagingMutation::new(
            "seed-init-plan",
            None::<String>,
            format!("{staging_root}/init-plan.json"),
        )
        .with_detail("materialize ordered init candidates for bounded boot arbitration"),
        StagingMutation::new(
            "stage-vendored-kernel",
            None::<String>,
            kernel_artifact.display().to_string(),
        )
        .with_detail("stage the vendored kernel selected for the native-host boot"),
        StagingMutation::new(
            "write-preinit",
            None::<String>,
            preinit_path.display().to_string(),
        )
        .with_detail("materialize the FAT preinit handoff script inside the guest root"),
        StagingMutation::new(
            "record-partition-assembly",
            None::<String>,
            assembly_manifest.display().to_string(),
        )
        .with_detail("record source roles and staged-copy destinations for the assembled guest"),
        StagingMutation::new(
            "record-guest-adaptations",
            None::<String>,
            adaptation_manifest.display().to_string(),
        )
        .with_detail("record generated command, module, and materialized-mount shims"),
        StagingMutation::new(
            "build-rootfs-image",
            Some(staging_root.to_string()),
            rootfs_image.display().to_string(),
        )
        .with_detail("build the staged ext2 root filesystem image for the native-host boot"),
        StagingMutation::new(
            "write-qemu-command",
            None::<String>,
            launch_root.join("qemu-command.sh").display().to_string(),
        )
        .with_detail("materialize the native-host system launch command"),
        StagingMutation::new(
            "write-surface-manifest",
            None::<String>,
            launch_root
                .join("surface-manifest.json")
                .display()
                .to_string(),
        )
        .with_detail("materialize registered serial, monitor, and debugger surfaces"),
        StagingMutation::new(
            "allocate-monitor-socket",
            None::<String>,
            monitor_socket.clone(),
        )
        .with_detail("materialize the QEMU monitor socket for the native-host boot"),
        StagingMutation::new(
            "allocate-serial-socket",
            None::<String>,
            serial_socket.clone(),
        )
        .with_detail("materialize the QEMU serial socket for the native-host boot"),
    ]);

    SystemRunnerPlan {
        kernel_profile,
        nvram_seed,
        network_seed,
        init_plan,
        fidelity_caveats,
        staging_manifest,
    }
}

pub fn build_system_runner_blueprint(
    plan: &EmulationPlan,
    staging_root: &Path,
) -> SystemRunnerBlueprint {
    let source_root = staging_root.join("source-rootfs");
    let run_staging_root = staging_root.join("guest-root");
    let launch_root = system_boot_root(&run_staging_root);
    let runner_plan = build_system_runner_plan(
        plan.target_model.project_id.as_str(),
        plan.target_model.target_id.as_str(),
        source_root.to_string_lossy().as_ref(),
        run_staging_root.to_string_lossy().as_ref(),
        plan,
    );
    let initial_confidence = build_initial_confidence(
        plan.target_model.project_id.as_str(),
        plan.target_model.target_id.as_str(),
        plan.session.session_id.as_str(),
        plan.run.record.run_id.as_str(),
        plan.rehosting_recipe.selected_substrate,
        runner_plan.fidelity_caveats.clone(),
        plan.rehosting_recipe
            .validators
            .iter()
            .map(|validator| validator.goal.clone())
            .collect(),
    );
    let kernel_profile = runner_plan.kernel_profile.clone();
    // Resolved before the machine profile so the host's QEMU can decide which
    // of the kernel's validated profiles to use.
    let qemu_binary = system_qemu_binary(
        kernel_profile.as_ref(),
        plan.target_model.architecture.as_deref(),
    );
    let detected_qemu_version = kernel_profile
        .as_ref()
        .and_then(|profile| profile.required_machine_profile.as_ref())
        .and_then(|_| host_qemu_version(&qemu_binary));
    let machine_profile = kernel_profile.as_ref().and_then(|profile| {
        load_machine_profile_for_host(profile, detected_qemu_version.as_deref())
            .ok()
            .flatten()
    });
    // A managed kernel's exact machine contract takes precedence. External
    // profiles may use a rehosting-pack override or the architecture default.
    let machine = machine_profile
        .as_ref()
        .map(|profile| profile.machine.clone())
        .or_else(|| plan.rehosting_recipe.qemu_machine.clone())
        .unwrap_or_else(|| system_qemu_machine(plan.target_model.architecture.as_deref()));
    let serial_log = launch_root.join("serial.log").display().to_string();
    let serial_socket = system_socket_path(&launch_root, "serial");
    let monitor_socket = system_socket_path(&launch_root, "monitor");
    let gdb_address = allocate_gdb_address();
    let kernel_path = runner_plan_kernel_artifact(kernel_profile.as_ref(), &launch_root)
        .display()
        .to_string();
    let rootfs_image = launch_root.join("rootfs.ext2").display().to_string();
    let preinit_path = run_staging_root
        .join("fat")
        .join("preinit.sh")
        .display()
        .to_string();
    let block_contract = system_block_contract(&machine, &rootfs_image);
    let boot_args = system_boot_args(
        plan.target_model.architecture.as_deref(),
        machine_profile.as_ref(),
        &block_contract,
    );
    let gdb_port = gdb_address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(1234);
    let host_forwards = system_host_forwards(&plan.rehosting_recipe.validators, gdb_port);
    let kernel_profile_id = kernel_profile
        .as_ref()
        .map(|profile| profile.profile_id.clone());
    let args = system_qemu_args(
        machine.clone(),
        plan.target_model.architecture.as_deref(),
        kernel_profile.as_ref(),
        machine_profile.as_ref().map(|profile| profile.cpu.as_str()),
        &kernel_path,
        &block_contract,
        &boot_args,
        &serial_socket,
        &serial_log,
        &monitor_socket,
        &gdb_address,
        &host_forwards,
    );
    let mut boot_artifacts = vec![
        kernel_path.clone(),
        rootfs_image.clone(),
        preinit_path.clone(),
        format!("{}/kernel-profile.json", run_staging_root.display()),
        format!("{}/kernel-identity.json", run_staging_root.display()),
        format!("{}/nvram-seed.json", run_staging_root.display()),
        format!("{}/network-seed.json", run_staging_root.display()),
        format!("{}/init-plan.json", run_staging_root.display()),
        format!("{}/qemu-command.sh", launch_root.display()),
        format!("{}/surface-manifest.json", launch_root.display()),
        serial_log.clone(),
    ];
    if plan.target_model.architecture.as_deref() == Some("mipsel") {
        boot_artifacts.extend([
            run_staging_root
                .join("fat/init-trampoline")
                .display()
                .to_string(),
            run_staging_root
                .join("fat/init-trampoline-identity.json")
                .display()
                .to_string(),
        ]);
    }
    let mut registered_surfaces = vec![
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
    ];
    registered_surfaces.extend(host_forwards.iter().map(|forward| {
        let name = if forward.validator_kind == "http" {
            format!("http-{}", forward.guest_port)
        } else {
            format!("listener-{}", forward.guest_port)
        };
        let uri = if forward.validator_kind == "http" {
            format!("http://{}:{}", forward.host_address, forward.host_port)
        } else {
            format!("tcp://{}:{}", forward.host_address, forward.host_port)
        };
        RuntimeEndpoint::new(
            RuntimeEndpointKind::PortForward,
            name,
            forward.host_address.clone(),
            forward.host_port,
        )
        .with_target_port(forward.guest_port)
        .with_uri(uri)
    }));

    SystemRunnerBlueprint {
        kernel_profile,
        nvram_seed: runner_plan.nvram_seed,
        network_seed: runner_plan.network_seed,
        init_plan: runner_plan.init_plan,
        fidelity_caveats: runner_plan.fidelity_caveats,
        staging: runner_plan.staging_manifest,
        initial_confidence,
        launch: SystemLaunchSpec {
            kernel_profile_id,
            machine,
            qemu_binary,
            required_qemu_version: machine_profile.map(|profile| profile.qemu_version),
            args,
            kernel_path,
            rootfs_image,
            preinit_path,
            boot_args,
            serial_log,
            serial_socket,
            monitor_socket,
            gdb_address,
            boot_artifacts,
            registered_surfaces,
            host_forwards,
            instrumentation: None,
        },
    }
}

fn system_host_forwards(
    validators: &[fat_core::rehosting_recipe::RecipeValidator],
    gdb_port: u16,
) -> Vec<SystemHostForward> {
    let mut requested = std::collections::BTreeMap::<u16, String>::new();
    for validator in validators {
        if !matches!(validator.validator_kind.as_str(), "http" | "listener") {
            continue;
        }
        let Some(guest_port) = validator.port else {
            continue;
        };
        requested
            .entry(guest_port)
            .and_modify(|kind| {
                if validator.validator_kind == "http" {
                    *kind = "http".to_string();
                }
            })
            .or_insert_with(|| validator.validator_kind.clone());
    }

    let mut reserved = std::collections::BTreeSet::from([gdb_port, 10022, 10023]);
    requested
        .into_iter()
        .map(|(guest_port, validator_kind)| {
            let host_port = allocate_loopback_port(&reserved);
            reserved.insert(host_port);
            SystemHostForward {
                protocol: "tcp".to_string(),
                host_address: "127.0.0.1".to_string(),
                host_port,
                guest_port,
                validator_kind,
            }
        })
        .collect()
}

fn allocate_loopback_port(reserved: &std::collections::BTreeSet<u16>) -> u16 {
    for _ in 0..16 {
        if let Some(port) = TcpListener::bind(("127.0.0.1", 0))
            .ok()
            .and_then(|listener| listener.local_addr().ok())
            .map(|address| address.port())
        {
            if !reserved.contains(&port) {
                return port;
            }
        }
    }
    (20000..60000)
        .find(|port| !reserved.contains(port))
        .unwrap_or(20000)
}

fn allocate_gdb_address() -> String {
    TcpListener::bind(("127.0.0.1", 0))
        .ok()
        .and_then(|listener| listener.local_addr().ok())
        .map(|address| address.to_string())
        .unwrap_or_else(|| "127.0.0.1:1234".to_string())
}

fn system_socket_path(launch_root: &Path, kind: &str) -> String {
    let identity = stable_prefixed_id("socket", [launch_root.to_string_lossy().as_ref(), kind]);
    let hash = identity.rsplit('-').next().unwrap_or(identity.as_str());
    Path::new("/tmp")
        .join(format!("fat-{hash}-{kind}.sock"))
        .display()
        .to_string()
}

fn system_nvram_seed(facts: &[TargetModelNvramFact]) -> Vec<SystemNvramSeedEntry> {
    facts
        .iter()
        .map(|fact| SystemNvramSeedEntry {
            key: fact.key.clone(),
            resolution_state: fact.resolution_state.clone(),
        })
        .collect()
}

fn system_network_seed(hypotheses: &[TargetModelNetworkHypothesis]) -> Vec<SystemNetworkSeedEntry> {
    hypotheses
        .iter()
        .map(|hypothesis| SystemNetworkSeedEntry {
            interface_name: hypothesis.interface_name.clone(),
            role: hypothesis.role.clone(),
            mode: None,
            fallback_ip: None,
        })
        .collect()
}

fn system_init_plan(init_candidates: &[TargetModelInitCandidate]) -> SystemInitPlan {
    let selected_init = init_candidates
        .first()
        .map(|candidate| candidate.path.clone());
    let alternate_inits = init_candidates
        .iter()
        .skip(1)
        .map(|candidate| candidate.path.clone())
        .collect();
    SystemInitPlan {
        selected_init,
        alternate_inits,
    }
}

fn system_qemu_machine(architecture: Option<&str>) -> String {
    match architecture {
        Some("mipsel") | Some("mips") => "malta".to_string(),
        Some("arm") | Some("armel") | Some("armhf") => "virt".to_string(),
        Some("aarch64") => "virt".to_string(),
        Some(other) if !other.is_empty() => "virt".to_string(),
        _ => "malta".to_string(),
    }
}

fn system_qemu_binary(
    kernel_profile: Option<&KernelProfile>,
    architecture: Option<&str>,
) -> String {
    if let Some(profile) = kernel_profile {
        return match profile.architecture.as_str() {
            "mipsel" => "qemu-system-mipsel".to_string(),
            "mips" => "qemu-system-mips".to_string(),
            "arm" | "armel" | "armhf" => "qemu-system-arm".to_string(),
            "aarch64" => "qemu-system-aarch64".to_string(),
            _ => system_qemu_binary_from_architecture(architecture),
        };
    }

    system_qemu_binary_from_architecture(architecture)
}

fn system_qemu_binary_from_architecture(architecture: Option<&str>) -> String {
    match architecture {
        Some("mipsel") => "qemu-system-mipsel".to_string(),
        Some("mips") => "qemu-system-mips".to_string(),
        Some("arm") | Some("armel") | Some("armhf") => "qemu-system-arm".to_string(),
        Some("aarch64") => "qemu-system-aarch64".to_string(),
        _ => "qemu-system-mipsel".to_string(),
    }
}

fn system_qemu_args(
    machine: String,
    architecture: Option<&str>,
    kernel_profile: Option<&KernelProfile>,
    cpu: Option<&str>,
    kernel_path: &str,
    block_contract: &SystemBlockContract,
    boot_args: &str,
    serial_socket: &str,
    serial_log: &str,
    monitor_socket: &str,
    gdb_address: &str,
    host_forwards: &[SystemHostForward],
) -> Vec<String> {
    let mut netdev = "user,id=fatnet0".to_string();
    for forward in host_forwards {
        netdev.push_str(&format!(
            ",hostfwd={}:{}:{}-:{}",
            forward.protocol, forward.host_address, forward.host_port, forward.guest_port
        ));
    }
    let nic = if machine == "malta" {
        "e1000,netdev=fatnet0"
    } else {
        "virtio-net-device,netdev=fatnet0"
    };
    let mut args = vec![
        "-M".to_string(),
        machine,
        "-nographic".to_string(),
        // Serial goes to an interactive socket AND is durably captured to a log
        // file via the chardev `logfile=` option.
        "-chardev".to_string(),
        format!("socket,id=fatserial,path={serial_socket},server=on,wait=off,logfile={serial_log}"),
        "-serial".to_string(),
        "chardev:fatserial".to_string(),
        "-monitor".to_string(),
        format!("unix:{monitor_socket},server,nowait"),
        "-device".to_string(),
        nic.to_string(),
        "-netdev".to_string(),
        netdev,
        "-gdb".to_string(),
        format!("tcp:{gdb_address}"),
        "-kernel".to_string(),
        kernel_path.to_string(),
        "-drive".to_string(),
        block_contract.drive.clone(),
        "-append".to_string(),
        boot_args.to_string(),
        "-m".to_string(),
        "256".to_string(),
        "-no-reboot".to_string(),
    ];
    if let Some(device) = &block_contract.device {
        // Immediately after the -drive it backs, so the pair reads as one unit.
        let drive_index = args
            .iter()
            .position(|arg| arg == "-drive")
            .map(|index| index + 2)
            .unwrap_or(args.len());
        args.splice(
            drive_index..drive_index,
            ["-device".to_string(), device.clone()],
        );
    }
    if let Some(cpu) = cpu {
        args.splice(2..2, ["-cpu".to_string(), cpu.to_string()]);
    }
    // kernel_profile and architecture are FAT metadata, not QEMU flags
    let _ = kernel_profile;
    let _ = architecture;
    args
}

fn system_boot_root(staging_root: &Path) -> std::path::PathBuf {
    staging_root.parent().unwrap_or(staging_root).join("boot")
}

fn runner_plan_kernel_artifact(
    kernel_profile: Option<&KernelProfile>,
    launch_root: &Path,
) -> std::path::PathBuf {
    let file_name = kernel_profile
        .map(|profile| profile.image_hint.as_str())
        .unwrap_or("kernel.bin");
    launch_root.join(file_name)
}

/// How a QEMU machine exposes the root disk.
///
/// `malta` carries a default IDE bus, so a bare `-drive` lands on `/dev/sda`.
/// The virt-style machines FAT targets have no default block controller at all:
/// a bare `-drive` there attaches to nothing, the kernel finds no root, and the
/// guest dies before it can say so. They need an explicit virtio-blk device and
/// a `/dev/vda` root. This mirrors the NIC decision above, which already gives
/// malta `e1000` and everything else `virtio-net-device`.
struct SystemBlockContract {
    drive: String,
    device: Option<String>,
    root_device: &'static str,
    /// Console to assume when no machine profile pins one. A managed kernel's
    /// profile still wins; this only stops an unprofiled run from defaulting to
    /// a serial port the machine does not have.
    fallback_console: &'static str,
}

fn system_block_contract(machine: &str, rootfs_image: &str) -> SystemBlockContract {
    if machine == "malta" {
        SystemBlockContract {
            drive: format!("file={rootfs_image},format=raw"),
            device: None,
            root_device: "/dev/sda",
            fallback_console: "ttyS0",
        }
    } else {
        SystemBlockContract {
            drive: format!("file={rootfs_image},format=raw,if=none,id=fatroot"),
            device: Some("virtio-blk-device,drive=fatroot".to_string()),
            root_device: "/dev/vda",
            // virt exposes a PL011, not an 8250. ttyS0 there means a kernel
            // that boots in silence, which is indistinguishable from one that
            // never booted at all.
            fallback_console: "ttyAMA0",
        }
    }
}

fn system_boot_args(
    architecture: Option<&str>,
    machine_profile: Option<&KernelMachineProfile>,
    block_contract: &SystemBlockContract,
) -> String {
    let init = if architecture == Some("mipsel") {
        "/fat/init-trampoline"
    } else {
        "/fat/preinit.sh"
    };
    let console = machine_profile
        .map(|profile| profile.console.as_str())
        .unwrap_or(block_contract.fallback_console);
    let root_device = block_contract.root_device;
    // Report user-mode faults on the console. Without this a firmware process
    // that segfaults dies silently, and a silent crash is indistinguishable
    // from one that merely exited -- the opposite of what a rehosting run is
    // for. `print_fatal_signals` is the generic switch behind the kernel's
    // print_fatal_signal(), and it carries the faulting register dump on every
    // architecture FAT builds kernels for, so it needs no arch gating.
    //
    // ARM's `user_debug=` is not a substitute: it is inert unless the kernel
    // was built with CONFIG_DEBUG_USER, which the FAT recipes do not set.
    format!("root={root_device} rw console={console} init={init} print-fatal-signals=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine_profile(console: &str) -> KernelMachineProfile {
        KernelMachineProfile {
            schema_version: "1.0".to_string(),
            id: "mch-test".to_string(),
            qemu_version: "10.2.2".to_string(),
            machine: "virt-10.2".to_string(),
            cpu: "cortex-a15".to_string(),
            console: console.to_string(),
            classes: Vec::new(),
            capability_tier: "fixture-validated".to_string(),
        }
    }

    // A guest whose userspace segfaults silently is useless for the thing this
    // runner exists to do. `print-fatal-signals=1` is what turns a silent death
    // into a console record with the faulting registers, so it belongs on every
    // boot regardless of architecture or machine profile.
    #[test]
    fn boot_args_enable_user_fault_reporting() {
        let profile = machine_profile("ttyAMA0");
        for architecture in [Some("armel"), Some("mipsel"), Some("mips"), None] {
            let args = system_boot_args(
                architecture,
                Some(&profile),
                &system_block_contract("virt", "/boot/rootfs.ext2"),
            );
            assert!(
                args.contains("print-fatal-signals=1"),
                "architecture {architecture:?} lost fault reporting: {args}"
            );
        }
    }

    #[test]
    fn boot_args_keep_root_console_and_init() {
        let args = system_boot_args(
            Some("armel"),
            Some(&machine_profile("ttyAMA0")),
            &system_block_contract("virt", "/boot/rootfs.ext2"),
        );
        assert!(args.contains("root=/dev/vda rw"), "{args}");
        assert!(args.contains("console=ttyAMA0"), "{args}");
        assert!(args.contains("init=/fat/preinit.sh"), "{args}");
    }

    #[test]
    fn mipsel_boots_through_the_init_trampoline() {
        let args = system_boot_args(
            Some("mipsel"),
            Some(&machine_profile("ttyS0")),
            &system_block_contract("malta", "/boot/rootfs.ext2"),
        );
        assert!(args.contains("init=/fat/init-trampoline"), "{args}");
    }

    #[test]
    fn an_unprofiled_virt_run_still_gets_the_console_that_machine_has() {
        // Operator-supplied kernels carry no machine profile. Falling back to
        // ttyS0 on virt produced a silent boot that looked like a dead guest.
        let args = system_boot_args(
            Some("armel"),
            None,
            &system_block_contract("virt", "/boot/rootfs.ext2"),
        );
        assert!(args.contains("console=ttyAMA0"), "{args}");
        assert!(args.contains("root=/dev/vda"), "{args}");
    }

    #[test]
    fn an_unprofiled_malta_run_keeps_its_8250_console() {
        let args = system_boot_args(
            Some("mipsel"),
            None,
            &system_block_contract("malta", "/boot/rootfs.ext2"),
        );
        assert!(args.contains("console=ttyS0"), "{args}");
        assert!(args.contains("root=/dev/sda"), "{args}");
    }

    #[test]
    fn a_machine_profile_still_wins_over_the_fallback() {
        let args = system_boot_args(
            Some("armel"),
            Some(&machine_profile("ttyS1")),
            &system_block_contract("virt", "/boot/rootfs.ext2"),
        );
        assert!(args.contains("console=ttyS1"), "{args}");
    }

    #[test]
    fn malta_keeps_its_ide_root_and_needs_no_controller() {
        let contract = system_block_contract("malta", "/boot/rootfs.ext2");
        assert_eq!(contract.root_device, "/dev/sda");
        assert_eq!(contract.drive, "file=/boot/rootfs.ext2,format=raw");
        assert!(
            contract.device.is_none(),
            "malta has a default IDE bus, so a bare -drive is enough"
        );
    }

    #[test]
    fn virt_gets_a_virtio_root_disk_it_can_actually_attach() {
        // A bare -drive on virt attaches to nothing: there is no default block
        // controller, so the kernel finds no root and the guest dies silently.
        let contract = system_block_contract("virt", "/boot/rootfs.ext2");
        assert_eq!(contract.root_device, "/dev/vda");
        assert_eq!(
            contract.drive,
            "file=/boot/rootfs.ext2,format=raw,if=none,id=fatroot"
        );
        assert_eq!(
            contract.device.as_deref(),
            Some("virtio-blk-device,drive=fatroot")
        );
    }

    #[test]
    fn virt_argv_pairs_the_controller_with_its_drive() {
        let contract = system_block_contract("virt", "/boot/rootfs.ext2");
        let args = system_qemu_args(
            "virt".to_string(),
            Some("armel"),
            None,
            None,
            "/boot/zImage",
            &contract,
            "root=/dev/vda rw console=ttyAMA0",
            "/tmp/serial.sock",
            "/tmp/serial.log",
            "/tmp/monitor.sock",
            "127.0.0.1:1234",
            &[],
        );
        let drive = args.iter().position(|arg| arg == "-drive").expect("-drive");
        assert_eq!(args[drive + 1], contract.drive);
        assert_eq!(args[drive + 2], "-device");
        assert_eq!(args[drive + 3], "virtio-blk-device,drive=fatroot");
        // The NIC device must survive the splice.
        assert!(
            args.iter()
                .any(|arg| arg == "virtio-net-device,netdev=fatnet0"),
            "{args:?}"
        );
    }
}
