use std::cmp::Ordering;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fat_core::rehosting_policy::SubstrateKind as LogicalSubstrateKind;

use crate::driver::{BackendDriverContract, BackendDriverPhase};
use crate::managed_linux_vm::{
    firmae_docker_psql_ip_from_env, firmae_host_python_from_env, firmae_upstream_brand_from_env,
    firmae_upstream_dir_from_env, inspect_managed_linux_vm_bundle_from_env,
    managed_linux_vm_bundle_dir_from_env,
};
use crate::substrate::{
    BackendLogicalSubstrateContract, BackendSubstrateContract, BackendSubstrateKind,
    BackendSubstratePrecondition,
};
use crate::traits::{Backend, BackendAdapterMetadata, BackendCapability, BackendKind, FamilyMatch};
use serde::Serialize;

const EMUX_DIR_ENV: &str = "FAT_EMUX_DIR";
const EMUX_TUN_DEVICE_ENV: &str = "FAT_EMUX_TUN_DEVICE";
pub const EMUX_ROOTFUL_PODMAN_ENV: &str = "FAT_EMUX_ROOTFUL_PODMAN";
const EMUX_DEFAULT_TUN_DEVICE: &str = "/dev/net/tun";
const EMUX_REQUIRED_SCRIPTS: &[&str] = &[
    "run-emux-docker",
    "emux-docker-shell",
    "files/emux/run/launcher",
    "files/emux/run/userspace",
    "files/emux/run/emuxps",
    "files/emux/run/emuxmaps",
    "files/emux/run/emuxnetstat",
    "files/emux/run/emuxgdb",
    "files/emux/run/monitor",
];

#[derive(Debug, Clone, PartialEq)]
pub struct BackendAvailability {
    pub is_available: bool,
    pub detail: String,
    pub checks: Vec<BackendCheckRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendCheckRecord {
    pub check_type: String,
    pub subject: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackendHealthSummary {
    pub backend_id: String,
    pub display_name: String,
    pub required_commands: Vec<String>,
    pub available_commands: Vec<String>,
    pub is_available: bool,
    pub stable_summary: String,
    pub checks: Vec<BackendCheckRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendAvailabilitySummary {
    pub backend_id: String,
    pub display_name: String,
    pub matched_family_id: String,
    pub score: f32,
    pub is_available: bool,
    pub availability_detail: String,
    pub stable_summary: String,
    pub checks: Vec<BackendCheckRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackendScore {
    pub backend_id: String,
    pub display_name: String,
    pub score: f32,
    pub matched_family_id: String,
    pub rationale: String,
    pub availability: BackendAvailability,
}

pub trait CommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf>;
}

#[derive(Debug, Default)]
pub struct PathCommandProbe;

impl CommandProbe for PathCommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf> {
        if command.contains(std::path::MAIN_SEPARATOR) {
            let path = PathBuf::from(command);
            return is_executable_file(&path).then_some(path);
        }

        let path_var = env::var_os("PATH")?;
        for entry in env::split_paths(&path_var) {
            let candidate = entry.join(command);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }

        None
    }
}

#[derive(Debug, Default)]
pub struct BackendRegistry {
    backends: Vec<Box<dyn Backend>>,
}

impl BackendRegistry {
    pub fn new(backends: Vec<Box<dyn Backend>>) -> Self {
        Self { backends }
    }

    pub fn with_test_backends() -> Self {
        Self::new(vec![
            Box::new(StaticBackend::firmae()),
            Box::new(StaticBackend::emux()),
            Box::new(StaticBackend::firmadyne()),
            Box::new(StaticBackend::qemu_direct()),
            Box::new(StaticBackend::docker_native()),
        ])
    }

    pub fn rank_family(&self, family_id: &str) -> Vec<BackendScore> {
        let probe = PathCommandProbe;
        self.rank_family_with_probe(family_id, &probe)
    }

    pub fn rank_family_with_probe<P: CommandProbe + ?Sized>(
        &self,
        family_id: &str,
        probe: &P,
    ) -> Vec<BackendScore> {
        let mut scores: Vec<BackendScore> = self
            .backends
            .iter()
            .filter_map(|backend| {
                backend.score_family(family_id).map(|score| {
                    let capability = backend.capability();
                    let family_match = capability
                        .family_matches
                        .iter()
                        .find(|candidate| candidate.family_id == family_id)
                        .expect("score_family returned a score for a missing family");
                    BackendScore {
                        backend_id: backend.backend_id().to_string(),
                        display_name: backend.display_name().to_string(),
                        score,
                        matched_family_id: family_match.family_id.clone(),
                        rationale: family_match.rationale.clone(),
                        availability: availability_for(backend.backend_id(), family_id, probe),
                    }
                })
            })
            .collect();

        scores.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.backend_id.cmp(&right.backend_id))
        });

        scores
    }

    pub fn health_with_probe<P: CommandProbe + ?Sized>(
        &self,
        probe: &P,
    ) -> Vec<BackendHealthSummary> {
        self.backends
            .iter()
            .map(|backend| health_summary_for_backend(backend.as_ref(), probe))
            .collect()
    }

    pub fn driver_contracts(&self) -> Vec<BackendDriverContract> {
        self.backends
            .iter()
            .map(|backend| backend.driver_contract().clone())
            .collect()
    }

    pub fn logical_substrate_contracts(&self) -> Vec<BackendLogicalSubstrateContract> {
        let mut contracts = Vec::new();
        for driver in self.driver_contracts() {
            for logical_kind in logical_substrates_for_backend_id(&driver.backend_id) {
                contracts.push(BackendLogicalSubstrateContract {
                    logical_kind: *logical_kind,
                    backend_id: driver.backend_id.clone(),
                    display_name: driver.display_name.clone(),
                    supported_physical_substrates: driver.substrates.clone(),
                    execution_preconditions: driver
                        .substrates
                        .iter()
                        .map(substrate_precondition_for_contract)
                        .collect(),
                    fidelity_caveats: fidelity_caveats_for_backend(
                        &driver.backend_id,
                        *logical_kind,
                    ),
                });
            }
        }
        contracts.sort_by(|left, right| {
            logical_substrate_rank(left.logical_kind)
                .cmp(&logical_substrate_rank(right.logical_kind))
                .then(left.backend_id.cmp(&right.backend_id))
        });
        contracts
    }

    pub fn logical_substrate_contracts_for_evidence(
        &self,
        target_evidence: &[String],
    ) -> Vec<BackendLogicalSubstrateContract> {
        let mut contracts = Vec::new();
        for driver in self.driver_contracts() {
            let logical_kind = logical_substrate_for_backend(&driver.backend_id, target_evidence);
            contracts.push(BackendLogicalSubstrateContract {
                logical_kind,
                backend_id: driver.backend_id.clone(),
                display_name: driver.display_name.clone(),
                supported_physical_substrates: driver.substrates.clone(),
                execution_preconditions: driver
                    .substrates
                    .iter()
                    .map(substrate_precondition_for_contract)
                    .collect(),
                fidelity_caveats: fidelity_caveats_for_backend(&driver.backend_id, logical_kind),
            });
        }
        contracts.sort_by(|left, right| {
            logical_substrate_rank(left.logical_kind)
                .cmp(&logical_substrate_rank(right.logical_kind))
                .then(left.backend_id.cmp(&right.backend_id))
        });
        contracts
    }
}

pub fn logical_substrates_for_backend_id(backend_id: &str) -> &'static [LogicalSubstrateKind] {
    match backend_id {
        "docker-native" => &[LogicalSubstrateKind::Service],
        "emux" => &[LogicalSubstrateKind::Reference],
        "firmae" | "firmadyne" => &[LogicalSubstrateKind::System],
        "qemu-direct" => &[LogicalSubstrateKind::Service, LogicalSubstrateKind::System],
        _ => &[LogicalSubstrateKind::System],
    }
}

pub fn logical_substrate_for_backend(
    backend_id: &str,
    target_evidence: &[String],
) -> LogicalSubstrateKind {
    match backend_id {
        "emux" => LogicalSubstrateKind::Reference,
        "firmae" | "firmadyne" => LogicalSubstrateKind::System,
        "docker-native" => LogicalSubstrateKind::Service,
        "qemu-direct" => {
            let has_service = target_evidence.iter().any(|signal| {
                signal.starts_with("web:cgi")
                    || signal.starts_with("web:httpd")
                    || signal.starts_with("web:uhttpd")
                    || signal.starts_with("service:")
            });
            if has_service {
                LogicalSubstrateKind::Service
            } else {
                LogicalSubstrateKind::System
            }
        }
        _ => LogicalSubstrateKind::System,
    }
}

fn substrate_precondition_for_contract(
    contract: &BackendSubstrateContract,
) -> BackendSubstratePrecondition {
    BackendSubstratePrecondition::new(
        format!("physical substrate {}", contract.display_name),
        contract.capability.is_supported
            && contract.health.status != crate::substrate::BackendSubstrateStatus::Unavailable,
        format!("{}; {}", contract.capability.notes, contract.health.detail),
    )
}

fn fidelity_caveats_for_backend(
    backend_id: &str,
    logical_kind: LogicalSubstrateKind,
) -> Vec<String> {
    match (backend_id, logical_kind) {
        ("emux", LogicalSubstrateKind::Reference) => vec![
            "reference device foothold only; target services may be absent".to_string(),
            "reference-runner output must not be treated as target-faithful validation".to_string(),
        ],
        ("docker-native", LogicalSubstrateKind::Service) => {
            vec!["service-mode only; no appliance boot or kernel-backed fidelity".to_string()]
        }
        ("qemu-direct", LogicalSubstrateKind::Service) => {
            vec!["service-mode requires a runnable extracted userspace entrypoint".to_string()]
        }
        ("qemu-direct", LogicalSubstrateKind::System) => {
            vec!["system-mode fidelity depends on kernel and board compatibility".to_string()]
        }
        ("firmae" | "firmadyne", LogicalSubstrateKind::System) => {
            vec!["legacy system substrate with wrapper-mediated orchestration".to_string()]
        }
        _ => Vec::new(),
    }
}

fn logical_substrate_rank(kind: LogicalSubstrateKind) -> u8 {
    match kind {
        LogicalSubstrateKind::Service => 0,
        LogicalSubstrateKind::System => 1,
        LogicalSubstrateKind::Reference => 2,
    }
}

impl BackendScore {
    pub fn availability_summary(&self) -> BackendAvailabilitySummary {
        let availability_label = if self.availability.is_available {
            "available"
        } else {
            "unavailable"
        };

        BackendAvailabilitySummary {
            backend_id: self.backend_id.clone(),
            display_name: self.display_name.clone(),
            matched_family_id: self.matched_family_id.clone(),
            score: self.score,
            is_available: self.availability.is_available,
            availability_detail: self.availability.detail.clone(),
            stable_summary: format!(
                "{} [{}] for {}: {} ({})",
                self.display_name,
                self.backend_id,
                self.matched_family_id,
                availability_label,
                self.availability.detail
            ),
            checks: self.availability.checks.clone(),
        }
    }
}

#[derive(Debug)]
struct StaticBackend {
    backend_id: String,
    display_name: String,
    capability: BackendCapability,
    driver_contract: BackendDriverContract,
}

impl StaticBackend {
    fn firmae() -> Self {
        let capability = BackendCapability {
            supported_architectures: vec![
                "armel".to_string(),
                "mipsel".to_string(),
                "mipseb".to_string(),
            ],
            family_matches: vec![
                FamilyMatch {
                    family_id: "linux-router-arm".to_string(),
                    score: 0.95,
                    rationale: "Linux router family with FirmAE-style legacy wrapper support"
                        .to_string(),
                },
                FamilyMatch {
                    family_id: "linux-router-mips".to_string(),
                    score: 0.92,
                    rationale: "MIPS router family with FirmAE arbitration coverage".to_string(),
                },
            ],
            backend_kind: BackendKind::LegacyAdapter,
            adapter: Some(BackendAdapterMetadata {
                wrapper_id: "firmae-legacy-wrapper".to_string(),
                legacy_behavior: "Current Python wrapper behavior preserved behind the Rust backend metadata layer".to_string(),
                wrapped_backend: "Firmadyne-compatible flow".to_string(),
            }),
        };
        Self {
            backend_id: "firmae".to_string(),
            display_name: "FirmAE".to_string(),
            capability: capability.clone(),
            driver_contract: BackendDriverContract {
                backend_id: "firmae".to_string(),
                display_name: "FirmAE".to_string(),
                capability,
                phases: vec![
                    BackendDriverPhase::Suitability,
                    BackendDriverPhase::Provisioning,
                    BackendDriverPhase::Preparation,
                    BackendDriverPhase::Execution,
                    BackendDriverPhase::Observation,
                    BackendDriverPhase::Diagnostics,
                ],
                supported_substrates: vec![
                    BackendSubstrateKind::ManagedLinuxVm,
                    BackendSubstrateKind::DockerEngine,
                ],
                substrates: vec![
                    BackendSubstrateContract::healthy(
                        BackendSubstrateKind::ManagedLinuxVm,
                        "managed-linux-vm",
                        "FirmAE runs best inside a pinned managed Linux VM substrate",
                    ),
                    BackendSubstrateContract::healthy(
                        BackendSubstrateKind::DockerEngine,
                        "docker-engine",
                        "FirmAE can also execute through a managed container substrate",
                    ),
                ],
            },
        }
    }

    fn emux() -> Self {
        let capability = BackendCapability {
            supported_architectures: vec![
                "armel".to_string(),
                "arm64".to_string(),
                "mipsel".to_string(),
                "mipseb".to_string(),
            ],
            family_matches: vec![
                FamilyMatch {
                    family_id: "linux-router-arm".to_string(),
                    score: 0.58,
                    rationale:
                        "ARM router family with EMUX Docker launcher and hostfs workflow support"
                            .to_string(),
                },
                FamilyMatch {
                    family_id: "linux-router-mips".to_string(),
                    score: 0.84,
                    rationale:
                        "MIPS router family with EMUX Docker launcher and hostfs workflow support"
                            .to_string(),
                },
                FamilyMatch {
                    family_id: "linux-camera-mips".to_string(),
                    score: 0.82,
                    rationale:
                        "MIPS camera family with EMUX debugging and process inspection support"
                            .to_string(),
                },
            ],
            backend_kind: BackendKind::Native,
            adapter: None,
        };
        Self {
            backend_id: "emux".to_string(),
            display_name: "EMUX".to_string(),
            capability: capability.clone(),
            driver_contract: BackendDriverContract {
                backend_id: "emux".to_string(),
                display_name: "EMUX".to_string(),
                capability,
                phases: vec![
                    BackendDriverPhase::Suitability,
                    BackendDriverPhase::Provisioning,
                    BackendDriverPhase::Preparation,
                    BackendDriverPhase::Execution,
                    BackendDriverPhase::Observation,
                    BackendDriverPhase::Diagnostics,
                ],
                supported_substrates: vec![BackendSubstrateKind::DockerEngine],
                substrates: vec![BackendSubstrateContract::healthy(
                    BackendSubstrateKind::DockerEngine,
                    "docker-engine",
                    "EMUX runs through the local Docker container substrate",
                )],
            },
        }
    }

    fn firmadyne() -> Self {
        let capability = BackendCapability {
            supported_architectures: vec![
                "armel".to_string(),
                "mipsel".to_string(),
                "mipseb".to_string(),
            ],
            family_matches: vec![FamilyMatch {
                family_id: "linux-router-arm".to_string(),
                score: 0.75,
                rationale: "Baseline Linux router family coverage".to_string(),
            }],
            backend_kind: BackendKind::LegacyAdapter,
            adapter: Some(BackendAdapterMetadata {
                wrapper_id: "firmadyne-legacy-wrapper".to_string(),
                legacy_behavior: "Compatibility metadata for the older Firmadyne-style wrapper"
                    .to_string(),
                wrapped_backend: "Firmadyne".to_string(),
            }),
        };
        Self {
            backend_id: "firmadyne".to_string(),
            display_name: "Firmadyne".to_string(),
            capability: capability.clone(),
            driver_contract: BackendDriverContract {
                backend_id: "firmadyne".to_string(),
                display_name: "Firmadyne".to_string(),
                capability,
                phases: vec![
                    BackendDriverPhase::Suitability,
                    BackendDriverPhase::Provisioning,
                    BackendDriverPhase::Preparation,
                    BackendDriverPhase::Execution,
                    BackendDriverPhase::Observation,
                    BackendDriverPhase::Diagnostics,
                ],
                supported_substrates: vec![
                    BackendSubstrateKind::ManagedLinuxVm,
                    BackendSubstrateKind::DockerEngine,
                ],
                substrates: vec![
                    BackendSubstrateContract::healthy(
                        BackendSubstrateKind::ManagedLinuxVm,
                        "managed-linux-vm",
                        "Firmadyne prefers a managed Linux VM substrate for Linux-heavy workflows",
                    ),
                    BackendSubstrateContract::healthy(
                        BackendSubstrateKind::DockerEngine,
                        "docker-engine",
                        "Firmadyne can also execute through a managed container substrate",
                    ),
                ],
            },
        }
    }

    fn qemu_direct() -> Self {
        let capability = BackendCapability {
            supported_architectures: vec![
                "armel".to_string(),
                "arm64".to_string(),
                "mipsel".to_string(),
                "mipseb".to_string(),
            ],
            family_matches: vec![
                FamilyMatch {
                    family_id: "linux-router-arm".to_string(),
                    score: 0.63,
                    rationale: "Fallback full-system emulation path when router wrappers are unavailable".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-router-mips".to_string(),
                    score: 0.61,
                    rationale: "Fallback MIPS system emulation path when FirmAE-style tooling is unavailable".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-camera-mips".to_string(),
                    score: 0.58,
                    rationale: "Useful fallback for MIPS camera-style Linux appliances".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-gateway-arm64".to_string(),
                    score: 0.88,
                    rationale: "Strong fit for ARM64 Linux gateway images with direct QEMU boot paths".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-medical-appliance-arm".to_string(),
                    score: 0.57,
                    rationale: "Fallback ARM appliance emulation path when family-specific wrappers are absent".to_string(),
                },
            ],
            backend_kind: BackendKind::Native,
            adapter: None,
        };
        Self {
            backend_id: "qemu-direct".to_string(),
            display_name: "QEMU Direct".to_string(),
            capability: capability.clone(),
            driver_contract: BackendDriverContract {
                backend_id: "qemu-direct".to_string(),
                display_name: "QEMU Direct".to_string(),
                capability,
                phases: vec![
                    BackendDriverPhase::Suitability,
                    BackendDriverPhase::Provisioning,
                    BackendDriverPhase::Preparation,
                    BackendDriverPhase::Execution,
                    BackendDriverPhase::Observation,
                    BackendDriverPhase::Diagnostics,
                ],
                supported_substrates: vec![BackendSubstrateKind::NativeHost],
                substrates: vec![BackendSubstrateContract::healthy(
                    BackendSubstrateKind::NativeHost,
                    "native-host",
                    "QEMU direct can launch against the local host runtime substrate",
                )],
            },
        }
    }

    fn docker_native() -> Self {
        let capability = BackendCapability {
            supported_architectures: vec!["amd64".to_string(), "arm64".to_string()],
            family_matches: vec![
                FamilyMatch {
                    family_id: "linux-router-arm".to_string(),
                    score: 0.22,
                    rationale: "Weak fallback for service extraction, not a full router boot path".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-router-mips".to_string(),
                    score: 0.18,
                    rationale: "Weak fallback for extracted services only; not suitable for full router emulation".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-gateway-arm64".to_string(),
                    score: 0.51,
                    rationale: "Viable for service-centric gateway stacks that do not require board-level boot fidelity".to_string(),
                },
                FamilyMatch {
                    family_id: "linux-java-appliance".to_string(),
                    score: 0.93,
                    rationale: "Strong fit for Java-heavy appliance services packaged in a Linux filesystem".to_string(),
                },
            ],
            backend_kind: BackendKind::Native,
            adapter: None,
        };
        Self {
            backend_id: "docker-native".to_string(),
            display_name: "Docker Native".to_string(),
            capability: capability.clone(),
            driver_contract: BackendDriverContract {
                backend_id: "docker-native".to_string(),
                display_name: "Docker Native".to_string(),
                capability,
                phases: vec![
                    BackendDriverPhase::Suitability,
                    BackendDriverPhase::Provisioning,
                    BackendDriverPhase::Preparation,
                    BackendDriverPhase::Execution,
                    BackendDriverPhase::Observation,
                    BackendDriverPhase::Diagnostics,
                ],
                supported_substrates: vec![BackendSubstrateKind::DockerEngine],
                substrates: vec![BackendSubstrateContract::healthy(
                    BackendSubstrateKind::DockerEngine,
                    "docker-engine",
                    "Docker-native execution requires the managed container substrate",
                )],
            },
        }
    }
}

impl Backend for StaticBackend {
    fn backend_id(&self) -> &str {
        &self.backend_id
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn capability(&self) -> &BackendCapability {
        &self.capability
    }

    fn driver_contract(&self) -> &BackendDriverContract {
        &self.driver_contract
    }
}

fn health_summary_for_backend<P: CommandProbe + ?Sized>(
    backend: &dyn Backend,
    probe: &P,
) -> BackendHealthSummary {
    if backend.backend_id() == "docker-native" {
        return docker_native_health_summary_for_backend(backend, probe);
    }

    if backend.backend_id() == "emux" {
        return emux_health_summary_for_backend(backend, probe);
    }

    if matches!(backend.backend_id(), "firmae" | "firmadyne") {
        return managed_linux_vm_health_summary_for_backend(backend);
    }

    let required_commands = required_commands_for_host(backend.backend_id());
    let checks = command_checks(&required_commands, probe);
    let available_commands: Vec<String> = checks
        .iter()
        .filter(|check| check.passed)
        .map(|check| check.detail.clone())
        .collect();
    let is_available = !available_commands.is_empty();
    let stable_summary = if is_available {
        format!(
            "{} [{}]: available via {}",
            backend.display_name(),
            backend.backend_id(),
            available_commands.join(", ")
        )
    } else {
        format!(
            "{} [{}]: unavailable (missing one of: {})",
            backend.display_name(),
            backend.backend_id(),
            required_commands.join(", ")
        )
    };

    BackendHealthSummary {
        backend_id: backend.backend_id().to_string(),
        display_name: backend.display_name().to_string(),
        required_commands: required_commands
            .into_iter()
            .map(|command| command.to_string())
            .collect(),
        available_commands,
        is_available,
        stable_summary,
        checks,
    }
}

fn availability_for<P: CommandProbe + ?Sized>(
    backend_id: &str,
    family_id: &str,
    probe: &P,
) -> BackendAvailability {
    if backend_id == "docker-native" {
        let check = docker_daemon_check(probe);
        return BackendAvailability {
            is_available: check.passed,
            detail: check.detail.clone(),
            checks: vec![check],
        };
    }

    if backend_id == "emux" {
        let recipe_checks = emux_recipe_checks(probe);
        let is_available =
            !recipe_checks.is_empty() && recipe_checks.iter().all(|check| check.passed);
        return BackendAvailability {
            is_available,
            detail: if is_available {
                format!(
                    "available via EMUX recipe {}",
                    emux_recipe_dir_from_env()
                        .as_deref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            } else {
                emux_recipe_requirement_detail(&recipe_checks)
            },
            checks: recipe_checks,
        };
    }

    if backend_id == "firmae" {
        let recipe_checks = firmae_native_arm64_recipe_checks(backend_id, probe);
        return match inspect_managed_linux_vm_bundle_from_env() {
            Some(Ok(bundle)) if firmae_recipe_is_ready(&recipe_checks) => BackendAvailability {
                is_available: true,
                detail: availability_detail_with_recipe_status(
                    format!(
                        "available via managed-linux-vm bundle {}",
                        bundle
                            .base_image
                            .parent()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    ),
                    &recipe_checks,
                ),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: true,
                        detail: bundle
                            .base_image
                            .parent()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    }],
                    recipe_checks,
                ),
            },
            Some(Ok(bundle)) => BackendAvailability {
                is_available: false,
                detail: firmae_recipe_requirement_detail(&recipe_checks),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: true,
                        detail: bundle
                            .base_image
                            .parent()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    }],
                    recipe_checks,
                ),
            },
            Some(Err(contract)) => BackendAvailability {
                is_available: false,
                detail: contract.health.detail.clone(),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: false,
                        detail: contract.health.detail,
                    }],
                    recipe_checks,
                ),
            },
            // No managed VM bundle configured. That substrate exists because
            // FirmAE cannot run natively on macOS -- the VM is the workaround,
            // not the requirement. A Linux host runs upstream FirmAE directly,
            // so once the recipe checks are all satisfied there is nothing left
            // to provision and the backend really is available. Reporting it as
            // unavailable here sent Linux operators looking for a bundle they
            // never needed.
            None if cfg!(target_os = "linux") && firmae_recipe_is_ready(&recipe_checks) => {
                BackendAvailability {
                    is_available: true,
                    detail: availability_detail_with_recipe_status(
                        format!(
                            "available via native upstream FirmAE checkout {}",
                            firmae_upstream_dir_from_env()
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "unknown".to_string())
                        ),
                        &recipe_checks,
                    ),
                    checks: append_recipe_checks(
                        vec![BackendCheckRecord {
                            check_type: "substrate".to_string(),
                            subject: "native-host".to_string(),
                            passed: true,
                            detail: "linux host runs upstream FirmAE directly; \
                                     no managed VM bundle required"
                                .to_string(),
                        }],
                        recipe_checks,
                    ),
                }
            }
            None => BackendAvailability {
                is_available: false,
                detail: format!(
                    "missing {}",
                    crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                ),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: false,
                        detail: format!(
                            "missing {}",
                            crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                        ),
                    }],
                    recipe_checks,
                ),
            },
        };
    }

    if backend_id == "firmadyne" {
        if let Some(bundle_result) = inspect_managed_linux_vm_bundle_from_env() {
            return match bundle_result {
                Ok(bundle) => BackendAvailability {
                    is_available: true,
                    detail: format!(
                        "available via managed-linux-vm bundle {}",
                        bundle
                            .base_image
                            .parent()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    ),
                    checks: vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: true,
                        detail: bundle
                            .base_image
                            .parent()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    }],
                },
                Err(contract) => BackendAvailability {
                    is_available: false,
                    detail: contract.health.detail.clone(),
                    checks: vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: false,
                        detail: contract.health.detail,
                    }],
                },
            };
        }
    }

    let required_commands = required_commands_for(backend_id, family_id);
    let checks = command_checks(&required_commands, probe);
    if let Some(path) = checks.iter().find(|check| check.passed) {
        BackendAvailability {
            is_available: true,
            detail: format!("available via {}", path.detail),
            checks,
        }
    } else {
        BackendAvailability {
            is_available: false,
            detail: format!("missing one of: {}", required_commands.join(", ")),
            checks,
        }
    }
}

fn managed_linux_vm_health_summary_for_backend(backend: &dyn Backend) -> BackendHealthSummary {
    let required_commands = vec!["managed-linux-vm-bundle".to_string()];
    let recipe_checks = firmae_native_arm64_recipe_checks(backend.backend_id(), &PathCommandProbe);
    match inspect_managed_linux_vm_bundle_from_env() {
        Some(Ok(bundle))
            if backend.backend_id() != "firmae" || firmae_recipe_is_ready(&recipe_checks) =>
        {
            let bundle_dir = bundle
                .base_image
                .parent()
                .map(|path| path.display().to_string())
                .or_else(|| {
                    managed_linux_vm_bundle_dir_from_env().map(|path| path.display().to_string())
                })
                .unwrap_or_else(|| "managed-linux-vm".to_string());
            BackendHealthSummary {
                backend_id: backend.backend_id().to_string(),
                display_name: backend.display_name().to_string(),
                required_commands,
                available_commands: vec![bundle_dir.clone()],
                is_available: true,
                stable_summary: availability_summary_with_recipe_status(
                    backend.display_name(),
                    backend.backend_id(),
                    &format!("available via managed-linux-vm bundle {bundle_dir}"),
                    &recipe_checks,
                ),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: true,
                        detail: bundle_dir,
                    }],
                    recipe_checks,
                ),
            }
        }
        Some(Ok(bundle)) => {
            let bundle_dir = bundle
                .base_image
                .parent()
                .map(|path| path.display().to_string())
                .or_else(|| {
                    managed_linux_vm_bundle_dir_from_env().map(|path| path.display().to_string())
                })
                .unwrap_or_else(|| "managed-linux-vm".to_string());
            BackendHealthSummary {
                backend_id: backend.backend_id().to_string(),
                display_name: backend.display_name().to_string(),
                required_commands,
                available_commands: Vec::new(),
                is_available: false,
                stable_summary: format!(
                    "{} [{}]: unavailable ({})",
                    backend.display_name(),
                    backend.backend_id(),
                    if recipe_checks.is_empty() {
                        format!(
                            "missing upstream FirmAE recipe; managed-linux-vm bundle {bundle_dir} is not enough"
                        )
                    } else {
                        format!(
                            "managed-linux-vm bundle {}; {}",
                            bundle_dir,
                            firmae_recipe_requirement_detail(&recipe_checks)
                        )
                    }
                ),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "bundle".to_string(),
                        subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                            .to_string(),
                        passed: true,
                        detail: bundle_dir,
                    }],
                    recipe_checks,
                ),
            }
        }
        Some(Err(contract)) => BackendHealthSummary {
            backend_id: backend.backend_id().to_string(),
            display_name: backend.display_name().to_string(),
            required_commands,
            available_commands: Vec::new(),
            is_available: false,
            stable_summary: format!(
                "{} [{}]: unavailable ({})",
                backend.display_name(),
                backend.backend_id(),
                contract.health.detail
            ),
            checks: append_recipe_checks(
                vec![BackendCheckRecord {
                    check_type: "bundle".to_string(),
                    subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV.to_string(),
                    passed: false,
                    detail: contract.health.detail,
                }],
                recipe_checks,
            ),
        },
        // Mirrors the native-host branch in backend_availability(): a Linux host
        // runs upstream FirmAE directly, so a satisfied recipe needs no managed
        // VM bundle. Both paths have to agree, otherwise `fat doctor` reports a
        // backend as missing that `fat preflight` is willing to select.
        None if backend.backend_id() == "firmae"
            && cfg!(target_os = "linux")
            && firmae_recipe_is_ready(&recipe_checks) =>
        {
            let upstream = firmae_upstream_dir_from_env()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            BackendHealthSummary {
                backend_id: backend.backend_id().to_string(),
                display_name: backend.display_name().to_string(),
                required_commands: vec!["upstream-firmae-checkout".to_string()],
                available_commands: vec![upstream.clone()],
                is_available: true,
                stable_summary: availability_summary_with_recipe_status(
                    backend.display_name(),
                    backend.backend_id(),
                    &format!("available via native upstream FirmAE checkout {upstream}"),
                    &recipe_checks,
                ),
                checks: append_recipe_checks(
                    vec![BackendCheckRecord {
                        check_type: "substrate".to_string(),
                        subject: "native-host".to_string(),
                        passed: true,
                        detail: "linux host runs upstream FirmAE directly; \
                                 no managed VM bundle required"
                            .to_string(),
                    }],
                    recipe_checks,
                ),
            }
        }
        None => BackendHealthSummary {
            backend_id: backend.backend_id().to_string(),
            display_name: backend.display_name().to_string(),
            required_commands,
            available_commands: Vec::new(),
            is_available: false,
            stable_summary: format!(
                "{} [{}]: unavailable (missing {})",
                backend.display_name(),
                backend.backend_id(),
                crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
            ),
            checks: append_recipe_checks(
                vec![BackendCheckRecord {
                    check_type: "bundle".to_string(),
                    subject: crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV.to_string(),
                    passed: false,
                    detail: format!(
                        "missing {}",
                        crate::managed_linux_vm::MANAGED_LINUX_VM_BUNDLE_DIR_ENV
                    ),
                }],
                recipe_checks,
            ),
        },
    }
}

fn emux_health_summary_for_backend<P: CommandProbe + ?Sized>(
    backend: &dyn Backend,
    probe: &P,
) -> BackendHealthSummary {
    let required_commands = vec!["docker".to_string()];
    let recipe_checks = emux_recipe_checks(probe);
    let is_available = !recipe_checks.is_empty() && recipe_checks.iter().all(|check| check.passed);
    let available_commands = if is_available {
        recipe_checks
            .iter()
            .filter(|check| check.passed)
            .map(|check| check.detail.clone())
            .collect()
    } else {
        Vec::new()
    };

    BackendHealthSummary {
        backend_id: backend.backend_id().to_string(),
        display_name: backend.display_name().to_string(),
        required_commands,
        available_commands,
        is_available,
        stable_summary: if is_available {
            format!(
                "{} [{}]: available via EMUX recipe {}",
                backend.display_name(),
                backend.backend_id(),
                emux_recipe_dir_from_env()
                    .as_deref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )
        } else {
            format!(
                "{} [{}]: unavailable ({})",
                backend.display_name(),
                backend.backend_id(),
                emux_recipe_requirement_detail(&recipe_checks)
            )
        },
        checks: recipe_checks,
    }
}

fn docker_native_health_summary_for_backend<P: CommandProbe + ?Sized>(
    backend: &dyn Backend,
    probe: &P,
) -> BackendHealthSummary {
    let check = docker_daemon_check(probe);
    let is_available = check.passed;
    let available_commands = if is_available {
        vec![check.detail.clone()]
    } else {
        Vec::new()
    };
    let stable_summary = if is_available {
        format!(
            "{} [{}]: available via {}",
            backend.display_name(),
            backend.backend_id(),
            check.detail
        )
    } else {
        format!(
            "{} [{}]: unavailable ({})",
            backend.display_name(),
            backend.backend_id(),
            check.detail
        )
    };

    BackendHealthSummary {
        backend_id: backend.backend_id().to_string(),
        display_name: backend.display_name().to_string(),
        required_commands: vec!["docker".to_string()],
        available_commands,
        is_available,
        stable_summary,
        checks: vec![check],
    }
}

fn append_recipe_checks(
    mut checks: Vec<BackendCheckRecord>,
    recipe_checks: Vec<BackendCheckRecord>,
) -> Vec<BackendCheckRecord> {
    checks.extend(recipe_checks);
    checks
}

fn availability_detail_with_recipe_status(
    base_detail: String,
    recipe_checks: &[BackendCheckRecord],
) -> String {
    match recipe_readiness_suffix(recipe_checks) {
        Some(suffix) => format!("{base_detail}; {suffix}"),
        None => base_detail,
    }
}

fn availability_summary_with_recipe_status(
    display_name: &str,
    backend_id: &str,
    base_detail: &str,
    recipe_checks: &[BackendCheckRecord],
) -> String {
    match recipe_readiness_suffix(recipe_checks) {
        Some(suffix) => format!("{display_name} [{backend_id}]: {base_detail}; {suffix}"),
        None => format!("{display_name} [{backend_id}]: {base_detail}"),
    }
}

fn recipe_readiness_suffix(recipe_checks: &[BackendCheckRecord]) -> Option<&'static str> {
    if recipe_checks.is_empty() {
        None
    } else if recipe_checks.iter().all(|check| check.passed) {
        Some("native FirmAE recipe ready")
    } else {
        Some("native FirmAE recipe incomplete")
    }
}

fn firmae_recipe_is_ready(recipe_checks: &[BackendCheckRecord]) -> bool {
    !recipe_checks.is_empty() && recipe_checks.iter().all(|check| check.passed)
}

fn firmae_recipe_requirement_detail(recipe_checks: &[BackendCheckRecord]) -> String {
    if recipe_checks.is_empty() {
        "upstream FirmAE recipe is not configured".to_string()
    } else if recipe_checks.iter().all(|check| check.passed) {
        "native FirmAE recipe ready".to_string()
    } else {
        let failures = recipe_checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| format!("{}: {}", check.subject, check.detail))
            .collect::<Vec<_>>()
            .join("; ");
        format!("native FirmAE recipe incomplete: {failures}")
    }
}

fn firmae_native_arm64_recipe_checks<P: CommandProbe + ?Sized>(
    backend_id: &str,
    probe: &P,
) -> Vec<BackendCheckRecord> {
    if backend_id != "firmae" {
        return Vec::new();
    }

    let recipe_configured = firmae_upstream_dir_from_env().is_some()
        || firmae_host_python_from_env().is_some()
        || firmae_docker_psql_ip_from_env().is_some()
        || firmae_upstream_brand_from_env().is_some();
    if !recipe_configured {
        return Vec::new();
    }

    vec![
        firmae_docker_server_arch_check(probe),
        firmae_upstream_checkout_check(),
        firmae_host_python_check(),
        firmae_docker_psql_ip_check(),
        firmae_upstream_brand_check(),
    ]
}

fn firmae_docker_server_arch_check<P: CommandProbe + ?Sized>(probe: &P) -> BackendCheckRecord {
    let Some(docker) = probe.command_path("docker") else {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-server-arch".to_string(),
            passed: false,
            detail: "docker command is missing".to_string(),
        };
    };

    // What this check is really asking is whether containers run on the host's
    // own architecture, because that is what makes the upstream FirmAE path
    // native instead of a slow cross-architecture emulation. Requiring arm64
    // specifically was an artifact of validating the recipe on Apple Silicon:
    // an x86_64 Linux host running x86_64 containers is equally native, and was
    // rejected here for no reason.
    let host_arch = normalize_container_arch(env::consts::ARCH);

    match query_container_engine_arch(&docker) {
        Ok(reported) => {
            let arch = normalize_container_arch(&reported);
            let passed = arch == host_arch;
            BackendCheckRecord {
                check_type: "recipe".to_string(),
                subject: "docker-server-arch".to_string(),
                passed,
                detail: if passed {
                    format!("{arch} (native)")
                } else {
                    format!(
                        "container engine reports {arch} but the host is {host_arch}; \
                         FirmAE needs a native-architecture engine"
                    )
                },
            }
        }
        Err(detail) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-server-arch".to_string(),
            passed: false,
            detail: format!("container engine architecture unavailable: {detail}"),
        },
    }
}

/// Collapse the several spellings of an architecture onto one token so a
/// docker-reported `arm64` and a Rust-reported `aarch64` compare equal.
fn normalize_container_arch(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => "arm64".to_string(),
        "x86_64" | "amd64" => "amd64".to_string(),
        other => other.to_string(),
    }
}

/// Ask a container engine for the architecture it runs containers on.
///
/// Docker and podman disagree here. Docker exposes `.Server.Arch` from
/// `docker version`; podman's `define.Version` has no such field, so that
/// template errors out and podman reports the host architecture through
/// `podman info` instead. Try the docker form first, fall back to the podman
/// form, and only fail if neither answers -- a podman host should not be
/// reported as broken merely for being podman.
fn query_container_engine_arch(engine: &Path) -> Result<String, String> {
    let attempts: [&[&str]; 2] = [
        &["version", "--format", "{{.Server.Arch}}"],
        &["info", "--format", "{{.Host.Arch}}"],
    ];

    let mut last_detail = "no container engine query succeeded".to_string();
    for args in attempts {
        match Command::new(engine).args(args).output() {
            Ok(output) if output.status.success() => {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !value.is_empty() {
                    return Ok(value);
                }
                last_detail = "container engine reported an empty architecture".to_string();
            }
            Ok(output) => last_detail = failed_command_detail(&output),
            Err(err) => last_detail = err.to_string(),
        }
    }
    Err(last_detail)
}

fn docker_daemon_check<P: CommandProbe + ?Sized>(probe: &P) -> BackendCheckRecord {
    let Some(docker) = probe.command_path("docker") else {
        return BackendCheckRecord {
            check_type: "runtime".to_string(),
            subject: "docker-daemon".to_string(),
            passed: false,
            detail: "docker command is missing".to_string(),
        };
    };

    match Command::new(&docker)
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            BackendCheckRecord {
                check_type: "runtime".to_string(),
                subject: "docker-daemon".to_string(),
                passed: true,
                detail: if version.is_empty() {
                    docker.display().to_string()
                } else {
                    format!("{} (server {version})", docker.display())
                },
            }
        }
        Ok(output) => BackendCheckRecord {
            check_type: "runtime".to_string(),
            subject: "docker-daemon".to_string(),
            passed: false,
            detail: format!(
                "docker daemon is not reachable: {}",
                failed_command_detail(&output)
            ),
        },
        Err(err) => BackendCheckRecord {
            check_type: "runtime".to_string(),
            subject: "docker-daemon".to_string(),
            passed: false,
            detail: format!("failed to query docker daemon: {err}"),
        },
    }
}

fn failed_command_detail(output: &Output) -> String {
    let message = [&output.stderr, &output.stdout]
        .into_iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .flat_map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .next()
        .unwrap_or_else(|| "command produced no diagnostic output".to_string());
    let bounded = message.chars().take(512).collect::<String>();
    format!("{bounded} (exit {:?})", output.status.code())
}

fn firmae_upstream_checkout_check() -> BackendCheckRecord {
    let Some(upstream_dir) = firmae_upstream_dir_from_env() else {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "upstream-checkout".to_string(),
            passed: false,
            detail: format!(
                "missing {}",
                crate::managed_linux_vm::FIRMAE_UPSTREAM_DIR_ENV
            ),
        };
    };

    let required = [
        "docker-helper.py",
        "download.sh",
        "database/schema",
        "core/Dockerfile",
    ];
    let missing = required
        .iter()
        .map(|relative| upstream_dir.join(relative))
        .find(|path| !path.exists());

    match missing {
        Some(path) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "upstream-checkout".to_string(),
            passed: false,
            detail: format!("upstream checkout is missing {}", path.display()),
        },
        None => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "upstream-checkout".to_string(),
            passed: true,
            detail: upstream_dir.display().to_string(),
        },
    }
}

fn firmae_host_python_check() -> BackendCheckRecord {
    let Some(host_python) = firmae_host_python_from_env() else {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "host-helper-python".to_string(),
            passed: false,
            detail: format!(
                "missing {}",
                crate::managed_linux_vm::FIRMAE_HOST_PYTHON_ENV
            ),
        };
    };

    let passed = is_executable_file(&host_python);
    BackendCheckRecord {
        check_type: "recipe".to_string(),
        subject: "host-helper-python".to_string(),
        passed,
        detail: if passed {
            host_python.display().to_string()
        } else {
            "host helper python is missing or not executable".to_string()
        },
    }
}

/// The brand upstream FirmAE requires for `docker-helper.py -ec`.
///
/// FAT does not derive it from firmware evidence, so it is an operator input
/// like the checkout and the host python. It is checked here because a launch
/// without it fails at BackendProvisioning, and the diagnostic that failure
/// prints tells the operator to run `fat doctor` — which has to be able to see
/// the missing input for that advice to lead anywhere.
fn firmae_upstream_brand_check() -> BackendCheckRecord {
    let subject = "upstream-brand".to_string();
    match firmae_upstream_brand_from_env() {
        Some(Ok(brand)) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject,
            passed: true,
            detail: brand,
        },
        Some(Err(error)) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject,
            passed: false,
            detail: error,
        },
        None => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject,
            passed: false,
            detail: format!(
                "missing {}",
                crate::managed_linux_vm::FIRMAE_UPSTREAM_BRAND_ENV
            ),
        },
    }
}

fn firmae_docker_psql_ip_check() -> BackendCheckRecord {
    let Some(configured) = firmae_docker_psql_ip_from_env() else {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-psql-ip".to_string(),
            passed: false,
            detail: "docker psql host is not configured (set FAT_FIRMAE_DOCKER_PSQL_IP)"
                .to_string(),
        };
    };

    // `host.docker.internal` is a Docker Desktop alias for "the host box". It is
    // how a container on macOS reaches a PostgreSQL server running outside it,
    // and it is the right answer there. It is not the only right answer: on
    // Linux no such alias exists and none is needed, because both docker and
    // rootless podman publish ports straight onto host loopback. Upstream
    // FirmAE's own firmae.config says as much -- it uses PSQL_IP=127.0.0.1 for
    // native runs. Demanding the macOS spelling everywhere failed hosts that
    // were correctly configured.
    let host = configured.trim();
    let passed = host == "host.docker.internal" || is_loopback_host(host);
    BackendCheckRecord {
        check_type: "recipe".to_string(),
        subject: "docker-psql-ip".to_string(),
        passed,
        detail: if passed {
            host.to_string()
        } else {
            format!(
                "docker psql host {host} is neither host.docker.internal nor a loopback address; \
                 FirmAE containers are unlikely to reach PostgreSQL there"
            )
        },
    }
}

/// True when the host names the local machine, in any of its usual spellings.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

fn required_commands_for(backend_id: &str, family_id: &str) -> Vec<&'static str> {
    match backend_id {
        "firmae" => vec!["firmae"],
        "firmadyne" => vec!["firmadyne"],
        "emux" => vec!["docker"],
        "docker-native" => vec!["docker"],
        "qemu-direct" => match family_id {
            "linux-router-mips" | "linux-camera-mips" => {
                vec![
                    "qemu-system-mipsel",
                    "qemu-system-mips",
                    "qemu-system-mipseb",
                ]
            }
            "linux-router-arm" | "linux-medical-appliance-arm" => {
                vec!["qemu-system-arm", "qemu-system-aarch64"]
            }
            "linux-gateway-arm64" => vec!["qemu-system-aarch64", "qemu-system-arm"],
            _ => vec![
                "qemu-system-arm",
                "qemu-system-aarch64",
                "qemu-system-mipsel",
            ],
        },
        _ => Vec::new(),
    }
}

fn required_commands_for_host(backend_id: &str) -> Vec<&'static str> {
    match backend_id {
        "firmae" => vec!["firmae"],
        "firmadyne" => vec!["firmadyne"],
        "emux" => vec!["docker"],
        "docker-native" => vec!["docker"],
        "qemu-direct" => vec![
            "qemu-system-mipsel",
            "qemu-system-mips",
            "qemu-system-mipseb",
            "qemu-system-arm",
            "qemu-system-aarch64",
        ],
        _ => Vec::new(),
    }
}

fn command_checks<P: CommandProbe + ?Sized>(
    commands: &[&str],
    probe: &P,
) -> Vec<BackendCheckRecord> {
    commands
        .iter()
        .map(|command| match probe.command_path(command) {
            Some(path) => BackendCheckRecord {
                check_type: "command".to_string(),
                subject: (*command).to_string(),
                passed: true,
                detail: path.display().to_string(),
            },
            None => BackendCheckRecord {
                check_type: "command".to_string(),
                subject: (*command).to_string(),
                passed: false,
                detail: "missing".to_string(),
            },
        })
        .collect()
}

fn emux_recipe_dir_from_env() -> Option<PathBuf> {
    env::var_os(EMUX_DIR_ENV).map(PathBuf::from)
}

fn emux_recipe_checks<P: CommandProbe + ?Sized>(probe: &P) -> Vec<BackendCheckRecord> {
    let Some(recipe_root) = emux_recipe_dir_from_env() else {
        return vec![BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: EMUX_DIR_ENV.to_string(),
            passed: false,
            detail: format!("missing {EMUX_DIR_ENV}"),
        }];
    };

    if !recipe_root.exists() {
        return vec![BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: EMUX_DIR_ENV.to_string(),
            passed: false,
            detail: format!("missing {}", recipe_root.display()),
        }];
    }

    let mut checks = vec![BackendCheckRecord {
        check_type: "recipe".to_string(),
        subject: EMUX_DIR_ENV.to_string(),
        passed: true,
        detail: recipe_root.display().to_string(),
    }];

    for relative in EMUX_REQUIRED_SCRIPTS {
        let path = recipe_root.join(relative);
        let passed = is_executable_file(&path);
        checks.push(BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: (*relative).to_string(),
            passed,
            detail: if passed {
                path.display().to_string()
            } else {
                format!("missing {}", path.display())
            },
        });
    }

    checks.push(emux_docker_runtime_check(probe));
    checks.push(emux_tun_device_check());
    checks
}

fn emux_recipe_requirement_detail(recipe_checks: &[BackendCheckRecord]) -> String {
    if recipe_checks.is_empty() {
        return "EMUX recipe is not configured".to_string();
    }

    let missing: Vec<&str> = recipe_checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.subject.as_str())
        .collect();

    if missing.is_empty() {
        "EMUX recipe ready".to_string()
    } else {
        let runtime_detail = recipe_checks
            .iter()
            .find(|check| check.subject == "docker-runtime" && !check.passed)
            .map(|check| format!(" ({})", check.detail))
            .unwrap_or_default();
        format!(
            "EMUX recipe incomplete; missing {}{}",
            missing.join(", "),
            runtime_detail
        )
    }
}

fn emux_docker_runtime_check<P: CommandProbe + ?Sized>(probe: &P) -> BackendCheckRecord {
    let Some(docker) = probe.command_path("docker") else {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-runtime".to_string(),
            passed: false,
            detail: "docker command is missing".to_string(),
        };
    };

    let version = Command::new(&docker).arg("--version").output();
    let is_podman = version.as_ref().is_ok_and(|output| {
        String::from_utf8_lossy(&output.stdout)
            .to_ascii_lowercase()
            .contains("podman")
            || String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("podman")
    });
    if is_podman && env::var(EMUX_ROOTFUL_PODMAN_ENV).as_deref() != Ok("1") {
        return BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-runtime".to_string(),
            passed: false,
            detail: format!(
                "Podman detected; EMUX requires rootful privileged networking. Set {EMUX_ROOTFUL_PODMAN_ENV}=1 only on an isolated lab host to opt in"
            ),
        };
    }

    let output = if is_podman {
        let Some(sudo) = probe.command_path("sudo") else {
            return BackendCheckRecord {
                check_type: "recipe".to_string(),
                subject: "docker-runtime".to_string(),
                passed: false,
                detail: format!(
                    "{EMUX_ROOTFUL_PODMAN_ENV}=1 is set, but sudo is unavailable for rootful Podman"
                ),
            };
        };
        Command::new(sudo)
            .arg("-n")
            .arg(&docker)
            .arg("info")
            .output()
    } else {
        Command::new(&docker)
            .args(["info", "--format", "{{.ServerVersion}}"])
            .output()
    };

    match output {
        Ok(output) if output.status.success() => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-runtime".to_string(),
            passed: true,
            detail: if is_podman {
                format!(
                    "rootful Podman runtime available through explicit {EMUX_ROOTFUL_PODMAN_ENV}=1 opt-in"
                )
            } else {
                "docker runtime available".to_string()
            },
        },
        Ok(output) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-runtime".to_string(),
            passed: false,
            detail: format!(
                "docker runtime is not usable (exit {:?})",
                output.status.code()
            ),
        },
        Err(err) => BackendCheckRecord {
            check_type: "recipe".to_string(),
            subject: "docker-runtime".to_string(),
            passed: false,
            detail: format!("failed to run docker info: {err}"),
        },
    }
}

fn emux_tun_device_check() -> BackendCheckRecord {
    let tun_path = env::var_os(EMUX_TUN_DEVICE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(EMUX_DEFAULT_TUN_DEVICE));
    let passed = tun_path.exists();
    BackendCheckRecord {
        check_type: "recipe".to_string(),
        subject: "tun-device".to_string(),
        passed,
        detail: if passed {
            tun_path.display().to_string()
        } else {
            format!("missing {}", tun_path.display())
        },
    }
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}
