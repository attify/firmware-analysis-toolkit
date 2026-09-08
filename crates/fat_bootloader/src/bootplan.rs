use crate::profile::BootloaderProfile;
use fat_core::bootloader::BootloaderSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootArtifact {
    pub kind: String,
    pub path: String,
    pub source_path: String,
    pub format: String,
    pub arch: String,
    pub load_addr: Option<String>,
    pub entry_addr: Option<String>,
    pub compression: Option<String>,
    pub provenance: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootArtifactSet {
    pub primary: Option<BootArtifact>,
    pub alternates: Vec<BootArtifact>,
    pub missing_requirements: Vec<String>,
    pub selection_rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BootPlan {
    pub boot_method: String,
    pub kernel: Option<BootArtifact>,
    pub dtb: Option<BootArtifact>,
    pub implicit_fdt_reference: Option<String>,
    pub initramfs: Option<BootArtifact>,
    pub rootfs: Option<BootArtifact>,
    pub fit: Option<BootArtifact>,
    pub console_device: Option<String>,
    pub baud_rate: Option<u32>,
    pub bootargs_template: Option<String>,
    pub u_boot_commands: Vec<String>,
    pub load_addresses: Vec<String>,
    pub expected_handoff: Option<String>,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BootExecutionResult {
    pub stage: String,
    pub result: String,
    pub observed_output: Vec<String>,
    pub error: Option<String>,
}

pub fn build_boot_plan(
    artifact_set: &BootArtifactSet,
    snapshot: Option<&BootloaderSnapshot>,
    profile: &BootloaderProfile,
) -> BootPlan {
    let primary = artifact_set.primary.as_ref();
    let fit = primary.filter(|artifact| artifact.kind == "fit").cloned();
    let kernel = primary
        .filter(|artifact| artifact.kind == "kernel")
        .cloned();
    let dtb = artifact_set
        .alternates
        .iter()
        .find(|artifact| artifact.kind == "dtb")
        .cloned();
    let implicit_fdt_reference = if dtb.is_none() {
        bootloader_fdt_reference(snapshot)
    } else {
        None
    };
    let rootfs = artifact_set
        .alternates
        .iter()
        .find(|artifact| artifact.kind == "rootfs")
        .cloned();
    let bootargs =
        bootloader_value(snapshot, "bootargs").unwrap_or_else(|| profile.bootargs.clone());
    let (console_device, baud_rate) = parse_console_settings(&bootargs);
    let boot_method = primary
        .map(|artifact| boot_method_for(artifact, snapshot))
        .unwrap_or_else(|| "unsupported".to_string());
    let load_address = primary
        .and_then(|artifact| artifact.load_addr.clone())
        .or_else(|| bootloader_value(snapshot, "loadaddr"))
        .or_else(|| Some(profile.loadaddr.clone()));
    let load_addresses = load_address.clone().into_iter().collect();

    let mut plan = BootPlan {
        boot_method,
        kernel: kernel.map(|mut artifact| {
            if artifact.load_addr.is_none() {
                artifact.load_addr = load_address.clone();
            }
            artifact
        }),
        dtb: dtb.map(|mut artifact| {
            if artifact.load_addr.is_none() {
                artifact.load_addr = bootloader_value(snapshot, "fdt_addr_r")
                    .or_else(|| Some("0x43000000".to_string()));
            }
            artifact
        }),
        implicit_fdt_reference,
        initramfs: None,
        rootfs,
        fit: fit.map(|mut artifact| {
            if artifact.load_addr.is_none() {
                artifact.load_addr = load_address.clone();
            }
            artifact
        }),
        console_device,
        baud_rate,
        bootargs_template: Some(bootargs),
        u_boot_commands: Vec::new(),
        load_addresses,
        expected_handoff: Some("kernel_handoff_attempted".into()),
        rejection_reason: None,
    };
    plan.u_boot_commands = plan.u_boot_commands();
    plan
}

impl BootPlan {
    pub fn u_boot_commands(&self) -> Vec<String> {
        if self.rejection_reason.is_some() {
            return Vec::new();
        }

        let mut commands = Vec::new();
        if let Some(loadaddr) = self
            .load_addresses
            .first()
            .cloned()
            .or_else(|| {
                self.kernel
                    .as_ref()
                    .and_then(|artifact| artifact.load_addr.clone())
            })
            .or_else(|| {
                self.fit
                    .as_ref()
                    .and_then(|artifact| artifact.load_addr.clone())
            })
        {
            commands.push(format!("setenv loadaddr {loadaddr}"));
        }
        if let Some(bootargs) = &self.bootargs_template {
            commands.push(format!("setenv bootargs {bootargs}"));
        }
        if let Some(fdt_addr) = self
            .dtb
            .as_ref()
            .and_then(|artifact| artifact.load_addr.as_ref())
        {
            commands.push(format!("setenv fdt_addr_r {fdt_addr}"));
        }

        match self.boot_method.as_str() {
            "bootm" if self.dtb.is_some() => {
                commands.push("bootm ${loadaddr} - ${fdt_addr_r}".into())
            }
            "bootm" if self.implicit_fdt_reference.is_some() => {
                commands.push("bootm ${loadaddr} - ${fdtcontroladdr}".into())
            }
            "bootm" => commands.push("bootm ${loadaddr}".into()),
            "bootz" if self.dtb.is_some() => {
                commands.push("bootz ${loadaddr} - ${fdt_addr_r}".into())
            }
            "bootz" if self.implicit_fdt_reference.is_some() => {
                commands.push("bootz ${loadaddr} - ${fdtcontroladdr}".into())
            }
            "bootz" => commands.push("bootz ${loadaddr}".into()),
            "booti" if self.dtb.is_some() => {
                commands.push("booti ${loadaddr} - ${fdt_addr_r}".into())
            }
            "booti" if self.implicit_fdt_reference.is_some() => {
                commands.push("booti ${loadaddr} - ${fdtcontroladdr}".into())
            }
            "booti" => commands.push("booti ${loadaddr}".into()),
            _ => {}
        }

        commands
    }
}

fn boot_method_for(artifact: &BootArtifact, snapshot: Option<&BootloaderSnapshot>) -> String {
    let explicit = match artifact.kind.as_str() {
        "fit" => "bootm".into(),
        "kernel" => match artifact.format.as_str() {
            "uImage" => "bootm".into(),
            "zImage" => "bootz".into(),
            "Image" => "booti".into(),
            _ => "unsupported".into(),
        },
        _ => "unsupported".into(),
    };

    if explicit != "unsupported" {
        return explicit;
    }

    boot_method_from_snapshot(snapshot).unwrap_or(explicit)
}

fn boot_method_from_snapshot(snapshot: Option<&BootloaderSnapshot>) -> Option<String> {
    let bootcmd = bootloader_value(snapshot, "bootcmd")?;
    let lowered = bootcmd.to_ascii_lowercase();
    if lowered.contains("bootm") {
        Some("bootm".into())
    } else if lowered.contains("bootz") {
        Some("bootz".into())
    } else if lowered.contains("booti") {
        Some("booti".into())
    } else {
        None
    }
}

fn bootloader_value(snapshot: Option<&BootloaderSnapshot>, key: &str) -> Option<String> {
    snapshot.and_then(|snapshot| {
        snapshot
            .env_variables
            .iter()
            .find(|variable| variable.key.eq_ignore_ascii_case(key))
            .map(|variable| variable.value.clone())
    })
}

fn bootloader_fdt_reference(snapshot: Option<&BootloaderSnapshot>) -> Option<String> {
    let snapshot = snapshot?;

    if bootloader_value(Some(snapshot), "fdtcontroladdr").is_some() {
        return Some("${fdtcontroladdr}".into());
    }

    snapshot
        .env_variables
        .iter()
        .map(|variable| variable.value.to_ascii_lowercase())
        .find(|value| value.contains("fdtcontroladdr"))
        .map(|_| "${fdtcontroladdr}".to_string())
}

fn parse_console_settings(bootargs: &str) -> (Option<String>, Option<u32>) {
    for token in bootargs.split_whitespace() {
        if let Some(value) = token.strip_prefix("console=") {
            let mut parts = value.split(',');
            let device = parts
                .next()
                .filter(|part| !part.is_empty())
                .map(str::to_string);
            let baud_rate = parts.next().and_then(|part| part.parse::<u32>().ok());
            return (device, baud_rate);
        }
    }

    (None, None)
}
