use crate::bootloader_image::{BootloaderCompatibility, BootloaderImage};
use crate::bootplan::BootArtifactSet;
use std::fs;
use std::path::Path;

pub fn evaluate_true_boot_chain(
    image: &BootloaderImage,
    selected_artifacts: Option<&BootArtifactSet>,
    requested_machine: Option<&str>,
) -> BootloaderCompatibility {
    if !image.family.eq_ignore_ascii_case("u-boot") {
        return downgrade(
            "bootloader family is not in the true boot-chain support table".into(),
            "unsupported-family".into(),
        );
    }

    match image.architecture.to_ascii_lowercase().as_str() {
        "arm" => evaluate_arm_u_boot(image, selected_artifacts, requested_machine),
        "mips" => downgrade(
            "no supported QEMU machine mapping exists yet for this bootloader architecture".into(),
            "machine-mapping".into(),
        ),
        _ => downgrade(
            "bootloader architecture is not in the true boot-chain support table".into(),
            "unsupported-architecture".into(),
        ),
    }
}

fn evaluate_arm_u_boot(
    image: &BootloaderImage,
    selected_artifacts: Option<&BootArtifactSet>,
    requested_machine: Option<&str>,
) -> BootloaderCompatibility {
    let machine = requested_machine.unwrap_or("virt");
    if machine != "virt" {
        return downgrade(
            format!("requested machine {machine} is not supported for true boot-chain U-Boot ARM"),
            "machine-mapping".into(),
        );
    }

    let bootloader_board = bootloader_board_profile(Path::new(&image.path));
    let artifact_board = artifact_board_profile(selected_artifacts);
    if let (Some(bootloader_board), Some(artifact_board)) =
        (bootloader_board.as_deref(), artifact_board.as_deref())
    {
        if bootloader_board != artifact_board {
            return downgrade(
                format!(
                    "bootloader board profile {bootloader_board} does not match extracted artifact board profile {artifact_board}"
                ),
                "board-coherence".into(),
            );
        }
    }

    BootloaderCompatibility {
        mode: "true-boot-chain".into(),
        machine: Some("virt".into()),
        qemu_binary: Some("qemu-system-arm".into()),
        compatible: true,
        confidence: 0.7,
        reasons: vec![
            "supported U-Boot ARM mapping to QEMU virt machine".into(),
            "bootloader and boot artifacts passed board-coherence checks".into(),
        ],
        blocking_requirements: Vec::new(),
    }
}

fn bootloader_board_profile(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    board_profile_from_bytes(&bytes)
}

fn artifact_board_profile(selected_artifacts: Option<&BootArtifactSet>) -> Option<String> {
    let selected_artifacts = selected_artifacts?;
    for artifact in &selected_artifacts.alternates {
        if artifact.kind == "dtb" {
            if let Ok(bytes) = fs::read(&artifact.path) {
                if let Some(profile) = board_profile_from_bytes(&bytes) {
                    return Some(profile);
                }
            }
        }
    }

    let primary = selected_artifacts.primary.as_ref()?;
    let bytes = fs::read(&primary.path).ok()?;
    board_profile_from_bytes(&bytes)
}

fn board_profile_from_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();

    if text.contains("board=qemu-arm")
        || text.contains("board_name=qemu-arm")
        || text.contains("qemu,fw-cfg-mmio")
        || text.contains("virtio-mmio")
    {
        return Some("qemu-arm-virt".into());
    }

    if text.contains("hisilicon,hi3516ev200")
        || text.contains("hisilicon hi3516ev200")
        || text.contains("hi3516ev200")
    {
        return Some("hisilicon-hi3516ev200".into());
    }

    if text.contains("vexpress") {
        return Some("arm-vexpress".into());
    }

    None
}

fn downgrade(reason: String, blocking_requirement: String) -> BootloaderCompatibility {
    BootloaderCompatibility {
        mode: "hybrid-boot-chain".into(),
        machine: None,
        qemu_binary: None,
        compatible: false,
        confidence: 0.0,
        reasons: vec![reason],
        blocking_requirements: vec![blocking_requirement],
    }
}
