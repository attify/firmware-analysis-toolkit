use std::process::Command;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tempfile::tempdir;

struct FakeCommandProbe {
    commands: HashMap<String, PathBuf>,
}

impl FakeCommandProbe {
    fn with_commands(entries: &[(&str, &str)]) -> Self {
        Self {
            commands: entries
                .iter()
                .map(|(command, path)| ((*command).to_string(), PathBuf::from(path)))
                .collect(),
        }
    }
}

impl fat_backend::CommandProbe for FakeCommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf> {
        self.commands.get(command).cloned()
    }
}

#[test]
fn test_preflight_reports_ranked_backends_and_reasons() {
    let probe = FakeCommandProbe::with_commands(&[("qemu-system-arm", "/usr/bin/qemu-system-arm")]);
    let report = fat_emulate::preflight::PreflightReport::from_signals_with_probe(
        [
            "arch:armel",
            "fs:squashfs",
            "init:busybox",
            "web:cgi",
            "nvram:present",
        ],
        &probe,
    );
    assert_eq!(report.primary_family.family_id, "linux-router-arm");
    assert!(!report.backends.is_empty());
    assert!(report.backends[0].reason.contains("family"));
    assert!(!report
        .backends
        .iter()
        .filter(|backend| backend.is_available)
        .collect::<Vec<_>>()
        .is_empty());
    assert!(report.host_capabilities.report_id.starts_with("preflight:"));
    assert!(report
        .host_capabilities
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.report_id == report.host_capabilities.report_id));
    assert!(report
        .host_capabilities
        .backend_summaries
        .iter()
        .any(|summary| summary
            .checks
            .iter()
            .any(|check| check.subject == "qemu-system-arm")));
}

#[test]
fn test_preflight_cli_renders_ranked_report() {
    let path_dir = tempdir().expect("tempdir");
    make_executable(path_dir.path().join("qemu-system-arm"));

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args([
            "preflight",
            "--signal",
            "arch:armel",
            "--signal",
            "fs:squashfs",
            "--signal",
            "init:busybox",
            "--signal",
            "web:cgi",
            "--signal",
            "nvram:present",
        ])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("linux-router-arm"));
    assert!(stdout.contains("family linux-router-arm"));
    assert!(stdout.contains("preferred backend:"));
    assert!(stdout.contains("FirmAE [firmae] (0.95) - unavailable"));
    assert!(stdout.contains("available backends:"));
    assert!(stdout.contains("unavailable backends:"));
}

#[test]
fn test_preflight_cli_can_use_project_analysis_signals() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:mips\nfs:squashfs\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_dir = tempdir().expect("tempdir");
    make_executable(path_dir.path().join("qemu-system-mipsel"));

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env_remove("FAT_MANAGED_LINUX_VM_BUNDLE_DIR")
        .env_remove("FAT_FIRMAE_UPSTREAM_DIR")
        .env_remove("FAT_FIRMAE_HOST_PYTHON")
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("linux-router-mips"));
    assert!(stdout.contains("boot mode support: inspect-only"));
    assert!(stdout.contains("preferred backend: FirmAE [firmae]"));
    assert!(stdout.contains("missing FAT_MANAGED_LINUX_VM_BUNDLE_DIR"));
    assert!(stdout.contains("QEMU Direct [qemu-direct]"));
}

#[test]
fn test_preflight_cli_reports_true_boot_chain_support_for_coherent_project() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("coherent-project");
    let analysis_dir = project_dir.join("analysis");
    let extracted_dir = project_dir.join("extracted");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::create_dir_all(&extracted_dir).expect("extracted dir");

    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:armel\nfs:cpio\nweb:cgi\n",
    )
    .expect("signals file");
    std::fs::write(
        analysis_dir.join("bootloader.json"),
        r#"{
  "family": "u-boot",
  "version_hint": "U-Boot 2023.01",
  "env_variables": [
    {"key":"bootargs","value":"console=ttyAMA0,115200 root=/dev/mmcblk0p2 rw","source":"Observed"},
    {"key":"loadaddr","value":"0x40200000","source":"Observed"},
    {"key":"bootcmd_qfw","value":"bootz $kernel_addr_r $ramdisk_addr_r:$filesize $fdtcontroladdr","source":"Observed"}
  ],
  "flow_hints": [],
  "secure_boot_hints": [],
  "findings": []
}"#,
    )
    .expect("bootloader snapshot");
    std::fs::write(
        extracted_dir.join("u-boot.bin"),
        b"U-Boot 2023.01\0board=qemu-arm\0board_name=qemu-arm\0virtio-mmio\0",
    )
    .expect("u-boot");
    std::fs::write(extracted_dir.join("zImage"), b"zImage").expect("kernel");

    let path_dir = tempdir().expect("tempdir");
    make_executable(path_dir.path().join("qemu-system-arm"));

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("boot mode support: true-boot-chain"),
        "{stdout}"
    );
    assert!(
        stdout.contains("supported U-Boot ARM mapping to QEMU virt machine"),
        "{stdout}"
    );
}

#[test]
fn test_preflight_cli_allows_empty_project_signals() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("empty-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(analysis_dir.join("signals.txt"), "").expect("signals file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("primary family: unknown (0% confidence)"));
    assert!(stdout.contains("preferred backend: none"));
}

#[test]
fn test_preflight_cli_surfaces_incomplete_native_arm64_firmae_recipe() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    let upstream_dir = tempdir().expect("upstream dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf 'amd64\\n'; exit 0; fi\nexit 1\n",
    );
    std::fs::create_dir_all(upstream_dir.path().join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.path().join("core")).expect("core dir");
    std::fs::write(
        upstream_dir.path().join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.path().join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(
        upstream_dir.path().join("database").join("schema"),
        b"-- schema\n",
    )
    .expect("schema");
    std::fs::write(
        upstream_dir.path().join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .env("FAT_FIRMAE_UPSTREAM_DIR", upstream_dir.path())
        .env(
            "FAT_FIRMAE_HOST_PYTHON",
            project_dir.join("missing-host-python"),
        )
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "172.17.0.1")
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("preferred backend: FirmAE [firmae]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("FirmAE [firmae] (0.95) - unavailable"),
        "{stdout}"
    );
    assert!(
        stdout.contains("native FirmAE recipe incomplete"),
        "{stdout}"
    );
    assert!(stdout.contains("host diagnostics:"), "{stdout}");
}

#[test]
fn test_preflight_cli_requires_upstream_recipe_when_managed_bundle_exists() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    make_executable(path_dir.path().join("docker"));
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FirmAE [firmae] (0.95) - unavailable"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("FirmAE [firmae] (0.95) - available"),
        "{stdout}"
    );
}

#[test]
fn test_doctor_cli_requires_upstream_recipe_when_managed_bundle_exists() {
    let path_dir = tempdir().expect("path dir");
    let bundle_dir = tempdir().expect("bundle dir");
    make_executable(path_dir.path().join("docker"));
    std::fs::write(bundle_dir.path().join("base-image.qcow2"), b"image").expect("base image");
    std::fs::write(bundle_dir.path().join("guest-agent"), b"agent").expect("guest agent");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", bundle_dir.path())
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FirmAE [firmae]: unavailable"), "{stdout}");
    assert!(!stdout.contains("FirmAE [firmae]: available"), "{stdout}");
}

#[test]
fn test_preflight_cli_reports_emux_available_when_emux_recipe_is_present() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:mips\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emux_dir = dir.path().join("emux");
    write_emux_recipe(&emux_dir);
    std::fs::write(emux_dir.join("tun"), b"tun").expect("tun device");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '24.0.0\\n'; exit 0; fi\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("tun"))
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("available backends:"), "{stdout}");
    let available_section = stdout
        .split("unavailable backends:")
        .next()
        .expect("available backend section");
    assert!(available_section.contains("- EMUX [emux]:"), "{stdout}");
}

#[test]
fn test_doctor_cli_reports_emux_unavailable_when_emux_recipe_is_incomplete() {
    let dir = tempdir().expect("tempdir");
    let emux_dir = dir.path().join("emux");
    std::fs::create_dir_all(&emux_dir).expect("emux dir");
    write_executable(emux_dir.join("run-emux-docker"), "#!/bin/sh\nexit 0\n");
    std::fs::write(emux_dir.join("tun"), b"tun").expect("tun device");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '24.0.0\\n'; exit 0; fi\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("tun"))
        .arg("doctor")
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]: unavailable"), "{stdout}");
    assert!(stdout.contains("EMUX recipe incomplete"), "{stdout}");
}

#[test]
fn test_preflight_cli_reports_emux_unavailable_when_docker_runtime_is_unusable() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:mips\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emux_dir = dir.path().join("emux");
    write_emux_recipe(&emux_dir);
    std::fs::write(emux_dir.join("tun"), b"tun").expect("tun device");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then exit 1; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("tun"))
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("unavailable"), "{stdout}");
    assert!(stdout.contains("docker-runtime"), "{stdout}");
}

#[test]
fn test_preflight_cli_rejects_podman_without_explicit_rootful_opt_in() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(analysis_dir.join("signals.txt"), "arch:mips\nfs:squashfs\n")
        .expect("signals file");

    let emux_dir = dir.path().join("emux");
    write_emux_recipe(&emux_dir);
    std::fs::write(emux_dir.join("tun"), b"tun").expect("tun device");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'podman version 5.8.1\n'; exit 0; fi\nif [ \"$1\" = \"info\" ]; then exit 125; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("tun"))
        .env_remove("FAT_EMUX_ROOTFUL_PODMAN")
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("unavailable"), "{stdout}");
    assert!(stdout.contains("FAT_EMUX_ROOTFUL_PODMAN=1"), "{stdout}");
}

#[test]
fn test_preflight_cli_accepts_explicit_rootful_podman_adapter() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(analysis_dir.join("signals.txt"), "arch:mips\nfs:squashfs\n")
        .expect("signals file");

    let emux_dir = dir.path().join("emux");
    write_emux_recipe(&emux_dir);
    std::fs::write(emux_dir.join("tun"), b"tun").expect("tun device");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'podman version 5.8.1\n'; exit 0; fi\nif [ \"$1\" = \"info\" ]; then exit 125; fi\nexit 0\n",
    );
    write_executable(
        path_dir.path().join("sudo"),
        "#!/bin/sh\n[ \"$1\" = \"-n\" ] || exit 64\nshift\ncontainer_runtime=$1\nshift\n[ -x \"$container_runtime\" ] || exit 65\nif [ \"$1\" = \"info\" ]; then [ \"$#\" -eq 1 ] || exit 66; printf '5.8.1\n'; exit 0; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("tun"))
        .env("FAT_EMUX_ROOTFUL_PODMAN", "1")
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("available backends:"), "{stdout}");
    assert!(stdout.contains("- EMUX [emux]:"), "{stdout}");
}

#[test]
fn test_preflight_cli_reports_emux_unavailable_when_tun_device_is_missing() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:mips\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emux_dir = dir.path().join("emux");
    write_emux_recipe(&emux_dir);

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '24.0.0\\n'; exit 0; fi\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 0\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", &emux_dir)
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.join("missing-tun"))
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("unavailable"), "{stdout}");
    assert!(stdout.contains("tun-device"), "{stdout}");
}

#[test]
fn test_preflight_cli_requires_explicit_emux_dir_configuration() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:mips\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let path_dir = tempdir().expect("path dir");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '24.0.0\\n'; exit 0; fi\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 0\n",
    );

    let tun_path = dir.path().join("tun");
    std::fs::write(&tun_path, b"tun").expect("tun device");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env_remove("FAT_EMUX_DIR")
        .env("FAT_EMUX_TUN_DEVICE", &tun_path)
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMUX [emux]"), "{stdout}");
    assert!(stdout.contains("unavailable"), "{stdout}");
    assert!(stdout.contains("missing FAT_EMUX_DIR"), "{stdout}");
}

#[test]
fn test_preflight_cli_does_not_fallback_to_firmae_command_without_bundle() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("demo-project");
    let analysis_dir = project_dir.join("analysis");
    let upstream_dir = dir.path().join("upstream");
    std::fs::create_dir_all(&analysis_dir).expect("analysis dir");
    std::fs::create_dir_all(upstream_dir.join("database")).expect("database dir");
    std::fs::create_dir_all(upstream_dir.join("core")).expect("core dir");
    std::fs::write(
        analysis_dir.join("signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");
    std::fs::write(
        upstream_dir.join("docker-helper.py"),
        b"#!/usr/bin/env python3\n",
    )
    .expect("docker helper");
    std::fs::write(upstream_dir.join("download.sh"), b"#!/bin/sh\n").expect("download");
    std::fs::write(upstream_dir.join("database").join("schema"), b"-- schema\n").expect("schema");
    std::fs::write(
        upstream_dir.join("core").join("Dockerfile"),
        b"FROM ubuntu:24.04\n",
    )
    .expect("dockerfile");

    let path_dir = tempdir().expect("path dir");
    make_executable(path_dir.path().join("firmae"));
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf 'arm64\\n'; exit 0; fi\nexit 1\n",
    );
    let host_python = path_dir.path().join("python3");
    make_executable(host_python.clone());

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env_remove("FAT_MANAGED_LINUX_VM_BUNDLE_DIR")
        .env("FAT_FIRMAE_UPSTREAM_DIR", &upstream_dir)
        .env("FAT_FIRMAE_HOST_PYTHON", &host_python)
        .env("FAT_FIRMAE_DOCKER_PSQL_IP", "host.docker.internal")
        .args(["preflight", project_dir.to_str().expect("project path")])
        .output()
        .expect("fat preflight runs");

    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FirmAE [firmae] (0.95) - unavailable"),
        "{stdout}"
    );
    assert!(
        stdout.contains("missing FAT_MANAGED_LINUX_VM_BUNDLE_DIR"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("FirmAE [firmae] (0.95) - available"),
        "{stdout}"
    );
}

fn make_executable(path: PathBuf) {
    write_executable(path, "#!/bin/sh\nexit 0\n");
}

fn write_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}

fn write_emux_recipe(root: &Path) {
    std::fs::create_dir_all(root.join("files/emux/run")).expect("recipe dirs");
    write_executable(root.join("run-emux-docker"), "#!/bin/sh\nexit 0\n");
    write_executable(root.join("emux-docker-shell"), "#!/bin/sh\nexit 0\n");
    std::fs::write(root.join("tun"), b"").expect("tun marker");
    for script in [
        "launcher",
        "userspace",
        "emuxps",
        "emuxmaps",
        "emuxnetstat",
        "emuxgdb",
        "monitor",
    ] {
        write_executable(
            root.join("files/emux/run").join(script),
            "#!/bin/sh\nexit 0\n",
        );
    }
}
