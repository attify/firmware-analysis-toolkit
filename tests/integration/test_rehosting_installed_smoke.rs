use std::fs;
use std::path::Path;
use std::process::Command;

use fat_core::rehosting::{ReadinessReport, RuntimeSurfaceRecord, SurfaceReadiness};
use fat_core::rehosting_pack::{parse_rehosting_pack_yaml, validate_rehosting_pack};
use fat_core::rehosting_pack_overlay::PackOverlay;
use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_emulate::validators::{apply_runtime_validation, RuntimeValidationSnapshot};

const PACK: &str = r#"id: acme/router
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  signals: ["fs:squashfs", "init:busybox"]
  paths: ["/etc/init.d/rcS"]
runtime:
  network:
    interface: eth0
    mode: dhcp
repairs:
  init:
    materialize_paths: ["/configs"]
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: rcS-ready
caveats: ["hermetic installed-layout smoke test"]
"#;

#[test]
fn installed_pack_is_discovered_applied_and_validated_outside_the_checkout() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let binary = prefix.join("bin/fat");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_fat"), &binary).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
    }
    // The pack lives where the operator put it, not inside the installation.
    let chosen_packs = temp.path().join("operator-packs");
    let pack_path = chosen_packs.join("router.yaml");
    fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
    fs::write(&pack_path, PACK).unwrap();
    let project = temp.path().join("project");
    let rootfs = project.join("work/rootfs");
    fs::create_dir_all(rootfs.join("etc/init.d")).unwrap();
    fs::create_dir_all(project.join("analysis")).unwrap();
    fs::create_dir_all(project.join("input")).unwrap();
    fs::write(rootfs.join("etc/init.d/rcS"), "#!/bin/sh\n").unwrap();
    fs::write(
        project.join("analysis/signals.txt"),
        "arch:armel\nfs:squashfs\ninit:busybox\n",
    )
    .unwrap();
    fs::write(project.join("input/firmware.bin"), b"firmware").unwrap();
    fs::write(
        project.join("work/extraction-manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "rootfs_path": rootfs,
            "kernel_paths": [],
            "file_count": 1
        }))
        .unwrap(),
    )
    .unwrap();
    let unrelated = temp.path().join("unrelated");
    fs::create_dir_all(&unrelated).unwrap();

    let output = Command::new(&binary)
        .args(["rehost", "match"])
        .arg(&project)
        .arg("--json")
        .current_dir(&unrelated)
        .env_remove("FAT_DATA_DIR")
        .env("FAT_REHOSTING_PACKS", &chosen_packs)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows[0]["id"], "acme/router");
    assert_eq!(rows[0]["is_match"], true);
    assert_eq!(rows[0]["matched_paths"][0], "/etc/init.d/rcS");

    let pack = parse_rehosting_pack_yaml(&fs::read_to_string(&pack_path).unwrap()).unwrap();
    assert!(validate_rehosting_pack(&pack).valid);
    let overlay = PackOverlay::from_pack(&pack);
    let mut recipe = RehostingRecipe::new(
        "target",
        "model",
        "run",
        "emulate",
        SubstratePreference::Auto,
        SubstrateKind::System,
    );
    overlay.apply_to_recipe(&mut recipe);
    assert_eq!(
        recipe.network.as_ref().unwrap().mode.as_deref(),
        Some("dhcp")
    );
    assert_eq!(recipe.filesystem_transforms[0].destination, "/configs");
    assert!(recipe.rehosting_capability.as_ref().unwrap().is_degraded());

    let readiness = ReadinessReport::new(
        "project",
        "target",
        "session",
        "run",
        vec!["init-handoff".into()],
        vec![RuntimeSurfaceRecord::new(
            "project",
            "target",
            "session",
            "run",
            "serial",
            "monitor",
            "serial",
            SurfaceReadiness::Ready,
        )],
    );
    let validated = apply_runtime_validation(
        &recipe,
        &readiness,
        &RuntimeValidationSnapshot {
            serial_log: "boot rcS-ready".into(),
            ..Default::default()
        },
    );
    assert!(validated.validated_goals.contains(&"init-handoff".into()));
    assert!(Path::new(&pack_path).starts_with(&chosen_packs));
}
