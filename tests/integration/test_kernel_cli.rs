use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fat_core::kernel_system::{
    ArtifactFile, KernelArtifactBundleManifest, KernelClass, SupportTier,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn fat(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .output()
        .expect("run fat")
}

fn digest(content: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(content))
}

fn write_artifact(root: &Path, name: &str, content: &[u8], role: &str) -> ArtifactFile {
    fs::write(root.join(name), content).expect("write artifact");
    ArtifactFile {
        path: name.into(),
        digest: digest(content),
        role: role.into(),
    }
}

fn bundle(root: &Path) -> KernelArtifactBundleManifest {
    KernelArtifactBundleManifest {
        schema_version: "1.0".into(),
        id: String::new(),
        recipe_id: "krc-0123456789abcdef".into(),
        class: KernelClass::Mips32O32LeR1Page4k,
        support_tier: SupportTier::Experimental,
        source_lock_id: "ksl-0123456789abcdef".into(),
        builder_id: "kbi-0123456789abcdef".into(),
        kernel_image: write_artifact(root, "vmlinux", b"kernel", "kernel-image"),
        final_config: write_artifact(root, "config.final", b"CONFIG_TEST=y\n", "kernel-config"),
        build_log: write_artifact(root, "build.log", b"ok\n", "build-log"),
        declared_files: vec![],
        attribution: vec![],
        recipe_reproducible: true,
        bit_reproducible: false,
    }
    .seal()
    .expect("bundle")
}

#[test]
fn kernel_recipes_lists_the_three_checked_in_tier_a_classes() {
    let output = fat(&["kernel", "recipes", "--json"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(value["recipes"].as_array().unwrap().len(), 3);
}

#[test]
fn kernel_verify_install_list_and_show_are_one_consistent_workflow() {
    let source = tempdir().expect("source");
    let store = tempdir().expect("store");
    let manifest = bundle(source.path());
    let manifest_path = source.path().join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let verify = fat(&[
        "kernel",
        "verify",
        "--bundle",
        source.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let install = fat(&[
        "kernel",
        "install",
        "--bundle",
        source.path().to_str().unwrap(),
        "--store",
        store.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );

    let list = fat(&[
        "kernel",
        "list",
        "--store",
        store.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(list.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed["bundles"][0]["id"], manifest.id);

    let show = fat(&[
        "kernel",
        "show",
        "--store",
        store.path().to_str().unwrap(),
        "--id",
        &manifest.id,
        "--json",
    ]);
    assert!(show.status.success());
    let shown: KernelArtifactBundleManifest = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(shown, manifest);
}

#[test]
fn kernel_verify_fails_closed_after_tampering() {
    let source = tempdir().expect("source");
    let manifest = bundle(source.path());
    fs::write(
        source.path().join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(source.path().join("vmlinux"), b"tampered").unwrap();

    let output = fat(&[
        "kernel",
        "verify",
        "--bundle",
        source.path().to_str().unwrap(),
        "--json",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("artifact-digest-mismatch"));
}

#[test]
fn kernel_promotion_cli_emits_content_addressed_not_promoted_evidence() {
    let temp = tempdir().expect("request");
    let bundle_dir = temp.path().join("bundle");
    fs::create_dir(&bundle_dir).unwrap();
    let manifest = bundle(&bundle_dir);
    fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let request = temp.path().join("promotion.json");
    fs::write(
        &request,
        serde_json::to_vec_pretty(&serde_json::json!({
            "policy": {
                "schema_version": "1.0",
                "id": "kernel-promotion-v1",
                "minimum_distinct_vendors": 2,
                "minimum_distinct_targets": 2,
                "minimum_distinct_families": 2,
                "minimum_fixture_machines": 2,
                "require_holdout": true,
                "maximum_semantic_risk": "medium"
            },
            "evidence": {
                "class": "mips32-o32-le-r1-page4k",
                "bundle_id": manifest.id,
                "artifact_verified": true,
                "fixtures": [],
                "experiments": []
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let output = fat(&[
        "kernel",
        "evaluate-promotion",
        "--request",
        request.to_str().unwrap(),
        "--bundle",
        bundle_dir.to_str().unwrap(),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "not-promoted");
    assert!(value["id"].as_str().unwrap().starts_with("kpr-"));
    assert!(value["missing_predicates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "vendor-breadth"));
}

#[test]
fn kernel_promotion_cli_rejects_a_forged_bundle_binding() {
    let temp = tempdir().expect("request");
    let bundle_dir = temp.path().join("bundle");
    fs::create_dir(&bundle_dir).unwrap();
    let manifest = bundle(&bundle_dir);
    fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let request = temp.path().join("promotion.json");
    fs::write(
        &request,
        serde_json::to_vec_pretty(&serde_json::json!({
            "policy": {
                "schema_version": "1.0",
                "id": "kernel-promotion-v1",
                "minimum_distinct_vendors": 2,
                "minimum_distinct_targets": 2,
                "minimum_distinct_families": 2,
                "minimum_fixture_machines": 2,
                "require_holdout": true,
                "maximum_semantic_risk": "medium"
            },
            "evidence": {
                "class": "mips32-o32-be-r1-page4k",
                "bundle_id": manifest.id,
                "artifact_verified": true,
                "fixtures": [],
                "experiments": []
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let output = fat(&[
        "kernel",
        "evaluate-promotion",
        "--request",
        request.to_str().unwrap(),
        "--bundle",
        bundle_dir.to_str().unwrap(),
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("binding does not match"));
}

#[test]
fn emulate_exposes_only_declared_kernel_class_assertions() {
    let help = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--help"])
        .output()
        .expect("emulate help");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("--kernel-class"));
    assert!(stdout.contains("mips32-o32-le-r1-page4k"));

    let invalid = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["emulate", "--kernel-class", "mipsel-best-effort"])
        .output()
        .expect("invalid class validation");
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid value"));
}
